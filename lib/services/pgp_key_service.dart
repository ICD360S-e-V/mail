import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart';
import 'package:dart_pg/src/common/config.dart' as pgp_config;
import 'package:enough_mail/enough_mail.dart';
import 'package:flutter/foundation.dart' show compute, listEquals;

import 'logger_service.dart';
import 'certificate_service.dart';
import 'master_vault.dart';
import 'mtls_client_pool.dart';
import 'mtls_service.dart';
import 'pgp_isolate_worker.dart';
import 'le_issuer_check.dart';
import 'pgp_sync_service.dart';
import 'pinned_security_context.dart';

/// OpenPGP E2EE — key management + encrypt/decrypt (dart_pg 2.x API).
///
/// v2.41.0: Per-account PGP keys. Each account gets its own Ed25519/X25519
/// keypair stored in the vault under `pgp_private_key_v1_{email}`.
/// Previously was a singleton — only one key for all 36 accounts,
/// and only the first account's key was ever uploaded.
class PgpKeyService {
  static const _vaultKeyPrivatePrefix = 'pgp_private_key_v1';
  static const _vaultKeyV6Backup = 'pgp_private_key_v6_backup';
  static const _vaultKeyPassphrase = 'pgp_passphrase_v1';
  static const _uploadEndpoint =
      'https://mail.icd360s.de/api/upload-pubkey.php';
  static const _pubkeyEndpoint = 'https://mail.icd360s.de/api/pubkeys';

  // Per-account key caches (email → key)
  static final Map<String, dynamic> _privateKeys = {};
  static final Map<String, dynamic> _publicKeys = {};
  static final Map<String, Future<dynamic>> _keyGenFutures = {};

  // The "active" account for decrypt operations (set by the currently
  // selected account in the UI — decrypt worker uses this key).
  static String? _activeEmail;
  static dynamic get _cachedPrivateKey => _activeEmail != null ? _privateKeys[_activeEmail] : null;
  static dynamic get _cachedPublicKey => _activeEmail != null ? _publicKeys[_activeEmail] : null;

  // Background isolate worker for non-blocking decrypt
  static PgpIsolateWorker? _worker;

  // Recipient key cache (RAM only) with 5-minute TTL. Without a TTL
  // an app session that cached the recipient's OLD pubkey before the
  // recipient's device republished would keep encrypting to the stale
  // key forever — decryption on the receiver fails with "Bad state:
  // Decryption failed" even after server-side pubkey reconciliation.
  static final Map<String, dynamic> _recipientKeyCache = {};
  static final Map<String, DateTime> _recipientKeyCacheAt = {};
  static const _recipientCacheTtl = Duration(minutes: 5);
  // Negative cache: tracks failed lookups to avoid hammering the server,
  // but expires after 30s so keys uploaded during the session are found.
  static final Map<String, DateTime> _negativeCache = {};

  // TOFU: first-seen fingerprint per email (key substitution protection)
  static final Map<String, List<int>> _tofuFingerprints = {};

  /// Vault key for a specific account's private PGP key.
  static String _vaultKey(String email) =>
      '${_vaultKeyPrivatePrefix}_${email.toLowerCase()}';

  // ── Key Management ───────────────────────────────────────────────

  static Future<dynamic> getOrCreatePrivateKey(String email) {
    final key = email.toLowerCase();
    return _keyGenFutures[key] ??= _doGetOrCreate(email).whenComplete(() {
      _keyGenFutures.remove(key);
    });
  }

  static Future<dynamic> _doGetOrCreate(String email) async {
    final key = email.toLowerCase();

    // Return cached key if already loaded for this account
    if (_privateKeys.containsKey(key)) return _privateKeys[key];

    final vault = MasterVault.instance;
    final passphrase = await _getOrCreatePassphrase();

    // Try account-specific vault key first, then legacy singleton key
    var existingArmor = await vault.read(key: _vaultKey(email));
    if (existingArmor == null) {
      // Migration: check legacy singleton key (pre-v2.41.0)
      existingArmor = await vault.read(key: 'pgp_private_key_v1');
      if (existingArmor != null) {
        // Migrate: save under account-specific key
        await vault.write(key: _vaultKey(email), value: existingArmor);
        LoggerService.log('PGP', 'Migrated legacy PGP key to per-account for $email');
      }
    }

    if (existingArmor != null) {
      try {
        final privateKey = OpenPGP.decryptPrivateKey(existingArmor, passphrase);

        // MIGRATION: v6 keys (Ed25519/X25519) use AEAD/OCB which has a
        // confirmed dart_pg bug: MAC check fails on multi-chunk messages
        // (>~2KB). Regenerate as v4 keys (EdDSA legacy/ECDH) which use
        // CFB+MDC (SEIPD v1) — no AEAD, no OCB bug.
        if (privateKey.publicKey.aeadSupported) {
          LoggerService.log('PGP',
              '⚠ Detected v6 key for $email (AEAD-capable) — migrating to v4');
          // Backup v6 key for decrypting old messages
          final v6Backup = await vault.read(key: '${_vaultKeyV6Backup}_$key');
          if (v6Backup == null) {
            await vault.write(key: '${_vaultKeyV6Backup}_$key', value: existingArmor);
            LoggerService.log('PGP', 'v6 key backed up for decrypt fallback');
          }
          // Fall through to key generation below (will create v4 key)
        } else {
          _privateKeys[key] = privateKey;
          _publicKeys[key] = privateKey.publicKey;
          if (_activeEmail == null) {
            _activeEmail = key;
            await _startWorker(existingArmor, passphrase);
          }
          LoggerService.log('PGP', 'Loaded existing v4 PGP key for $email');
          return privateKey;
        }
      } catch (ex) {
        LoggerService.logWarning('PGP', 'Failed to load PGP key for $email: $ex');
      }
    }

    // NEW DEVICE FLOW: vault is empty — try fetching an existing key from the
    // sync server before generating a brand-new one.
    try {
      final syncedArmor = await PgpSyncService.downloadAndDecrypt(email);
      if (syncedArmor != null) {
        final privateKey = OpenPGP.decryptPrivateKey(syncedArmor, passphrase);
        if (privateKey.publicKey.aeadSupported) {
          LoggerService.log('PGP',
              '⚠ Sync server returned v6 key for $email — discarding, will generate v4');
          final v6Backup = await vault.read(key: '${_vaultKeyV6Backup}_$key');
          if (v6Backup == null) {
            await vault.write(key: '${_vaultKeyV6Backup}_$key', value: syncedArmor);
            LoggerService.log('PGP', 'v6 sync key backed up for decrypt fallback');
          }
        } else {
          LoggerService.log('PGP', 'Fetched PGP key from sync server for $email (new device)');
          await vault.write(key: _vaultKey(email), value: syncedArmor);
          _privateKeys[key] = privateKey;
          _publicKeys[key] = privateKey.publicKey;
          if (_activeEmail == null) {
            _activeEmail = key;
            await _startWorker(syncedArmor, passphrase);
          }
          return privateKey;
        }
      }
      LoggerService.log('PGP', 'No key blob on sync server for $email — will generate new key');
    } catch (ex) {
      LoggerService.logWarning('PGP',
          'PgpSyncService.downloadAndDecrypt failed for $email (falling back to local gen): $ex');
    }

    // FIRST DEVICE FLOW (or v6→v4 migration): generate a fresh v4 keypair.
    // v4 keys use EdDSA legacy + ECDH (Curve25519) — no AEAD/SEIPD v2,
    // avoiding dart_pg's OCB bug on multi-chunk messages.
    LoggerService.log('PGP', 'Generating v4 EdDSA/ECDH keypair for $email...');
    final privateKey = await compute(_generateKeyIsolate, [email, passphrase]);

    final armoredKey = privateKey.armor();
    await vault.write(key: _vaultKey(email), value: armoredKey);
    _privateKeys[key] = privateKey;
    _publicKeys[key] = privateKey.publicKey;
    if (_activeEmail == null) {
      _activeEmail = key;
      await _startWorker(armoredKey, passphrase);
    }

    // Upload encrypted blob so other devices can fetch this key.
    try {
      await PgpSyncService.encryptAndUpload(email, armoredKey);
      LoggerService.log('PGP', 'PGP key blob uploaded to sync server for $email');
    } catch (ex) {
      LoggerService.logWarning('PGP',
          'PgpSyncService.encryptAndUpload failed for $email (key still saved locally): $ex');
    }

    await _uploadPublicKey(privateKey.publicKey, email);
    LoggerService.log('PGP', '✓ PGP keypair generated and uploaded for $email');
    return privateKey;
  }

  // ── Migration ────────────────────────────────────────────────────

  /// Reconcile local vault keys with the sync server: for each account
  /// that has a local key but no server blob yet, upload it. Idempotent —
  /// safe to call on every startup. Accounts added later, or accounts
  /// whose upload failed on a previous run (e.g. transient 401), get
  /// synced the next time this runs.
  static Future<void> migrateExistingKeysToServer(
      List<dynamic> accounts) async {
    final passphrase = await _getOrCreatePassphrase();
    for (final account in accounts) {
      final email = (account.username as String).toLowerCase();
      try {
        // Skip if we have no local key for this account.
        final existingArmor =
            await MasterVault.instance.read(key: _vaultKey(email));
        if (existingArmor == null) continue;

        // 1) Upload the encrypted private-key blob if not on server yet.
        final alreadySynced = await PgpSyncService.hasServerBlob(email);
        if (!alreadySynced) {
          await PgpSyncService.encryptAndUpload(email, existingArmor);
          LoggerService.log('PGP',
              'Migration: uploaded PGP blob to sync server for $email');
        }

        // 2) Republish our local public key to the server unconditionally.
        //    Earlier attempts tried to detect a mismatch and only republish
        //    on diff — but dart_pg's armor() is not byte-stable across
        //    parse→serialize (whitespace / headers / comment lines differ),
        //    and checking only the primary fingerprint missed subkey
        //    rotations (OpenPGP v6 encrypts to the ENCRYPTION SUBKEY, not
        //    the primary). The result was either a false-negative (skip
        //    republish while the subkey actually differed → decryption
        //    failed on recipients) or a false-positive (republish every
        //    startup anyway).
        //
        //    Unconditional republish is idempotent on the server side
        //    (writes the same file) and only runs once per app startup.
        //    Safe in our deployment because at most one device owns the
        //    private key per account, so there's no inter-device race over
        //    who the authoritative pubkey should be.
        try {
          final local = OpenPGP.decryptPrivateKey(existingArmor, passphrase);
          _recipientKeyCache.remove(email);
          _recipientKeyCacheAt.remove(email);
          _negativeCache.remove(email);
          await _uploadPublicKey(local.publicKey, email);
        } catch (ex) {
          LoggerService.logWarning('PGP',
              'Migration: pubkey republish failed for $email (non-fatal): $ex');
        }
      } catch (ex) {
        LoggerService.logWarning('PGP',
            'Migration: failed to upload blob for $email (non-fatal): $ex');
      }
    }
  }

  static Future<dynamic> getPublicKey(String email) async {
    final key = email.toLowerCase();
    if (_publicKeys.containsKey(key)) return _publicKeys[key];
    final priv = await getOrCreatePrivateKey(email);
    return priv.publicKey;
  }

  /// Set the active account for decrypt operations.
  /// Call when user selects an account in the UI.
  static Future<void> setActiveAccount(String email) async {
    final key = email.toLowerCase();
    if (_activeEmail == key) return;
    // Ensure the private key is actually loaded before switching.
    // Race observed in the wild: during startup the FIRST account to
    // finish loading sets _activeEmail and starts the worker. If the
    // UI (or selectFolder) calls setActiveAccount for a DIFFERENT
    // account before that account's load has populated _privateKeys,
    // the old flow saw priv == null, skipped _startWorker, but still
    // flipped _activeEmail — leaving the worker running on the wrong
    // account's private key. Every incoming encrypted mail then
    // failed with "Bad state: Decryption failed" even though the
    // local private key and server pubkey were consistent.
    final priv = _privateKeys[key] ?? await getOrCreatePrivateKey(email);
    _activeEmail = key;
    if (priv != null) {
      final passphrase = await _getOrCreatePassphrase();
      await _startWorker(priv.armor(), passphrase);
      LoggerService.log('PGP', 'Switched active decrypt key to $email');
    } else {
      LoggerService.logWarning('PGP',
          'setActiveAccount: no private key available for $email — worker NOT switched');
    }
  }

  static void clearCache() {
    _privateKeys.clear();
    _publicKeys.clear();
    _activeEmail = null;
    _recipientKeyCache.clear();
    _recipientKeyCacheAt.clear();
    _negativeCache.clear();
    _worker?.close();
    _worker = null;
    LoggerService.log('PGP', 'PGP key cache + worker cleared');
  }

  // ── Decrypt (via background isolate worker) ───────────────────────

  /// Decrypt a single PGP message. Runs on background isolate.
  static Future<String> decrypt(String armoredCiphertext) async {
    if (_worker == null) {
      throw StateError('PGP worker not started — unlock vault first');
    }
    final results = await _worker!.decryptBatch([armoredCiphertext]);
    final plaintext = results.first;
    if (plaintext == null) throw StateError('Decryption failed');
    return plaintext;
  }

  /// Decrypt a batch of PGP messages. One isolate call, zero UI blocking.
  static Future<List<String?>> decryptBatch(List<String> ciphertexts) async {
    if (_worker == null) {
      throw StateError('PGP worker not started — unlock vault first');
    }
    return _worker!.decryptBatch(ciphertexts);
  }

  /// Start the background decrypt worker with optional v6 fallback key.
  static Future<void> _startWorker(String armoredKey, String passphrase) async {
    _worker?.close();
    // Load v6 backup key for decrypting old messages (pre-migration)
    final email = _activeEmail ?? '';
    String? v6Backup;
    try {
      v6Backup = await MasterVault.instance.read(key: '${_vaultKeyV6Backup}_$email');
    } catch (_) {}
    _worker = await PgpIsolateWorker.spawn(
      armoredKey: armoredKey,
      passphrase: passphrase,
      fallbackArmoredKey: v6Backup,
    );
    _worker!.diagCallback = (msg) => LoggerService.log('PGP_WORKER', msg);
    LoggerService.log('PGP', '✓ Decrypt worker started${v6Backup != null ? " (with v6 fallback)" : ""}');
  }

  // ── PGP/MIME Detection + Extraction ──────────────────────────────

  static String? extractPgpCiphertext(MimeMessage message) {
    final ct = message.getHeaderContentType();
    if (ct == null) return null;

    // RFC 3156: multipart/encrypted has exactly 2 parts:
    //   Part 1: application/pgp-encrypted (just "Version: 1")
    //   Part 2: application/octet-stream (the actual PGP ciphertext)
    // We only want Part 2.
    if (ct.mediaType.sub == MediaSubtype.multipartEncrypted) {
      for (final part in message.allPartsFlat) {
        if (part.mediaType.sub == MediaSubtype.applicationOctetStream) {
          final text = part.decodeContentText();
          if (text != null && text.contains('-----BEGIN PGP MESSAGE-----')) {
            final cleaned = _cleanArmor(text);
            LoggerService.log('PGP',
                'Extracted PGP ciphertext: ${cleaned.length} chars');
            return cleaned;
          }
        }
      }
    }

    final body = message.decodeTextPlainPart() ?? '';
    if (body.contains('-----BEGIN PGP MESSAGE-----')) return _cleanArmor(body);
    return null;
  }

  /// Clean armored PGP text extracted from MIME parts.
  /// enough_mail's decodeContentText() can leave \r line endings,
  /// leading/trailing whitespace, or BOM bytes that make dart_pg's
  /// base64 parser throw FormatException at the armor header.
  static String _cleanArmor(String raw) {
    // Extract just the PGP block (drop any MIME preamble / trailing boundary)
    final start = raw.indexOf('-----BEGIN PGP MESSAGE-----');
    final end = raw.indexOf('-----END PGP MESSAGE-----');
    if (start < 0 || end < 0) return raw.trim();
    // Include the trailing \n after the END marker — it's part of the
    // armor format. Missing it drops 1 byte which breaks OCB MAC on
    // large messages. Server has N bytes, we must extract exactly N.
    var endIdx = end + '-----END PGP MESSAGE-----'.length;
    if (endIdx < raw.length && (raw[endIdx] == '\n' || raw[endIdx] == '\r')) {
      endIdx++; // include trailing newline
      if (endIdx < raw.length && raw[endIdx] == '\n') {
        endIdx++; // \r\n case: include both
      }
    }
    final block = raw.substring(start, endIdx);
    // Normalize line endings: \r\n → \n, stray \r → \n
    return block.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
  }

  static bool isPgpEncryptedHeaders(Map<String, String> headers) {
    final ct = headers['content-type'] ?? headers['Content-Type'] ?? '';
    return ct.contains('multipart/encrypted') ||
        ct.contains('application/pgp-encrypted');
  }

  // ── Recipient Key Discovery ──────────────────────────────────────

  static Future<dynamic> fetchRecipientKey(String email,
      {String? senderEmail, bool forceRefresh = false}) async {
    if (!email.endsWith('@icd360s.de')) return null;

    final key = email.toLowerCase();
    if (forceRefresh) {
      _recipientKeyCache.remove(key);
      _recipientKeyCacheAt.remove(key);
      _negativeCache.remove(key);
    }
    final cached = _recipientKeyCache[key];
    final cachedAt = _recipientKeyCacheAt[key];
    if (cached != null &&
        cachedAt != null &&
        DateTime.now().difference(cachedAt) < _recipientCacheTtl) {
      return cached;
    }
    if (cached != null) {
      _recipientKeyCache.remove(key);
      _recipientKeyCacheAt.remove(key);
    }

    // Negative cache: don't re-fetch within 30s of a miss
    final lastMiss = _negativeCache[key];
    if (lastMiss != null && DateTime.now().difference(lastMiss).inSeconds < 30) {
      return null;
    }

    final username = email.split('@').first;
    final url = Uri(
      scheme: 'https',
      host: 'mail.icd360s.de',
      path: '/api/pubkeys/${Uri.encodeComponent(username)}.asc',
    );

    try {
      // /api/pubkeys requires mTLS (any valid client cert). Prefer the
      // sender's pooled client when we know who's composing, so we never
      // depend on the shared global SecurityContext that Android races.
      HttpClient? client;
      if (senderEmail != null) {
        try {
          client = await MtlsClientPool.instance.get(senderEmail);
          LoggerService.log('PGP', 'Key fetch using mTLS pool for $senderEmail');
        } catch (e) {
          LoggerService.logWarning('PGP',
              'mTLS pool failed for $senderEmail (falling back): $e');
          client = null;
        }
      }
      client ??= MtlsService.createMtlsHttpClient() ??
          (PinnedSecurityContext.createHttpClient()
            ..badCertificateCallback = (cert, host, port) {
              if (host == 'mail.icd360s.de') {
                return isTrustedLetsEncryptIssuer(cert.issuer);
              }
              return false;
            });

      final request =
          await client.getUrl(url).timeout(const Duration(seconds: 8));
      final response =
          await request.close().timeout(const Duration(seconds: 8));

      if (response.statusCode != 200) {
        final errBody = await response.transform(utf8.decoder).join();
        // Pool owns client when senderEmail path was taken; closing an
        // already-pooled client would break future requests. Only close
        // the fallback (non-pooled) clients.
        LoggerService.logWarning('PGP',
            'Key fetch HTTP ${response.statusCode} for $email: $errBody');
        _negativeCache[key] = DateTime.now();
        return null;
      }

      final armored = await response.transform(utf8.decoder).join();

      final pubKey = OpenPGP.readPublicKey(armored);

      // TOFU: check fingerprint consistency
      final fpr = List<int>.from(pubKey.fingerprint as Iterable<int>);
      final prevFpr = _tofuFingerprints[key];
      if (prevFpr != null && !listEquals(fpr, prevFpr)) {
        LoggerService.logWarning('PGP',
            '⚠ KEY CHANGED for $email! Previous fingerprint differs. '
            'Possible key substitution attack.');
        // Still use the new key but warn — full KT is out of scope
      }
      _tofuFingerprints[key] = fpr;

      _recipientKeyCache[key] = pubKey;
      _recipientKeyCacheAt[key] = DateTime.now();
      LoggerService.log('PGP', '✓ Fetched key for $email');
      return pubKey;
    } catch (ex) {
      LoggerService.logWarning('PGP', 'Key fetch failed for $email: $ex');
      _negativeCache[key] = DateTime.now();
      return null;
    }
  }

  static Future<Map<String, dynamic>> lookupAllRecipients(
      List<String> emails,
      {String? senderEmail, bool forceRefresh = false}) async {
    final results = <String, dynamic>{};
    await Future.wait(emails.map((email) async {
      results[email] = await fetchRecipientKey(email,
          senderEmail: senderEmail, forceRefresh: forceRefresh);
    }));
    return results;
  }

  // ── PGP/MIME Outbound (RFC 3156) ─────────────────────────────────

  /// Build RFC 3156 PGP/MIME. Encrypts innerMimeBody (body MIME tree
  /// WITHOUT transport headers) to all recipients + self.
  static Future<String> buildPgpMimeMessage({
    required String from,
    required String to,
    String cc = '',
    required String subject,
    required String date,
    required String messageId,
    required String innerMimeBody,
    required List<dynamic> recipientKeys,
  }) async {
    if (_cachedPrivateKey == null || _cachedPublicKey == null) {
      throw StateError('PGP keys not loaded');
    }

    // Encrypt to all recipients + self (fingerprint compared by content)
    final allKeys = <dynamic>[...recipientKeys];
    final selfFpr = List<int>.from(
        _cachedPublicKey.fingerprint as Iterable<int>);
    final alreadyHasSelf = allKeys.any((k) {
      final fpr = List<int>.from(k.fingerprint as Iterable<int>);
      return listEquals(fpr, selfFpr);
    });
    if (!alreadyHasSelf) allKeys.add(_cachedPublicKey);

    // Encrypt on background isolate (Proton/Tuta pattern: never block UI).
    // Serialize keys to armored strings — Isolate boundary cannot transfer
    // dart_pg key objects (they contain closures/FFI handles).
    final armoredKeys = allKeys.map((k) => k.armor() as String).toList();
    final ciphertext = await compute(_encryptIsolate, [
      innerMimeBody,
      ...armoredKeys,
    ]);

    // RFC 2047 encode subject if non-ASCII
    final encodedSubject = _rfc2047Encode(subject);

    // Build outer wrapper with CRLF line endings (RFC 5321)
    final boundary = 'pgp-${DateTime.now().millisecondsSinceEpoch}';
    final buf = StringBuffer()
      ..write('MIME-Version: 1.0\r\n')
      ..write('Date: $date\r\n')
      ..write('Message-ID: $messageId\r\n')
      ..write('From: $from\r\n')
      ..write('To: $to\r\n');
    if (cc.isNotEmpty) buf.write('Cc: $cc\r\n');
    // BCC intentionally omitted — SMTP envelope handles delivery
    buf
      ..write('Subject: $encodedSubject\r\n')
      ..write('Content-Type: multipart/encrypted;\r\n')
      ..write('\tprotocol="application/pgp-encrypted";\r\n')
      ..write('\tboundary="$boundary"\r\n')
      ..write('\r\n')
      ..write('This is an OpenPGP/MIME encrypted message (RFC 3156).\r\n')
      ..write('\r\n')
      ..write('--$boundary\r\n')
      ..write('Content-Type: application/pgp-encrypted\r\n')
      ..write('Content-Description: PGP/MIME version identification\r\n')
      ..write('\r\n')
      ..write('Version: 1\r\n')
      ..write('\r\n')
      ..write('--$boundary\r\n')
      ..write('Content-Type: application/octet-stream\r\n')
      ..write('Content-Transfer-Encoding: 7bit\r\n')
      ..write('Content-Description: OpenPGP encrypted message\r\n')
      ..write('Content-Disposition: inline; filename="encrypted.asc"\r\n')
      ..write('\r\n')
      ..write(ciphertext)
      ..write('\r\n')
      ..write('--$boundary--\r\n');

    return buf.toString();
  }

  // ── Isolate-safe functions (must be top-level or static) ────────

  /// Key generation for compute() — must be static, not a lambda.
  /// Uses v4 ECC (EdDSA legacy + ECDH/Curve25519) instead of v6
  /// (Ed25519/X25519) to avoid dart_pg's AEAD/OCB multi-chunk bug.
  static dynamic _generateKeyIsolate(List<String> args) {
    return OpenPGP.generateKey(
      [args[0]],
      args[1],
      type: KeyType.ecc,
      curve: Ecc.ed25519,
    );
  }

  /// PGP encryption on background isolate — prevents UI freeze on large
  /// messages (5-7MB with attachments caused 10-30s freeze on Android).
  /// args[0] = plaintext MIME body, args[1..N] = armored public keys.
  static String _encryptIsolate(List<String> args) {
    final plaintext = args[0];
    final armoredKeys = args.sublist(1);
    final keys = armoredKeys.map((a) => OpenPGP.readPublicKey(a)).toList();
    pgp_config.Config.aeadProtect = false;
    final encrypted = OpenPGP.encryptBinaryData(
      Uint8List.fromList(utf8.encode(plaintext)),
      encryptionKeys: keys,
    );
    return encrypted.armor();
  }

  // ── Helpers ──────────────────────────────────────────────────────

  static String _rfc2047Encode(String text) {
    // Check if encoding needed (non-ASCII chars)
    if (text.codeUnits.every((c) => c < 128)) return text;
    final bytes = utf8.encode(text);
    final b64 = base64.encode(bytes);
    return '=?UTF-8?B?$b64?=';
  }

  static Future<String> _getOrCreatePassphrase() async {
    final vault = MasterVault.instance;
    var passphrase = await vault.read(key: _vaultKeyPassphrase);
    if (passphrase == null) {
      final rng = Random.secure();
      final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
      passphrase =
          bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      await vault.write(key: _vaultKeyPassphrase, value: passphrase);
    }
    return passphrase;
  }

  static Future<void> _uploadPublicKey(dynamic key, String email) async {
    try {
      // Use MtlsClientPool — per-account HttpClient avoids the global
      // SecurityContext race that made uploads pick up whichever cert
      // was loaded last.
      final client = await MtlsClientPool.instance.get(email);
      final request = await client
          .postUrl(Uri.parse(_uploadEndpoint))
          .timeout(const Duration(seconds: 15));
      request.headers.set('Content-Type', 'application/json');
      request.write(jsonEncode({
        'email': email,
        'public_key': key.armor(),
      }));

      final response =
          await request.close().timeout(const Duration(seconds: 15));
      final body = await response.transform(utf8.decoder).join();
      // Pool owns client; do not close

      if (response.statusCode == 200) {
        LoggerService.log('PGP', '✓ Public key uploaded for $email');
      } else {
        LoggerService.logWarning('PGP', 'Upload failed: HTTP ${response.statusCode} $body');
      }
    } catch (ex) {
      LoggerService.logWarning('PGP', 'Upload error: $ex');
    }
  }
}
