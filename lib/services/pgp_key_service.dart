import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart';
import 'package:enough_mail/enough_mail.dart';
import 'package:flutter/foundation.dart' show compute, listEquals;

import 'logger_service.dart';
import 'master_vault.dart';
import 'mtls_service.dart';
import 'pgp_isolate_worker.dart';
import 'le_issuer_check.dart';
import 'pinned_security_context.dart';

/// OpenPGP E2EE — key management + encrypt/decrypt (dart_pg 2.x API).
class PgpKeyService {
  static const _vaultKeyPrivate = 'pgp_private_key_v1';
  static const _vaultKeyPassphrase = 'pgp_passphrase_v1';
  static const _uploadEndpoint =
      'https://mail.icd360s.de/api/upload-pubkey.php';
  static const _pubkeyEndpoint = 'https://mail.icd360s.de/api/pubkeys';

  // dart_pg 2.x returns interface types
  static dynamic _cachedPrivateKey; // PrivateKeyInterface
  static dynamic _cachedPublicKey;  // KeyInterface
  static Future<dynamic>? _keyGenFuture;

  // Background isolate worker for non-blocking decrypt
  static PgpIsolateWorker? _worker;

  // Recipient key cache (RAM only)
  static final Map<String, dynamic> _recipientKeyCache = {};

  // TOFU: first-seen fingerprint per email (key substitution protection)
  static final Map<String, List<int>> _tofuFingerprints = {};

  // ── Key Management ───────────────────────────────────────────────

  static Future<dynamic> getOrCreatePrivateKey(String email) {
    return _keyGenFuture ??= _doGetOrCreate(email).whenComplete(() {
      _keyGenFuture = null;
    });
  }

  static Future<dynamic> _doGetOrCreate(String email) async {
    if (_cachedPrivateKey != null) return _cachedPrivateKey;

    final vault = MasterVault.instance;
    final passphrase = await _getOrCreatePassphrase();

    final existingArmor = await vault.read(key: _vaultKeyPrivate);
    if (existingArmor != null) {
      try {
        _cachedPrivateKey =
            OpenPGP.decryptPrivateKey(existingArmor, passphrase);
        _cachedPublicKey = _cachedPrivateKey.publicKey;
        await _startWorker(existingArmor, passphrase);
        LoggerService.log('PGP', 'Loaded existing PGP key for $email');
        return _cachedPrivateKey;
      } catch (ex) {
        LoggerService.logWarning('PGP', 'Failed to load PGP key: $ex');
      }
    }

    LoggerService.log('PGP', 'Generating Ed25519/X25519 keypair...');
    // dart_pg 2.x: generateKey is synchronous — offload to isolate
    // compute() requires a top-level or static function (not a lambda)
    final privateKey = await compute(_generateKeyIsolate, [email, passphrase]);

    final armoredKey = privateKey.armor();
    await vault.write(key: _vaultKeyPrivate, value: armoredKey);
    _cachedPrivateKey = privateKey;
    _cachedPublicKey = privateKey.publicKey;
    await _startWorker(armoredKey, passphrase);

    await _uploadPublicKey(privateKey.publicKey, email);
    LoggerService.log('PGP', '✓ PGP keypair generated and uploaded');
    return privateKey;
  }

  static Future<dynamic> getPublicKey(String email) async {
    if (_cachedPublicKey != null) return _cachedPublicKey;
    final priv = await getOrCreatePrivateKey(email);
    return priv.publicKey;
  }

  static void clearCache() {
    _cachedPrivateKey = null;
    _cachedPublicKey = null;
    _recipientKeyCache.clear();
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

  /// Start the background decrypt worker.
  static Future<void> _startWorker(String armoredKey, String passphrase) async {
    _worker?.close();
    _worker = await PgpIsolateWorker.spawn(
      armoredKey: armoredKey,
      passphrase: passphrase,
    );
    LoggerService.log('PGP', '✓ Decrypt worker started (background isolate)');
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
            return text;
          }
        }
      }
    }

    final body = message.decodeTextPlainPart() ?? '';
    if (body.contains('-----BEGIN PGP MESSAGE-----')) return body;
    return null;
  }

  static bool isPgpEncryptedHeaders(Map<String, String> headers) {
    final ct = headers['content-type'] ?? headers['Content-Type'] ?? '';
    return ct.contains('multipart/encrypted') ||
        ct.contains('application/pgp-encrypted');
  }

  // ── Recipient Key Discovery ──────────────────────────────────────

  static Future<dynamic> fetchRecipientKey(String email) async {
    if (!email.endsWith('@icd360s.de')) return null;

    final key = email.toLowerCase();
    final cached = _recipientKeyCache[key];
    if (cached != null) return cached;

    final username = email.split('@').first;
    final url = Uri(
      scheme: 'https',
      host: 'mail.icd360s.de',
      path: '/api/pubkeys/${Uri.encodeComponent(username)}.asc',
    );

    try {
      final baseClient = MtlsService.createMtlsHttpClient();
      final client = baseClient ??
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
        await response.drain<void>();
        client.close();
        return null;
      }

      final armored = await response.transform(utf8.decoder).join();
      client.close();

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
      LoggerService.log('PGP', '✓ Fetched key for $email');
      return pubKey;
    } catch (ex) {
      LoggerService.logWarning('PGP', 'Key fetch failed for $email: $ex');
      return null;
    }
  }

  static Future<Map<String, dynamic>> lookupAllRecipients(
      List<String> emails) async {
    final results = <String, dynamic>{};
    await Future.wait(emails.map((email) async {
      results[email] = await fetchRecipientKey(email);
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

    // dart_pg 2.x: encryptCleartext for text encryption
    // Cast dynamic lists to the expected types for dart_pg
    final encrypted = OpenPGP.encryptCleartext(
      innerMimeBody,
      encryptionKeys: List.from(allKeys),
      signingKeys: List.from([_cachedPrivateKey]),
    );
    final ciphertext = encrypted.armor();

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
  static dynamic _generateKeyIsolate(List<String> args) {
    return OpenPGP.generateKey(
      [args[0]],
      args[1],
      type: KeyType.curve25519,
    );
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
      final baseClient = MtlsService.createMtlsHttpClient();
      final client = baseClient ??
          (PinnedSecurityContext.createHttpClient()
            ..badCertificateCallback = (cert, host, port) {
              if (host == 'mail.icd360s.de') {
                return isTrustedLetsEncryptIssuer(cert.issuer);
              }
              return false;
            });

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
      client.close();

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
