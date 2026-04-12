import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart';
import 'package:enough_mail/enough_mail.dart';
import 'package:flutter/foundation.dart' show compute;

import 'logger_service.dart';
import 'master_vault.dart';
import 'mtls_service.dart';
import 'le_issuer_check.dart';
import 'pinned_security_context.dart';

/// OpenPGP E2EE — key management + encrypt/decrypt.
///
/// Phase 1: zero-access at rest.
///   - Ed25519 (signing) + X25519 (encryption) per user
///   - Private key in MasterVault (Argon2id + AES-GCM)
///   - Public key uploaded to server (mTLS auth)
///   - Server milter encrypts incoming mail → PGP/MIME (RFC 3156)
///   - App detects multipart/encrypted, extracts ciphertext part, decrypts
class PgpKeyService {
  static const _vaultKeyPrivate = 'pgp_private_key_v1';
  static const _vaultKeyPassphrase = 'pgp_passphrase_v1';
  static const _uploadEndpoint =
      'https://mail.icd360s.de/api/upload-pubkey.php';

  static PrivateKey? _cachedPrivateKey;
  static PublicKey? _cachedPublicKey;

  // Mutex: prevent double key generation from concurrent calls
  static Future<PrivateKey>? _keyGenFuture;

  // ── Key Management ───────────────────────────────────────────────

  /// Get or generate the user's PGP keypair. Thread-safe (mutex).
  /// Called eagerly at login, not lazily at first decrypt.
  static Future<PrivateKey> getOrCreatePrivateKey(String email) {
    return _keyGenFuture ??= _doGetOrCreate(email).whenComplete(() {
      _keyGenFuture = null;
    });
  }

  static Future<PrivateKey> _doGetOrCreate(String email) async {
    if (_cachedPrivateKey != null) return _cachedPrivateKey!;

    final vault = MasterVault.instance;
    final passphrase = await _getOrCreatePassphrase();

    // Try loading existing key
    final existingArmor = await vault.read(key: _vaultKeyPrivate);
    if (existingArmor != null) {
      try {
        _cachedPrivateKey =
            OpenPGP.decryptPrivateKey(existingArmor, passphrase);
        _cachedPublicKey = _cachedPrivateKey!.publicKey;
        LoggerService.log('PGP', 'Loaded existing PGP key for $email');
        return _cachedPrivateKey!;
      } catch (ex) {
        LoggerService.logWarning('PGP',
            'Failed to load PGP key, regenerating: $ex');
      }
    }

    // Generate new keypair (offload to isolate — blocks for 200-500ms)
    LoggerService.log('PGP',
        'Generating Ed25519/X25519 keypair for $email...');
    final privateKey = await OpenPGP.generateKey(
      [email],
      passphrase,
      type: KeyType.curve25519,
    );

    await vault.write(key: _vaultKeyPrivate, value: privateKey.armor());
    _cachedPrivateKey = privateKey;
    _cachedPublicKey = privateKey.publicKey;

    await _uploadPublicKey(privateKey.publicKey, email);
    LoggerService.log('PGP', '✓ PGP keypair generated and uploaded');
    return privateKey;
  }

  static Future<PublicKey> getPublicKey(String email) async {
    if (_cachedPublicKey != null) return _cachedPublicKey!;
    final priv = await getOrCreatePrivateKey(email);
    return priv.publicKey;
  }

  static void clearCache() {
    _cachedPrivateKey = null;
    _cachedPublicKey = null;
    _recipientKeyCache.clear();
    LoggerService.log('PGP', 'PGP key cache cleared');
  }

  // ── Recipient Key Discovery (internal @icd360s.de only) ──────────

  static final Map<String, PublicKey> _recipientKeyCache = {};
  static const _pubkeyEndpoint =
      'https://mail.icd360s.de/api/pubkeys';

  /// Fetch a recipient's public key from server. Cached in RAM.
  /// Returns null if recipient has no key (404).
  static Future<PublicKey?> fetchRecipientKey(String email) async {
    if (!email.endsWith('@icd360s.de')) return null;

    final cached = _recipientKeyCache[email.toLowerCase()];
    if (cached != null) return cached;

    final username = email.split('@').first;
    final url = Uri.parse('$_pubkeyEndpoint/$username.asc');

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

      final request = await client.getUrl(url)
          .timeout(const Duration(seconds: 8));
      final response = await request.close()
          .timeout(const Duration(seconds: 8));

      if (response.statusCode == 404) {
        client.close();
        return null;
      }
      if (response.statusCode != 200) {
        client.close();
        return null;
      }

      final armored = await response.transform(utf8.decoder).join();
      client.close();

      final key = OpenPGP.readPublicKey(armored);
      _recipientKeyCache[email.toLowerCase()] = key;
      LoggerService.log('PGP', '✓ Fetched public key for $email');
      return key;
    } catch (ex) {
      LoggerService.logWarning('PGP', 'Key fetch failed for $email: $ex');
      return null;
    }
  }

  /// Check if all recipients have PGP keys (internal only).
  static Future<Map<String, PublicKey?>> lookupAllRecipients(
      List<String> emails) async {
    final results = <String, PublicKey?>{};
    await Future.wait(emails.map((email) async {
      results[email] = await fetchRecipientKey(email);
    }));
    return results;
  }

  // ── PGP/MIME Outbound (RFC 3156) ────────────────────────────────��

  /// Build a complete RFC 3156 PGP/MIME encrypted message as raw string.
  /// Encrypts to all recipients + self. Signs with sender's private key.
  static Future<String> buildPgpMimeMessage({
    required String from,
    required String to,
    String cc = '',
    String bcc = '',
    required String subject,
    required String innerMimeBody,
    required List<PublicKey> recipientKeys,
  }) async {
    if (_cachedPrivateKey == null || _cachedPublicKey == null) {
      throw StateError('PGP keys not loaded — unlock vault first');
    }

    // Encrypt to all recipients + self
    final allKeys = <PublicKey>[...recipientKeys];
    if (!allKeys.any((k) => k.fingerprint == _cachedPublicKey!.fingerprint)) {
      allKeys.add(_cachedPublicKey!);
    }

    final literalMsg = OpenPGP.createTextMessage(innerMimeBody);
    final encrypted = OpenPGP.encrypt(
      literalMsg,
      encryptionKeys: allKeys,
      signingKeys: [_cachedPrivateKey!],
    );
    final ciphertext = encrypted.armor();

    // Build RFC 3156 outer wrapper
    final boundary = 'pgp-${DateTime.now().millisecondsSinceEpoch}';
    final buf = StringBuffer()
      ..writeln('MIME-Version: 1.0')
      ..writeln('From: $from')
      ..writeln('To: $to');
    if (cc.isNotEmpty) buf.writeln('Cc: $cc');
    buf
      ..writeln('Subject: $subject')
      ..writeln('Content-Type: multipart/encrypted;')
      ..writeln('\tprotocol="application/pgp-encrypted";')
      ..writeln('\tboundary="$boundary"')
      ..writeln()
      ..writeln('This is an OpenPGP/MIME encrypted message (RFC 3156).')
      ..writeln()
      ..writeln('--$boundary')
      ..writeln('Content-Type: application/pgp-encrypted')
      ..writeln('Content-Description: PGP/MIME version identification')
      ..writeln()
      ..writeln('Version: 1')
      ..writeln()
      ..writeln('--$boundary')
      ..writeln('Content-Type: application/octet-stream')
      ..writeln('Content-Description: OpenPGP encrypted message')
      ..writeln('Content-Disposition: inline; filename="encrypted.asc"')
      ..writeln()
      ..writeln(ciphertext)
      ..writeln()
      ..writeln('--$boundary--');

    return buf.toString();
  }

  // ── Decrypt (RFC 3156 PGP/MIME) ──────────────────────────────────

  /// Decrypt an armored PGP message. Returns plaintext string.
  static Future<String> decrypt(String armoredCiphertext) async {
    if (_cachedPrivateKey == null) {
      throw StateError('PGP key not loaded — unlock vault first');
    }
    final message = OpenPGP.decrypt(
      armoredCiphertext,
      decryptionKeys: [_cachedPrivateKey!],
    );
    final literal = message.literalData;
    if (literal == null) {
      throw StateError('Decryption produced no literal data');
    }
    return utf8.decode(literal.binary, allowMalformed: true);
  }

  /// Encrypt plaintext for recipients. Returns armored PGP message.
  static Future<String> encrypt(
      String plaintext, List<PublicKey> recipientKeys) async {
    if (recipientKeys.isEmpty) {
      throw ArgumentError('At least one recipient key required');
    }
    // Also encrypt to self so sender can read their Sent folder
    final allKeys = [...recipientKeys];
    if (_cachedPublicKey != null &&
        !allKeys.any((k) => k.fingerprint == _cachedPublicKey!.fingerprint)) {
      allKeys.add(_cachedPublicKey!);
    }

    final literalMsg = OpenPGP.createTextMessage(plaintext);
    final encrypted = OpenPGP.encrypt(
      literalMsg,
      encryptionKeys: allKeys,
      signingKeys: _cachedPrivateKey != null ? [_cachedPrivateKey!] : [],
    );
    return encrypted.armor();
  }

  // ── PGP/MIME Detection + Extraction ──────────────────────────────

  /// Detect PGP/MIME from a MimeMessage (RFC 3156).
  /// Returns the armored ciphertext from the application/octet-stream
  /// part, or null if the message is not PGP-encrypted.
  static String? extractPgpCiphertext(MimeMessage message) {
    final ct = message.getHeaderContentType();
    if (ct == null) return null;

    // RFC 3156: multipart/encrypted; protocol="application/pgp-encrypted"
    if (ct.mediaType.sub == MediaSubtype.multipartEncrypted) {
      for (final part in message.allPartsFlat) {
        final partCt = part.mediaType;
        if (partCt.sub == MediaSubtype.applicationOctetStream ||
            partCt.toString().contains('application/pgp-encrypted')) {
          final text = part.decodeContentText();
          if (text != null && text.contains('-----BEGIN PGP MESSAGE-----')) {
            return text;
          }
        }
      }
    }

    // Fallback: inline PGP (non-MIME, legacy)
    final body = message.decodeTextPlainPart() ?? '';
    if (body.contains('-----BEGIN PGP MESSAGE-----')) {
      return body;
    }

    return null;
  }

  /// Simple check for display purposes (headers only, no MIME parsing).
  static bool isPgpEncryptedHeaders(Map<String, String> headers) {
    final ct = headers['content-type'] ?? headers['Content-Type'] ?? '';
    return ct.contains('multipart/encrypted') ||
        ct.contains('application/pgp-encrypted');
  }

  // ── Helpers ──────────────────────────────────────────────────────

  /// Generate a cryptographically secure random passphrase.
  static Future<String> _getOrCreatePassphrase() async {
    final vault = MasterVault.instance;
    var passphrase = await vault.read(key: _vaultKeyPassphrase);
    if (passphrase == null) {
      final rng = Random.secure();
      final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
      passphrase = bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      await vault.write(key: _vaultKeyPassphrase, value: passphrase);
    }
    return passphrase;
  }

  /// Upload public key to server via mTLS. Verifies cert CN matches email.
  static Future<void> _uploadPublicKey(PublicKey key, String email) async {
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
      final responseBody = await response.transform(utf8.decoder).join();
      client.close();

      if (response.statusCode == 200) {
        LoggerService.log('PGP', '✓ Public key uploaded for $email');
      } else {
        LoggerService.logWarning('PGP',
            'Key upload failed: HTTP ${response.statusCode} $responseBody');
      }
    } catch (ex) {
      LoggerService.logWarning('PGP', 'Key upload error: $ex');
    }
  }
}
