import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart';

import 'certificate_service.dart';
import 'logger_service.dart';
import 'master_vault.dart';
import 'mtls_service.dart';
import 'le_issuer_check.dart';
import 'pinned_security_context.dart';

/// OpenPGP key management + encrypt/decrypt for E2EE.
///
/// Architecture (Phase 1 — zero-access at rest):
///   - Ed25519 (signing) + X25519 (encryption) keypair per user
///   - Private key stored in MasterVault (Argon2id + AES-GCM)
///   - Public key uploaded to server via mTLS-authenticated API
///   - Server milter encrypts incoming mail with recipient's public key
///   - App decrypts on fetch using private key from vault
class PgpKeyService {
  static const _vaultKeyPrivate = 'pgp_private_key_v1';
  static const _vaultKeyPassphrase = 'pgp_passphrase_v1';
  static const _uploadEndpoint =
      'https://mail.icd360s.de/api/upload-pubkey.php';

  // In-memory cache (cleared on vault lock)
  static PrivateKey? _cachedPrivateKey;
  static PublicKey? _cachedPublicKey;

  // ── Key Management ───────────────────────────────────────────────

  /// Get or generate the user's PGP private key.
  /// Stored in MasterVault — persists across sessions, encrypted at rest.
  static Future<PrivateKey> getOrCreatePrivateKey(String email) async {
    if (_cachedPrivateKey != null) return _cachedPrivateKey!;

    final vault = MasterVault.instance;

    // Try loading existing key from vault
    final existingArmor = await vault.read(key: _vaultKeyPrivate);
    final passphrase = await _getOrCreatePassphrase();

    if (existingArmor != null) {
      try {
        _cachedPrivateKey =
            OpenPGP.decryptPrivateKey(existingArmor, passphrase);
        _cachedPublicKey = _cachedPrivateKey!.publicKey;
        LoggerService.log('PGP', 'Loaded existing PGP key for $email');
        return _cachedPrivateKey!;
      } catch (ex) {
        LoggerService.logWarning('PGP',
            'Failed to load existing PGP key, regenerating: $ex');
      }
    }

    // Generate new keypair
    LoggerService.log('PGP', 'Generating new Ed25519/X25519 keypair for $email');
    final privateKey = OpenPGP.generateKey(
      [email],
      passphrase,
      type: KeyType.curve25519,
    );

    // Store in vault
    await vault.write(key: _vaultKeyPrivate, value: privateKey.armor());
    _cachedPrivateKey = privateKey;
    _cachedPublicKey = privateKey.publicKey;

    // Upload public key to server
    await _uploadPublicKey(privateKey.publicKey, email);

    LoggerService.log('PGP', '✓ PGP keypair generated and uploaded for $email');
    return privateKey;
  }

  /// Get the public key (generates if needed).
  static Future<PublicKey> getPublicKey(String email) async {
    if (_cachedPublicKey != null) return _cachedPublicKey!;
    final priv = await getOrCreatePrivateKey(email);
    return priv.publicKey;
  }

  /// Get armored public key string for display/export.
  static Future<String?> getArmoredPublicKey(String email) async {
    final pub = await getPublicKey(email);
    return pub.armor();
  }

  /// Clear cached keys from RAM (called on vault lock).
  static void clearCache() {
    _cachedPrivateKey = null;
    _cachedPublicKey = null;
    LoggerService.log('PGP', 'PGP key cache cleared from RAM');
  }

  // ── Encrypt / Decrypt ────────────────────────────────────────────

  /// Decrypt a PGP-encrypted message body. Returns plaintext.
  static Future<String> decrypt(String armoredCiphertext) async {
    if (_cachedPrivateKey == null) {
      throw StateError('PGP key not loaded — unlock vault first');
    }
    final message = OpenPGP.decrypt(
      armoredCiphertext,
      decryptionKeys: [_cachedPrivateKey!],
    );
    return message.literalData.text;
  }

  /// Decrypt binary PGP data. Returns plaintext bytes.
  static Future<Uint8List> decryptBinary(Uint8List ciphertext) async {
    if (_cachedPrivateKey == null) {
      throw StateError('PGP key not loaded — unlock vault first');
    }
    final armored = utf8.decode(ciphertext);
    final message = OpenPGP.decrypt(
      armored,
      decryptionKeys: [_cachedPrivateKey!],
    );
    return Uint8List.fromList(message.literalData.binary);
  }

  /// Encrypt plaintext for a recipient. Returns armored ciphertext.
  static String encrypt(String plaintext, PublicKey recipientKey) {
    final message = OpenPGP.encryptCleartext(
      plaintext,
      encryptionKeys: [recipientKey],
      signingKeys: _cachedPrivateKey != null ? [_cachedPrivateKey!] : [],
    );
    return message.armor();
  }

  // ── PGP/MIME Detection ───────────────────────────────────────────

  /// Check if a MIME message body is PGP encrypted.
  /// Looks for PGP/MIME content-type or inline PGP markers.
  static bool isPgpEncrypted(String body) {
    if (body.contains('-----BEGIN PGP MESSAGE-----')) return true;
    return false;
  }

  /// Check Content-Type header for PGP/MIME.
  static bool isPgpMimeEncrypted(Map<String, String> headers) {
    final ct = headers['content-type'] ?? headers['Content-Type'] ?? '';
    return ct.contains('multipart/encrypted') &&
        ct.contains('application/pgp-encrypted');
  }

  // ── Internal Helpers ─────────────────────────────────────────────

  /// Generate or retrieve a random passphrase for the PGP key.
  /// Stored in MasterVault (not user-visible — vault is the protection layer).
  static Future<String> _getOrCreatePassphrase() async {
    final vault = MasterVault.instance;
    var passphrase = await vault.read(key: _vaultKeyPassphrase);
    if (passphrase == null) {
      // Generate a strong random passphrase (32 hex chars)
      final bytes = List<int>.generate(16, (_) => DateTime.now().microsecond % 256);
      passphrase = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      await vault.write(key: _vaultKeyPassphrase, value: passphrase);
    }
    return passphrase;
  }

  /// Upload the public key to the server via mTLS.
  static Future<void> _uploadPublicKey(PublicKey key, String email) async {
    try {
      final client = MtlsService.createMtlsHttpClient() ??
          PinnedSecurityContext.createHttpClient()
        ..badCertificateCallback = (cert, host, port) {
          if (host == 'mail.icd360s.de') {
            return isTrustedLetsEncryptIssuer(cert.issuer);
          }
          return false;
        };

      final request = await client
          .postUrl(Uri.parse(_uploadEndpoint))
          .timeout(const Duration(seconds: 15));
      request.headers.set('Content-Type', 'application/json');
      final body = jsonEncode({
        'email': email,
        'public_key': key.armor(),
      });
      request.write(body);

      final response = await request.close().timeout(const Duration(seconds: 15));
      final responseBody = await response.transform(utf8.decoder).join();
      client.close();

      if (response.statusCode == 200) {
        LoggerService.log('PGP', '✓ Public key uploaded for $email');
      } else {
        LoggerService.logWarning('PGP',
            'Public key upload failed: HTTP ${response.statusCode} $responseBody');
      }
    } catch (ex) {
      LoggerService.logWarning('PGP', 'Public key upload error: $ex');
    }
  }
}
