// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';

import 'aes_gcm_helpers.dart';
import 'logger_service.dart';
import 'mtls_service.dart';
import 'le_issuer_check.dart';
import 'pinned_security_context.dart';

/// Password-protected email for external recipients (Proton Mail pattern).
///
/// Flow:
///   Sender sets password → PBKDF2(600k) → AES-256-GCM encrypt body
///   → Upload ciphertext to server → Get token URL
///   → Send notification email with link
///   Recipient opens link → enters password → browser decrypts via WebCrypto
///   Server NEVER sees password or plaintext.
class SecureMailService {
  static const _sendEndpoint =
      'https://mail.icd360s.de/api/secure-send.php';
  static const _revokeEndpoint =
      'https://mail.icd360s.de/api/secure-revoke.php';
  static const _pbkdf2Iterations = 600000;
  static const _keyBytes = 32;
  static const _saltBytes = 16;
  static const _ivBytes = 12;
  static const _version = 0x02;

  /// Encrypt message body with password and upload to server.
  /// Returns the secure URL for the recipient.
  /// Encrypt and upload. No subject/metadata sent to server (zero-knowledge).
  static Future<SecureMailResult> encryptAndUpload({
    required String body,
    required String password,
    required String senderEmail,
    int expiryDays = 7,
  }) async {
    // 1. Derive key from password
    final salt = _randomBytes(_saltBytes);
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, _pbkdf2Iterations, _keyBytes));
    final key = derivator.process(Uint8List.fromList(utf8.encode(password)));

    // 2. Encrypt body with AES-256-GCM
    final iv = _randomBytes(_ivBytes);
    final plaintext = Uint8List.fromList(utf8.encode(body));
    final encrypted = AesGcmHelpers.encryptRaw(key, iv, plaintext);

    // 3. Build blob: version(1) || salt(16) || iv(12) || ciphertext+tag
    final blob = BytesBuilder()
      ..addByte(_version)
      ..add(salt)
      ..add(iv)
      ..add(encrypted);
    final blobBytes = blob.toBytes();

    // Zero key from memory
    for (var i = 0; i < key.length; i++) key[i] = 0;

    // 4. Upload to server
    final result = await _upload(
      ciphertext: blobBytes,
      senderEmail: senderEmail,
      expiryDays: expiryDays,
    );

    LoggerService.log('SECURE_MAIL',
        '✓ Encrypted message uploaded (${blobBytes.length} bytes, expires in ${expiryDays}d)');

    return result;
  }

  /// Build the notification email body (plain text, no HTML).
  static String buildNotificationEmail({
    required String senderName,
    required String senderEmail,
    required String secureUrl,
    required String expiresAt,
  }) {
    return '''$senderName ($senderEmail) hat Ihnen eine vertrauliche, verschlüsselte Nachricht gesendet.

Nachricht lesen: $secureUrl

Das Passwort wurde Ihnen separat mitgeteilt (Telefon, Signal, persönlich).
Der Link läuft am $expiresAt ab.

Diese Nachricht wurde mit AES-256-GCM verschlüsselt.
Der Server kann den Inhalt nicht lesen.

---
$senderName ($senderEmail) sent you a confidential, encrypted message.

Read message: $secureUrl

The password was communicated to you separately (phone, Signal, in person).
The link expires on $expiresAt.

This message is encrypted with AES-256-GCM.
The server cannot read the content.''';
  }

  /// Revoke access to a secure message.
  /// Hashes the token client-side before sending (server stores only hashes).
  static Future<bool> revoke(String token) async {
    try {
      // Hash token client-side — matches server's SHA-256(token) storage
      final tokenHash = SHA256Digest()
          .process(Uint8List.fromList(utf8.encode(token)));
      final tokenHashHex = tokenHash
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();

      final client = _createClient();
      final request = await client
          .postUrl(Uri.parse(_revokeEndpoint))
          .timeout(const Duration(seconds: 10));
      request.headers.set('Content-Type', 'application/json');
      request.write(jsonEncode({'token_hash': tokenHashHex}));

      final response =
          await request.close().timeout(const Duration(seconds: 10));
      final body = await response.transform(utf8.decoder).join();
      client.close();

      if (response.statusCode == 200) {
        LoggerService.log('SECURE_MAIL', '✓ Message revoked');
        return true;
      }
      LoggerService.logWarning('SECURE_MAIL', 'Revoke failed: $body');
      return false;
    } catch (ex) {
      LoggerService.logWarning('SECURE_MAIL', 'Revoke error: $ex');
      return false;
    }
  }

  // ── Internal ─────────────────────────────────────────────────────

  static Future<SecureMailResult> _upload({
    required Uint8List ciphertext,
    required String senderEmail,
    required int expiryDays,
  }) async {
    final client = _createClient();
    final request = await client
        .postUrl(Uri.parse(_sendEndpoint))
        .timeout(const Duration(seconds: 15));
    request.headers.set('Content-Type', 'application/json');
    // Zero-knowledge: only ciphertext + sender + expiry. No subject/metadata.
    request.write(jsonEncode({
      'ciphertext': base64.encode(ciphertext),
      'sender_email': senderEmail,
      'expiry_days': expiryDays,
    }));

    final response =
        await request.close().timeout(const Duration(seconds: 15));
    final body = await response.transform(utf8.decoder).join();
    client.close();

    if (response.statusCode != 200) {
      throw HttpException('Upload failed: HTTP ${response.statusCode} $body');
    }

    final json = jsonDecode(body) as Map<String, dynamic>;
    return SecureMailResult(
      token: json['token'] as String,
      url: json['url'] as String,
      expiresAt: json['expires_at'] as String,
    );
  }

  static HttpClient _createClient() {
    final baseClient = MtlsService.createMtlsHttpClient();
    return baseClient ??
        (PinnedSecurityContext.createHttpClient()
          ..badCertificateCallback = (cert, host, port) {
            if (host == 'mail.icd360s.de') {
              return isTrustedLetsEncryptIssuer(cert.issuer);
            }
            return false;
          });
  }

  static Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }
}

class SecureMailResult {
  final String token;
  final String url;
  final String expiresAt;

  const SecureMailResult({
    required this.token,
    required this.url,
    required this.expiresAt,
  });
}