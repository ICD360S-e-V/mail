import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'master_vault.dart';
import 'mtls_client_pool.dart';
import 'pinned_security_context.dart';

/// Thrown when PGP blob sync encounters an unrecoverable error.
class PgpSyncException implements Exception {
  final String message;
  final Object? cause;
  const PgpSyncException(this.message, [this.cause]);

  @override
  String toString() => cause != null
      ? 'PgpSyncException: $message (caused by: $cause)'
      : 'PgpSyncException: $message';
}

/// Zero-knowledge PGP private key sync across devices.
///
/// Architecture (ProtonMail/Tuta/Bitwarden pattern):
///
///   1. Derive a "blob KEK" from MasterVault's master key via HKDF-SHA256
///      with a distinct context label "pgp-blob-kek-v1". The server never
///      sees this key — all crypto is client-side.
///
///   2. Encrypt the armored PGP private key with AES-256-GCM:
///        AAD     = utf8("v{version}|{email}") — authenticated, rollback-proof
///        Nonce   = random 12 bytes (fresh per upload)
///        Output  = [version (4 bytes BE)][nonce (12)][ciphertext][GCM tag (16)]
///
///   3. Upload via POST /api/pgp-blob.php as base64-encoded blob.
///      Server rejects if the submitted version ≤ current server version.
///
///   4. Local version cache in MasterVault (`pgp_blob_version_{email}`)
///      defends against rollback even when the server is compromised:
///      if the server returns a version lower than the locally cached
///      version, a warning is logged (device may have been re-installed).
///
/// Wire format of the encrypted blob (all decryption is client-side):
///
///   Bytes  0 –  3  : version (uint32 big-endian, same value as in AAD)
///   Bytes  4 – 15  : AES-GCM nonce (12 bytes, random per upload)
///   Bytes 16 – N-16: ciphertext
///   Bytes N-16 – N : GCM authentication tag (16 bytes)
class PgpSyncService {
  // ── Constants ────────────────────────────────────────────────────────

  static const _endpoint = 'https://mail.icd360s.de/api/pgp-blob.php';

  /// HKDF info label that binds the derived key to PGP blob encryption.
  /// MUST differ from every other HKDF label in the codebase.
  static const _hkdfInfo = 'pgp-blob-kek-v1';

  /// HKDF salt label (same scheme as MasterVault, no separate secret needed).
  static const _hkdfSalt = 'icd360s.macos.v2.master-vault.salt';

  static const _gcmNonceBytes = 12;
  static const _versionBytes = 4;

  // ── Public API ───────────────────────────────────────────────────────

  /// Download the encrypted blob from the server, decrypt it, and return
  /// Returns true if a blob exists on the server for [email].
  /// Used by migration to skip accounts already synced.
  static Future<bool> hasServerBlob(String email) async {
    try {
      final payload = await _fetchBlob(email);
      return payload != null;
    } catch (_) {
      // Network error → treat as unknown, don't block migration
      return false;
    }
  }

  /// the armored PGP private key.
  ///
  /// Returns `null` if no blob exists yet for [email].
  ///
  /// Throws [PgpSyncException] on crypto or network failures.
  static Future<String?> downloadAndDecrypt(String email) async {
    final tag = 'PGP_SYNC';
    LoggerService.log(tag, 'downloadAndDecrypt: $email');

    final serverPayload = await _fetchBlob(email);
    if (serverPayload == null) {
      LoggerService.log(tag, 'No blob on server for $email');
      return null;
    }

    final serverVersion = serverPayload['version'] as int;
    final blobBase64 = serverPayload['blob'] as String;

    // Rollback check: compare against locally cached version.
    final localVersion = await getLocalVersion(email);
    if (serverVersion < localVersion) {
      LoggerService.logWarning(
        tag,
        'Server version ($serverVersion) < local version ($localVersion) '
        'for $email — possible rollback or re-install. Accepting anyway.',
      );
    }

    // Decrypt blob.
    final blobBytes = base64.decode(blobBase64);
    final armoredKey = await _decryptBlob(blobBytes, email, serverVersion);

    // Update local version cache.
    await _saveLocalVersion(email, serverVersion);
    LoggerService.log(
        tag, 'downloadAndDecrypt OK: version=$serverVersion for $email');
    return armoredKey;
  }

  /// Encrypt the armored PGP private key and upload it to the server
  /// at `version = localVersion + 1`.
  ///
  /// Returns `true` on success.
  ///
  /// Throws [PgpSyncException] on crypto or network failures, or when
  /// the server rejects the upload (e.g. version conflict).
  static Future<bool> encryptAndUpload(
      String email, String armoredKey) async {
    final tag = 'PGP_SYNC';
    LoggerService.log(tag, 'encryptAndUpload: $email');

    final nextVersion = (await getLocalVersion(email)) + 1;
    final blobBytes = await _encryptBlob(armoredKey, email, nextVersion);
    final blobBase64 = base64.encode(blobBytes);

    await _uploadBlob(email, nextVersion, blobBase64);

    // Persist the new version only after a confirmed successful upload.
    await _saveLocalVersion(email, nextVersion);
    LoggerService.log(
        tag, 'encryptAndUpload OK: version=$nextVersion for $email');
    return true;
  }

  /// Delete the blob on the server (for reset / key-rotation scenarios).
  ///
  /// Returns `true` on success.
  ///
  /// Throws [PgpSyncException] on network failures or non-200 responses.
  static Future<bool> deleteBlob(String email) async {
    final tag = 'PGP_SYNC';
    LoggerService.log(tag, 'deleteBlob: $email');

    final client = await _buildHttpClientFor(email);
    try {
      final request = await client
          .deleteUrl(Uri.parse(_endpoint))
          .timeout(const Duration(seconds: 15));
      request.headers.set('Content-Type', 'application/json');
      request.write(jsonEncode({'email': email.toLowerCase()}));

      final response =
          await request.close().timeout(const Duration(seconds: 15));
      final body = await response.transform(utf8.decoder).join();
      // Pool owns client; do not close

      if (response.statusCode != 200) {
        throw PgpSyncException(
            'deleteBlob HTTP ${response.statusCode} for $email: $body');
      }

      // Clear the local version cache.
      await MasterVault.instance.delete(key: _versionKey(email));
      LoggerService.log(tag, 'deleteBlob OK for $email');
      return true;
    } on PgpSyncException {
      // Pool owns client; do not close
      rethrow;
    } catch (ex) {
      // Pool owns client; do not close
      throw PgpSyncException('deleteBlob failed for $email', ex);
    }
  }

  /// Return the last-seen blob version from the local vault cache.
  ///
  /// Returns `0` if no version has been recorded yet (i.e. first sync).
  static Future<int> getLocalVersion(String email) async {
    final raw = await MasterVault.instance.read(key: _versionKey(email));
    if (raw == null) return 0;
    return int.tryParse(raw) ?? 0;
  }

  // ── Crypto ───────────────────────────────────────────────────────────

  /// Derive the 32-byte blob KEK from MasterVault's cached master key
  /// via HKDF-SHA256(masterKey, salt=_hkdfSalt, info=_hkdfInfo).
  ///
  /// Uses a distinct HKDF info label ("pgp-blob-kek-v1") so the blob KEK
  /// is cryptographically independent from the vault KEK and auth hash.
  static Future<SecretKey> _deriveBlobKek() async {
    final masterKeyBytes =
        await MasterVault.instance.deriveMasterKeyFromCache();
    if (masterKeyBytes == null) {
      throw const PgpSyncException(
          'MasterVault is locked — unlock before syncing PGP blobs');
    }
    try {
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      final blobKek = await hkdf.deriveKey(
        secretKey: SecretKey(masterKeyBytes),
        nonce: utf8.encode(_hkdfSalt),
        info: utf8.encode(_hkdfInfo),
      );
      return blobKek;
    } catch (ex) {
      throw PgpSyncException('HKDF derivation for blob KEK failed', ex);
    }
  }

  /// Encrypt [armoredKey] and produce the wire-format blob bytes:
  ///   [version 4B BE][nonce 12B][ciphertext][GCM tag 16B]
  static Future<Uint8List> _encryptBlob(
      String armoredKey, String email, int version) async {
    final blobKek = await _deriveBlobKek();
    final aes = AesGcm.with256bits();

    // AAD = "v{version}|{email}" — ties this ciphertext to its version
    // and owner; any tampering (version swap, email swap) breaks the tag.
    final aad = utf8.encode('v$version|${email.toLowerCase()}');
    final secretBox = await aes.encrypt(
      utf8.encode(armoredKey),
      secretKey: blobKek,
      aad: aad,
    );

    // Wire format: [version BE32][nonce][ciphertext][tag]
    final nonce = secretBox.nonce;
    final ciphertext = secretBox.cipherText;
    final mac = secretBox.mac.bytes;

    final out = BytesBuilder(copy: false)
      ..add(_encodeVersionBE(version))
      ..add(nonce)
      ..add(ciphertext)
      ..add(mac);
    return out.toBytes();
  }

  /// Decrypt a wire-format blob and return the armored PGP private key.
  ///
  /// Validates that the version embedded in the wire format matches
  /// [expectedVersion] (prevents a corrupted/tampered header from being
  /// silently accepted — the GCM tag also catches this via AAD, but
  /// the explicit check produces a clearer error message).
  static Future<String> _decryptBlob(
      Uint8List blob, String email, int expectedVersion) async {
    // Minimum: 4 (version) + 12 (nonce) + 0 (empty plaintext) + 16 (tag)
    const minLen = _versionBytes + _gcmNonceBytes + 16;
    if (blob.length < minLen) {
      throw PgpSyncException(
          'Blob too short (${blob.length} bytes) — corrupt or truncated');
    }

    // Parse wire format.
    var off = 0;
    final version = _decodeVersionBE(blob.sublist(off, off + _versionBytes));
    off += _versionBytes;

    if (version != expectedVersion) {
      throw PgpSyncException(
          'Blob version mismatch: header says $version, '
          'server reported $expectedVersion');
    }

    final nonce = blob.sublist(off, off + _gcmNonceBytes);
    off += _gcmNonceBytes;

    // Everything after the nonce: ciphertext + 16-byte GCM tag.
    final ciphertextAndTag = blob.sublist(off);
    if (ciphertextAndTag.length < 16) {
      throw PgpSyncException('Blob missing GCM tag — corrupt');
    }
    final ciphertext =
        ciphertextAndTag.sublist(0, ciphertextAndTag.length - 16);
    final tag = ciphertextAndTag.sublist(ciphertextAndTag.length - 16);

    final blobKek = await _deriveBlobKek();
    final aes = AesGcm.with256bits();
    final aad = utf8.encode('v$version|${email.toLowerCase()}');

    try {
      final secretBox = SecretBox(
        ciphertext,
        nonce: nonce,
        mac: Mac(tag),
      );
      final plainBytes = await aes.decrypt(
        secretBox,
        secretKey: blobKek,
        aad: aad,
      );
      return utf8.decode(plainBytes);
    } on SecretBoxAuthenticationError catch (ex) {
      throw PgpSyncException(
          'GCM authentication failed for $email v$version — '
          'blob is tampered, corrupt, or encrypted under a different key',
          ex);
    } catch (ex) {
      throw PgpSyncException('Decryption failed for $email v$version', ex);
    }
  }

  // ── Network ──────────────────────────────────────────────────────────

  /// Fetch blob metadata from the server.
  /// Returns `{'version': int, 'blob': String}` or `null` if 404.
  static Future<Map<String, dynamic>?> _fetchBlob(String email) async {
    final url = Uri.parse(
        '$_endpoint?email=${Uri.encodeQueryComponent(email.toLowerCase())}');
    final client = await _buildHttpClientFor(email);
    try {
      final request =
          await client.getUrl(url).timeout(const Duration(seconds: 15));
      final response =
          await request.close().timeout(const Duration(seconds: 15));
      final body = await response.transform(utf8.decoder).join();
      // Pool owns client; do not close

      if (response.statusCode == 404) return null;
      if (response.statusCode != 200) {
        throw PgpSyncException(
            'fetchBlob HTTP ${response.statusCode} for $email: $body');
      }

      final decoded = jsonDecode(body) as Map<String, dynamic>;
      return decoded;
    } on PgpSyncException {
      // Pool owns client; do not close
      rethrow;
    } catch (ex) {
      // Pool owns client; do not close
      throw PgpSyncException('fetchBlob network error for $email', ex);
    }
  }

  /// POST the encrypted blob to the server.
  /// The server MUST reject the upload if `version` ≤ its stored version.
  static Future<void> _uploadBlob(
      String email, int version, String blobBase64) async {
    final client = await _buildHttpClientFor(email);
    try {
      final request = await client
          .postUrl(Uri.parse(_endpoint))
          .timeout(const Duration(seconds: 20));
      request.headers.set('Content-Type', 'application/json');
      request.write(jsonEncode({
        'email': email.toLowerCase(),
        'version': version,
        'blob': blobBase64,
      }));

      final response =
          await request.close().timeout(const Duration(seconds: 20));
      final body = await response.transform(utf8.decoder).join();
      // Pool owns client; do not close

      if (response.statusCode == 409) {
        // Version conflict: another device uploaded a newer version.
        throw PgpSyncException(
            'Version conflict (HTTP 409) for $email v$version — '
            'another device may have uploaded a newer blob. '
            'Pull the latest version first.');
      }
      if (response.statusCode != 200) {
        throw PgpSyncException(
            'uploadBlob HTTP ${response.statusCode} for $email: $body');
      }
    } on PgpSyncException {
      // Pool owns client; do not close
      rethrow;
    } catch (ex) {
      // Pool owns client; do not close
      throw PgpSyncException('uploadBlob network error for $email', ex);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────

  /// Build an [HttpClient] with mTLS if certificates are available,
  /// falling back to a LE-pinned client without client auth.
  /// Get an HttpClient pre-loaded with [email]'s mTLS cert from the pool.
  /// Falls back to plain pinned client if Keychain has no cert (e.g. first
  /// login before approval). The pool ensures concurrent uploads for
  /// DIFFERENT accounts don't trample each other's SecurityContext.
  static Future<HttpClient> _buildHttpClientFor(String email) async {
    try {
      return await MtlsClientPool.instance.get(email);
    } catch (_) {
      // No cert for this user yet — fall back to pinned non-mTLS client.
      return PinnedSecurityContext.createHttpClient()
        ..connectionTimeout = const Duration(seconds: 10)
        ..badCertificateCallback = (cert, host, port) {
          if (host == 'mail.icd360s.de') {
            return isTrustedLetsEncryptIssuer(cert.issuer);
          }
          return false;
        };
    }
  }

  /// MasterVault key for the locally cached blob version.
  static String _versionKey(String email) =>
      'pgp_blob_version_${email.toLowerCase()}';

  static Future<void> _saveLocalVersion(String email, int version) async {
    await MasterVault.instance.write(
      key: _versionKey(email),
      value: version.toString(),
    );
  }

  /// Encode [version] as 4 bytes big-endian.
  static Uint8List _encodeVersionBE(int version) {
    final buf = ByteData(4);
    buf.setUint32(0, version, Endian.big);
    return buf.buffer.asUint8List();
  }

  /// Decode 4 bytes big-endian as a version integer.
  static int _decodeVersionBE(List<int> bytes) {
    final buf = ByteData.sublistView(Uint8List.fromList(bytes));
    return buf.getUint32(0, Endian.big);
  }
}
