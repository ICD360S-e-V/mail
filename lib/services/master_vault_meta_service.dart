// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'mtls_client_pool.dart';
import 'pinned_security_context.dart';

/// Thrown when the master vault meta sync hits an unrecoverable error.
class MasterVaultMetaSyncException implements Exception {
  final String message;
  final Object? cause;
  const MasterVaultMetaSyncException(this.message, [this.cause]);

  @override
  String toString() => cause != null
      ? 'MasterVaultMetaSyncException: $message (caused by: $cause)'
      : 'MasterVaultMetaSyncException: $message';
}

/// Argon2id salt sync across devices — the missing piece that made
/// [PgpSyncService] blobs unreadable on a fresh install of a second device.
///
/// Without server-bound salts, every device generates its own random
/// Argon2id salt at vault creation time, so the same master password
/// derives a *different* master key per device. The PgpSync blob KEK is
/// derived from that master key, so the second device's KEK doesn't match
/// the one the blob was encrypted with — decryption fails silently, the
/// fall-through path generates a brand-new PGP keypair, and all old
/// encrypted mail becomes unreadable.
///
/// With this service, the first device binds its random salt on the server
/// (one-shot: the server refuses subsequent overwrites — `first-write-wins`).
/// Every subsequent device fetches the bound salt before creating its local
/// vault, so the same master password produces the same master key
/// everywhere, the PgpSync blob decrypts, and old mail stays readable.
///
/// Wire format:
///
///   GET  /api/master-vault-meta.php
///     → 200 {salt: base64(16 bytes), created_at: iso}
///     → 404 {error: 'no salt bound yet'}
///
///   POST /api/master-vault-meta.php  {salt: base64(16 bytes)}
///     → 201 {status: 'bound', created_at: iso}    — first write, our salt wins
///     → 409 {error: 'already bound', created_at}  — someone else got here first
///
/// The salt is *not* cryptographically secret — it only prevents pre-computed
/// Argon2id tables across users. Leaking it is harmless. mTLS is still required
/// so the server can route per-user files.
class MasterVaultMetaService {
  static const _endpoint =
      'https://mail.icd360s.de/api/master-vault-meta.php';

  static const _expectedSaltBytes = 16;

  // ── Public API ───────────────────────────────────────────────────────

  /// Fetch the server-bound salt for [email]. Returns the raw salt bytes
  /// (16 bytes) if the user has already bound a salt, or `null` if not.
  ///
  /// Throws [MasterVaultMetaSyncException] on network/protocol errors.
  static Future<Uint8List?> fetchBoundSalt(String email) async {
    const tag = 'MASTER_VAULT_META';
    LoggerService.log(tag, 'fetchBoundSalt: $email');

    final client = await _buildHttpClientFor(email);
    try {
      final request = await client
          .getUrl(Uri.parse(_endpoint))
          .timeout(const Duration(seconds: 15));
      request.headers.set('Accept', 'application/json');

      final response =
          await request.close().timeout(const Duration(seconds: 15));
      final body = await response.transform(utf8.decoder).join();

      if (response.statusCode == 404) {
        LoggerService.log(tag, 'No salt bound yet for $email');
        return null;
      }
      if (response.statusCode != 200) {
        throw MasterVaultMetaSyncException(
            'fetchBoundSalt HTTP ${response.statusCode} for $email: $body');
      }

      final payload = jsonDecode(body) as Map<String, dynamic>;
      final saltB64 = payload['salt'] as String?;
      if (saltB64 == null) {
        throw MasterVaultMetaSyncException(
            'fetchBoundSalt: response missing "salt" field: $body');
      }
      final saltBytes = base64.decode(saltB64);
      if (saltBytes.length != _expectedSaltBytes) {
        throw MasterVaultMetaSyncException(
            'fetchBoundSalt: salt length ${saltBytes.length} != $_expectedSaltBytes');
      }
      LoggerService.log(tag, 'Fetched bound salt for $email');
      return Uint8List.fromList(saltBytes);
    } on MasterVaultMetaSyncException {
      rethrow;
    } catch (ex) {
      throw MasterVaultMetaSyncException(
          'fetchBoundSalt failed for $email', ex);
    }
  }

  /// Attempt to bind [salt] (16 bytes) as the user's vault salt on the
  /// server. Returns `true` if the bind succeeded (we are the first device),
  /// `false` if another device already bound a different salt (caller should
  /// then call [fetchBoundSalt] and use that instead).
  ///
  /// Throws [MasterVaultMetaSyncException] on network/protocol errors.
  static Future<bool> uploadSalt(String email, Uint8List salt) async {
    const tag = 'MASTER_VAULT_META';
    if (salt.length != _expectedSaltBytes) {
      throw MasterVaultMetaSyncException(
          'uploadSalt: salt length ${salt.length} != $_expectedSaltBytes');
    }
    LoggerService.log(tag, 'uploadSalt: $email');

    final client = await _buildHttpClientFor(email);
    try {
      final request = await client
          .postUrl(Uri.parse(_endpoint))
          .timeout(const Duration(seconds: 15));
      request.headers.set('Content-Type', 'application/json');
      request.write(jsonEncode({'salt': base64.encode(salt)}));

      final response =
          await request.close().timeout(const Duration(seconds: 15));
      final body = await response.transform(utf8.decoder).join();

      if (response.statusCode == 201) {
        LoggerService.log(tag, 'Salt bound for $email (we won the race)');
        return true;
      }
      if (response.statusCode == 409) {
        LoggerService.log(
            tag, 'Salt already bound for $email — another device beat us');
        return false;
      }
      throw MasterVaultMetaSyncException(
          'uploadSalt HTTP ${response.statusCode} for $email: $body');
    } on MasterVaultMetaSyncException {
      rethrow;
    } catch (ex) {
      throw MasterVaultMetaSyncException(
          'uploadSalt failed for $email', ex);
    }
  }

  /// Convenience: GET first, POST if 404, return the salt the server
  /// agrees is the bound one. This is the typical call site for fresh
  /// vault creation.
  ///
  /// Behaviour:
  ///   1. GET — if a salt is already bound, return it.
  ///   2. POST [localFallback] — if 201, the salt is now bound, return it.
  ///   3. If POST returns 409 (race lost), GET again and return the winner.
  ///
  /// On network errors, returns `null` and lets the caller decide whether
  /// to use the local random salt offline (it can re-attempt sync later).
  static Future<Uint8List?> fetchOrBindSalt({
    required String email,
    required Uint8List localFallback,
  }) async {
    const tag = 'MASTER_VAULT_META';
    try {
      final existing = await fetchBoundSalt(email);
      if (existing != null) return existing;

      final won = await uploadSalt(email, localFallback);
      if (won) return localFallback;

      // Lost the race — read what the other device bound.
      final winner = await fetchBoundSalt(email);
      if (winner == null) {
        // Should not happen — POST returned 409 so a salt exists. Treat
        // as transient and let the caller fall back to local.
        LoggerService.logWarning(
            tag, 'fetchOrBindSalt: 409 then 404 for $email (transient?)');
      }
      return winner;
    } on MasterVaultMetaSyncException catch (ex) {
      // Network/protocol error: do NOT block vault creation. The caller
      // can use its local salt and try to reconcile on a later launch.
      LoggerService.logWarning(
          tag, 'fetchOrBindSalt: $ex — falling back to local salt');
      return null;
    }
  }

  // ── Internals ────────────────────────────────────────────────────────

  static Future<HttpClient> _buildHttpClientFor(String email) async {
    try {
      return await MtlsClientPool.instance.get(email);
    } catch (_) {
      // No cert for this user yet — fall back to pinned non-mTLS client.
      // The endpoint will reject with 401, which we surface as an exception.
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
}
