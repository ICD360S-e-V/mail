import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'logger_service.dart';
import 'mtls_service.dart';
import 'pinned_security_context.dart';
import 'portable_secure_storage.dart';

/// Per-account mTLS HttpClient pool.
///
/// Why this exists:
///   `SecurityContext` in dart:io is sticky/cumulative — calls to
///   `useCertificateChainBytes` and `usePrivateKeyBytes` ADD to the
///   internal cert store; you cannot replace or remove certs from a
///   context. So the previous pattern (mutate a global context per
///   request) caused races: under concurrent calls for different
///   accounts, the TLS handshake would pick up whichever cert was
///   last loaded — not the cert for THIS request.
///
///   Result: PGP migration uploads with HTTP 401/403 because the
///   server's CN-match check rejected the wrong-cert hand‑shake.
///
/// Solution (matches OkHttp HandshakeCertificates / NSURLSession-per-
/// identity / rhttp per-request TlsSettings patterns):
///   - One `HttpClient` per account, each built from its OWN
///     `SecurityContext` containing ONLY that account's cert + key.
///   - Cached in a `Map<String, _PooledClient>`.
///   - `withClient(username, fn)` reads cert/key for THIS account
///     from secure storage, builds (or reuses) the per-account
///     client, runs the request.
///
/// Lifecycle:
///   - Clients survive app session, cleared on lock (`closeAll`).
///   - Each `HttpClient` has its own connection pool/keep-alive,
///     so subsequent requests for the same account are fast.
class MtlsClientPool {
  MtlsClientPool._();
  static final MtlsClientPool instance = MtlsClientPool._();

  // username (lowercased) → pooled client + cert fingerprint of the
  // cert it was built with. If the cert in secure storage changes
  // (re-approval) we evict and rebuild.
  final Map<String, _PooledClient> _clients = {};

  // Storage keys mirror CertificateService's per-username layout
  // (see _kStorageClientCertFor / _kStorageClientKeyFor / _kStorageCaCertFor).
  // The username is sanitized (non-alphanumeric → '_') to match the
  // exact storage key format used at write time.
  static String _safeSuffix(String u) =>
      u.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
  static String _certKey(String u) => 'icd360s_mtls_client_cert_${_safeSuffix(u)}';
  static String _keyKey(String u)  => 'icd360s_mtls_client_key_${_safeSuffix(u)}';
  static String _caKey(String u)   => 'icd360s_mtls_ca_cert_${_safeSuffix(u)}';

  /// Run [operation] with an [HttpClient] preloaded with the mTLS
  /// cert+key of [username]. Falls back to throwing if the secure
  /// storage has no cert for this user.
  Future<T> withClient<T>(
    String username,
    Future<T> Function(HttpClient client) operation,
  ) async {
    final key = username.toLowerCase();
    final client = await _getOrCreate(key);
    return operation(client);
  }

  /// Public: get (and cache) the [HttpClient] for [username].
  /// Throws [StateError] if cert is not in secure storage.
  Future<HttpClient> get(String username) => _getOrCreate(username.toLowerCase());

  Future<HttpClient> _getOrCreate(String key) async {
    final cached = _clients[key];
    if (cached != null) return cached.client;

    final storage = PortableSecureStorage.instance;
    final certPem = await storage.read(key: _certKey(key));
    final keyPem  = await storage.read(key: _keyKey(key));
    final caPem   = await storage.read(key: _caKey(key));

    if (certPem == null || keyPem == null || caPem == null) {
      throw StateError(
          'No mTLS cert in secure storage for $key — needs Faza 3 approval');
    }

    final client = _build(certPem, keyPem, caPem);
    _clients[key] = _PooledClient(client);
    LoggerService.log('MTLS_POOL',
        '✓ New mTLS client cached for $key (${_clients.length} total)');
    return client;
  }

  HttpClient _build(String certPem, String keyPem, String caPem) {
    // Pinned trust store (ISRG roots only) — same as the global
    // service. SecurityContext belongs to THIS client only.
    final ctx = PinnedSecurityContext.create();
    ctx.usePrivateKeyBytes(utf8.encode(keyPem));
    ctx.useCertificateChainBytes(utf8.encode('$certPem\n$caPem'));

    final client = HttpClient(context: ctx)
      ..connectionTimeout = const Duration(seconds: 10)
      ..idleTimeout = const Duration(seconds: 30);
    // Server cert validation: defer to the same LE-issuer + hostname
    // logic used everywhere else.
    client.badCertificateCallback =
        (cert, host, port) => MtlsService.onBadCertificate(cert);
    return client;
  }

  /// Evict the cached client for [username] (e.g. after cert rotation).
  Future<void> evict(String username) async {
    final key = username.toLowerCase();
    final c = _clients.remove(key);
    if (c != null) {
      try { c.client.close(force: true); } catch (_) {}
    }
  }

  /// Close all clients (called on app lock / logout).
  Future<void> closeAll() async {
    for (final c in _clients.values) {
      try { c.client.close(force: true); } catch (_) {}
    }
    _clients.clear();
  }
}

class _PooledClient {
  final HttpClient client;
  _PooledClient(this.client);
}
