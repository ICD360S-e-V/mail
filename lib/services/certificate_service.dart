import 'dart:convert';
import 'dart:io';
import 'package:http/io_client.dart';
import 'certificate_expiry_monitor.dart';
import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'master_vault.dart';
import 'pinned_security_context.dart';

/// Service for downloading per-user certificates from server
/// Eliminates hardcoded certificates vulnerability
class CertificateService {
  static const String _apiUrl = 'https://mail.icd360s.de/api/get-certificate.php';

  /// Downloaded certificates (stored in memory only)
  // SECURITY (M7): in-memory cache of the per-user mTLS certificate.
  // This cache is populated at login (downloadCertificateForUser) and
  // refilled from [_secureStorage] after each lock/unlock cycle. The
  // cache is intentionally NOT static-final and IS cleared by
  // [lockCache] so a process heap dump captured outside an active
  // unlocked session does not reveal the private key. The
  // authoritative copy lives in the platform's secure storage
  // (Android Keystore-protected EncryptedSharedPreferences, iOS
  // Keychain, Windows DPAPI Credential Manager, macOS Keychain,
  // Linux libsecret) so it survives process restarts without ever
  // being touched by the public filesystem.
  static String? _clientCert;
  static String? _clientKey;
  static String? _caCert;
  static String? _currentUsername;

  // Storage backend for cert/key/CA: MasterVault on macOS (B5,
  // v2.30.0+) which is locked behind the user's master password via
  // Argon2id+HKDF+AES-GCM. On iOS/Android/Windows/Linux MasterVault
  // is a thin pass-through to PortableSecureStorage which itself
  // delegates to flutter_secure_storage (Keychain / Keystore /
  // DPAPI / libsecret) — already password/biometric-protected at
  // the OS level.
  //
  // The legacy `secure_store.bin` migration is handled inside
  // MasterVault.unlock() — the first successful unlock after upgrade
  // moves the cert/key/CA out of PortableSecureStorage into the
  // master-pwd-protected vault, then deletes them from the legacy
  // store.
  static final _secureStorage = MasterVault.instance;

  // Per-username storage keys (v2.30.2+).
  // The pre-v2.30.2 storage used GLOBAL keys without a username
  // suffix, which broke when the user added a SECOND Faza 3 account:
  // the second cert overwrote the first, and the first account
  // could never restore its cert. Migration is handled at the
  // start of restoreFromSecureStorage().
  static String _kStorageClientCertFor(String username) =>
      'icd360s_mtls_client_cert::$username';
  static String _kStorageClientKeyFor(String username) =>
      'icd360s_mtls_client_key::$username';
  static String _kStorageCaCertFor(String username) =>
      'icd360s_mtls_ca_cert::$username';

  // Legacy global keys (v2.27.0 — v2.30.1) — used only for one-time
  // migration into the per-username keys above.
  static const String _kStorageClientCertLegacy = 'icd360s_mtls_client_cert';
  static const String _kStorageClientKeyLegacy = 'icd360s_mtls_client_key';
  static const String _kStorageCaCertLegacy = 'icd360s_mtls_ca_cert';
  static const String _kStorageUsernameLegacy = 'icd360s_mtls_username';

  // Registry of usernames that have a cert in secure storage. Allows
  // [clearCertificates] (factory reset / explicit logout) to wipe ALL
  // per-user entries without scanning the entire keystore.
  static const String _kKnownCertUsernames = 'icd360s_mtls_known_cert_users';

  /// Append [username] to the known-users JSON list (idempotent).
  static Future<void> _registerKnownUser(String username) async {
    try {
      final raw = await _secureStorage.read(key: _kKnownCertUsernames);
      final List<dynamic> list =
          raw == null || raw.isEmpty ? <dynamic>[] : (jsonDecode(raw) as List);
      if (!list.contains(username)) {
        list.add(username);
        await _secureStorage.write(
            key: _kKnownCertUsernames, value: jsonEncode(list));
      }
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// Read the known-users registry. Returns empty list on error.
  static Future<List<String>> _getKnownUsers() async {
    try {
      final raw = await _secureStorage.read(key: _kKnownCertUsernames);
      if (raw == null || raw.isEmpty) return <String>[];
      return (jsonDecode(raw) as List).cast<String>();
    } catch (_) {
      return <String>[];
    }
  }

  /// Track if network is down to avoid spamming all accounts
  static bool _networkDown = false;

  /// Validate server certificate — only accept trusted Let's Encrypt issuers.
  /// Uses the shared `isTrustedLetsEncryptIssuer` helper which parses the
  /// slash-format DN that Dart returns from X509Certificate.issuer.
  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    return isTrustedLetsEncryptIssuer(cert.issuer);
  }

  /// Check if network/DNS is working before batch operations
  static Future<bool> isNetworkAvailable() async {
    try {
      final result = await InternetAddress.lookup('mail.icd360s.de')
          .timeout(const Duration(seconds: 5));
      _networkDown = result.isEmpty;
      return result.isNotEmpty;
    } catch (_) {
      _networkDown = true;
      return false;
    }
  }

  /// Whether network was detected as down
  static bool get isNetworkDown => _networkDown;

  /// Download unique certificate for user from server
  /// Returns true if successful, false otherwise
  /// Retries up to 3 times with DNS refresh on network failure
  static Future<bool> downloadCertificateForUser(String username, {required String password}) async {
    // If network was already detected as down, do a quick check first
    if (_networkDown) {
      final available = await isNetworkAvailable();
      if (!available) {
        LoggerService.log('CERT-DOWNLOAD',
            '⚠️ Network still down, skipping $username');
        return false;
      }
      LoggerService.log('CERT-DOWNLOAD', '✓ Network recovered!');
    }

    const maxRetries = 3;

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
      IOClient? client;
      HttpClient? ioClient;
      try {
        if (attempt == 1) {
          LoggerService.log('CERT-DOWNLOAD', 'Requesting certificate for $username...');
        } else {
          LoggerService.log('CERT-DOWNLOAD', 'Retry $attempt/$maxRetries for $username...');
          // Wait before retry to let network stabilize after sleep/wake
          await Future.delayed(Duration(seconds: attempt));
          // Force fresh DNS lookup
          try {
            await InternetAddress.lookup('mail.icd360s.de')
                .timeout(const Duration(seconds: 5));
          } catch (_) {
            // DNS still failing, continue to attempt anyway
          }
        }

        // Remove @icd360s.de if present (API expects just username)
        final cleanUsername = username.replaceAll('@icd360s.de', '');

        // Fresh HttpClient each time to avoid stale connections/DNS cache
        ioClient = PinnedSecurityContext.createHttpClient()
          ..connectionTimeout = const Duration(seconds: 10)
          ..idleTimeout = const Duration(seconds: 1);
        ioClient.badCertificateCallback = _validateCertificate;
        client = IOClient(ioClient);

        final response = await client.post(
          Uri.parse(_apiUrl),
          headers: {
            'Content-Type': 'application/json',
          },
          body: jsonEncode({
            'username': cleanUsername,
            'password': password,
          }),
        ).timeout(const Duration(seconds: 15));

        if (response.statusCode != 200) {
          LoggerService.log('CERT-DOWNLOAD',
              '❌ API error: ${response.statusCode} - ${response.body}');
          return false;
        }

        // Parse JSON response
        final data = jsonDecode(response.body) as Map<String, dynamic>;

        if (data['success'] != true) {
          LoggerService.log('CERT-DOWNLOAD', '❌ API returned error: ${data['error']}');
          return false;
        }

        // Extract certificates from response
        _clientCert = data['client_cert'] as String?;
        _clientKey = data['client_key'] as String?;
        _caCert = data['ca_cert'] as String?;
        _currentUsername = username;

        if (_clientCert == null || _clientKey == null || _caCert == null) {
          LoggerService.log('CERT-DOWNLOAD', '❌ Missing certificate data in response');
          return false;
        }

        // SECURITY (M7): write-through to secure storage so the
        // certificate survives process restarts and lock/unlock
        // cycles WITHOUT having to live in the Dart heap permanently.
        // v2.30.2: per-username keys so multiple Faza 3 accounts each
        // get their own cert in storage.
        try {
          final u = _currentUsername!;
          await _secureStorage.write(
              key: _kStorageClientCertFor(u), value: _clientCert);
          await _secureStorage.write(
              key: _kStorageClientKeyFor(u), value: _clientKey);
          await _secureStorage.write(
              key: _kStorageCaCertFor(u), value: _caCert);
          await _registerKnownUser(u);
          LoggerService.log('CERT-DOWNLOAD',
              '✓ Certificate persisted to platform secure storage for $u');
        } catch (ex, st) {
          LoggerService.logError('CERT-DOWNLOAD', ex, st);
          // Best-effort: cache is still populated in memory so the
          // current session works, but next unlock will need a
          // fresh download.
        }

        // Parse the real expiry from the certificate PEM and persist it.
        // This replaces the old 90-day estimate with the actual NotAfter date.
        await CertificateExpiryMonitor.parseCertAndPersistExpiry(_clientCert!);

        final validityDays = data['validity_days'] ?? 365;
        LoggerService.log('CERT-DOWNLOAD',
            '✓ Certificate downloaded for $username (valid $validityDays days)');

        _networkDown = false;
        return true;
      } catch (ex) {
        // Check if it's a network/DNS error (SocketException or ClientException wrapping SocketException)
        final isNetworkError = ex.toString().contains('Failed host lookup') ||
            ex.toString().contains('SocketException') ||
            ex.toString().contains('Connection refused') ||
            ex.toString().contains('Network is unreachable') ||
            ex.toString().contains('errno = 8');

        if (isNetworkError) {
          LoggerService.log('CERT-DOWNLOAD',
              '⚠️ Network error (attempt $attempt/$maxRetries): ${ex.toString().split('\n').first}');
          if (attempt == maxRetries) {
            _networkDown = true;
            return false;
          }
          // Continue to next retry
        } else {
          // Non-network error, don't retry
          LoggerService.logError('CERT-DOWNLOAD', ex, StackTrace.current);
          return false;
        }
      } finally {
        client?.close();
        try { ioClient?.close(force: true); } catch (_) {}
      }
    }
    return false;
  }

  /// Get downloaded client certificate (or null if not downloaded)
  static String? get clientCert => _clientCert;

  /// Get downloaded client key (or null if not downloaded)
  static String? get clientKey => _clientKey;

  /// Get downloaded CA certificate (or null if not downloaded)
  static String? get caCert => _caCert;

  /// Get current username for downloaded certificate
  static String? get currentUsername => _currentUsername;

  /// Check if certificates are available in memory
  static bool get hasCertificates =>
      _clientCert != null && _clientKey != null && _caCert != null;

  /// Persist a cert bundle obtained out-of-band (Faza 3 / device
  /// approval flow) under the per-username keys, register the user
  /// in the known-users registry, and load it into the in-memory
  /// cache. This is the single entry point for code that already
  /// has cert/key/CA in hand and just needs to store it.
  static Future<void> storeBundle({
    required String username,
    required String clientCert,
    required String clientKey,
    required String caCert,
  }) async {
    await _secureStorage.write(
        key: _kStorageClientCertFor(username), value: clientCert);
    await _secureStorage.write(
        key: _kStorageClientKeyFor(username), value: clientKey);
    await _secureStorage.write(
        key: _kStorageCaCertFor(username), value: caCert);
    await _registerKnownUser(username);
    _clientCert = clientCert;
    _clientKey = clientKey;
    _caCert = caCert;
    _currentUsername = username;
    // Persist real expiry parsed from the cert PEM.
    try {
      await CertificateExpiryMonitor.parseCertAndPersistExpiry(clientCert);
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
    LoggerService.log('CERT-DOWNLOAD',
        'Cert bundle stored for $username (per-username keys)');
  }

  /// Clear the in-memory certificate cache only (auto-lock path).
  ///
  /// SECURITY (M7): Called when the master-password session is
  /// auto-locked. Removes references to the PEM strings so the next
  /// garbage-collection cycle wipes them from the Dart heap. The
  /// authoritative copy in [_secureStorage] is left alone so the
  /// next [restoreFromSecureStorage] call after unlock can repopulate
  /// the cache without re-downloading from the server.
  static void lockCache() {
    if (_clientCert == null && _clientKey == null && _caCert == null) {
      return;
    }
    _clientCert = null;
    _clientKey = null;
    _caCert = null;
    _currentUsername = null;
    LoggerService.log('CERT-DOWNLOAD',
        'mTLS cert cache cleared from memory (lock)');
  }

  /// One-time migration: if the legacy global keys still hold a cert
  /// (v2.27.0 — v2.30.1 layout), copy it under the per-username keys
  /// for the legacy username and delete the global entries. Idempotent.
  ///
  /// Multi-account note: the legacy layout could only ever hold ONE
  /// cert (the most-recently-downloaded one). After migration, the
  /// "first" account on this device gets its cert restored; any other
  /// Faza 3 accounts must re-trigger the approval flow on their first
  /// post-upgrade login (which will then write under per-user keys
  /// and stay isolated).
  static Future<void> _migrateLegacyGlobalKeys() async {
    try {
      final legacyUser = await _secureStorage.read(key: _kStorageUsernameLegacy);
      if (legacyUser == null || legacyUser.isEmpty) return;
      final cert = await _secureStorage.read(key: _kStorageClientCertLegacy);
      final key = await _secureStorage.read(key: _kStorageClientKeyLegacy);
      final ca = await _secureStorage.read(key: _kStorageCaCertLegacy);
      if (cert == null || key == null || ca == null) {
        // Partial legacy state — just clean it up.
        await _secureStorage.delete(key: _kStorageClientCertLegacy);
        await _secureStorage.delete(key: _kStorageClientKeyLegacy);
        await _secureStorage.delete(key: _kStorageCaCertLegacy);
        await _secureStorage.delete(key: _kStorageUsernameLegacy);
        return;
      }
      await _secureStorage.write(
          key: _kStorageClientCertFor(legacyUser), value: cert);
      await _secureStorage.write(
          key: _kStorageClientKeyFor(legacyUser), value: key);
      await _secureStorage.write(
          key: _kStorageCaCertFor(legacyUser), value: ca);
      await _registerKnownUser(legacyUser);
      await _secureStorage.delete(key: _kStorageClientCertLegacy);
      await _secureStorage.delete(key: _kStorageClientKeyLegacy);
      await _secureStorage.delete(key: _kStorageCaCertLegacy);
      await _secureStorage.delete(key: _kStorageUsernameLegacy);
      LoggerService.log('CERT-DOWNLOAD',
          'Migrated legacy global mTLS cert keys → per-username keys for $legacyUser');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// Repopulate the in-memory cache from [_secureStorage] for a
  /// SPECIFIC user (v2.30.2+).
  ///
  /// SECURITY (M7): Called by EmailProvider when (re)connecting an
  /// account so each account loads its own per-username cert. The
  /// in-memory cache holds at most one cert at a time — switching to
  /// a different user replaces it.
  ///
  /// Multi-account: this is the correct entry point for code that
  /// knows which account it wants. The legacy [restoreFromSecureStorage]
  /// (no username) is preserved only for the master-password unlock
  /// path which has no account context.
  static Future<bool> restoreFromSecureStorageFor(String username) async {
    if (_currentUsername == username && hasCertificates) return true;
    try {
      // Run legacy migration first so a freshly upgraded user with the
      // old global keys can still be restored under the new layout.
      await _migrateLegacyGlobalKeys();

      final cert = await _secureStorage.read(key: _kStorageClientCertFor(username));
      final key = await _secureStorage.read(key: _kStorageClientKeyFor(username));
      final ca = await _secureStorage.read(key: _kStorageCaCertFor(username));
      if (cert == null || key == null || ca == null) {
        return false;
      }
      _clientCert = cert;
      _clientKey = key;
      _caCert = ca;
      _currentUsername = username;
      // Restore persisted expiry dates (parsed from PEM at download time)
      await CertificateExpiryMonitor.loadPersistedExpiry();
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert cache restored from secure storage for $username');
      return true;
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
      return false;
    }
  }

  /// Best-effort restore at master-password unlock time, when no
  /// account context is available yet.
  ///
  /// Tries (in order):
  ///   1. Legacy global key migration (populates per-username keys).
  ///   2. The first known user from the registry — so the in-memory
  ///      cache is non-empty and the IMAP/SMTP layer can establish
  ///      the initial connection. EmailProvider will subsequently
  ///      call [restoreFromSecureStorageFor] per account to swap in
  ///      the correct cert before each connect.
  static Future<bool> restoreFromSecureStorage() async {
    if (hasCertificates) return true;
    try {
      await _migrateLegacyGlobalKeys();
      final users = await _getKnownUsers();
      if (users.isEmpty) return false;
      return await restoreFromSecureStorageFor(users.first);
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
      return false;
    }
  }

  /// Clear certificates from BOTH memory cache AND persistent secure
  /// storage (explicit logout / sign-out / factory reset).
  ///
  /// After this call, the next session must re-download the cert via
  /// [downloadCertificateForUser]. Use [lockCache] for the auto-lock
  /// path that should preserve the secure-storage copy.
  ///
  /// v2.30.2: iterates the known-users registry so every per-username
  /// cert triple is wiped, then deletes the registry itself and the
  /// legacy global keys for backward compatibility.
  static Future<void> clearCertificates() async {
    lockCache();
    try {
      final users = await _getKnownUsers();
      for (final u in users) {
        await _secureStorage.delete(key: _kStorageClientCertFor(u));
        await _secureStorage.delete(key: _kStorageClientKeyFor(u));
        await _secureStorage.delete(key: _kStorageCaCertFor(u));
      }
      await _secureStorage.delete(key: _kKnownCertUsernames);
      // Legacy global keys (pre-v2.30.2) — defensive cleanup.
      await _secureStorage.delete(key: _kStorageClientCertLegacy);
      await _secureStorage.delete(key: _kStorageClientKeyLegacy);
      await _secureStorage.delete(key: _kStorageCaCertLegacy);
      await _secureStorage.delete(key: _kStorageUsernameLegacy);
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert wiped from secure storage (explicit logout, ${users.length} users)');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }

  /// Clear cert for a SINGLE user (used when one account is removed
  /// from the app while others remain). Does not touch the in-memory
  /// cache unless it currently belongs to [username].
  static Future<void> clearCertificatesFor(String username) async {
    if (_currentUsername == username) lockCache();
    try {
      await _secureStorage.delete(key: _kStorageClientCertFor(username));
      await _secureStorage.delete(key: _kStorageClientKeyFor(username));
      await _secureStorage.delete(key: _kStorageCaCertFor(username));
      // Remove from known-users registry.
      final users = await _getKnownUsers();
      users.remove(username);
      if (users.isEmpty) {
        await _secureStorage.delete(key: _kKnownCertUsernames);
      } else {
        await _secureStorage.write(
            key: _kKnownCertUsernames, value: jsonEncode(users));
      }
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert wiped from secure storage for $username');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }
}
