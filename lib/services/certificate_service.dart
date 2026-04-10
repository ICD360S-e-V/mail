import 'dart:convert';
import 'dart:io';
import 'package:http/io_client.dart';
import 'certificate_expiry_monitor.dart';
import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'pinned_security_context.dart';
import 'portable_secure_storage.dart';

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

  // PortableSecureStorage uses native storage on iOS/Android/Windows/
  // Linux and AES-GCM file backend on macOS (Keychain unavailable on
  // ad-hoc signed builds).
  static final _secureStorage = PortableSecureStorage.instance;
  static const String _kStorageClientCert = 'icd360s_mtls_client_cert';
  static const String _kStorageClientKey = 'icd360s_mtls_client_key';
  static const String _kStorageCaCert = 'icd360s_mtls_ca_cert';
  static const String _kStorageUsername = 'icd360s_mtls_username';

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
        try {
          await _secureStorage.write(
              key: _kStorageClientCert, value: _clientCert);
          await _secureStorage.write(
              key: _kStorageClientKey, value: _clientKey);
          await _secureStorage.write(key: _kStorageCaCert, value: _caCert);
          await _secureStorage.write(
              key: _kStorageUsername, value: _currentUsername);
          LoggerService.log('CERT-DOWNLOAD',
              '✓ Certificate persisted to platform secure storage');
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

  /// Repopulate the in-memory cache from [_secureStorage].
  ///
  /// SECURITY (M7): Called after a successful master-password verify
  /// (see MasterPasswordService.verifyMasterPassword). If the
  /// platform secure storage holds a previously-downloaded
  /// certificate, the in-memory cache is filled from there so the
  /// caller does not need to re-issue the network download. Returns
  /// true if the cache is populated (either freshly restored or
  /// already present), false otherwise.
  static Future<bool> restoreFromSecureStorage() async {
    if (hasCertificates) return true;
    try {
      final cert = await _secureStorage.read(key: _kStorageClientCert);
      final key = await _secureStorage.read(key: _kStorageClientKey);
      final ca = await _secureStorage.read(key: _kStorageCaCert);
      final username = await _secureStorage.read(key: _kStorageUsername);
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

  /// Clear certificates from BOTH memory cache AND persistent secure
  /// storage (explicit logout / sign-out / factory reset).
  ///
  /// After this call, the next session must re-download the cert via
  /// [downloadCertificateForUser]. Use [lockCache] for the auto-lock
  /// path that should preserve the secure-storage copy.
  static Future<void> clearCertificates() async {
    lockCache();
    try {
      await _secureStorage.delete(key: _kStorageClientCert);
      await _secureStorage.delete(key: _kStorageClientKey);
      await _secureStorage.delete(key: _kStorageCaCert);
      await _secureStorage.delete(key: _kStorageUsername);
      LoggerService.log('CERT-DOWNLOAD',
          'mTLS cert wiped from secure storage (explicit logout)');
    } catch (ex, st) {
      LoggerService.logError('CERT-DOWNLOAD', ex, st);
    }
  }
}
