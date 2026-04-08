import 'dart:convert';
import 'dart:io';
import 'package:http/io_client.dart';
import 'le_issuer_check.dart';
import 'logger_service.dart';

/// Service for downloading per-user certificates from server
/// Eliminates hardcoded certificates vulnerability
class CertificateService {
  static const String _apiUrl = 'https://mail.icd360s.de/api/get-certificate.php';

  /// Downloaded certificates (stored in memory only)
  static String? _clientCert;
  static String? _clientKey;
  static String? _caCert;
  static String? _currentUsername;

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
        ioClient = HttpClient()
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

  /// Clear certificates from memory (on logout)
  static void clearCertificates() {
    _clientCert = null;
    _clientKey = null;
    _caCert = null;
    _currentUsername = null;
    LoggerService.log('CERT-DOWNLOAD', 'Certificates cleared from memory');
  }
}
