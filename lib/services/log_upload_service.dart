import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'logger_service.dart';
import 'update_service.dart';
import 'platform_service.dart';

/// Log upload service for diagnostics (cross-platform)
class LogUploadService {
  static const String uploadUrl = 'https://mail.icd360s.de/logs/upload.php';
  static String? _deviceId;
  static bool _loggingEnabled = false;

  // Trusted Let's Encrypt issuer DNs
  static const _trustedIssuers = [
    'CN=R3,O=Let\'s Encrypt,C=US',
    'CN=R10,O=Let\'s Encrypt,C=US',
    'CN=R11,O=Let\'s Encrypt,C=US',
    'CN=R12,O=Let\'s Encrypt,C=US',
    'CN=E5,O=Let\'s Encrypt,C=US',
    'CN=E6,O=Let\'s Encrypt,C=US',
    'CN=E7,O=Let\'s Encrypt,C=US',
    'CN=E8,O=Let\'s Encrypt,C=US',
    'CN=ISRG Root X1,O=Internet Security Research Group,C=US',
    'CN=ISRG Root X2,O=Internet Security Research Group,C=US',
  ];

  /// Validate server certificate
  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    final issuer = cert.issuer;
    return _trustedIssuers.any(
      (trusted) => issuer == trusted || issuer.contains(trusted),
    );
  }

  /// Get or create device ID (using CSPRNG, not PII)
  static Future<String> getDeviceId() async {
    if (_deviceId != null) return _deviceId!;

    try {
      // Generate anonymous device ID using secure random
      final random = Random.secure();
      final bytes = List<int>.generate(16, (_) => random.nextInt(256));
      final hash = sha256.convert(bytes);
      _deviceId = hash.toString().substring(0, 16);

      LoggerService.log('DEVICE_ID', 'Generated device ID: $_deviceId');
      return _deviceId!;
    } catch (e) {
      _deviceId = 'unknown-device';
      return _deviceId!;
    }
  }

  /// Check if logging is enabled
  static bool isLoggingEnabled() => _loggingEnabled;

  /// Enable/disable logging
  static void setLoggingEnabled(bool enabled) {
    _loggingEnabled = enabled;
    LoggerService.log('SETTINGS', 'Logging to server: ${enabled ? "ENABLED" : "DISABLED"}');
  }

  /// Upload logs to server
  static Future<bool> uploadLogs() async {
    if (!_loggingEnabled) {
      LoggerService.log('LOG_UPLOAD', 'Logging disabled - skipping upload');
      return false;
    }

    try {
      final deviceId = await getDeviceId();
      final logs = LoggerService.getLogs(); // Get all logs

      final payload = {
        'device_id': deviceId,
        'timestamp': DateTime.now().toIso8601String(),
        'app_version': UpdateService.currentVersion,
        'platform': Platform.operatingSystem,
        'logs': logs,
      };

      LoggerService.log('LOG_UPLOAD', 'Uploading ${logs.length} log entries to server');

      final client = HttpClient()
        ..badCertificateCallback = _validateCertificate;
      try {
        final request = await client.postUrl(Uri.parse(uploadUrl));
        request.headers.set('Content-Type', 'application/json; charset=utf-8');
        request.add(utf8.encode(jsonEncode(payload)));

        final response = await request.close();
        final responseBody = await response.transform(utf8.decoder).join();

        if (response.statusCode == 200) {
          final now = DateTime.now();
          LoggerService.log('LOG_UPLOAD', '✓ Logs uploaded successfully at ${now.hour}:${now.minute.toString().padLeft(2, '0')} (${logs.length} entries)');
          return true;
        } else {
          LoggerService.log('LOG_UPLOAD', '✗ Upload failed: ${response.statusCode} - $responseBody');
          return false;
        }
      } finally {
        client.close();
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('LOG_UPLOAD', ex, stackTrace);
      return false;
    }
  }

  /// Auto-upload logs periodically (if enabled)
  static Timer? _uploadTimer;

  static void startAutoUpload() {
    if (!_loggingEnabled) return;

    // Cancel existing timer first to prevent duplicates
    _uploadTimer?.cancel();

    // Upload logs immediately on startup
    uploadLogs();

    // Upload logs every 15 minutes
    _uploadTimer = Timer.periodic(const Duration(minutes: 15), (timer) {
      uploadLogs();
    });

    LoggerService.log('LOG_UPLOAD', 'Auto-upload started (every 15 minutes)');
  }

  static void stopAutoUpload() {
    _uploadTimer?.cancel();
    _uploadTimer = null;
    LoggerService.log('LOG_UPLOAD', 'Auto-upload stopped');
  }
}