import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'logger_service.dart';
import 'update_service.dart';
import 'platform_service.dart';

/// Log upload service for diagnostics (cross-platform)
class LogUploadService {
  static const String uploadUrl = 'https://mail.icd360s.de/logs/upload.php';
  static String? _deviceId;
  static bool _loggingEnabled = false;

  /// Get or create device ID
  static Future<String> getDeviceId() async {
    if (_deviceId != null) return _deviceId!;

    try {
      // Generate device ID based on computer name + username (cross-platform)
      final platform = PlatformService.instance;
      final computerName = platform.computerName;
      final username = platform.username;
      final combined = '$computerName-$username-${DateTime.now().millisecondsSinceEpoch}';

      // Hash to create unique ID
      final bytes = utf8.encode(combined);
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
        ..badCertificateCallback = (cert, host, port) =>
            host == 'mail.icd360s.de' && (cert.issuer.contains("Let's Encrypt") || cert.issuer.contains('ISRG Root'));
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
