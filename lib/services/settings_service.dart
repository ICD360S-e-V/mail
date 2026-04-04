import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// Settings service for user preferences (cross-platform)
class SettingsService {
  static const String _settingsFileName = 'settings.json';
  static String? _settingsPath;
  static Completer<void>? _writeLock;

  /// Get settings file path
  static String _getSettingsPath() {
    if (_settingsPath != null) return _settingsPath!;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    final dir = Directory(appDataPath);
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
    }

    _settingsPath = p.join(appDataPath, _settingsFileName);
    return _settingsPath!;
  }

  /// Check if first run (settings file doesn't exist)
  /// Wrapped in try-catch for GrapheneOS/hardened ROMs where storage
  /// access may fail on first launch before permissions are granted.
  static bool isFirstRun() {
    try {
      final path = _getSettingsPath();
      return !File(path).existsSync();
    } catch (ex) {
      LoggerService.logError('SETTINGS', ex, StackTrace.current);
      return true; // Treat as first run if we can't check
    }
  }

  /// Save settings (serialized to prevent concurrent write corruption)
  static Future<void> saveSettings({
    required bool autoUpdateEnabled,
    required bool loggingEnabled,
    bool? notificationsEnabled,
    String? theme,
    String? language,
  }) async {
    // Wait for any pending write to complete
    while (_writeLock != null) {
      await _writeLock!.future;
    }
    _writeLock = Completer<void>();

    try {
      // Load existing settings first to preserve other fields
      final existing = await loadSettings();
      existing['autoUpdateEnabled'] = autoUpdateEnabled;
      existing['loggingEnabled'] = loggingEnabled;
      existing['notificationsEnabled'] = notificationsEnabled ?? existing['notificationsEnabled'] ?? true;
      existing['theme'] = theme ?? existing['theme'] ?? 'light';
      existing['language'] = language ?? existing['language'];
      existing['lastUpdated'] = DateTime.now().toIso8601String();

      final path = _getSettingsPath();
      await File(path).writeAsString(jsonEncode(existing));

      LoggerService.log('SETTINGS', 'Settings saved: auto-update=$autoUpdateEnabled, logging=$loggingEnabled, notifications=${notificationsEnabled ?? true}, theme=${theme ?? "light"}, language=$language');
    } catch (ex, stackTrace) {
      LoggerService.logError('SETTINGS', ex, stackTrace);
    } finally {
      _writeLock!.complete();
      _writeLock = null;
    }
  }

  /// Load settings
  static Future<Map<String, dynamic>> loadSettings() async {
    try {
      final path = _getSettingsPath();
      if (File(path).existsSync()) {
        final content = await File(path).readAsString();
        final settings = jsonDecode(content) as Map<String, dynamic>;
        LoggerService.log('SETTINGS', 'Settings loaded from disk');
        return settings;
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('SETTINGS', ex, stackTrace);
    }

    // Return defaults if file doesn't exist or error
    return {
      'autoUpdateEnabled': true,
      'loggingEnabled': true,
      'notificationsEnabled': true,
      'theme': 'light',
      'language': null,
    };
  }

  /// Get auto-update preference
  static Future<bool> getAutoUpdateEnabled() async {
    final settings = await loadSettings();
    return settings['autoUpdateEnabled'] as bool? ?? true;
  }

  /// Get logging preference
  static Future<bool> getLoggingEnabled() async {
    final settings = await loadSettings();
    return settings['loggingEnabled'] as bool? ?? true;
  }

  /// Get notifications preference
  static Future<bool> getNotificationsEnabled() async {
    final settings = await loadSettings();
    return settings['notificationsEnabled'] as bool? ?? true;
  }

  /// Get theme preference
  static Future<String> getTheme() async {
    final settings = await loadSettings();
    return settings['theme'] as String? ?? 'light';
  }

  /// Get language preference
  static Future<String?> getLanguage() async {
    final settings = await loadSettings();
    return settings['language'] as String?;
  }
}
