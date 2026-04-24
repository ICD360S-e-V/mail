// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// How much email content to show in system notifications.
enum NotificationPrivacyLevel {
  /// "New email" — no sender, no subject. Maximum privacy.
  none,
  /// "New email from Marcel" — sender only, no subject. Default.
  senderOnly,
  /// "New email from Marcel: Meeting tomorrow" — full content.
  full,
}

/// Settings service for user preferences (cross-platform)
class SettingsService {
  static const String _settingsFileName = 'settings.json';
  static String? _settingsPath;

  /// Write serialization chain: every saveSettings call appends its work to
  /// this future so concurrent saves are processed in order. The chain is
  /// updated atomically because Dart's event loop is single-threaded — there
  /// is no `await` between reading and writing _writeChain.
  ///
  /// SECURITY/CORRECTNESS (L2): The previous Completer-based lock had a
  /// classic check-then-set race — two concurrent saves could both pass the
  /// `while (_writeLock != null)` guard before either set the lock, causing
  /// one save to be silently lost.
  static Future<void> _writeChain = Future.value();

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
    // Append our write to the serialization chain. The previous future is
    // captured and our new work is queued after it. Updating _writeChain to
    // include our future ensures the next caller waits for us, in order.
    // This is atomic because no await separates the read and the assignment.
    final previous = _writeChain;
    final ourTurn = previous.then((_) async {
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
      }
    });
    // Swallow errors when the chain is consumed by the next caller — we
    // don't want one failed write to block all future writes.
    _writeChain = ourTurn.catchError((_) {});
    return ourTurn;
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

  /// Get notification privacy level. Default: senderOnly.
  static Future<NotificationPrivacyLevel> getNotificationPrivacyLevel() async {
    final settings = await loadSettings();
    final value = settings['notificationPrivacyLevel'] as String?;
    return switch (value) {
      'none' => NotificationPrivacyLevel.none,
      'full' => NotificationPrivacyLevel.full,
      _ => NotificationPrivacyLevel.senderOnly,
    };
  }

  /// Save notification privacy level.
  static Future<void> setNotificationPrivacyLevel(
      NotificationPrivacyLevel level) async {
    final settings = await loadSettings();
    settings['notificationPrivacyLevel'] = level.name;
    final path = _getSettingsPath();
    await File(path).writeAsString(jsonEncode(settings));
    LoggerService.log('SETTINGS',
        'Notification privacy level set to: ${level.name}');
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

  /// Read a single boolean flag (returns false if absent).
  static Future<bool> getFlag(String key) async {
    final settings = await loadSettings();
    return settings[key] as bool? ?? false;
  }

  /// Persist a single boolean flag without touching other settings.
  static Future<void> setFlag(String key, {required bool value}) async {
    final previous = _writeChain;
    final ourTurn = previous.then((_) async {
      try {
        final settings = await loadSettings();
        settings[key] = value;
        final path = _getSettingsPath();
        await File(path).writeAsString(jsonEncode(settings));
        LoggerService.log('SETTINGS', 'Flag set: $key=$value');
      } catch (ex, stackTrace) {
        LoggerService.logError('SETTINGS', ex, stackTrace);
      }
    });
    _writeChain = ourTurn.catchError((_) {});
    return ourTurn;
  }
}
