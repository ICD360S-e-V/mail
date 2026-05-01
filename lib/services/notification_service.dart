// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import '../models/models.dart';
import '../utils/pii_redactor.dart';
import 'logger_service.dart';
import 'localization_service.dart';
import 'settings_service.dart';

/// Cross-platform notification service for in-app and system notifications.
/// Uses flutter_local_notifications for macOS, Linux, Android, iOS.
/// Windows uses in-app notifications only (InfoBar).
class NotificationService {
  // Notification callbacks - will be set by main window
  static Function(String title, String message, NotificationType type)? onShowNotification;

  // Flutter Local Notifications plugin (cross-platform except Windows)
  static final FlutterLocalNotificationsPlugin _notificationsPlugin =
      FlutterLocalNotificationsPlugin();
  static bool _isInitialized = false;
  static bool _notificationsEnabled = true; // User preference

  /// Initialize notifications for all platforms
  static Future<void> initialize() async {
    if (_isInitialized) return;

    // Skip system notifications on Windows - use in-app only
    if (Platform.isWindows) {
      _isInitialized = true;
      LoggerService.log('NOTIFICATION', 'Windows: Using in-app notifications only');
      return;
    }

    try {
      // Platform-specific initialization settings
      const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
      const darwinSettings = DarwinInitializationSettings(
        requestAlertPermission: true,
        requestBadgePermission: true,
        requestSoundPermission: true,
      );
      final linuxSettings = LinuxInitializationSettings(
        defaultActionName: 'Open',
        defaultIcon: AssetsLinuxIcon('assets/logo.png'),
      );

      final initSettings = InitializationSettings(
        android: androidSettings,
        iOS: darwinSettings,
        macOS: darwinSettings,
        linux: linuxSettings,
      );

      await _notificationsPlugin.initialize(
        settings: initSettings,
        onDidReceiveNotificationResponse: _onNotificationTapped,
      );

      _isInitialized = true;
      final platform = Platform.operatingSystem;
      LoggerService.log('NOTIFICATION', 'Notifications initialized for $platform (enabled: $_notificationsEnabled)');
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION_INIT', ex, stackTrace);
    }
  }

  /// Handle notification tap
  static void _onNotificationTapped(NotificationResponse response) {
    LoggerService.log('NOTIFICATION', 'Notification tapped: ${response.payload}');
    // Could navigate to specific email here based on payload
  }

  /// Set notifications enabled/disabled
  static void setNotificationsEnabled(bool enabled) {
    _notificationsEnabled = enabled;
    LoggerService.log('SETTINGS', 'System notifications: ${enabled ? "ENABLED" : "DISABLED"}');
  }

  /// Check if notifications are enabled
  static bool areNotificationsEnabled() => _notificationsEnabled;

  /// Show notification for new email (both in-app and system notification)
  static Future<void> showNewEmailToast(Email email) async {
    try {
      final from = _extractName(email.from);
      final l10nService = LocalizationService.instance;
      final privacyLevel = await SettingsService.getNotificationPrivacyLevel();

      // Build title/body based on privacy level (Proton Mail pattern):
      //   none       → "New email" / "Tap to open"
      //   senderOnly → "New email from Marcel" / "Tap to open"
      //   full       → "New email from Marcel" / subject + threat level
      final String title;
      final String body;
      final String inAppMessage;

      switch (privacyLevel) {
        case NotificationPrivacyLevel.none:
          title = l10nService.getText(
            (l10n) => l10n.notificationNewEmail,
            'New email',
          );
          body = '';
          inAppMessage = title;
        case NotificationPrivacyLevel.senderOnly:
          title = l10nService.getText(
            (l10n) => l10n.notificationNewEmailFrom(from),
            'New email from $from',
          );
          body = '';
          inAppMessage = title;
        case NotificationPrivacyLevel.full:
          title = l10nService.getText(
            (l10n) => l10n.notificationNewEmailFrom(from),
            'New email from $from',
          );
          body = email.subject;
          inAppMessage = l10nService.getText(
            (l10n) => l10n.notificationEmailSubjectThreat(
                email.subject, email.threatLevel),
            '${email.subject}\nThreat: ${email.threatLevel}',
          );
      }

      // In-app notification (InfoBar) — always shows full for UX
      // (the app is already unlocked if visible)
      onShowNotification?.call('📧 $title', inAppMessage, NotificationType.info);

      // System notification — respects privacy level
      if (!Platform.isWindows) {
        await _showSystemNotification(
          title: title,
          body: body.isNotEmpty ? body : null,
          payload: 'email:${email.messageId}',
        );
      }

      LoggerService.log('NOTIFICATION',
          'Notification shown (privacy=${privacyLevel.name}) for ${piiEmail(email.from)}');
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION', ex, stackTrace);
    }
  }

  /// Show system notification (cross-platform except Windows)
  static Future<void> _showSystemNotification({
    required String title,
    String? body,
    String? payload,
  }) async {
    // Skip on Windows
    if (Platform.isWindows) return;

    // Check if user enabled notifications
    if (!_notificationsEnabled) {
      LoggerService.log('NOTIFICATION', 'System notification skipped (user disabled)');
      return;
    }

    if (!_isInitialized) {
      await initialize();
    }

    try {
      // Notification details for each platform.
      //
      // SECURITY (Android): visibility = private. On a secure lock
      // screen the system replaces our title and body with the
      // generic placeholder "Sensitive notification content is
      // hidden", showing only the app icon and the count. After the
      // user unlocks, the full title (sender) and body (subject) are
      // revealed. This is the standard pattern for messaging apps
      // (Signal, WhatsApp, ProtonMail) and protects against shoulder-
      // surfing, casual observers and notification mirroring to
      // smartwatches that don't share the device lock state.
      const androidDetails = AndroidNotificationDetails(
        'icd360s_mail_channel',
        'ICD360S Mail',
        channelDescription: 'New email notifications',
        importance: Importance.high,
        priority: Priority.high,
        ticker: 'New email',
        visibility: NotificationVisibility.private,
      );

      // SECURITY (iOS / macOS): Apple does NOT expose a public API
      // for forcing lock-screen content redaction from the
      // application side. The behaviour is controlled exclusively by
      // the user via Settings → Notifications → ICD360S Mail →
      // Show Previews → "When Unlocked" (recommended) or "Never".
      // We therefore put the real subject in the body and rely on
      // the user setting + the in-app blur overlay (M4) to keep the
      // content private. Recommend the "When Unlocked" setting in
      // user-facing documentation. (This matches Apple Mail.app
      // behaviour.)
      const darwinDetails = DarwinNotificationDetails(
        presentAlert: true,
        presentBadge: true,
        presentSound: true,
      );

      const linuxDetails = LinuxNotificationDetails(
        urgency: LinuxNotificationUrgency.normal,
      );

      const notificationDetails = NotificationDetails(
        android: androidDetails,
        iOS: darwinDetails,
        macOS: darwinDetails,
        linux: linuxDetails,
      );

      // Use a unique ID based on timestamp
      final id = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      await _notificationsPlugin.show(
        id: id,
        title: title,
        body: body,
        notificationDetails: notificationDetails,
        payload: payload,
      );

      LoggerService.log('NOTIFICATION', 'System notification sent (new email)');
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION', ex, stackTrace);
    }
  }

  /// Show info notification (in-app only)
  static void showInfoToast(String title, String message) {
    try {
      onShowNotification?.call(title, message, NotificationType.info);
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION', ex, stackTrace);
    }
  }

  /// Show error notification (in-app only)
  static void showErrorToast(String title, String message) {
    try {
      final errorTitle = '❌ $title';
      onShowNotification?.call(errorTitle, message, NotificationType.error);
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION', ex, stackTrace);
    }
  }

  /// Show success notification (in-app only)
  static void showSuccessToast(String title, String message) {
    try {
      onShowNotification?.call(title, message, NotificationType.success);
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION', ex, stackTrace);
    }
  }

  /// Extract name from email address "Name `<email@example.com>`"
  static String _extractName(String emailAddress) {
    if (emailAddress.contains('<') && emailAddress.contains('>')) {
      final end = emailAddress.indexOf('<');
      final name = emailAddress.substring(0, end).trim();
      return name.isNotEmpty ? name : emailAddress;
    }
    return emailAddress;
  }
}

/// Notification type for UI display
enum NotificationType {
  info,
  success,
  warning,
  error,
}
