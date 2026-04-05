import 'dart:io';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import '../models/models.dart';
import 'logger_service.dart';
import 'localization_service.dart';

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
        initSettings,
        onDidReceiveNotificationResponse: _onNotificationTapped,
      );

      _isInitialized = true;
      final platform = Platform.operatingSystem;
      LoggerService.log('NOTIFICATION', 'Notifications initialized for $platform (enabled: $_notificationsEnabled)');
      // NOTE: permission is requested contextually via requestPermission()
      // after user consents in FirstRunConsentDialog or after first email fetch
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION_INIT', ex, stackTrace);
    }
  }

  /// Request notification permission (Android 13+, iOS, macOS)
  /// Call this AFTER showing a pre-prompt dialog explaining why notifications are needed
  /// Returns true if permission granted
  static Future<bool> requestPermission() async {
    try {
      // Linux/Windows: no OS permission needed
      if (Platform.isLinux || Platform.isWindows) return true;

      if (Platform.isAndroid) {
        final androidPlugin = _notificationsPlugin
            .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();
        if (androidPlugin != null) {
          final granted = await androidPlugin.requestNotificationsPermission();
          LoggerService.log('NOTIFICATION', 'Android permission ${granted == true ? "GRANTED" : "DENIED"}');
          return granted ?? false;
        }
      } else if (Platform.isIOS) {
        final iosPlugin = _notificationsPlugin
            .resolvePlatformSpecificImplementation<IOSFlutterLocalNotificationsPlugin>();
        if (iosPlugin != null) {
          final granted = await iosPlugin.requestPermissions(alert: true, badge: true, sound: true);
          LoggerService.log('NOTIFICATION', 'iOS permission ${granted == true ? "GRANTED" : "DENIED"}');
          return granted ?? false;
        }
      } else if (Platform.isMacOS) {
        final macPlugin = _notificationsPlugin
            .resolvePlatformSpecificImplementation<MacOSFlutterLocalNotificationsPlugin>();
        if (macPlugin != null) {
          final granted = await macPlugin.requestPermissions(alert: true, badge: true, sound: true);
          LoggerService.log('NOTIFICATION', 'macOS permission ${granted == true ? "GRANTED" : "DENIED"}');
          return granted ?? false;
        }
      }
    } catch (ex) {
      LoggerService.logError('NOTIFICATION_PERMISSION', ex, StackTrace.current);
    }
    return false;
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
      final title = l10nService.getText(
        (l10n) => l10n.notificationNewEmailFrom(from),
        'New Email from $from'
      );
      final message = l10nService.getText(
        (l10n) => l10n.notificationEmailSubjectThreat(email.subject, email.threatLevel),
        '${email.subject}\nThreat: ${email.threatLevel}'
      );

      // Show in-app notification (InfoBar)
      onShowNotification?.call('📧 $title', message, NotificationType.info);

      // Show system notification (non-Windows platforms)
      if (!Platform.isWindows) {
        await _showSystemNotification(
          title: title,
          body: email.subject,
          payload: 'email:${email.messageId}',
        );
      }

      LoggerService.log('NOTIFICATION', 'Notification shown for email from ${email.from}');
    } catch (ex, stackTrace) {
      LoggerService.logError('NOTIFICATION', ex, stackTrace);
    }
  }

  /// Show system notification (cross-platform except Windows)
  static Future<void> _showSystemNotification({
    required String title,
    required String body,
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
      // Notification details for each platform
      const androidDetails = AndroidNotificationDetails(
        'icd360s_mail_channel',
        'ICD360S Mail',
        channelDescription: 'New email notifications',
        importance: Importance.high,
        priority: Priority.high,
        ticker: 'New email',
      );

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
        id,
        title,
        body,
        notificationDetails,
        payload: payload,
      );

      LoggerService.log('NOTIFICATION', 'System notification sent: $title');
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
