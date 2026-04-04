import 'package:fluent_ui/fluent_ui.dart';
import 'package:window_manager/window_manager.dart';
import '../utils/l10n_helper.dart';
import '../services/master_password_service.dart';
import '../services/settings_service.dart';
import '../services/log_upload_service.dart';
import '../services/notification_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import 'first_run_consent_dialog.dart';
import 'master_password_dialog.dart';
import 'main_window.dart';

/// Authentication wrapper - shows master password dialog at startup
class AuthWrapper extends StatefulWidget {
  const AuthWrapper({super.key});

  @override
  State<AuthWrapper> createState() => _AuthWrapperState();
}

class _AuthWrapperState extends State<AuthWrapper> {
  bool _isAuthenticated = false;
  bool _isChecking = true;

  @override
  void initState() {
    super.initState();
    // Wait for first frame to be rendered before showing dialogs
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _checkAuthentication();
    });
  }

  Future<void> _checkAuthentication() async {
    // Check if first run
    if (SettingsService.isFirstRun()) {
      // Show consent dialog first
      if (mounted) {
        final consent = await showDialog<Map<String, bool>>(
          context: context,
          barrierDismissible: false,
          builder: (context) => const FirstRunConsentDialog(),
        );

        if (consent != null) {
          // Save preferences
          await SettingsService.saveSettings(
            autoUpdateEnabled: consent['autoUpdate'] ?? true,
            loggingEnabled: consent['logging'] ?? true,
            notificationsEnabled: consent['notifications'] ?? true,
          );

          // Enable logging if user consented
          LogUploadService.setLoggingEnabled(consent['logging'] ?? true);
          if (consent['logging'] == true) {
            LogUploadService.startAutoUpload();
          }

          // Enable notifications if user consented
          NotificationService.setNotificationsEnabled(consent['notifications'] ?? true);
        }
      }
    } else {
      // Load existing settings
      final loggingEnabled = await SettingsService.getLoggingEnabled();
      LogUploadService.setLoggingEnabled(loggingEnabled);
      if (loggingEnabled) {
        LogUploadService.startAutoUpload();
      }

      // Load notifications preference
      final notificationsEnabled = await SettingsService.getNotificationsEnabled();
      NotificationService.setNotificationsEnabled(notificationsEnabled);
    }

    // Check if master password is required
    final hasPassword = await MasterPasswordService.hasMasterPassword();

    if (!hasPassword) {
      // First-time setup - show dialog to set password
      if (mounted) {
        final result = await _showMasterPasswordDialog();
        if (mounted) {
          setState(() {
            _isAuthenticated = result;
            _isChecking = false;
          });
        }
      }
    } else {
      // Show login dialog
      if (mounted) {
        setState(() => _isChecking = false);
        final result = await _showMasterPasswordDialog();
        if (mounted) {
          setState(() => _isAuthenticated = result);
        }
      }
    }
  }

  Future<bool> _showMasterPasswordDialog() async {
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => const MasterPasswordDialog(),
    );

    // Maximize window after successful authentication (desktop only)
    if (result == true && PlatformService.instance.isDesktop) {
      try {
        await windowManager.maximize();
        LoggerService.log('WINDOW', 'Window maximized after authentication');
      } catch (ex, stackTrace) {
        LoggerService.logError('WINDOW', ex, stackTrace);
      }
    }

    return result ?? false;
  }

  @override
  Widget build(BuildContext context) {
    final l10n = l10nOf(context);

    if (_isChecking) {
      // Show loading screen while checking - use ScaffoldPage with solid background
      return const ScaffoldPage(
        content: Center(
          child: ProgressRing(),
        ),
      );
    }

    if (!_isAuthenticated) {
      // Authentication failed - show error or exit
      return ScaffoldPage(
        content: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(FluentIcons.lock, size: 64),
              const SizedBox(height: 16),
              Text(l10n.authWrapperAuthRequired),
              const SizedBox(height: 8),
              Button(
                child: Text(l10n.authWrapperButtonExit),
                onPressed: () {
                  // Exit app
                  // In a real app, you'd call SystemNavigator.pop() or exit(0)
                },
              ),
            ],
          ),
        ),
      );
    }

    // Authenticated - show main window
    return const MainWindow();
  }
}
