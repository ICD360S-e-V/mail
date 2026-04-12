import 'package:fluent_ui/fluent_ui.dart';
import 'package:window_manager/window_manager.dart';
import '../utils/l10n_helper.dart';
import '../services/master_password_service.dart';
import '../services/master_vault.dart';
import '../services/pin_unlock_service.dart';
import '../services/settings_service.dart';
import '../services/log_upload_service.dart';
import '../services/notification_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import 'first_run_consent_dialog.dart';
import 'master_password_dialog.dart';
import 'pin_unlock_screen.dart';
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
      // First-time setup — set master password, then offer PIN setup
      if (mounted) {
        final result = await _showMasterPasswordDialog();
        if (result && mounted) {
          await _offerPinSetup();
        }
        if (mounted) {
          setState(() {
            _isAuthenticated = result;
            _isChecking = false;
          });
        }
      }
    } else {
      // Returning user — try PIN first if configured
      if (mounted) {
        setState(() => _isChecking = false);

        final hasPin = await PinUnlockService.hasPinConfigured();
        if (hasPin) {
          final pinResult = await _showPinUnlock();
          if (pinResult && mounted) {
            setState(() => _isAuthenticated = true);
            return;
          }
          // PIN failed/expired — fall through to master password
        }

        final result = await _showMasterPasswordDialog();
        if (result && mounted) {
          // After master password success, offer PIN setup if not configured
          final hasPinNow = await PinUnlockService.hasPinConfigured();
          if (!hasPinNow) {
            await _offerPinSetup();
          }
        }
        if (mounted) {
          setState(() => _isAuthenticated = result);
        }
      }
    }
  }

  /// Show PIN unlock screen. Returns true if PIN unlock succeeded.
  Future<bool> _showPinUnlock() async {
    final result = await Navigator.of(context).push<bool>(
      FluentPageRoute(
        builder: (_) => PinUnlockScreen(
          onPinSubmitted: (pin) async {
            final masterKey = await PinUnlockService.verifyPin(pin);
            if (masterKey == null) return false;
            try {
              await PinUnlockService.unlockWithMasterKey(masterKey);
              // Zero masterKey
              for (var i = 0; i < masterKey.length; i++) masterKey[i] = 0;
              if (mounted) Navigator.of(context).pop(true);
              return true;
            } catch (ex, st) {
              LoggerService.logError('PIN_UNLOCK', ex, st);
              for (var i = 0; i < masterKey.length; i++) masterKey[i] = 0;
              return false;
            }
          },
          onFallbackToPassword: () {
            if (mounted) Navigator.of(context).pop(false);
          },
        ),
      ),
    );

    if (result == true && PlatformService.instance.isDesktop) {
      try {
        await windowManager.maximize();
      } catch (_) {}
    }
    return result ?? false;
  }

  /// Offer PIN setup after successful master password unlock.
  Future<void> _offerPinSetup() async {
    if (!mounted) return;
    final wantPin = await showDialog<bool>(
      context: context,
      builder: (ctx) => ContentDialog(
        title: const Text('Set up quick PIN unlock?'),
        content: const Text(
          'Set a 6-digit PIN for quick unlock. The PIN uses a '
          'randomized keypad for maximum security against shoulder '
          'surfing and smudge attacks.\n\n'
          'Your master password is still required every 72 hours '
          'and after 5 wrong PIN attempts.',
        ),
        actions: [
          Button(
            child: const Text('Skip'),
            onPressed: () => Navigator.pop(ctx, false),
          ),
          FilledButton(
            child: const Text('Set PIN'),
            onPressed: () => Navigator.pop(ctx, true),
          ),
        ],
      ),
    );
    if (wantPin != true || !mounted) return;

    // Get masterKey from vault for wrapping under PIN
    final vault = MasterVault.instance;
    // We need the masterKey that was just derived — it's in the vault's
    // internal state. Since we just unlocked, derive it again from the
    // password hash's argon2 salt. Actually, the simplest approach:
    // PinUnlockService.setupPin needs the masterKey. We'll get it by
    // re-reading from MasterPasswordService the password that was just
    // verified, but that's not accessible. Instead, we show PIN setup
    // as a separate screen where the user enters the PIN.
    await Navigator.of(context).push<void>(
      FluentPageRoute(
        builder: (_) => PinUnlockScreen(
          isSetup: true,
          onPinSubmitted: (pin) async {
            try {
              final masterKey = await vault.deriveMasterKeyFromCache();
              if (masterKey == null) {
                LoggerService.logWarning('PIN_SETUP',
                    'masterKey cache is null — cannot setup PIN');
                return false;
              }
              await PinUnlockService.setupPin(pin: pin, masterKey: masterKey);
              for (var i = 0; i < masterKey.length; i++) masterKey[i] = 0;
              LoggerService.log('PIN_SETUP', '✓ PIN set successfully');
              if (mounted) Navigator.of(context).pop();
              return true;
            } catch (ex, st) {
              LoggerService.logError('PIN_SETUP', 'Setup failed: $ex', st);
              return false;
            }
          },
          onFallbackToPassword: () {
            if (mounted) Navigator.of(context).pop();
          },
        ),
      ),
    );
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
