// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:io';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/models.dart';
import '../providers/email_provider.dart';
import '../providers/theme_provider.dart';
import '../services/notification_service.dart';
import '../services/update_service.dart';
import '../services/logger_service.dart';
import '../services/settings_service.dart';
import '../services/account_service.dart';
import '../services/master_password_service.dart';
import '../services/master_vault.dart';
import '../services/security_health_service.dart';
import '../services/certificate_service.dart';
import '../services/imap_pool.dart';
import '../services/mtls_client_pool.dart';
import '../services/mail_status_service.dart';
import '../services/pgp_key_service.dart';
import '../services/trash_tracker_service.dart';
import '../services/connection_monitor.dart';
import '../utils/l10n_helper.dart';
import 'compose_window.dart';
import 'email_viewer.dart';
import 'add_account_dialog.dart';
import 'factory_reset_dialog.dart';
import 'log_viewer_window.dart';
import 'changelog_window.dart';
import 'security_health_view.dart';
import 'device_revoked_screen.dart';
import 'server_info.dart';
import '../utils/text_safety.dart';
import '../utils/pii_redactor.dart';

/// Main window with Fluent Design
class MainWindow extends StatefulWidget {
  const MainWindow({super.key});

  @override
  State<MainWindow> createState() => _MainWindowState();
}

class _MainWindowState extends State<MainWindow> {
  String? _notificationTitle;
  String? _notificationMessage;
  NotificationType _notificationType = NotificationType.info;
  bool _showNotification = false;

  // Timers for auto-refresh
  Timer? _healthCheckTimer;
  Timer? _performanceTimer;
  Timer? _emailCheckTimer;
  Timer? _autoLockTimer;
  Timer? _updateCheckTimer;

  // Track selected email for keyboard shortcuts
  Email? _selectedEmail;

  // Lock state
  bool _isLocked = false;
  DateTime? _sessionStartedAt;
  static const Duration _maxSessionDuration = Duration(hours: 8);

  // Track whether we've already shown the "device limit reached" dialog
  // for the current EmailProvider state, to avoid re-opening on each
  // build cycle while the flag is set.
  bool _deviceLimitDialogShown = false;

  // Ping/connection quality
  Timer? _pingTimer;
  int? _pingMs;
  bool _pingError = false;

  @override
  void initState() {
    super.initState();

    // Set up notification callback
    NotificationService.onShowNotification = _showNotificationBar;

    // C2 (rolling auto-lock) — register a global hardware-keyboard
    // handler so ANY key press resets the inactivity timer, even when
    // no specific widget has focus. The handler returns false to let
    // the event propagate normally (we don't consume keys).
    HardwareKeyboard.instance.addHandler(_handleHardwareKeyEvent);

    // Initialize email provider
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final emailProvider = context.read<EmailProvider>();
      await emailProvider.initialize();

      // Start auto-refresh timers after initialization
      _startTimers();

      // Start auto-lock timer + session clock
      _sessionStartedAt = DateTime.now();
      _startAutoLockTimer();

      // Check for updates on startup
      _checkForUpdates();
    });
  }

  /// Global hardware-keyboard hook for the rolling auto-lock timer.
  /// Returning `false` means we DO NOT consume the event — Flutter's
  /// normal focus / shortcut machinery still sees every key press.
  bool _handleHardwareKeyEvent(KeyEvent event) {
    if (event is KeyDownEvent && !_isLocked) {
      _resetAutoLockTimer();
    }
    return false;
  }

  /// Auto-lock inactivity threshold. After this duration with NO user
  /// activity (any pointer event, keyboard input, or explicit action
  /// like compose/refresh), the app locks itself and demands the
  /// master password to resume.
  // v2.30.2: tightened from 15 min to 5 min as part of the RAM-dump
  // hardening pack. Reduces the window during which MasterVault
  // keys (`_dataKey`, `_kek`) and CertificateService cert/key live in
  // process memory by 3×. Trade-off: user re-enters master password
  // more often, but most actions reset the rolling timer (C2) so
  // active use never triggers an auto-lock.
  static const Duration _autoLockInactivity = Duration(minutes: 5);

  /// Throttle for the rolling reset. We do NOT want to call
  /// `Timer.cancel() + Timer()` on every pixel of mouse movement
  /// (that would be ~thousands of calls per second on a moving cursor
  /// and would burn CPU for nothing). Instead, the reset is rate-
  /// limited: at most one reset every [_resetThrottle].
  ///
  /// Worst-case extra delay before lock = `_autoLockInactivity` +
  /// `_resetThrottle`, which is acceptable for a 15-minute timeout.
  static const Duration _resetThrottle = Duration(seconds: 30);
  DateTime? _lastResetAt;

  /// Start auto-lock timer (15 minutes of inactivity).
  void _startAutoLockTimer() {
    _autoLockTimer?.cancel();
    _autoLockTimer = Timer(_autoLockInactivity, () {
      if (mounted && !_isLocked) {
        LoggerService.log('SECURITY',
            'Auto-lock triggered after ${_autoLockInactivity.inMinutes} minutes of inactivity');
        _lockApp();
      }
    });
  }

  /// Reset the auto-lock timer in response to user activity (any
  /// pointer event, keyboard event, or explicit action). This
  /// implements C2 from the audit — true rolling inactivity timeout
  /// rather than the old "fires N minutes after app start regardless
  /// of activity" behavior.
  ///
  /// Throttled per [_resetThrottle] so a moving mouse doesn't burn CPU.
  void _resetAutoLockTimer() {
    if (_isLocked) return;
    final now = DateTime.now();
    if (_sessionStartedAt != null &&
        now.difference(_sessionStartedAt!) > _maxSessionDuration) {
      LoggerService.log('SECURITY',
          'Maximum session duration (${_maxSessionDuration.inHours}h) reached — forcing lock');
      _lockApp();
      return;
    }
    if (_lastResetAt != null &&
        now.difference(_lastResetAt!) < _resetThrottle) {
      return;
    }
    _lastResetAt = now;
    _startAutoLockTimer();
  }

  /// Lock the application
  Future<void> _lockApp() async {
    // Stop all timers while locked (prevents failed connections during sleep/network change)
    _healthCheckTimer?.cancel();
    _performanceTimer?.cancel();
    _emailCheckTimer?.cancel();
    _updateCheckTimer?.cancel();
    _pingTimer?.cancel();
    LoggerService.log('SECURITY', 'All timers stopped (app locked)');

    // SECURITY (M4): Wipe the in-memory AES key used for fallback credential
    // storage. While locked, the .passwords file becomes unreadable.
    AccountService.lockSession();
    // SECURITY: Close all pooled IMAP connections.
    try {
      await ImapPool.instance.closeAll();
    } catch (_) {}
    // SECURITY: Close all pooled mTLS HTTP clients (per-account).
    try {
      await MtlsClientPool.instance.closeAll();
    } catch (_) {}
    // SECURITY: Wipe all cached emails from RAM.
    try {
      final provider = context.read<EmailProvider>();
      provider.wipeSessionCache();
    } catch (_) {}
    // Clear in-memory mTLS certificates. Must happen BEFORE vault.lock()
    // because clearCertificates() may access vault for cleanup.
    try {
      CertificateService.clearCertificates();
    } catch (_) {}
    // SECURITY (B5): zero vault keys LAST — after all vault consumers
    // have finished their cleanup.
    MasterVault.instance.lock();
    PgpKeyService.clearCache();
    MailStatusService.clearCache();

    setState(() => _isLocked = true);
    LoggerService.log('SECURITY', 'Application locked');

    final unlocked = await _showMasterPasswordDialog();

    if (unlocked) {
      _sessionStartedAt = DateTime.now();
      setState(() => _isLocked = false);
      LoggerService.log('SECURITY', 'Application unlocked');

      final emailProvider = context.read<EmailProvider>();

      // Restore certificates from secure storage for all accounts
      for (final account in emailProvider.accounts) {
        try {
          final success = await CertificateService.restoreFromSecureStorageFor(account.username);
          if (success) {
            LoggerService.log('SECURITY', '✓ Certificate restored for ${piiEmail(account.username)}');
          } else {
            LoggerService.log('SECURITY', '⚠️ No certificate in secure storage for ${piiEmail(account.username)}');
          }
        } catch (e) {
          LoggerService.log('SECURITY', '⚠️ Certificate restore error for ${piiEmail(account.username)}: $e');
        }
      }

      // Restart all timers
      _startTimers();
      LoggerService.log('SECURITY', 'All timers restarted after unlock');

      // Force refresh emails
      await emailProvider.checkForNewEmails();
    }
  }

  /// Show master password dialog for unlock
  Future<bool> _showMasterPasswordDialog() async {
    final passwordController = TextEditingController();
    var verifying = false;
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        final l10n = l10nOf(context);
        Future<void> submit() async {
          if (verifying) return;
          verifying = true;
          final isValid = await MasterPasswordService.verifyMasterPassword(passwordController.text);
          verifying = false;
          if (context.mounted) {
            Navigator.of(context).pop(isValid);
          }
        }
        return ContentDialog(
          title: Row(
            children: [
              const ExcludeSemantics(child: Icon(FluentIcons.lock, size: 20)),
              const SizedBox(width: 8),
              Text(l10n.mainWindowDialogLockedTitle),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(l10n.mainWindowDialogLockedEnterPassword),
              const SizedBox(height: 16),
              TextBox(
                controller: passwordController,
                placeholder: l10n.mainWindowPlaceholderMasterPassword,
                obscureText: true,
                autofocus: true,
                onSubmitted: (_) => submit(),
              ),
            ],
          ),
          actions: [
            Button(
              child: Text(l10n.buttonCancel),
              onPressed: () => Navigator.of(context).pop(false),
            ),
            FilledButton(
              child: Text(l10n.mainWindowButtonUnlock),
              onPressed: submit,
            ),
          ],
        );
      },
    );
    passwordController.dispose();
    return result ?? false;
  }

  /// True while a manual update check is in progress (for spinner UI).
  bool _manualUpdateChecking = false;

  /// Manually check for updates — triggered by footer button.
  /// Bypasses the auto-update setting; user explicitly requested.
  /// On success, downloads and installs in background, then exits the
  /// app and relaunches the new version (macOS / Linux / Windows).
  Future<void> _checkForUpdatesManual() async {
    if (_manualUpdateChecking) return;
    setState(() => _manualUpdateChecking = true);

    final l10n = l10nOf(context);
    LoggerService.log('UPDATE', 'Manual update check requested');

    try {
      final updateInfo = await UpdateService.checkForUpdates();

      if (!mounted) return;

      if (updateInfo == null) {
        // Already up to date — show confirmation toast
        NotificationService.showInfoToast(
          'Update check',
          'You are already on the latest version (v${UpdateService.currentVersion})',
        );
        LoggerService.log('UPDATE', 'Manual check: no update available');
        return;
      }

      LoggerService.log('UPDATE',
          'Manual check: update v${updateInfo.version} found, starting install');

      // Show download progress in the notification bar
      _showNotificationBar(
        l10n.mainWindowNotificationUpdateAvailable,
        l10n.mainWindowNotificationDownloading(updateInfo.version),
        NotificationType.info,
      );

      UpdateService.onProgress = (downloaded, total, status) {
        if (mounted) {
          setState(() {
            _notificationTitle = l10n.mainWindowNotificationUpdateInProgress;
            _notificationMessage = status;
            _notificationType = NotificationType.info;
            _showNotification = true;
          });
        }
      };

      // Background install: downloads, verifies, mounts DMG (macOS),
      // copies new .app, writes self-deleting relaunch script, then
      // exits the current process. The relaunch script polls until
      // the current PID is gone, waits for LaunchServices cache flush,
      // then opens the new .app bundle.
      await UpdateService.downloadAndInstallAuto(updateInfo);
    } catch (ex, st) {
      LoggerService.logError('UPDATE', ex, st);
      if (mounted) {
        NotificationService.showErrorToast(
          'Update check failed',
          ex.toString(),
        );
      }
    } finally {
      if (mounted) setState(() => _manualUpdateChecking = false);
    }
  }

  /// Check for updates from mail.icd360s.de - AUTO INSTALL
  Future<void> _checkForUpdates() async {
    // Check if auto-update is enabled in settings
    final autoUpdateEnabled = await SettingsService.getAutoUpdateEnabled();
    if (!autoUpdateEnabled) {
      LoggerService.log('UPDATE', 'Auto-update disabled by user - skipping check');
      return;
    }

    try {
      final updateInfo = await UpdateService.checkForUpdates();

      if (updateInfo != null && mounted) {
        LoggerService.log('UPDATE', 'Update found: v${updateInfo.version} - starting auto-download');

        final l10n = l10nOf(context);

        // Show initial notification
        _showNotificationBar(
          l10n.mainWindowNotificationUpdateAvailable,
          l10n.mainWindowNotificationDownloading(updateInfo.version),
          NotificationType.info,
        );

        // Set up progress callback
        UpdateService.onProgress = (downloaded, total, status) {
          if (mounted) {
            setState(() {
              _notificationTitle = l10n.mainWindowNotificationUpdateInProgress;
              _notificationMessage = status;
              _notificationType = NotificationType.info;
              _showNotification = true;
            });
          }
        };

        // Start auto-download and install (will exit app when done)
        await UpdateService.downloadAndInstallAuto(updateInfo);
      }
    } catch (e) {
      LoggerService.log('UPDATE', 'Update check error: $e');
    }
  }

  @override
  void dispose() {
    HardwareKeyboard.instance.removeHandler(_handleHardwareKeyEvent);
    _healthCheckTimer?.cancel();
    _performanceTimer?.cancel();
    _emailCheckTimer?.cancel();
    _autoLockTimer?.cancel();
    _updateCheckTimer?.cancel();
    _pingTimer?.cancel();
    super.dispose();
  }

  /// Start all auto-refresh timers
  void _startTimers() {
    // 1. Health check timer - Every 1 hour
    _healthCheckTimer = Timer.periodic(const Duration(hours: 1), (timer) {
      final emailProvider = context.read<EmailProvider>();
      emailProvider.checkServerHealth();
      emailProvider.checkPortConnections();
    });

    // 2. Performance stats timer - Every 5 minutes (for log uploads only, not UI)
    _performanceTimer = Timer.periodic(const Duration(minutes: 5), (timer) {
      final emailProvider = context.read<EmailProvider>();
      emailProvider.updatePerformanceStats();
    });

    // 3. Email check timer - Every 60 seconds (auto-check for new emails - optimized for many accounts)
    _emailCheckTimer = Timer.periodic(const Duration(seconds: 60), (timer) async {
      await _autoCheckNewEmails();
    });

    // 4. Update check timer - Every 15 minutes (background update check)
    _updateCheckTimer = Timer.periodic(const Duration(minutes: 15), (timer) {
      LoggerService.log('UPDATE', 'Background update check (15 min timer)');
      _checkForUpdates();
    });

    // 5. Ping timer - Every 60 seconds (was 10s — caused excessive battery drain)
    _measurePing();
    _pingTimer = Timer.periodic(const Duration(seconds: 60), (timer) {
      _measurePing();
    });
  }

  /// Measure ping to mail server via TCP connect (no file descriptor leak)
  Future<void> _measurePing() async {
    try {
      final stopwatch = Stopwatch()..start();
      final socket = await Socket.connect(
        'mail.icd360s.de',
        443,
        timeout: const Duration(seconds: 3),
      );
      stopwatch.stop();
      socket.destroy();
      if (mounted) {
        setState(() {
          _pingMs = stopwatch.elapsedMilliseconds;
          _pingError = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _pingMs = null;
          _pingError = true;
        });
      }
    }
  }

  /// Auto-check for new emails (check actual emails, not just count)
  /// This will trigger Windows Toast notifications when NEW emails are detected
  Future<void> _autoCheckNewEmails() async {
    final emailProvider = context.read<EmailProvider>();

    // Call checkForNewEmails which compares email IDs and shows Windows Toast
    await emailProvider.checkForNewEmails();

    // Update taskbar badge with total unread count
    int totalNewEmails = 0;
    for (final account in emailProvider.accounts) {
      totalNewEmails += account.folderCounts['INBOX'] ?? 0;
    }
    _updateTaskbarBadge(totalNewEmails);
  }

  /// Set desktop window title.
  ///
  /// SECURITY: Never expose unread-mail count in the window title.
  /// The title is visible to anyone looking at the screen (screen
  /// sharing, over-the-shoulder, taskbar previews), and revealing
  /// "X unread" leaks mailbox activity to bystanders.
  Future<void> _updateTaskbarBadge(int count) async {
    if (!Platform.isWindows && !Platform.isMacOS && !Platform.isLinux) return;
    try {
      await windowManager.setTitle(
          'Mail Client by ICD360S e.V gemeinnützige Verein');
    } catch (ex, stackTrace) {
      LoggerService.logError('TASKBAR', ex, stackTrace);
    }
  }

  void _showNotificationBar(String title, String message, NotificationType type) {
    setState(() {
      _notificationTitle = title;
      _notificationMessage = message;
      _notificationType = type;
      _showNotification = true;
    });

    // Auto-hide after 3 seconds (faster to avoid overlap)
    Future.delayed(const Duration(seconds: 3), () {
      if (mounted) {
        setState(() => _showNotification = false);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final themeProvider = context.watch<ThemeProvider>();
    final emailProvider = context.watch<EmailProvider>();
    final l10n = l10nOf(context);

    // ── Remote revocation: blocking screen ──
    // If admin revoked this device, show full-screen block immediately.
    final revokedUser = emailProvider.revokedUsername;
    if (revokedUser != null) {
      return DeviceRevokedScreen(
        username: revokedUser,
        onRequestAccess: () {
          // Navigate to add-account flow for re-enrollment
          Navigator.of(context).pushReplacement(
            FluentPageRoute(builder: (_) => const AddAccountDialog()),
          );
        },
        onExit: () => exit(0),
      );
    }

    // ── mail-admin: device limit dialog ──
    // If the backend rejected this device with `device_limit_reached`,
    // show a blocking dialog explaining the situation. Use a post-frame
    // callback so we can call showDialog from the build phase safely.
    final lockedUsername = emailProvider.deviceLimitReachedFor;
    if (lockedUsername != null && !_deviceLimitDialogShown) {
      _deviceLimitDialogShown = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        showDialog<void>(
          context: context,
          barrierDismissible: false,
          builder: (ctx) => ContentDialog(
            title: const Text('Device limit reached'),
            content: Text(
              'The account $lockedUsername is restricted to a single '
              'device.\n\nThis device cannot be activated because another '
              'device is already registered.\n\nContact the ICD360S '
              'administrator to transfer access to this device.',
            ),
            actions: [
              FilledButton(
                onPressed: () {
                  Navigator.pop(ctx);
                  emailProvider.clearDeviceLimitFlag();
                  _deviceLimitDialogShown = false;
                },
                child: const Text('Understood'),
              ),
            ],
          ),
        );
      });
    }

    // If locked, show lock screen (timers continue in background for notifications)
    if (_isLocked) {
      return Container(
        color: theme.scaffoldBackgroundColor.withValues(alpha: 0.95),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const ExcludeSemantics(
                child: Icon(FluentIcons.lock, size: 64),
              ),
              const SizedBox(height: 16),
              Text(l10n.mainWindowLockedTitle, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Text(l10n.mainWindowLockedSubtitle),
              const SizedBox(height: 8),
              Text(l10n.mainWindowLockedNotification),
            ],
          ),
        ),
      );
    }

    // C2 (rolling auto-lock) — wrap the entire unlocked UI with a
    // translucent Listener so that any pointer event (tap, drag,
    // hover, scroll wheel) on any descendant resets the inactivity
    // timer. `HitTestBehavior.translucent` means the Listener is hit
    // AND its descendants still receive the event normally — no
    // gesture handling is consumed. Throttling lives inside
    // [_resetAutoLockTimer] so a moving cursor doesn't burn CPU.
    return Listener(
      behavior: HitTestBehavior.translucent,
      onPointerDown: (_) => _resetAutoLockTimer(),
      onPointerMove: (_) => _resetAutoLockTimer(),
      onPointerHover: (_) => _resetAutoLockTimer(),
      onPointerSignal: (_) => _resetAutoLockTimer(),
      child: Shortcuts(
      shortcuts: {
        // Delete key - Delete selected email
        LogicalKeySet(LogicalKeyboardKey.delete): const DeleteEmailIntent(),
        // Ctrl+N - Compose email
        LogicalKeySet(LogicalKeyboardKey.control, LogicalKeyboardKey.keyN):
            const ComposeEmailIntent(),
        // F5 - Refresh
        LogicalKeySet(LogicalKeyboardKey.f5): const RefreshIntent(),
        // Ctrl+R - Refresh
        LogicalKeySet(LogicalKeyboardKey.control, LogicalKeyboardKey.keyR):
            const RefreshIntent(),
      },
      child: Actions(
        actions: {
          DeleteEmailIntent: CallbackAction<DeleteEmailIntent>(
            onInvoke: (intent) {
              if (_selectedEmail != null) {
                emailProvider.deleteEmail(_selectedEmail!);
                _selectedEmail = null;
              }
              return null;
            },
          ),
          ComposeEmailIntent: CallbackAction<ComposeEmailIntent>(
            onInvoke: (intent) {
              _resetAutoLockTimer();
              _showComposeWindow(context);
              return null;
            },
          ),
          RefreshIntent: CallbackAction<RefreshIntent>(
            onInvoke: (intent) {
              _resetAutoLockTimer();
              if (!emailProvider.isLoading) {
                emailProvider.refresh();
              }
              return null;
            },
          ),
        },
        child: Column(
          children: [
            Expanded(
              child: NavigationView(
      titleBar: Row(
          children: [
            const SizedBox(width: 16),
            Text(l10n.mainWindowTitle, style: theme.typography.subtitle),
            // Spacer to push buttons to far right
            const Spacer(),

            // Version label — clickable, opens changelog
            HoverButton(
              onPressed: _showChangelog,
              builder: (context, states) {
                final theme = FluentTheme.of(context);
                return Padding(
                  padding: const EdgeInsets.only(right: 8.0),
                  child: Text(
                    'v${UpdateService.currentVersion}',
                    style: theme.typography.caption?.copyWith(
                      color: states.isHovered
                          ? theme.accentColor.light
                          : theme.accentColor,
                      decoration: states.isHovered ? TextDecoration.underline : null,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                );
              },
            ),

            // (Log Viewer, Security Health, Update, Server Info → moved to footer)

            // Switch Account button — opens account picker dialog
            Padding(
              padding: const EdgeInsets.only(right: 4.0),
              child: Tooltip(
                message: l10nOf(context).mainWindowSwitchAccount,
                child: IconButton(
                  icon: const Icon(FluentIcons.switch_user, size: 16),
                  onPressed: () {
                    _resetAutoLockTimer();
                    _showAccountPicker(emailProvider);
                  },
                ),
              ),
            ),

            // Accessibility info
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: Tooltip(
                message: 'Accessibility',
                child: IconButton(
                  icon: const Icon(FluentIcons.people, size: 16),
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (_) => ContentDialog(
                        title: Row(
                          children: [
                            const Icon(FluentIcons.people, size: 20),
                            const SizedBox(width: 8),
                            const Text('Accessibility'),
                          ],
                        ),
                        content: const Text(
                          'This app is designed following WCAG 2.1 Level AA guidelines.\n\n'
                          '• Screen reader support (TalkBack / VoiceOver)\n'
                          '• Full keyboard navigation\n'
                          '• High contrast mode support\n'
                          '• System font scaling\n'
                          '• Color-independent status indicators\n\n'
                          'If you encounter accessibility barriers, please contact kontakt@icd360s.de',
                        ),
                        actions: [
                          FilledButton(
                            child: const Text('OK'),
                            onPressed: () => Navigator.of(context).pop(),
                          ),
                        ],
                      ),
                    );
                  },
                ),
              ),
            ),

            // (Source Code → moved to Rechtliches dialog)

            // Settings button — notification privacy + PIN management
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: Tooltip(
                message: 'Settings',
                child: IconButton(
                  icon: const Icon(FluentIcons.settings, size: 16),
                  onPressed: () async {
                    _resetAutoLockTimer();
                    await _showSettingsDialog(context);
                  },
                ),
              ),
            ),

            // (Factory Reset → moved to Settings dialog)

            // Add Account Button
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: Tooltip(
                message: 'Add account',
                child: IconButton(
                  icon: const Icon(FluentIcons.add, size: 16),
                  onPressed: () => _showAddAccountDialog(context, emailProvider),
                ),
              ),
            ),

            // Lock Button
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: Tooltip(
                message: 'Lock app',
                child: IconButton(
                  icon: const Icon(FluentIcons.lock, size: 16),
                  onPressed: () {
                    LoggerService.log('SECURITY', 'User clicked lock button');
                    _resetAutoLockTimer();
                    _lockApp();
                  },
                ),
              ),
            ),

            // Dark Mode Toggle (right)
            Padding(
              padding: const EdgeInsets.only(right: 16.0),
              child: ToggleButton(
                checked: themeProvider.isDarkMode,
                onChanged: (value) {
                  _resetAutoLockTimer();
                  themeProvider.toggleTheme();
                },
                child: Icon(
                  themeProvider.isDarkMode ? FluentIcons.sunny : FluentIcons.clear_night,
                  size: 16,
                ),
              ),
            ),
          ],
        ),
      pane: NavigationPane(
        selected: 0,
        displayMode: PaneDisplayMode.auto,
        header: Padding(
          padding: const EdgeInsets.all(12.0),
          child: Text(
            l10n.mainWindowAccountsHeader,
            style: theme.typography.subtitle?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        items: _buildAccountTree(emailProvider),
        footerItems: [],
      ),
              ), // Close NavigationView
            ), // Close Expanded

            // Footer Status Bar (shown once, not duplicated)
            _buildFooter(theme, emailProvider),
          ], // Close Column children
        ), // Close Column
      ), // Close Actions
      ), // Close Shortcuts
    ); // Close Listener (C2 rolling auto-lock)
  }

  /// Build notification bar
  Widget _buildNotificationBar(FluentThemeData theme) {
    InfoBarSeverity severity;
    switch (_notificationType) {
      case NotificationType.success:
        severity = InfoBarSeverity.success;
        break;
      case NotificationType.warning:
        severity = InfoBarSeverity.warning;
        break;
      case NotificationType.error:
        severity = InfoBarSeverity.error;
        break;
      default:
        severity = InfoBarSeverity.info;
    }

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      child: InfoBar(
        title: Text(_notificationTitle ?? '', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
        content: Text(_notificationMessage ?? '', style: const TextStyle(fontSize: 12)),
        severity: severity,
        isLong: false,
        onClose: () => setState(() => _showNotification = false),
      ),
    );
  }

  /// Show compose window
  Future<void> _showComposeWindow(BuildContext context) async {
    await showDialog(
      context: context,
      builder: (context) => const ComposeWindow(),
    );
  }

  /// Open draft email in compose window for editing
  Future<void> _openDraftInCompose(BuildContext context, Email email) async {
    LoggerService.log('UI', 'Opening draft in compose: ${email.subject}');
    await showDialog(
      context: context,
      builder: (context) => ComposeWindow(
        replyTo: email.to,
        replySubject: email.subject,
        initialBody: email.body,
      ),
    );
  }

  /// Show email viewer
  Future<void> _showEmailViewer(BuildContext context, Email email) async {
    await showDialog(
      context: context,
      builder: (context) => EmailViewer(email: email),
    );
  }

  /// Show add account dialog
  Future<void> _showAddAccountDialog(BuildContext context, EmailProvider emailProvider) async {
    final account = await showDialog<EmailAccount>(
      context: context,
      builder: (context) => const AddAccountDialog(),
    );

    if (account != null) {
      await emailProvider.addAccount(account);
      // Force UI rebuild
      setState(() {});
      LoggerService.log('UI', 'Account tree refreshed after adding account');
    }
  }

  /// Show log viewer window
  Future<void> _showLogViewer() async {
    LoggerService.log('UI_CLICK', 'Footer: Log Viewer button clicked');
    await showDialog(
      context: context,
      builder: (context) => const LogViewerWindow(),
    );
  }

  /// Show changelog window
  Future<void> _showChangelog() async {
    LoggerService.log('UI_CLICK', 'Footer: Version/Changelog button clicked');
    await showDialog(
      context: context,
      builder: (context) => const ChangelogWindow(),
    );
  }

  /// Settings dialog — notification privacy.
  Future<void> _showSettingsDialog(BuildContext ctx) async {
    LoggerService.log('UI_CLICK', 'Footer: Settings button clicked');
    var privacyLevel = await SettingsService.getNotificationPrivacyLevel();

    if (!ctx.mounted) return;
    await showDialog(
      context: ctx,
      builder: (dialogCtx) => StatefulBuilder(
        builder: (dialogCtx, setDialogState) {
          return ContentDialog(
            title: const Text('Settings'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // ── Notification Privacy ────────────────────────
                Text('Notification Content',
                    style: FluentTheme.of(dialogCtx).typography.bodyStrong),
                const SizedBox(height: 8),
                ComboBox<NotificationPrivacyLevel>(
                  value: privacyLevel,
                  items: const [
                    ComboBoxItem(
                      value: NotificationPrivacyLevel.none,
                      child: Text('Minimal — "New email" only'),
                    ),
                    ComboBoxItem(
                      value: NotificationPrivacyLevel.senderOnly,
                      child: Text('Sender only — "New email from Marcel"'),
                    ),
                    ComboBoxItem(
                      value: NotificationPrivacyLevel.full,
                      child: Text('Full — sender + subject'),
                    ),
                  ],
                  onChanged: (v) {
                    if (v != null) {
                      setDialogState(() => privacyLevel = v);
                      SettingsService.setNotificationPrivacyLevel(v);
                    }
                  },
                ),

                const SizedBox(height: 20),
                // ── Factory Reset ──────────────────────────────
                Text('Danger Zone',
                    style: FluentTheme.of(dialogCtx).typography.bodyStrong?.copyWith(
                      color: Colors.red,
                    )),
                const SizedBox(height: 8),
                Button(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(FluentIcons.delete, size: 14, color: Colors.red),
                      const SizedBox(width: 6),
                      Text('Factory Reset', style: TextStyle(color: Colors.red)),
                    ],
                  ),
                  onPressed: () async {
                    Navigator.pop(dialogCtx);
                    LoggerService.log('SECURITY', 'User clicked factory reset from settings');
                    _resetAutoLockTimer();
                    await FactoryResetDialog.show(ctx);
                  },
                ),
              ],
            ),
            actions: [
              FilledButton(
                child: const Text('Close'),
                onPressed: () => Navigator.pop(dialogCtx),
              ),
            ],
          );
        },
      ),
    );
  }

  /// Show security health dialog (v2.30.2 — runs platform-aware
  /// security audit: FileVault on macOS, BitLocker on Windows, LUKS
  /// on Linux, plus universal master pwd / vault state checks).
  Future<void> _showSecurityHealth() async {
    LoggerService.log('UI_CLICK', 'Footer: Security Health button clicked');
    await showDialog(
      context: context,
      builder: (context) => const SecurityHealthDialog(),
    );
  }

  /// Open URL in integrated browser
  Future<void> _openUrl(String url) async {
    String title = 'Browser';
    if (url.contains('impressum')) {
      title = 'Impressum';
    } else if (url.contains('datenschutz')) {
      title = 'Datenschutz';
    } else if (url.contains('widerrufsrecht')) {
      title = 'Widerrufsrecht';
    } else if (url.contains('kundigung')) {
      title = 'Kündigung';
    } else if (url.contains('satzung')) {
      title = 'Satzung';
    }

    LoggerService.log('UI_CLICK', 'Footer: Legal link clicked ($title) - URL: $url');
    // Open in external browser (cross-platform)
    try {
      final uri = Uri.parse(url);
      if (await canLaunchUrl(uri)) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('BROWSER', ex, stackTrace);
    }
  }

  /// Get quota indicator color based on percentage
  /// Verde (0-25%), Albastru (25-50%), Galben (50-75%), Roșu (75-100%)
  Color _getQuotaColor(double percentage) {
    if (percentage <= 25) {
      return Colors.green; // 0-25%: Verde (OK)
    } else if (percentage <= 50) {
      return Colors.blue; // 25-50%: Albastru (bine)
    } else if (percentage <= 75) {
      return Colors.yellow; // 50-75%: Galben (atenție)
    } else {
      return Colors.red; // 75-100%: Roșu (pericol)
    }
  }

  /// Build navigation pane — flat list of folders for the ACTIVE account only.
  /// Account switcher lives in the header (next to Settings), not in the sidebar.
  List<NavigationPaneItem> _buildAccountTree(EmailProvider emailProvider) {
    final items = <NavigationPaneItem>[];
    final theme = FluentTheme.of(context);

    final activeAccount = emailProvider.currentAccount;
    // Fluent UI NavigationView crashes with RangeError on empty items list
    // (body.dart accesses index 0). Always provide a placeholder PaneItem
    // so the pane can render during the 30-60s initial account loading.
    if (activeAccount == null) {
      items.add(PaneItem(
        icon: const Icon(FluentIcons.sync),
        title: const Text('Loading accounts…'),
        body: const Center(child: ProgressRing()),
      ));
      return items;
    }

    // Same guard for an account with no folders yet (cert still downloading).
    if (activeAccount.folders.isEmpty) {
      items.add(PaneItem(
        icon: const Icon(FluentIcons.sync),
        title: const Text('Loading folders…'),
        body: const Center(child: ProgressRing()),
      ));
      return items;
    }

    // ── Folders for the active account (flat) ─────────────────────
    for (final folder in activeAccount.folders) {
      items.add(
        PaneItem(
          icon: _getFolderIcon(folder),
          title: Text('$folder (${activeAccount.folderCounts[folder] ?? 0})'),
          body: Stack(
            children: [
              _buildEmailList(theme, emailProvider),
              if (_showNotification)
                Positioned(
                  bottom: 8,
                  left: 16,
                  right: 16,
                  child: _buildNotificationBar(theme),
                ),
              Positioned(
                bottom: 24,
                right: 24,
                child: Tooltip(
                  message: 'Compose',
                  child: FilledButton(
                    style: const ButtonStyle(
                      shape: WidgetStatePropertyAll(CircleBorder()),
                      padding: WidgetStatePropertyAll(EdgeInsets.all(16)),
                    ),
                    onPressed: () {
                      _resetAutoLockTimer();
                      _showComposeWindow(context);
                    },
                    child: const Icon(FluentIcons.edit_mail, size: 24),
                  ),
                ),
              ),
            ],
          ),
          onTap: () => emailProvider.selectFolder(activeAccount, folder),
        ),
      );
    }

    return items;
  }

  /// Show account picker dialog — list of all accounts, click to switch.
  Future<void> _showAccountPicker(EmailProvider emailProvider) async {
    _resetAutoLockTimer();
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);

    await showDialog<void>(
      context: context,
      builder: (ctx) {
        return ContentDialog(
          constraints: const BoxConstraints(maxWidth: 500, maxHeight: 600),
          title: Text(l10n.mainWindowSwitchAccount),
          content: SizedBox(
            width: double.maxFinite,
            child: ListView.builder(
              shrinkWrap: true,
              itemCount: emailProvider.accounts.length,
              itemBuilder: (_, i) {
                final acc = emailProvider.accounts[i];
                final isActive = acc.username == emailProvider.currentAccount?.username;
                Color statusColor;
                IconData statusIcon;
                String statusLabel;
                switch (acc.connectionStatus) {
                  case AccountConnectionStatus.connected:
                    statusColor = Colors.green;
                    statusIcon = FluentIcons.accept_medium;
                    statusLabel = 'Connected';
                    break;
                  case AccountConnectionStatus.authError:
                    statusColor = Colors.red;
                    statusIcon = FluentIcons.error_badge;
                    statusLabel = 'Authentication error';
                    break;
                  case AccountConnectionStatus.networkError:
                    statusColor = Colors.orange;
                    statusIcon = FluentIcons.warning;
                    statusLabel = 'Network error';
                    break;
                  case AccountConnectionStatus.unknown:
                    statusColor = Colors.grey;
                    statusIcon = FluentIcons.contact;
                    statusLabel = 'Unknown status';
                    break;
                }
                return HoverButton(
                  onPressed: () {
                    Navigator.of(ctx).pop();
                    emailProvider.selectFolder(acc, 'INBOX');
                  },
                  builder: (_, states) {
                    final hovering = states.isHovered;
                    return Container(
                      margin: const EdgeInsets.symmetric(vertical: 2),
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      decoration: BoxDecoration(
                        color: isActive
                            ? theme.accentColor.withValues(alpha: 0.15)
                            : hovering
                                ? theme.resources.subtleFillColorSecondary
                                : theme.resources.subtleFillColorTransparent,
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(
                          color: isActive
                              ? theme.accentColor
                              : theme.resources.controlStrokeColorDefault,
                          width: isActive ? 2 : 1,
                        ),
                      ),
                      child: Row(
                        children: [
                          Semantics(
                            label: statusLabel,
                            child: Icon(statusIcon, color: statusColor, size: 18),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  acc.username,
                                  style: theme.typography.body?.copyWith(
                                    fontWeight: isActive ? FontWeight.bold : FontWeight.normal,
                                  ),
                                ),
                                Text(
                                  '${acc.folderCounts['INBOX'] ?? 0} ${l10n.mainWindowInboxMessages}',
                                  style: theme.typography.caption?.copyWith(
                                    color: theme.inactiveColor,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Tooltip(
                            message: 'Remove account',
                            child: IconButton(
                              icon: const Icon(FluentIcons.cancel, size: 14),
                              onPressed: () async {
                                final l10nDialog = l10nOf(ctx);
                              final confirmed = await showDialog<bool>(
                                context: ctx,
                                builder: (c) => ContentDialog(
                                  title: Text(l10nDialog.mainWindowDialogDeleteAccountTitle),
                                  content: Text(l10nDialog.mainWindowDialogDeleteAccountMessage(acc.username)),
                                  actions: [
                                    Button(
                                      child: Text(l10nDialog.buttonCancel),
                                      onPressed: () => Navigator.of(c).pop(false),
                                    ),
                                    FilledButton(
                                      child: Text(l10nDialog.mainWindowButtonDeleteFromApp),
                                      onPressed: () => Navigator.of(c).pop(true),
                                    ),
                                  ],
                                ),
                              );
                              if (confirmed == true) {
                                await emailProvider.removeAccount(acc);
                                if (ctx.mounted) Navigator.of(ctx).pop();
                              }
                              },
                            ),
                          ),
                        ],
                      ),
                    );
                  },
                );
              },
            ),
          ),
          actions: [
            FilledButton(
              child: Text(l10n.changelogButtonClose),
              onPressed: () => Navigator.of(ctx).pop(),
            ),
          ],
        );
      },
    );
  }

  /// Get icon for folder type
  Icon _getFolderIcon(String folder) {
    switch (folder.toLowerCase()) {
      case 'inbox':
        return const Icon(FluentIcons.inbox);
      case 'sent':
        return const Icon(FluentIcons.send);
      case 'drafts':
        return const Icon(FluentIcons.edit);
      case 'trash':
        return const Icon(FluentIcons.delete);
      case 'junk':
        return const Icon(FluentIcons.blocked2);
      default:
        return const Icon(FluentIcons.folder);
    }
  }

  /// Build email list
  Widget _buildEmailList(FluentThemeData theme, EmailProvider emailProvider) {
    final l10n = l10nOf(context);

    return LayoutBuilder(
      builder: (context, constraints) {
        final isMobile = constraints.maxWidth < 600;
        return Column(
      children: [
        // Mobile folder selector (NavigationPane hidden on small screens)
        if (isMobile && emailProvider.currentAccount != null &&
            emailProvider.currentAccount!.folders.isNotEmpty)
          Container(
            height: 40,
            padding: const EdgeInsets.symmetric(horizontal: 8),
            decoration: BoxDecoration(
              color: theme.scaffoldBackgroundColor,
              border: Border(
                bottom: BorderSide(color: theme.inactiveBackgroundColor, width: 1),
              ),
            ),
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: emailProvider.currentAccount!.folders.map((folder) {
                final isActive = folder == emailProvider.currentFolder;
                final count = emailProvider.currentAccount!.folderCounts[folder] ?? 0;
                return Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 2, vertical: 4),
                  child: ToggleButton(
                    checked: isActive,
                    onChanged: (_) => emailProvider.selectFolder(
                        emailProvider.currentAccount!, folder),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _getFolderIcon(folder),
                        const SizedBox(width: 4),
                        Text('$folder ($count)', style: const TextStyle(fontSize: 12)),
                      ],
                    ),
                  ),
                );
              }).toList(),
            ),
          ),

        // Header
        Container(
          padding: EdgeInsets.all(isMobile ? 10.0 : 16.0),
          decoration: BoxDecoration(
            color: theme.scaffoldBackgroundColor,
            border: Border(
              bottom: BorderSide(
                color: theme.inactiveBackgroundColor,
                width: 1,
              ),
            ),
          ),
          child: Row(
            children: [
              Text(
                emailProvider.currentFolder,
                style: theme.typography.subtitle?.copyWith(
                  fontWeight: FontWeight.bold,
                  fontSize: isMobile ? 14 : 18,
                ),
              ),
              const Spacer(),
              if (emailProvider.isLoading)
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: ProgressRing(strokeWidth: 2),
                )
              else
                Text(
                  l10n.mainWindowEmailsCount(emailProvider.emails.length),
                  style: theme.typography.body?.copyWith(
                    color: theme.inactiveColor,
                  ),
                ),
            ],
          ),
        ),

        // Email List
        Expanded(
          child: emailProvider.isLoading
              ? const Center(child: ProgressRing())
              : emailProvider.emails.isEmpty
                  ? Center(
                      child: Text(
                        l10n.mainWindowNoEmails(emailProvider.currentFolder),
                        style: theme.typography.body?.copyWith(
                          color: theme.inactiveColor,
                        ),
                      ),
                    )
                  : Builder(
                      builder: (ctx) {
                        // Fetch delivery status for ALL visible emails in
                        // ONE batch request (not per-widget). Previous
                        // implementation fired 50 concurrent HTTP requests
                        // when opening Sent folder on Android, blocking
                        // the UI thread for 25+ seconds.
                        final ids = emailProvider.emails
                            .map((e) => e.messageId)
                            .where((id) =>
                                id.isNotEmpty &&
                                !id.startsWith('CORRUPT-') &&
                                MailStatusService.getCached(id) == null)
                            .toList();
                        if (ids.isNotEmpty) {
                          final sender = emailProvider.currentAccount?.username;
                          WidgetsBinding.instance.addPostFrameCallback((_) {
                            MailStatusService.fetchBatch(ids, senderUsername: sender).then((_) {
                              if (mounted) setState(() {});
                            });
                          });
                        }
                        return ListView.builder(
                          itemCount: emailProvider.emails.length,
                          itemBuilder: (context, index) {
                            final email = emailProvider.emails[index];
                            return Dismissible(
                              key: ValueKey(email.messageId),
                              direction: DismissDirection.endToStart,
                              background: Container(
                                alignment: Alignment.centerRight,
                                padding: const EdgeInsets.only(right: 24),
                                color: Colors.red,
                                child: const Icon(FluentIcons.delete, color: Color(0xFFFFFFFF), size: 24),
                              ),
                              confirmDismiss: (direction) async {
                                emailProvider.deleteEmail(email);
                                return false;
                              },
                              child: _buildEmailListItem(email, theme, emailProvider.currentFolder),
                            );
                          },
                        );
                      },
                    ),
        ),
      ],
    );
      },
    );
  }

  /// Build email list item
  Widget _buildEmailListItem(Email email, FluentThemeData theme, String currentFolder) {
    final dateFormat = DateFormat('yyyy-MM-dd HH:mm');

    // Calculate days until auto-deletion for Trash folder (30 days from when moved to Trash)
    final isTrash = currentFolder.toLowerCase() == 'trash';
    int? daysUntilDeletion;
    if (isTrash) {
      // Use TrashTrackerService to get accurate days (based on when moved to Trash, not email date)
      daysUntilDeletion = TrashTrackerService.getDaysUntilDeletion(email.messageId, email.date);
    }

    Color threatColor;
    switch (email.threatLevel.toLowerCase()) {
      case 'critical':
        threatColor = Colors.red;
        break;
      case 'high':
        threatColor = Colors.orange;
        break;
      case 'medium':
        threatColor = Colors.yellow;
        break;
      case 'low':
        threatColor = Colors.blue;
        break;
      default:
        threatColor = Colors.green;
    }

    final isDraft = currentFolder.toLowerCase() == 'drafts';

    return HoverButton(
      onPressed: () {
        setState(() => _selectedEmail = email);
        if (isDraft) {
          _openDraftInCompose(context, email);
        } else {
          _showEmailViewer(context, email);
        }
      },
      builder: (context, states) {
        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 12.0),
          decoration: BoxDecoration(
            color: states.isHovered
                ? theme.menuColor.withValues(alpha: 0.5)
                : Colors.transparent,
            border: Border(
              bottom: BorderSide(
                color: theme.inactiveBackgroundColor,
                width: 0.5,
              ),
            ),
          ),
          child: LayoutBuilder(
            builder: (context, constraints) {
              final isMobile = constraints.maxWidth < 500;
              if (isMobile) {
                // Mobile: vertical compact layout
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            sanitizeBidi(email.from),
                            style: theme.typography.body?.copyWith(
                              fontWeight: email.isRead ? FontWeight.normal : FontWeight.bold,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: threatColor.withValues(alpha: 0.2),
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: threatColor),
                          ),
                          child: Text(
                            email.threatLevel,
                            style: theme.typography.caption?.copyWith(
                              color: threatColor,
                              fontWeight: FontWeight.bold,
                              fontSize: 10,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      sanitizeBidi(email.subject),
                      style: theme.typography.body,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 2),
                    Row(
                      children: [
                        Text(
                          dateFormat.format(email.date),
                          style: theme.typography.caption?.copyWith(
                            color: theme.inactiveColor,
                            fontSize: 11,
                          ),
                        ),
                        if (isTrash && daysUntilDeletion != null) ...[
                          const SizedBox(width: 8),
                          Builder(
                            builder: (context) {
                              final l10nList = l10nOf(context);
                              final days = daysUntilDeletion!;
                              return Container(
                                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                                decoration: BoxDecoration(
                                  color: days <= 7
                                      ? Colors.red.withValues(alpha: 0.2)
                                      : Colors.orange.withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(4),
                                  border: Border.all(
                                    color: days <= 7 ? Colors.red : Colors.orange,
                                  ),
                                ),
                                child: Text(
                                  days == 0
                                      ? l10nList.mainWindowBadgeToday
                                      : l10nList.mainWindowBadgeDaysShort(days),
                                  style: theme.typography.caption?.copyWith(
                                    color: days <= 7 ? Colors.red : Colors.orange,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 10,
                                  ),
                                ),
                              );
                            },
                          ),
                        ],
                        const Spacer(),
                        _buildDeliveryStatusIcon(email, theme),
                        Tooltip(
                          message: 'Delete',
                          child: IconButton(
                            icon: Icon(FluentIcons.delete, size: 14, color: Colors.red),
                            onPressed: () {
                              final emailProvider = Provider.of<EmailProvider>(context, listen: false);
                              emailProvider.deleteEmail(email);
                              if (_selectedEmail?.messageId == email.messageId) {
                                setState(() => _selectedEmail = null);
                              }
                            },
                          ),
                        ),
                      ],
                    ),
                  ],
                );
              }
              // Desktop: horizontal row layout
              return Row(
                children: [
                  // From
                  SizedBox(
                    width: 250,
                    child: Text(
                      sanitizeBidi(email.from),
                      style: theme.typography.body?.copyWith(
                        fontWeight: email.isRead ? FontWeight.normal : FontWeight.bold,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  const SizedBox(width: 16),

                  // Subject
                  Expanded(
                    child: Text(
                      sanitizeBidi(email.subject),
                      style: theme.typography.body,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  const SizedBox(width: 16),

                  // Date
                  SizedBox(
                    width: 150,
                    child: Text(
                      dateFormat.format(email.date),
                      style: theme.typography.caption?.copyWith(
                        color: theme.inactiveColor,
                      ),
                    ),
                  ),
                  const SizedBox(width: 16),

                  // Days until auto-deletion (only in Trash folder)
                  if (isTrash && daysUntilDeletion != null) ...[
                    Builder(
                      builder: (context) {
                        final l10nList = l10nOf(context);
                        final days = daysUntilDeletion!;
                        return Tooltip(
                          message: days == 0
                              ? l10nList.mainWindowTooltipAutoDeleteToday
                              : l10nList.mainWindowTooltipAutoDelete(days),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: days <= 7
                                  ? Colors.red.withValues(alpha: 0.2)
                                  : Colors.orange.withValues(alpha: 0.2),
                              borderRadius: BorderRadius.circular(4),
                              border: Border.all(
                                color: days <= 7 ? Colors.red : Colors.orange,
                              ),
                            ),
                            child: Text(
                              days == 0
                                  ? l10nList.mainWindowBadgeToday
                                  : l10nList.mainWindowBadgeDaysShort(days),
                              style: theme.typography.caption?.copyWith(
                                color: days <= 7 ? Colors.red : Colors.orange,
                                fontWeight: FontWeight.bold,
                                fontSize: 11,
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                    const SizedBox(width: 12),
                  ],

                  // Threat level
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: threatColor.withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: threatColor),
                    ),
                    child: Text(
                      email.threatLevel,
                      style: theme.typography.caption?.copyWith(
                        color: threatColor,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),

                  // Delivery status icon — shows server-side delivery status
                  const SizedBox(width: 8),
                  _buildDeliveryStatusIcon(email, theme),

                  // Delete button — always visible in all folders
                  const SizedBox(width: 8),
                  Tooltip(
                    message: 'Delete',
                    child: IconButton(
                      icon: Icon(FluentIcons.delete, size: 16, color: Colors.red),
                      onPressed: () {
                        final emailProvider = Provider.of<EmailProvider>(context, listen: false);
                        emailProvider.deleteEmail(email);
                        if (_selectedEmail?.messageId == email.messageId) {
                          setState(() => _selectedEmail = null);
                        }
                      },
                    ),
                  ),
                ],
              );
            },
          ),
        );
      },
    );
  }

  /// Build delivery status icon for an email.
  /// Reads server-side status from the RAM cache populated by a single
  /// batch fetch in _buildEmailList — no per-widget HTTP calls.
  Widget _buildDeliveryStatusIcon(Email email, FluentThemeData theme) {
    final cached = MailStatusService.getCached(email.messageId);

    IconData icon;
    Color color;
    String tooltipMsg;
    switch (cached?.status) {
      case MailDeliveryStatus.sent:
        icon = FluentIcons.completed;
        color = Colors.green;
        tooltipMsg = 'Delivered';
        if (cached?.relay != null) tooltipMsg += ' via ${cached!.relay}';
        if (cached?.timestamp != null) tooltipMsg += ' (${cached!.timestamp})';
        break;
      case MailDeliveryStatus.deferred:
        icon = FluentIcons.clock;
        color = Colors.orange;
        tooltipMsg = 'Deferred — retrying';
        break;
      case MailDeliveryStatus.bounced:
        icon = FluentIcons.error_badge;
        color = Colors.red;
        tooltipMsg = 'Bounced — permanent failure';
        break;
      case MailDeliveryStatus.expired:
        icon = FluentIcons.blocked2;
        color = Colors.red;
        tooltipMsg = 'Expired — gave up retrying';
        break;
      case MailDeliveryStatus.pending:
        icon = FluentIcons.send;
        color = Colors.blue;
        tooltipMsg = 'Pending — in queue';
        break;
      case MailDeliveryStatus.notFound:
      case MailDeliveryStatus.forbidden:
        icon = FluentIcons.help;
        color = theme.inactiveColor;
        tooltipMsg = 'No delivery status available';
        break;
      case null:
      case MailDeliveryStatus.unknown:
        icon = FluentIcons.sync;
        color = theme.inactiveColor;
        tooltipMsg = 'Checking delivery status…';
        break;
    }

    return Tooltip(
      message: tooltipMsg,
      child: Icon(icon, size: 14, color: color),
    );
  }

  /// Build ping quality indicator
  /// Build compact port status indicators for footer.
  Widget _buildPortIndicators(FluentThemeData theme, EmailProvider emailProvider) {
    final status = emailProvider.connectionStatus;
    if (status == null) return const SizedBox.shrink();

    Widget dot(String label, PortStatus portStatus) {
      final Color color;
      switch (portStatus.status) {
        case 'OPEN':
          color = Colors.green;
          break;
        case 'TIMEOUT':
          color = Colors.orange;
          break;
        case 'CLOSED':
          color = Colors.red;
          break;
        default:
          color = Colors.grey;
      }
      return Tooltip(
        message: '${portStatus.protocol}:${portStatus.port} — ${portStatus.status}',
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 7,
              height: 7,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
              ),
            ),
            const SizedBox(width: 3),
            Text(
              label,
              style: theme.typography.caption?.copyWith(
                fontSize: 9,
                color: color,
              ),
            ),
          ],
        ),
      );
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        dot('HTTPS', status.httpsStatus),
        const SizedBox(width: 6),
        dot('SMTP', status.smtpStatus),
        const SizedBox(width: 6),
        dot('IMAP', status.imapStatus),
      ],
    );
  }

  Widget _buildPingIndicator(FluentThemeData theme) {
    final Color color;
    final String label;
    final int bars;

    if (_pingError || _pingMs == null) {
      color = Colors.grey;
      label = 'Offline';
      bars = 0;
    } else if (_pingMs! <= 30) {
      color = Colors.green;
      label = '${_pingMs}ms';
      bars = 4;
    } else if (_pingMs! <= 50) {
      color = Colors.yellow.dark;
      label = '${_pingMs}ms';
      bars = 3;
    } else if (_pingMs! <= 100) {
      color = Colors.orange;
      label = '${_pingMs}ms';
      bars = 2;
    } else {
      color = Colors.red;
      label = '${_pingMs}ms';
      bars = 1;
    }

    return Tooltip(
      message: _pingError ? 'Server unreachable' : 'Ping: $label',
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Signal bars
          SizedBox(
            width: 16,
            height: 14,
            child: CustomPaint(
              painter: _SignalBarsPainter(
                bars: bars,
                color: color,
                inactiveColor: theme.inactiveBackgroundColor,
              ),
            ),
          ),
          const SizedBox(width: 4),
          Text(
            label,
            style: theme.typography.caption?.copyWith(
              color: color,
              fontWeight: FontWeight.bold,
              fontSize: 10,
            ),
          ),
        ],
      ),
    );
  }

  /// Build footer status bar
  /// Build footer status bar
  Widget _buildFooter(FluentThemeData theme, EmailProvider emailProvider) {
    final l10n = l10nOf(context);
    final activeAccount = emailProvider.currentAccount;

    // Last sync relative time
    String syncText = 'Not synced';
    if (emailProvider.isLoading) {
      syncText = 'Syncing...';
    } else if (emailProvider.lastSyncTime != null) {
      final diff = DateTime.now().difference(emailProvider.lastSyncTime!);
      if (diff.inSeconds < 30) {
        syncText = 'Just synced';
      } else if (diff.inMinutes < 1) {
        syncText = 'Synced ${diff.inSeconds}s ago';
      } else if (diff.inHours < 1) {
        syncText = 'Synced ${diff.inMinutes}m ago';
      } else {
        syncText = 'Synced ${diff.inHours}h ago';
      }
    }

    // Status color
    final statusColor = emailProvider.error != null
        ? Colors.red
        : emailProvider.isLoading
            ? Colors.orange
            : Colors.green;

    // Quota for selected account
    Widget quotaWidget = const SizedBox.shrink();
    if (activeAccount != null && activeAccount.quotaLimitKB != null && activeAccount.quotaLimitKB! > 0) {
      final usedMB = (activeAccount.quotaUsedKB ?? 0) / 1024;
      final limitMB = activeAccount.quotaLimitKB! / 1024;
      final pct = activeAccount.quotaPercentage ?? 0;
      final quotaColor = pct > 90 ? Colors.red : pct > 70 ? Colors.orange : Colors.green;
      final usedStr = usedMB >= 1024 ? '${(usedMB / 1024).toStringAsFixed(1)}GB' : '${usedMB.toStringAsFixed(0)}MB';
      final limitStr = limitMB >= 1024 ? '${(limitMB / 1024).toStringAsFixed(1)}GB' : '${limitMB.toStringAsFixed(0)}MB';

      quotaWidget = Tooltip(
        message: '${activeAccount.username}: $usedStr / $limitStr (${pct.toStringAsFixed(0)}%)',
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            ExcludeSemantics(
              child: Icon(FluentIcons.hard_drive, size: 11, color: theme.inactiveColor),
            ),
            const SizedBox(width: 4),
            SizedBox(
              width: 60,
              height: 6,
              child: ProgressBar(
                value: pct.clamp(0, 100),
                backgroundColor: theme.inactiveBackgroundColor,
                activeColor: quotaColor,
              ),
            ),
            const SizedBox(width: 4),
            Text(
              '$usedStr/$limitStr',
              style: TextStyle(fontSize: 10, color: theme.inactiveColor),
            ),
          ],
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 6.0),
      decoration: BoxDecoration(
        color: theme.scaffoldBackgroundColor,
        border: Border(
          top: BorderSide(
            color: theme.inactiveBackgroundColor,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Sync status
          Tooltip(
            message: emailProvider.error != null
                ? l10n.mainWindowStatusError(emailProvider.error!)
                : syncText,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                ExcludeSemantics(
                  child: Icon(
                    emailProvider.error != null
                        ? FluentIcons.error
                        : emailProvider.isLoading
                            ? FluentIcons.sync
                            : FluentIcons.check_mark,
                    size: 12,
                    color: statusColor,
                  ),
                ),
                const SizedBox(width: 4),
                Text(
                  syncText,
                  style: TextStyle(fontSize: 11, color: statusColor),
                ),
              ],
            ),
          ),

          const SizedBox(width: 12),

          // E2E indicator
          if (emailProvider.accounts.isNotEmpty)
            Tooltip(
              message: 'End-to-end encrypted (OpenPGP)',
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  ExcludeSemantics(
                    child: Icon(FluentIcons.lock_solid,
                        size: 11, color: const Color(0xFF107C10)),
                  ),
                  const SizedBox(width: 3),
                  const Text('E2E',
                      style: TextStyle(fontSize: 10, color: Color(0xFF107C10), fontWeight: FontWeight.bold)),
                ],
              ),
            ),

          const SizedBox(width: 12),

          // Ping
          if (_pingMs != null && !_pingError)
            Tooltip(
              message: 'Server latency',
              child: Text(
                '${_pingMs}ms',
                style: TextStyle(
                  fontSize: 10,
                  color: _pingMs! <= 50 ? Colors.green : _pingMs! <= 100 ? Colors.orange : Colors.red,
                ),
              ),
            ),

          const SizedBox(width: 12),

          // Quota (selected account)
          quotaWidget,

          const Spacer(),

          // Log Viewer
          Tooltip(
            message: 'Log Viewer',
            child: IconButton(
              icon: Icon(FluentIcons.code, size: 11, color: theme.inactiveColor),
              onPressed: _showLogViewer,
            ),
          ),

          const SizedBox(width: 4),

          // Security Health
          Tooltip(
            message: 'Security Health',
            child: IconButton(
              icon: Icon(FluentIcons.shield, size: 11, color: theme.inactiveColor),
              onPressed: _showSecurityHealth,
            ),
          ),

          const SizedBox(width: 4),

          // Server Info
          Tooltip(
            message: 'Server Info',
            child: IconButton(
              icon: Icon(FluentIcons.server, size: 11, color: theme.inactiveColor),
              onPressed: () {
                _resetAutoLockTimer();
                showDialog(
                  context: context,
                  builder: (_) => const ServerInfoDialog(),
                );
              },
            ),
          ),

          const SizedBox(width: 4),

          // Check for updates
          Tooltip(
            message: _manualUpdateChecking ? 'Checking...' : 'Check for updates',
            child: IconButton(
              icon: _manualUpdateChecking
                  ? const SizedBox(width: 11, height: 11, child: ProgressRing(strokeWidth: 2))
                  : Icon(FluentIcons.cloud_download, size: 11, color: theme.inactiveColor),
              onPressed: _manualUpdateChecking ? null : _checkForUpdatesManual,
            ),
          ),

          const SizedBox(width: 8),

          // Rechtliches
          Tooltip(
            message: 'Legal information',
            child: HoverButton(
              onPressed: () => _showRechtlichesDialog(),
              builder: (context, states) => Text(
                'Rechtliches',
                style: theme.typography.caption?.copyWith(
                  decoration: states.isHovered ? TextDecoration.underline : null,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// Show legal information dialog
  void _showRechtlichesDialog() {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);
    showDialog(
      context: context,
      builder: (context) => ContentDialog(
        title: Row(
          children: [
            Image.asset('assets/logo.png', width: 32, height: 32),
            const SizedBox(width: 12),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('ICD360S Mail',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                Text('v${UpdateService.currentVersion}',
                    style: TextStyle(fontSize: 12, color: theme.inactiveColor)),
              ],
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const SizedBox(height: 8),
            Text(
              'ICD360S e.V. — gemeinnütziger Verein',
              style: TextStyle(fontSize: 12, color: theme.inactiveColor),
            ),
            Text(
              'Amtsgericht Memmingen, VR 201335',
              style: TextStyle(fontSize: 11, color: theme.inactiveColor),
            ),
            const SizedBox(height: 4),
            Text(
              '\u00a9 2025\u2013${DateTime.now().year} ICD360S e.V.',
              style: TextStyle(fontSize: 11, color: theme.inactiveColor),
            ),
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 12),
            _buildLegalLink(theme, l10n.mainWindowLegalImpressum, 'https://icd360s.de/impressum/'),
            const SizedBox(height: 8),
            _buildLegalLink(theme, l10n.mainWindowLegalPrivacy, 'https://icd360s.de/datenschutz/'),
            const SizedBox(height: 8),
            _buildLegalLink(theme, l10n.mainWindowLegalWithdrawal, 'https://icd360s.de/widerrufsrecht/'),
            const SizedBox(height: 8),
            _buildLegalLink(theme, l10n.mainWindowLegalCancellation, 'https://icd360s.de/kundigung/'),
            const SizedBox(height: 8),
            _buildLegalLink(theme, l10n.mainWindowLegalConstitution, 'https://icd360s.de/satzung360s/'),
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 8),
            _buildLegalLink(theme, 'Source Code (AGPL-3.0)', 'https://github.com/ICD360S-e-V/mail'),
          ],
        ),
        actions: [
          FilledButton(
            child: const Text('Close'),
            onPressed: () => Navigator.of(context).pop(),
          ),
        ],
      ),
    );
  }

  Future<void> _openLegalUrl(String url) async {
    if (!mounted) return;
    Navigator.of(context).pop();
    try {
      final uri = Uri.parse(url);
      await launchUrl(uri, mode: LaunchMode.inAppBrowserView);
    } catch (e, stackTrace) {
      LoggerService.logError('LEGAL_URL', e, stackTrace);
    }
  }

  Widget _buildLegalLink(FluentThemeData theme, String label, String url) {
    return HoverButton(
      onPressed: () => _openLegalUrl(url),
      builder: (context, states) => Container(
        padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 8),
        decoration: BoxDecoration(
          color: states.isHovered
              ? theme.accentColor.withValues(alpha: 0.08)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(4),
        ),
        child: Row(
          children: [
            ExcludeSemantics(
              child: Icon(FluentIcons.open_in_new_window, size: 14, color: theme.accentColor),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                label,
                style: theme.typography.body?.copyWith(
                  color: theme.accentColor,
                  fontWeight: states.isHovered ? FontWeight.bold : FontWeight.normal,
                ),
              ),
            ),
            ExcludeSemantics(
              child: Icon(FluentIcons.chevron_right, size: 12, color: theme.inactiveColor),
            ),
          ],
        ),
      ),
    );
  }

}

// Keyboard shortcut intents
class DeleteEmailIntent extends Intent {
  const DeleteEmailIntent();
}

class ComposeEmailIntent extends Intent {
  const ComposeEmailIntent();
}

class RefreshIntent extends Intent {
  const RefreshIntent();
}

/// Custom painter for signal strength bars
class _SignalBarsPainter extends CustomPainter {
  final int bars;
  final Color color;
  final Color inactiveColor;

  _SignalBarsPainter({
    required this.bars,
    required this.color,
    required this.inactiveColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    const totalBars = 4;
    final barWidth = size.width / (totalBars * 2 - 1);
    final gap = barWidth;

    for (int i = 0; i < totalBars; i++) {
      final isActive = i < bars;
      final barHeight = size.height * (0.25 + 0.25 * i);
      final x = i * (barWidth + gap);
      final y = size.height - barHeight;

      final paint = Paint()
        ..color = isActive ? color : inactiveColor
        ..style = PaintingStyle.fill;

      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(x, y, barWidth, barHeight),
          const Radius.circular(1),
        ),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(covariant _SignalBarsPainter oldDelegate) {
    return oldDelegate.bars != bars || oldDelegate.color != color;
  }
}




