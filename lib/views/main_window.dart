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
import '../services/certificate_service.dart';
import '../services/trash_tracker_service.dart';
import '../utils/l10n_helper.dart';
import 'compose_window.dart';
import 'email_viewer.dart';
import 'add_account_dialog.dart';
import 'factory_reset_dialog.dart';
import 'log_viewer_window.dart';
import 'changelog_window.dart';

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

  // Ping/connection quality
  Timer? _pingTimer;
  int? _pingMs;
  bool _pingError = false;

  @override
  void initState() {
    super.initState();

    // Set up notification callback
    NotificationService.onShowNotification = _showNotificationBar;

    // Initialize email provider
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final emailProvider = context.read<EmailProvider>();
      await emailProvider.initialize();

      // Start auto-refresh timers after initialization
      _startTimers();

      // Start auto-lock timer (15 minutes)
      _startAutoLockTimer();

      // Check for updates on startup
      _checkForUpdates();
    });
  }

  /// Start auto-lock timer (15 minutes of inactivity)
  void _startAutoLockTimer() {
    _autoLockTimer?.cancel();
    _autoLockTimer = Timer(const Duration(minutes: 15), () {
      if (mounted && !_isLocked) {
        LoggerService.log('SECURITY', 'Auto-lock triggered after 15 minutes of inactivity');
        _lockApp();
      }
    });
  }

  /// Reset auto-lock timer on user activity
  void _resetAutoLockTimer() {
    if (!_isLocked) {
      _startAutoLockTimer();
    }
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
    // Also clear in-memory mTLS certificates so a memory dump while locked
    // cannot recover them. They are re-downloaded on unlock.
    CertificateService.clearCertificates();

    setState(() => _isLocked = true);
    LoggerService.log('SECURITY', 'Application locked');

    // Show master password dialog
    final result = await _showMasterPasswordDialog();

    if (result) {
      setState(() => _isLocked = false);
      LoggerService.log('SECURITY', 'Application unlocked');

      // Re-download certificates and reconnect after unlock
      _reconnectAfterUnlock();

      _startAutoLockTimer(); // Restart timer after unlock
    }
  }

  /// Re-download certificates and refresh connections after unlock
  Future<void> _reconnectAfterUnlock() async {
    LoggerService.log('SECURITY', 'Reconnecting after unlock...');

    final emailProvider = context.read<EmailProvider>();

    // Re-download certificates for all accounts
    for (final account in emailProvider.accounts) {
      try {
        final success = await CertificateService.downloadCertificateForUser(account.username, password: account.password ?? '');
        if (success) {
          LoggerService.log('SECURITY', '✓ Certificate re-downloaded for ${account.username}');
        } else {
          LoggerService.log('SECURITY', '⚠️ Certificate re-download failed for ${account.username}, will retry on next check');
        }
      } catch (e) {
        LoggerService.log('SECURITY', '⚠️ Certificate error for ${account.username}: $e');
      }
    }

    // Restart all timers
    _startTimers();
    LoggerService.log('SECURITY', 'All timers restarted after unlock');

    // Force refresh emails
    await emailProvider.checkForNewEmails();
  }

  /// Show master password dialog for unlock
  Future<bool> _showMasterPasswordDialog() async {
    final passwordController = TextEditingController();
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        final l10n = l10nOf(context);
        return ContentDialog(
          title: Row(
            children: [
              const Icon(FluentIcons.lock, size: 20),
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
                onSubmitted: (_) async {
                  final isValid = await MasterPasswordService.verifyMasterPassword(passwordController.text);
                  if (context.mounted) {
                    Navigator.of(context).pop(isValid);
                  }
                },
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
              onPressed: () async {
                final isValid = await MasterPasswordService.verifyMasterPassword(passwordController.text);
                if (context.mounted) {
                  Navigator.of(context).pop(isValid);
                }
              },
            ),
          ],
        );
      },
    );
    passwordController.dispose();
    return result ?? false;
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

    // 2. Performance stats timer - Every 10 seconds (reduced from 2s to prevent file descriptor exhaustion)
    _performanceTimer = Timer.periodic(const Duration(seconds: 10), (timer) {
      final emailProvider = context.read<EmailProvider>();
      emailProvider.updatePerformanceStats();
    });

    // 3. Email check timer - Every 60 seconds (auto-check for new emails - optimized for many accounts)
    _emailCheckTimer = Timer.periodic(const Duration(seconds: 60), (timer) async {
      await _autoCheckNewEmails();
    });

    // 4. Update check timer - Every 5 minutes (background update check)
    _updateCheckTimer = Timer.periodic(const Duration(minutes: 5), (timer) {
      LoggerService.log('UPDATE', 'Background update check (5 min timer)');
      _checkForUpdates();
    });

    // 5. Ping timer - Every 10 seconds
    _measurePing();
    _pingTimer = Timer.periodic(const Duration(seconds: 10), (timer) {
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

  /// Update Windows taskbar with unread email count (via window title, desktop only)
  Future<void> _updateTaskbarBadge(int count) async {
    if (!Platform.isWindows && !Platform.isMacOS && !Platform.isLinux) return;
    try {
      if (count > 0) {
        await windowManager.setTitle('ICD360S Mail Client ($count unread)');
        LoggerService.log('TASKBAR', 'Title updated: $count unread emails');
      } else {
        await windowManager.setTitle('ICD360S Mail Client');
        LoggerService.log('TASKBAR', 'Title cleared (no unread emails)');
      }
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

    // If locked, show lock screen (timers continue in background for notifications)
    if (_isLocked) {
      return Container(
        color: theme.scaffoldBackgroundColor.withValues(alpha: 0.95),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(FluentIcons.lock, size: 64),
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

    return Shortcuts(
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
            // Spacer to center compose button
            const Spacer(),

            // Compose Email Button (center)
            FilledButton(
              onPressed: () => _showComposeWindow(context),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(FluentIcons.edit_mail, size: 16),
                  const SizedBox(width: 8),
                  Text(l10n.mainWindowComposeButton),
                ],
              ),
            ),

            // Spacer to push buttons to far right
            const Spacer(),

            // Factory Reset button (requires typed "DELETE" confirmation).
            // SECURITY (M6): Only accessible post-login, not on the lock screen.
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: IconButton(
                icon: const Icon(FluentIcons.delete, size: 16),
                onPressed: () async {
                  LoggerService.log('SECURITY', 'User clicked factory reset button');
                  _resetAutoLockTimer();
                  await FactoryResetDialog.show(context);
                },
              ),
            ),

            // Lock Button
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: IconButton(
                icon: const Icon(FluentIcons.lock, size: 16),
                onPressed: () {
                  LoggerService.log('SECURITY', 'User clicked lock button');
                  _resetAutoLockTimer();
                  _lockApp();
                },
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
        footerItems: [
          PaneItem(
            icon: const Icon(FluentIcons.add),
            title: Text(l10n.mainWindowAddAccount),
            body: Stack(
              children: [
                _buildEmailList(theme, emailProvider),
                if (_showNotification)
                  Positioned(
                    top: 0,
                    left: 0,
                    right: 0,
                    child: _buildNotificationBar(theme),
                  ),
              ],
            ),
            onTap: () => _showAddAccountDialog(context, emailProvider),
          ),
        ],
      ),
              ), // Close NavigationView
            ), // Close Expanded

            // Footer Status Bar (shown once, not duplicated)
            _buildFooter(theme, emailProvider),
          ], // Close Column children
        ), // Close Column
      ), // Close Actions
    ); // Close Shortcuts
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

  /// Build account tree navigation
  List<NavigationPaneItem> _buildAccountTree(EmailProvider emailProvider) {
    final items = <NavigationPaneItem>[];
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);

    LoggerService.log('UI_BUILD', 'Building navigation pane. Accounts: ${emailProvider.accounts.length}');

    for (final account in emailProvider.accounts) {
      LoggerService.log('UI_BUILD', 'Building tree for ${account.username}: ${account.folders.length} folders (status: ${account.connectionStatus})');

      // Determine account color based on connection status
      Color accountColor;
      IconData accountIcon;
      String statusTooltip;

      switch (account.connectionStatus) {
        case AccountConnectionStatus.connected:
          accountColor = Colors.green;
          accountIcon = FluentIcons.accept_medium;
          statusTooltip = l10n.mainWindowStatusConnected;
          break;
        case AccountConnectionStatus.authError:
          accountColor = Colors.red;
          accountIcon = FluentIcons.error_badge;
          statusTooltip = l10n.mainWindowStatusAuthError(account.connectionError ?? "Wrong username or password");
          break;
        case AccountConnectionStatus.networkError:
          accountColor = Colors.orange;
          accountIcon = FluentIcons.warning;
          statusTooltip = l10n.mainWindowStatusNetworkError(account.connectionError ?? "Network error");
          break;
        case AccountConnectionStatus.unknown:
          accountColor = Colors.grey;
          accountIcon = FluentIcons.contact;
          statusTooltip = l10n.mainWindowStatusChecking;
          break;
      }

      items.add(
        PaneItemExpander(
          icon: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Tooltip(
                message: statusTooltip,
                child: Icon(accountIcon, color: accountColor, size: 16),
              ),
              // Quota indicator circle (lângă icon)
              if (account.quotaPercentage != null)
                Tooltip(
                  message: l10n.mainWindowTooltipQuota(
                    (account.quotaUsedKB! / 1024).toStringAsFixed(1),
                    (account.quotaLimitKB! / 1024).toStringAsFixed(0),
                    account.quotaPercentage!.toStringAsFixed(1),
                  ),
                  child: Container(
                    width: 8,
                    height: 8,
                    margin: const EdgeInsets.only(left: 4),
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: _getQuotaColor(account.quotaPercentage!),
                    ),
                  ),
                ),
            ],
          ),
          title: Text(
            '${account.username} (${account.folderCounts['INBOX'] ?? 0})',
            style: TextStyle(
              color: accountColor,
              fontWeight: account.connectionStatus == AccountConnectionStatus.authError
                  ? FontWeight.bold
                  : FontWeight.normal,
            ),
          ),
          trailing: IconButton(
            icon: const Icon(FluentIcons.cancel, size: 14),
            onPressed: () async {
              // Delete account from app only (not from server)
              final confirmed = await showDialog<bool>(
                context: context,
                builder: (ctx) {
                  final l10nDialog = l10nOf(ctx);
                  return ContentDialog(
                    title: Text(l10nDialog.mainWindowDialogDeleteAccountTitle),
                    content: Text(l10nDialog.mainWindowDialogDeleteAccountMessage(account.username)),
                    actions: [
                      Button(
                        child: Text(l10nDialog.buttonCancel),
                        onPressed: () => Navigator.of(ctx).pop(false),
                      ),
                      FilledButton(
                        child: Text(l10nDialog.mainWindowButtonDeleteFromApp),
                        onPressed: () => Navigator.of(ctx).pop(true),
                      ),
                    ],
                  );
                },
              );

              if (confirmed == true) {
                await emailProvider.removeAccount(account);
                NotificationService.showSuccessToast('Removed', '${account.username} removed (server untouched)');
                LoggerService.log('ACCOUNT', '✓ ${account.username} removed from app (NOT from server)');
              }
            },
          ),
          body: Stack(
            children: [
              _buildEmailList(theme, emailProvider),
              if (_showNotification)
                Positioned(
                  top: 0,
                  left: 0,
                  right: 0,
                  child: _buildNotificationBar(theme),
                ),
            ],
          ),
          items: account.folders
              .map(
                (folder) => PaneItem(
                  icon: _getFolderIcon(folder),
                  title: Text('$folder (${account.folderCounts[folder] ?? 0})'),
                  body: Stack(
                    children: [
                      _buildEmailList(theme, emailProvider),
                      if (_showNotification)
                        Positioned(
                          top: 0,
                          left: 0,
                          right: 0,
                          child: _buildNotificationBar(theme),
                        ),
                    ],
                  ),
                  onTap: () => emailProvider.selectFolder(account, folder),
                ),
              )
              .toList(),
        ),
      );
    }

    return items;
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

    return Column(
      children: [
        // Header
        Container(
          padding: const EdgeInsets.all(16.0),
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
                  fontSize: 18,
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
                  : ListView.builder(
                      itemCount: emailProvider.emails.length,
                      itemBuilder: (context, index) {
                        final email = emailProvider.emails[index];
                        return _buildEmailListItem(email, theme, emailProvider.currentFolder);
                      },
                    ),
        ),
      ],
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
                            email.from,
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
                      email.subject,
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
                        // Delete button (visible on hover - mobile)
                        if (states.isHovered) ...[
                          const Spacer(),
                          IconButton(
                            icon: Icon(FluentIcons.delete, size: 14, color: Colors.red),
                            onPressed: () {
                              final emailProvider = Provider.of<EmailProvider>(context, listen: false);
                              emailProvider.deleteEmail(email);
                              if (_selectedEmail?.messageId == email.messageId) {
                                setState(() => _selectedEmail = null);
                              }
                            },
                          ),
                        ],
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
                      email.from,
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
                      email.subject,
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

                  // Delete button (visible on hover)
                  if (states.isHovered) ...[
                    const SizedBox(width: 8),
                    IconButton(
                      icon: Icon(FluentIcons.delete, size: 16, color: Colors.red),
                      onPressed: () {
                        final emailProvider = Provider.of<EmailProvider>(context, listen: false);
                        emailProvider.deleteEmail(email);
                        if (_selectedEmail?.messageId == email.messageId) {
                          setState(() => _selectedEmail = null);
                        }
                      },
                    ),
                  ],
                ],
              );
            },
          ),
        );
      },
    );
  }

  /// Build ping quality indicator
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
  Widget _buildFooter(FluentThemeData theme, EmailProvider emailProvider) {
    final l10n = l10nOf(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      decoration: BoxDecoration(
        color: theme.scaffoldBackgroundColor,
        border: Border(
          top: BorderSide(
            color: theme.inactiveBackgroundColor,
            width: 1,
          ),
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Row 0: Application Status (ÎNTOTDEAUNA VIZIBIL - deasupra)
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            decoration: BoxDecoration(
              color: emailProvider.error != null
                  ? Colors.red.withValues(alpha: 0.1)
                  : emailProvider.isLoading
                      ? Colors.orange.withValues(alpha: 0.1)
                      : Colors.green.withValues(alpha: 0.05),
              border: Border(
                bottom: BorderSide(
                  color: emailProvider.error != null
                      ? Colors.red
                      : emailProvider.isLoading
                          ? Colors.orange
                          : Colors.green,
                  width: 1,
                ),
              ),
            ),
            child: Row(
              children: [
                Icon(
                  emailProvider.error != null
                      ? FluentIcons.error
                      : emailProvider.isLoading
                          ? FluentIcons.sync
                          : FluentIcons.check_mark,
                  size: 14,
                  color: emailProvider.error != null
                      ? Colors.red
                      : emailProvider.isLoading
                          ? Colors.orange
                          : Colors.green,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    emailProvider.isLoading
                        ? l10n.mainWindowStatusCheckingEmails(emailProvider.currentAccount?.username ?? "unknown")
                        : emailProvider.error != null
                            ? l10n.mainWindowStatusError(emailProvider.error!)
                            : l10n.mainWindowStatusReady,
                    style: theme.typography.caption?.copyWith(
                      color: emailProvider.error != null
                          ? Colors.red
                          : emailProvider.isLoading
                              ? Colors.orange
                              : Colors.green,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 4),

          // Row 1: Version & Log
          Row(
            children: [
              const Spacer(),

              // Ping indicator
              _buildPingIndicator(theme),
              const SizedBox(width: 12),

              // Version button (clickable)
              HoverButton(
                onPressed: _showChangelog,
                builder: (context, states) {
                  return Text(
                    l10n.mainWindowVersion('2.20.1'),
                    style: theme.typography.caption?.copyWith(
                      color: states.isHovered ? theme.accentColor.light : theme.accentColor,
                      fontWeight: FontWeight.bold,
                      decoration: states.isHovered ? TextDecoration.underline : null,
                    ),
                  );
                },
              ),
              const SizedBox(width: 16),
              // Log Viewer button
              IconButton(
                icon: const Icon(FluentIcons.code, size: 14),
                onPressed: _showLogViewer,
              ),
            ],
          ),

          // Row 2: Legal links (centered) (was Row 1)
          const SizedBox(height: 4),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Wrap(
                spacing: 8,
                children: [
              HoverButton(
                onPressed: () => _openUrl('https://icd360s.de/impressum/'),
                builder: (context, states) => Text(
                  l10n.mainWindowLegalImpressum,
                  style: theme.typography.caption?.copyWith(
                    decoration: states.isHovered ? TextDecoration.underline : null,
                  ),
                ),
              ),
              Text('|', style: theme.typography.caption),
              HoverButton(
                onPressed: () => _openUrl('https://icd360s.de/datenschutz/'),
                builder: (context, states) => Text(
                  l10n.mainWindowLegalPrivacy,
                  style: theme.typography.caption?.copyWith(
                    decoration: states.isHovered ? TextDecoration.underline : null,
                  ),
                ),
              ),
              Text('|', style: theme.typography.caption),
              HoverButton(
                onPressed: () => _openUrl('https://icd360s.de/widerrufsrecht/'),
                builder: (context, states) => Text(
                  l10n.mainWindowLegalWithdrawal,
                  style: theme.typography.caption?.copyWith(
                    decoration: states.isHovered ? TextDecoration.underline : null,
                  ),
                ),
              ),
              Text('|', style: theme.typography.caption),
              HoverButton(
                onPressed: () => _openUrl('https://icd360s.de/kundigung/'),
                builder: (context, states) => Text(
                  l10n.mainWindowLegalCancellation,
                  style: theme.typography.caption?.copyWith(
                    decoration: states.isHovered ? TextDecoration.underline : null,
                  ),
                ),
              ),
              Text('|', style: theme.typography.caption),
              HoverButton(
                onPressed: () => _openUrl('https://icd360s.de/satzung360s/'),
                builder: (context, states) => Text(
                  l10n.mainWindowLegalConstitution,
                  style: theme.typography.caption?.copyWith(
                    decoration: states.isHovered ? TextDecoration.underline : null,
                  ),
                ),
              ),
                ],
              ),
            ],
          ),

          // Row 3: Copyright (centered) (was Row 2)
          const SizedBox(height: 4),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(
                l10n.mainWindowFooterCopyright(DateTime.now().year),
                style: theme.typography.caption?.copyWith(
                  color: theme.inactiveColor,
                ),
              ),
            ],
          ),
        ],
      ), // Close Column
    ); // Close Container
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


