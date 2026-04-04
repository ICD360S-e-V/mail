import 'dart:io';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart' show SystemNavigator;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:url_launcher/url_launcher.dart';
import '../services/master_password_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import '../utils/l10n_helper.dart';

/// Master password dialog for app authentication
class MasterPasswordDialog extends StatefulWidget {
  const MasterPasswordDialog({super.key});

  @override
  State<MasterPasswordDialog> createState() => _MasterPasswordDialogState();
}

class _MasterPasswordDialogState extends State<MasterPasswordDialog> {
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  bool _isLoading = false;
  bool _isFirstTime = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _checkFirstTime();
  }

  @override
  void dispose() {
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _checkFirstTime() async {
    final hasPassword = await MasterPasswordService.hasMasterPassword();
    setState(() {
      _isFirstTime = !hasPassword;
    });
  }

  /// Open URL in external browser (cross-platform)
  Future<void> _openUrl(String url) async {
    try {
      final uri = Uri.parse(url);
      if (await canLaunchUrl(uri)) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('BROWSER', ex, stackTrace);
    }
  }

  Future<void> _submit() async {
    final l10n = l10nOf(context);

    if (_passwordController.text.isEmpty) {
      setState(() {
        _errorMessage = l10n.masterPasswordErrorEmpty;
      });
      return;
    }

    if (_isFirstTime) {
      // First-time setup - verify password match
      if (_passwordController.text != _confirmPasswordController.text) {
        setState(() {
          _errorMessage = l10n.masterPasswordErrorMismatch;
        });
        return;
      }

      setState(() => _isLoading = true);

      try {
        await MasterPasswordService.setMasterPassword(_passwordController.text);
        if (mounted) {
          Navigator.of(context).pop(true); // Success
        }
      } catch (ex) {
        setState(() {
          _errorMessage = l10n.masterPasswordErrorFailedToSet(ex.toString());
          _isLoading = false;
        });
      }
    } else {
      // Login - verify password
      setState(() => _isLoading = true);

      try {
        final isValid =
            await MasterPasswordService.verifyMasterPassword(_passwordController.text);

        if (isValid) {
          if (mounted) {
            Navigator.of(context).pop(true); // Success
          }
        } else {
          setState(() {
            _errorMessage = l10n.masterPasswordErrorIncorrect;
            _isLoading = false;
          });
        }
      } catch (ex) {
        setState(() {
          _errorMessage = l10n.masterPasswordErrorGeneric(ex.toString());
          _isLoading = false;
        });
      }
    }
  }

  /// Reset app to factory defaults (delete all data)
  Future<void> _resetApp() async {
    final l10n = l10nOf(context);

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => ContentDialog(
        title: Text(l10n.masterPasswordDialogResetTitle),
        content: Text(l10n.masterPasswordDialogResetMessage),
        actions: [
          Button(
            child: Text(l10n.buttonCancel),
            onPressed: () => Navigator.of(ctx).pop(false),
          ),
          FilledButton(
            child: Text(l10n.masterPasswordButtonResetApp),
            onPressed: () => Navigator.of(ctx).pop(true),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        // Cross-platform app data path
        final platform = PlatformService.instance;
        final appDataPath = platform.appDataPath;

        // Delete master password hash
        final masterPasswordFile = File(p.join(appDataPath, '.master_password_hash'));
        if (await masterPasswordFile.exists()) {
          await masterPasswordFile.delete();
          LoggerService.log('RESET', '✓ Deleted master password hash');
        }

        // Delete accounts.json
        final accountsFile = File(p.join(appDataPath, 'accounts.json'));
        if (await accountsFile.exists()) {
          await accountsFile.delete();
          LoggerService.log('RESET', '✓ Deleted accounts.json');
        }

        // Delete settings.json
        final settingsFile = File(p.join(appDataPath, 'settings.json'));
        if (await settingsFile.exists()) {
          await settingsFile.delete();
          LoggerService.log('RESET', '✓ Deleted settings.json');
        }

        // Delete ALL passwords from secure storage (Keychain/Credential Manager)
        const storage = FlutterSecureStorage();
        await storage.deleteAll();
        LoggerService.log('RESET', '✓ Deleted all passwords from secure storage');

        // Delete entire app data folder
        final appFolder = Directory(appDataPath);
        if (await appFolder.exists()) {
          await appFolder.delete(recursive: true);
          LoggerService.log('RESET', '✓ Deleted app data folder');
        }

        LoggerService.log('RESET', '✓✓✓ FACTORY RESET COMPLETE - restarting app as fresh process...');

        // Restart app as NEW process (fresh start) - desktop only
        if (platform.isDesktop) {
          final exePath = Platform.resolvedExecutable;
          await Process.start(exePath, [], mode: ProcessStartMode.detached);
          // Desktop: exit(0) is the only reliable way to terminate
          exit(0);
        } else {
          // Mobile: use SystemNavigator for graceful exit (iOS-safe)
          SystemNavigator.pop();
        }
      } catch (ex) {
        setState(() {
          _errorMessage = 'Reset failed: ${ex.toString()}';
        });
        LoggerService.logError('RESET', ex);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);
    final currentYear = DateTime.now().year;

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 500
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // App title
          Center(
            child: Text(
              l10n.masterPasswordDialogAppTitle,
              style: theme.typography.title?.copyWith(
                fontWeight: FontWeight.bold,
                fontSize: 24,
              ),
            ),
          ),
          const SizedBox(height: 20),

          if (_isFirstTime) ...[
            Text(
              l10n.masterPasswordDialogFirstTimeMessage,
              style: theme.typography.body,
            ),
            const SizedBox(height: 20),
          ] else ...[
            Text(
              l10n.masterPasswordDialogLoginMessage,
              style: theme.typography.body,
            ),
            const SizedBox(height: 20),
          ],

          // Password field
          InfoLabel(
            label: l10n.masterPasswordLabelPassword,
            child: PasswordBox(
              controller: _passwordController,
              placeholder: l10n.masterPasswordPlaceholderPassword,
              enabled: !_isLoading,
              onChanged: (_) => setState(() => _errorMessage = null),
              onSubmitted: (_) {
                if (!_isFirstTime) {
                  _submit();
                }
              },
            ),
          ),

          // Confirm password field (first-time only)
          if (_isFirstTime) ...[
            const SizedBox(height: 12),
            InfoLabel(
              label: l10n.masterPasswordLabelConfirm,
              child: PasswordBox(
                controller: _confirmPasswordController,
                placeholder: l10n.masterPasswordPlaceholderConfirm,
                enabled: !_isLoading,
                onChanged: (_) => setState(() => _errorMessage = null),
                onSubmitted: (_) => _submit(),
              ),
            ),
          ],

          // Error message
          if (_errorMessage != null) ...[
            const SizedBox(height: 16),
            InfoBar(
              title: Text(l10n.errorTitle),
              content: Text(_errorMessage!),
              severity: InfoBarSeverity.error,
            ),
          ],

          // Footer with legal links
          const SizedBox(height: 24),
          Center(
            child: Column(
              children: [
                Wrap(
                  alignment: WrapAlignment.center,
                  spacing: 8,
                  children: [
                    HoverButton(
                      onPressed: () => _openUrl('https://icd360s.de/impressum/'),
                      builder: (context, states) => Text(
                        l10n.masterPasswordLegalImpressum,
                        style: theme.typography.caption?.copyWith(
                          decoration: states.isHovered ? TextDecoration.underline : null,
                        ),
                      ),
                    ),
                    Text('|', style: theme.typography.caption),
                    HoverButton(
                      onPressed: () => _openUrl('https://icd360s.de/datenschutz/'),
                      builder: (context, states) => Text(
                        l10n.masterPasswordLegalPrivacy,
                        style: theme.typography.caption?.copyWith(
                          decoration: states.isHovered ? TextDecoration.underline : null,
                        ),
                      ),
                    ),
                    Text('|', style: theme.typography.caption),
                    HoverButton(
                      onPressed: () => _openUrl('https://icd360s.de/widerrufsrecht/'),
                      builder: (context, states) => Text(
                        l10n.masterPasswordLegalWithdrawal,
                        style: theme.typography.caption?.copyWith(
                          decoration: states.isHovered ? TextDecoration.underline : null,
                        ),
                      ),
                    ),
                    Text('|', style: theme.typography.caption),
                    HoverButton(
                      onPressed: () => _openUrl('https://icd360s.de/kundigung/'),
                      builder: (context, states) => Text(
                        l10n.masterPasswordLegalCancellation,
                        style: theme.typography.caption?.copyWith(
                          decoration: states.isHovered ? TextDecoration.underline : null,
                        ),
                      ),
                    ),
                    Text('|', style: theme.typography.caption),
                    HoverButton(
                      onPressed: () => _openUrl('https://icd360s.de/satzung360s/'),
                      builder: (context, states) => Text(
                        l10n.masterPasswordLegalConstitution,
                        style: theme.typography.caption?.copyWith(
                          decoration: states.isHovered ? TextDecoration.underline : null,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  l10n.masterPasswordFooterCopyright(currentYear),
                  style: theme.typography.caption?.copyWith(
                    color: theme.inactiveColor,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        // Reset App button (only show on login screen, not first-time setup)
        if (!_isFirstTime)
          Button(
            onPressed: _isLoading ? null : _resetApp,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(FluentIcons.refresh, size: 14),
                const SizedBox(width: 6),
                Text(l10n.masterPasswordButtonResetApp),
              ],
            ),
          ),
        Button(
          onPressed: _isLoading ? null : () => Navigator.of(context).pop(false),
          child: Text(l10n.masterPasswordButtonExitApp),
        ),
        FilledButton(
          onPressed: _isLoading ? null : _submit,
          child: _isLoading
              ? Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(
                      width: 16,
                      height: 16,
                      child: ProgressRing(strokeWidth: 2),
                    ),
                    const SizedBox(width: 8),
                    Text(l10n.masterPasswordButtonVerifying),
                  ],
                )
              : Text(_isFirstTime ? l10n.masterPasswordButtonSetPassword : l10n.masterPasswordButtonUnlock),
        ),
      ],
    );
  }
}
