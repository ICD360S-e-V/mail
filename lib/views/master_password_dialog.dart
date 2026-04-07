import 'package:fluent_ui/fluent_ui.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/master_password_service.dart';
import '../services/logger_service.dart';
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

  // Factory Reset functionality has been MOVED out of the lock screen (M6).
  // It is no longer accessible pre-authentication. The "Reset App" flow is
  // now available only post-login via FactoryResetDialog.show() in the main
  // window, and requires the user to type the exact phrase "DELETE" to
  // confirm. This prevents sabotage by an attacker with brief physical
  // access to a locked device.

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
        // SECURITY (M6): Factory Reset button REMOVED from lock screen.
        // Previously accessible pre-auth, allowing sabotage by anyone with
        // 30 seconds of physical access. Reset is now available only from
        // the main window after successful login (FactoryResetDialog).
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

