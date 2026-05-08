// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/master_password_service.dart';
import '../services/logger_service.dart';
import '../utils/l10n_helper.dart';
import 'factory_reset_dialog.dart';

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
    if (_isLoading) return;
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

    final isWide = MediaQuery.of(context).size.width > 700;

    Widget brandingPanel() => Container(
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            theme.accentColor.darkest,
            theme.accentColor.darker,
          ],
        ),
        borderRadius: isWide
            ? const BorderRadius.only(topLeft: Radius.circular(8), bottomLeft: Radius.circular(8))
            : const BorderRadius.only(topLeft: Radius.circular(8), topRight: Radius.circular(8)),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Image.asset('assets/logo.png', width: 80, height: 80,
              errorBuilder: (_, __, ___) => Icon(FluentIcons.mail, size: 64, color: Colors.white)),
          const SizedBox(height: 16),
          Text('ICD360S', style: theme.typography.titleLarge?.copyWith(
            color: Colors.white, fontWeight: FontWeight.bold, fontSize: 28)),
          Text('Mail', style: theme.typography.title?.copyWith(
            color: Colors.white.withValues(alpha: 0.9), fontWeight: FontWeight.w300, fontSize: 22)),
          const SizedBox(height: 24),
          Text('Sicher.', style: theme.typography.body?.copyWith(color: Colors.white.withValues(alpha: 0.8))),
          Text('Privat.', style: theme.typography.body?.copyWith(color: Colors.white.withValues(alpha: 0.8))),
          const SizedBox(height: 8),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(FluentIcons.shield, size: 14, color: Colors.white.withValues(alpha: 0.7)),
              const SizedBox(width: 6),
              Text('Ende-zu-Ende', style: theme.typography.caption?.copyWith(color: Colors.white.withValues(alpha: 0.7))),
            ],
          ),
        ],
      ),
    );

    Widget formPanel() => Padding(
      padding: const EdgeInsets.all(28),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (!isWide) ...[
            Center(child: Image.asset('assets/logo.png', width: 48, height: 48,
                errorBuilder: (_, __, ___) => Icon(FluentIcons.mail, size: 40, color: theme.accentColor))),
            const SizedBox(height: 8),
            Center(child: Text(l10n.masterPasswordDialogAppTitle, style: theme.typography.subtitle?.copyWith(fontWeight: FontWeight.bold))),
            const SizedBox(height: 16),
          ],

          Text(
            _isFirstTime ? l10n.masterPasswordDialogFirstTimeMessage : l10n.masterPasswordDialogLoginMessage,
            style: theme.typography.body,
          ),
          const SizedBox(height: 20),

          InfoLabel(
            label: l10n.masterPasswordLabelPassword,
            child: PasswordBox(
              controller: _passwordController,
              placeholder: l10n.masterPasswordPlaceholderPassword,
              enabled: !_isLoading,
              onChanged: (_) => setState(() => _errorMessage = null),
              onSubmitted: (_) { if (!_isFirstTime) _submit(); },
            ),
          ),

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

          if (_errorMessage != null) ...[
            const SizedBox(height: 16),
            InfoBar(title: Text(l10n.errorTitle), content: Text(_errorMessage!), severity: InfoBarSeverity.error),
          ],

          const SizedBox(height: 20),

          Row(
            children: [
              if (!_isFirstTime)
                Tooltip(
                  message: 'Reset App',
                  child: IconButton(
                    icon: Icon(FluentIcons.sync_icon, size: 18, color: Colors.red),
                    onPressed: _isLoading ? null : () async {
                      final confirmed = await _confirmFactoryReset(context);
                      if (confirmed && context.mounted) {
                        await FactoryResetDialog.show(context);
                      }
                    },
                  ),
                ),
              Tooltip(
                message: 'Copy Logs',
                child: IconButton(
                  icon: const Icon(FluentIcons.copy, size: 18),
                  onPressed: () {
                    final logs = LoggerService.getLogs().join('\n');
                    Clipboard.setData(ClipboardData(text: logs));
                  },
                ),
              ),
              const Spacer(),
              FilledButton(
                onPressed: _isLoading ? null : _submit,
                child: _isLoading
                    ? const SizedBox(width: 20, height: 20, child: ProgressRing(strokeWidth: 2))
                    : Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(_isFirstTime ? FluentIcons.save : FluentIcons.unlock, size: 16),
                          const SizedBox(width: 8),
                          Text(_isFirstTime ? l10n.masterPasswordButtonSetPassword : l10n.masterPasswordButtonUnlock),
                        ],
                      ),
              ),
            ],
          ),

          const SizedBox(height: 20),
          Wrap(
            alignment: WrapAlignment.center,
            spacing: 8,
            children: [
              for (final link in [
                (l10n.masterPasswordLegalImpressum, 'https://icd360s.de/impressum/'),
                (l10n.masterPasswordLegalPrivacy, 'https://icd360s.de/datenschutz/'),
                (l10n.masterPasswordLegalWithdrawal, 'https://icd360s.de/widerrufsrecht/'),
                (l10n.masterPasswordLegalCancellation, 'https://icd360s.de/kundigung/'),
                (l10n.masterPasswordLegalConstitution, 'https://icd360s.de/satzung360s/'),
              ]) ...[
                HoverButton(
                  onPressed: () => _openUrl(link.$2),
                  builder: (context, states) => Text(link.$1, style: theme.typography.caption?.copyWith(
                    decoration: states.isHovered ? TextDecoration.underline : null)),
                ),
                if (link.$1 != l10n.masterPasswordLegalConstitution)
                  Text('|', style: theme.typography.caption),
              ],
            ],
          ),
          const SizedBox(height: 6),
          Center(child: Text(l10n.masterPasswordFooterCopyright(currentYear),
            style: theme.typography.caption?.copyWith(color: theme.inactiveColor))),
        ],
      ),
    );

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: isWide ? 750 : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      content: isWide
          ? IntrinsicHeight(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Expanded(flex: 2, child: brandingPanel()),
                  Expanded(flex: 3, child: formPanel()),
                ],
              ),
            )
          : SingleChildScrollView(child: formPanel()),
      actions: const [],
    );
  }

  /// Confirm factory reset by typing "RESET". Prevents accidental clicks
  /// and adds a deliberate barrier against physical-access sabotage.
  Future<bool> _confirmFactoryReset(BuildContext context) async {
    final controller = TextEditingController();
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) {
          final typed = controller.text.trim().toUpperCase();
          final confirmed = typed == 'RESET';
          return ContentDialog(
            title: Row(
              children: [
                Semantics(
                  excludeSemantics: true,
                  child: Icon(FluentIcons.warning, color: Colors.red, size: 24),
                ),
                const SizedBox(width: 8),
                const Text('Factory Reset'),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'This will permanently delete ALL data:\n'
                  '  - All email accounts\n'
                  '  - All certificates and credentials\n'
                  '  - All settings\n'
                  '  - The master password\n\n'
                  'This action CANNOT be undone.',
                ),
                const SizedBox(height: 16),
                const Text('Type RESET to confirm:'),
                const SizedBox(height: 8),
                TextBox(
                  controller: controller,
                  placeholder: 'RESET',
                  autofocus: true,
                  onChanged: (_) => setDialogState(() {}),
                  onSubmitted: (_) {
                    if (confirmed) Navigator.pop(ctx, true);
                  },
                ),
              ],
            ),
            actions: [
              Button(
                child: const Text('Cancel'),
                onPressed: () => Navigator.pop(ctx, false),
              ),
              FilledButton(
                style: ButtonStyle(
                  backgroundColor: confirmed
                      ? WidgetStatePropertyAll(Colors.red)
                      : WidgetStatePropertyAll(Colors.grey),
                ),
                onPressed: confirmed ? () => Navigator.pop(ctx, true) : null,
                child: const Text('Reset Everything'),
              ),
            ],
          );
        },
      ),
    );
    controller.dispose();
    return result ?? false;
  }
}

