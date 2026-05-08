// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/master_password_service.dart';
import '../services/logger_service.dart';
import '../services/update_service.dart';
import '../utils/l10n_helper.dart';
import 'factory_reset_dialog.dart';

/// Master password dialog for app authentication
class MasterPasswordDialog extends StatefulWidget {
  const MasterPasswordDialog({super.key, this.onResult});

  final void Function(bool success)? onResult;

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

  void _showLegalDialog(BuildContext context) {
    final theme = FluentTheme.of(context);
    final links = <(IconData, String, String)>[
      (FluentIcons.info, 'Impressum', 'https://icd360s.de/impressum/'),
      (FluentIcons.shield, 'Datenschutz', 'https://icd360s.de/datenschutz/'),
      (FluentIcons.undo, 'Widerrufsrecht', 'https://icd360s.de/widerrufsrecht/'),
      (FluentIcons.cancel, 'K\u00fcndigung', 'https://icd360s.de/kundigung/'),
      (FluentIcons.document_set, 'Satzung', 'https://icd360s.de/satzung360s/'),
      (FluentIcons.code, 'Quellcode (AGPL-3.0)', 'https://github.com/ICD360S-e-V/mail'),
    ];
    showDialog(
      context: context,
      builder: (ctx) => ContentDialog(
        title: Row(children: [
          Icon(FluentIcons.document_set, size: 22, color: theme.accentColor),
          const SizedBox(width: 10),
          const Text('Rechtliches'),
        ]),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: links.map((l) => Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: HoverButton(
              onPressed: () => _openUrl(l.$3),
              builder: (_, states) => Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                decoration: BoxDecoration(
                  color: states.isHovered ? theme.accentColor.withValues(alpha: 0.1) : Colors.transparent,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Row(children: [
                  Icon(l.$1, size: 16, color: states.isHovered ? theme.accentColor : theme.inactiveColor),
                  const SizedBox(width: 12),
                  Text(l.$2, style: theme.typography.body?.copyWith(
                    color: states.isHovered ? theme.accentColor : null)),
                  const Spacer(),
                  Icon(FluentIcons.open_in_new_window, size: 12,
                      color: states.isHovered ? theme.accentColor : theme.inactiveColor),
                ]),
              ),
            ),
          )).toList(),
        ),
        actions: [
          FilledButton(
            child: const Text('Schlie\u00dfen'),
            onPressed: () => Navigator.pop(ctx),
          ),
        ],
      ),
    );
  }

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
          widget.onResult?.call(true);
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
            widget.onResult?.call(true);
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

    final isWide = MediaQuery.of(context).size.width > 800;
    final w = Colors.white;

    final features = <(IconData, String)>[
      (FluentIcons.lock, 'Ende-zu-Ende-Verschl\u00fcsselung (OpenPGP)'),
      (FluentIcons.certificate, 'mTLS Zertifikat-Authentifizierung'),
      (FluentIcons.shield, 'ClamAV Virenscan f\u00fcr Anh\u00e4nge'),
      (FluentIcons.mail, 'Phishing- & Spam-Erkennung (Rspamd)'),
      (FluentIcons.devices4, 'Windows, macOS, Linux, Android, iOS'),
      (FluentIcons.cloud_download, 'DANE + DNSSEC + MTA-STS'),
      (FluentIcons.lock_solid, 'MasterVault (Argon2id + XChaCha20)'),
      (FluentIcons.blocked2, 'Screenshot-Schutz (alle Plattformen)'),
      (FluentIcons.print, 'Drucken & PDF-Viewer'),
      (FluentIcons.code, 'Open Source (AGPL-3.0)'),
    ];

    Widget brandingPanel() => Container(
      padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 40),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [theme.accentColor.darkest, theme.accentColor.darker],
        ),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Image.asset('assets/logo.png', width: 72, height: 72,
              errorBuilder: (_, __, ___) => Icon(FluentIcons.mail, size: 56, color: w)),
          const SizedBox(height: 12),
          Text('ICD360S Mail', style: theme.typography.title?.copyWith(
              color: w, fontWeight: FontWeight.bold, fontSize: 26)),
          const SizedBox(height: 4),
          Text('Sicher. Privat. Verschl\u00fcsselt.',
              style: theme.typography.body?.copyWith(color: w.withValues(alpha: 0.8))),
          const SizedBox(height: 24),
          ...features.map((f) => Padding(
            padding: const EdgeInsets.symmetric(vertical: 3),
            child: Row(children: [
              Icon(f.$1, size: 14, color: w.withValues(alpha: 0.7)),
              const SizedBox(width: 10),
              Flexible(child: Text(f.$2, style: theme.typography.caption?.copyWith(
                  color: w.withValues(alpha: 0.85), fontSize: 12))),
            ]),
          )),
          const SizedBox(height: 20),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              border: Border.all(color: w.withValues(alpha: 0.3)),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text('Exklusiv f\u00fcr Mitglieder des ICD360S e.V.',
                style: theme.typography.caption?.copyWith(
                    color: w.withValues(alpha: 0.9), fontWeight: FontWeight.w600)),
          ),
        ],
      ),
    );

    Widget formPanel() => Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(32),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 400),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (!isWide) ...[
                Center(child: Image.asset('assets/logo.png', width: 48, height: 48,
                    errorBuilder: (_, __, ___) => Icon(FluentIcons.mail, size: 40, color: theme.accentColor))),
                const SizedBox(height: 8),
                Center(child: Text('ICD360S Mail', style: theme.typography.subtitle?.copyWith(fontWeight: FontWeight.bold))),
                const SizedBox(height: 4),
                Center(child: Text('Exklusiv f\u00fcr Vereinsmitglieder',
                    style: theme.typography.caption?.copyWith(color: theme.inactiveColor))),
                const SizedBox(height: 20),
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

              const SizedBox(height: 24),

              Row(
                children: [
                  if (!_isFirstTime)
                    Tooltip(
                      message: 'Reset App',
                      child: IconButton(
                        icon: Icon(FluentIcons.sync, size: 18, color: Colors.red),
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
              Center(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    HoverButton(
                      onPressed: () => _showLegalDialog(context),
                      builder: (context, states) => Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(FluentIcons.document_set, size: 14, color: states.isHovered ? theme.accentColor : theme.inactiveColor),
                          const SizedBox(width: 6),
                          Text('Rechtliches', style: theme.typography.caption?.copyWith(
                            color: states.isHovered ? theme.accentColor : theme.inactiveColor,
                            decoration: states.isHovered ? TextDecoration.underline : null)),
                        ],
                      ),
                    ),
                    const SizedBox(width: 16),
                    Text('\u00a9 2025\u2013$currentYear ICD360S e.V. \u2014 Gemeinn\u00fctziger Verein',
                        style: theme.typography.caption?.copyWith(color: theme.inactiveColor)),
                  ],
                ),
              ),
              const SizedBox(height: 4),
              Center(
                child: Text('v${UpdateService.currentVersion}',
                    style: theme.typography.caption?.copyWith(color: theme.inactiveColor, fontSize: 11)),
              ),
            ],
          ),
        ),
      ),
    );

    return ScaffoldPage(
      padding: EdgeInsets.zero,
      content: isWide
          ? Row(
              children: [
                Expanded(flex: 2, child: brandingPanel()),
                Expanded(flex: 3, child: formPanel()),
              ],
            )
          : SingleChildScrollView(child: Column(children: [
              brandingPanel(),
              formPanel(),
            ])),
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

