// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:ui';

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

    final serverSections = <(IconData, String, List<(IconData, String)>)>[
      (FluentIcons.command_prompt, 'Betriebssystem', [
        (FluentIcons.command_prompt, 'AlmaLinux 10.1 \u00b7 Heliotrope Lion'),
        (FluentIcons.processing, 'Kernel 6.12 \u00b7 KSPP-Hardening'),
      ]),
      (FluentIcons.globe, 'Infrastruktur', [
        (FluentIcons.globe, 'OVH-Rechenzentrum \u00b7 Deutschland'),
        (FluentIcons.encryption, '2\u00d7 NVMe \u00b7 LUKS2 \u00b7 AES-256-XTS'),
      ]),
      (FluentIcons.protect_restrict, 'Firewall', [
        (FluentIcons.protect_restrict, 'firewalld + nftables'),
        (FluentIcons.blocked2, 'Fail2Ban-RS \u00b7 portscan_guard'),
      ]),
      (FluentIcons.shield, 'Antivirus & Anti-Spam', [
        (FluentIcons.bug, 'ClamAV Virenscan'),
        (FluentIcons.mail, 'Rspamd (Phishing & Spam)'),
      ]),
      (FluentIcons.shield_solid, 'Hardening & Audit', [
        (FluentIcons.shield_solid, 'SELinux Enforcing'),
        (FluentIcons.activity_feed, 'auditd Audit-Logging'),
        (FluentIcons.verified_brand_solid, 'Lynis-Score: 91/100'),
      ]),
      (FluentIcons.mail, 'E-Mail-Sicherheit', [
        (FluentIcons.certificate, 'mTLS Zertifikat-Authentifizierung'),
        (FluentIcons.cloud_download, 'DANE + DNSSEC + MTA-STS'),
      ]),
    ];

    final appFeatures = <(IconData, String)>[
      (FluentIcons.lock, 'Ende-zu-Ende-Verschl\u00fcsselung (OpenPGP)'),
      (FluentIcons.lock_solid, 'MasterVault (Argon2id + XChaCha20)'),
      (FluentIcons.blocked2, 'Screenshot-Schutz (alle Plattformen)'),
      (FluentIcons.devices4, 'Windows, macOS, Linux, Android, iOS'),
      (FluentIcons.print, 'Drucken & PDF-Viewer'),
      (FluentIcons.code, 'Open Source (AGPL-3.0)'),
    ];

    Widget sectionHeader(IconData icon, String label, {bool large = false}) => Padding(
      padding: EdgeInsets.only(top: large ? 16 : 10, bottom: large ? 6 : 3),
      child: Row(children: [
        Icon(icon, size: large ? 13 : 12, color: w.withValues(alpha: 0.9)),
        const SizedBox(width: 8),
        Text(label.toUpperCase(),
            style: theme.typography.caption?.copyWith(
                color: w.withValues(alpha: 0.9),
                fontSize: large ? 11 : 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.2)),
        const SizedBox(width: 10),
        Expanded(child: Container(
          height: 1,
          color: w.withValues(alpha: 0.2),
        )),
      ]),
    );

    Widget featureRow((IconData, String) f) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(children: [
        Icon(f.$1, size: 14, color: w.withValues(alpha: 0.7)),
        const SizedBox(width: 10),
        Flexible(child: Text(f.$2, style: theme.typography.caption?.copyWith(
            color: w.withValues(alpha: 0.85), fontSize: 12))),
      ]),
    );

    Widget brandingPanel() => Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [theme.accentColor.darkest, theme.accentColor.darker],
        ),
      ),
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Center(child: Image.asset('assets/logo.png', width: 64, height: 64,
                errorBuilder: (_, __, ___) => Icon(FluentIcons.mail, size: 52, color: w))),
            const SizedBox(height: 10),
            Center(child: Text('ICD360S Mail', style: theme.typography.title?.copyWith(
                color: w, fontWeight: FontWeight.bold, fontSize: 24))),
            const SizedBox(height: 2),
            Center(child: Text('Sicher. Privat. Verschl\u00fcsselt.',
                style: theme.typography.body?.copyWith(color: w.withValues(alpha: 0.8)))),
            sectionHeader(FluentIcons.server_enviroment, 'Server', large: true),
            for (final section in serverSections) ...[
              sectionHeader(section.$1, section.$2),
              ...section.$3.map(featureRow),
            ],
            sectionHeader(FluentIcons.devices3, 'Anwendung', large: true),
            ...appFeatures.map(featureRow),
            const SizedBox(height: 18),
            Center(child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                border: Border.all(color: w.withValues(alpha: 0.3)),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text('Exklusiv f\u00fcr Mitglieder des ICD360S e.V.',
                  style: theme.typography.caption?.copyWith(
                      color: w.withValues(alpha: 0.9), fontWeight: FontWeight.w600)),
            )),
          ],
        ),
      ),
    );

    final accentDark = theme.accentColor.darkest;
    final accentMed = theme.accentColor.darker;

    // Full-screen "Wird entsperrt..." while Argon2id runs
    if (_isLoading) {
      return ScaffoldPage(
        padding: EdgeInsets.zero,
        content: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TweenAnimationBuilder<double>(
                tween: Tween(begin: 0.0, end: 1.0),
                duration: const Duration(milliseconds: 800),
                builder: (_, opacity, child) => Opacity(opacity: opacity, child: child),
                child: Container(
                  width: 72, height: 72,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: LinearGradient(colors: [accentDark, accentMed]),
                  ),
                  child: const Icon(FluentIcons.lock, size: 32, color: Colors.white),
                ),
              ),
              const SizedBox(height: 24),
              const ProgressRing(),
              const SizedBox(height: 16),
              Text(_isFirstTime ? 'Tresor wird erstellt\u2026' : 'Wird entsperrt\u2026',
                  style: theme.typography.body?.copyWith(color: theme.inactiveColor)),
              const SizedBox(height: 8),
              Text('Schl\u00fcssel werden abgeleitet',
                  style: theme.typography.caption?.copyWith(color: theme.inactiveColor.withValues(alpha: 0.6))),
            ],
          ),
        ),
      );
    }

    Widget formPanel() => Stack(
      children: [
        // Ambient gradient orbs — unique geometric identity
        Positioned(top: -60, right: -40, child: Container(
          width: 200, height: 200,
          decoration: BoxDecoration(shape: BoxShape.circle,
            gradient: RadialGradient(colors: [accentDark.withValues(alpha: 0.3), Colors.transparent])),
        )),
        Positioned(bottom: -80, left: -60, child: Container(
          width: 250, height: 250,
          decoration: BoxDecoration(shape: BoxShape.circle,
            gradient: RadialGradient(colors: [accentMed.withValues(alpha: 0.2), Colors.transparent])),
        )),
        // Glass card
        Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(16),
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                child: Container(
                  constraints: const BoxConstraints(maxWidth: 420),
                  padding: const EdgeInsets.all(28),
                  decoration: BoxDecoration(
                    color: theme.micaBackgroundColor.withValues(alpha: 0.7),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: theme.inactiveColor.withValues(alpha: 0.15)),
                  ),
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
                        Center(child: Text('Gemeinn\u00fctziger Verein',
                            style: theme.typography.caption?.copyWith(color: theme.inactiveColor))),
                        const SizedBox(height: 20),
                      ],

                      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Icon(FluentIcons.lock, size: 20, color: theme.accentColor),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            _isFirstTime ? l10n.masterPasswordDialogFirstTimeMessage : 'Willkommen zur\u00fcck',
                            style: theme.typography.bodyStrong,
                          ),
                        ),
                      ]),
                      if (!_isFirstTime) ...[
                        const SizedBox(height: 4),
                        Padding(
                          padding: const EdgeInsets.only(left: 30),
                          child: Text(l10n.masterPasswordDialogLoginMessage,
                              style: theme.typography.caption?.copyWith(color: theme.inactiveColor)),
                        ),
                      ],
                      const SizedBox(height: 20),

                      Container(
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: theme.inactiveColor.withValues(alpha: 0.2)),
                          color: theme.inactiveColor.withValues(alpha: 0.05),
                        ),
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
                        Container(
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: theme.inactiveColor.withValues(alpha: 0.2)),
                            color: theme.inactiveColor.withValues(alpha: 0.05),
                          ),
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
                        const SizedBox(height: 12),
                        InfoBar(title: Text(l10n.errorTitle), content: Text(_errorMessage!), severity: InfoBarSeverity.error),
                      ],

                      const SizedBox(height: 20),

                      SizedBox(
                        width: double.infinity,
                        height: 40,
                        child: FilledButton(
                          onPressed: _isLoading ? null : _submit,
                          style: ButtonStyle(
                            shape: WidgetStatePropertyAll(RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(8))),
                          ),
                          child: _isLoading
                              ? const SizedBox(width: 20, height: 20, child: ProgressRing(strokeWidth: 2))
                              : Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Icon(_isFirstTime ? FluentIcons.save : FluentIcons.unlock, size: 16),
                                    const SizedBox(width: 8),
                                    Text(_isFirstTime ? l10n.masterPasswordButtonSetPassword : l10n.masterPasswordButtonUnlock),
                                  ],
                                ),
                        ),
                      ),

                      const SizedBox(height: 16),

                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          if (!_isFirstTime)
                            Tooltip(message: 'Reset App', child: IconButton(
                              icon: Icon(FluentIcons.update_restore, size: 16, color: Colors.red.withValues(alpha: 0.7)),
                              onPressed: _isLoading ? null : () async {
                                final confirmed = await _confirmFactoryReset(context);
                                if (confirmed && context.mounted) await FactoryResetDialog.show(context);
                              },
                            )),
                          Tooltip(message: 'Copy Logs', child: IconButton(
                            icon: Icon(FluentIcons.copy, size: 16, color: theme.inactiveColor),
                            onPressed: () {
                              final logs = LoggerService.getLogs().join('\n');
                              Clipboard.setData(ClipboardData(text: logs));
                            },
                          )),
                          const SizedBox(width: 8),
                          HoverButton(
                            onPressed: () => _showLegalDialog(context),
                            builder: (context, states) => Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(FluentIcons.document_set, size: 12, color: states.isHovered ? theme.accentColor : theme.inactiveColor),
                                const SizedBox(width: 4),
                                Text('Rechtliches', style: theme.typography.caption?.copyWith(fontSize: 11,
                                  color: states.isHovered ? theme.accentColor : theme.inactiveColor,
                                  decoration: states.isHovered ? TextDecoration.underline : null)),
                              ],
                            ),
                          ),
                        ],
                      ),

                      const SizedBox(height: 12),
                      Center(child: Text('\u00a9 2025\u2013$currentYear ICD360S e.V. \u2014 Gemeinn\u00fctziger Verein',
                          style: theme.typography.caption?.copyWith(color: theme.inactiveColor, fontSize: 10))),
                      const SizedBox(height: 2),
                      Center(child: Text('v${UpdateService.currentVersion}',
                          style: theme.typography.caption?.copyWith(color: theme.inactiveColor, fontSize: 10))),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
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

