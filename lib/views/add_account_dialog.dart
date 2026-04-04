import 'package:fluent_ui/fluent_ui.dart';
import '../utils/l10n_helper.dart';
import '../models/models.dart';

/// Add account dialog
class AddAccountDialog extends StatefulWidget {
  const AddAccountDialog({super.key});

  @override
  State<AddAccountDialog> createState() => _AddAccountDialogState();
}

class _AddAccountDialogState extends State<AddAccountDialog> {
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _serverController = TextEditingController(text: 'mail.icd360s.de');
  final _imapPortController = TextEditingController(text: '10993'); // Dedicated mTLS-only port
  final _smtpPortController = TextEditingController(text: '465'); // Changed from 587 to 465 for mTLS direct SSL
  // SSL/TLS is always enabled (locked for security)
  static const bool _useSsl = true;

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    _serverController.dispose();
    _imapPortController.dispose();
    _smtpPortController.dispose();
    super.dispose();
  }

  void _addAccount() {
    if (_usernameController.text.isEmpty || _passwordController.text.isEmpty) {
      // Show error
      return;
    }

    // SECURITY: Only allow connection to mail.icd360s.de server
    const allowedServer = 'mail.icd360s.de';
    if (_serverController.text != allowedServer) {
      // Block unauthorized servers
      return;
    }

    // Append @icd360s.de to username
    final email = '${_usernameController.text.trim()}@icd360s.de';

    final account = EmailAccount(
      username: email,
      password: _passwordController.text,
      mailServer: allowedServer, // Force allowed server
      imapPort: int.tryParse(_imapPortController.text) ?? 10993, // Dedicated mTLS port
      smtpPort: int.tryParse(_smtpPortController.text) ?? 465, // mTLS SMTP port
      useSsl: _useSsl,
    );

    Navigator.of(context).pop(account);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = l10nOf(context);

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 600
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          const Icon(FluentIcons.contact, size: 24),
          const SizedBox(width: 12),
          Text(l10n.dialogTitleAddAccount),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Username with @icd360s.de suffix
            InfoLabel(
              label: l10n.labelEmailAddress,
              child: Row(
                children: [
                  Expanded(
                    child: TextBox(
                      controller: _usernameController,
                      placeholder: l10n.placeholderUsername,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    '@icd360s.de',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: FluentTheme.of(context).typography.body?.color,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),

            // Password
            InfoLabel(
              label: l10n.labelPassword,
              child: PasswordBox(
                controller: _passwordController,
                placeholder: l10n.placeholderPassword,
              ),
            ),
            const SizedBox(height: 12),

            // Mail server (LOCKED to mail.icd360s.de)
            InfoLabel(
              label: l10n.labelMailServer,
              child: TextBox(
                controller: _serverController,
                enabled: false, // SECURITY: Prevent changing server
                placeholder: 'mail.icd360s.de',
              ),
            ),
            const SizedBox(height: 12),

            // IMAP Port (LOCKED to 10993 - dedicated mTLS port)
            InfoLabel(
              label: l10n.labelImapPort,
              child: TextBox(
                controller: _imapPortController,
                enabled: false, // SECURITY: Prevent changing port
                placeholder: '10993',
              ),
            ),
            const SizedBox(height: 12),

            // SMTP Port (LOCKED to 587)
            InfoLabel(
              label: l10n.labelSmtpPort,
              child: TextBox(
                controller: _smtpPortController,
                enabled: false, // SECURITY: Prevent changing port
                placeholder: '587',
              ),
            ),
            const SizedBox(height: 16),

            // SSL/TLS info (always enabled, locked)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.green.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: Colors.green),
              ),
              child: Row(
                children: [
                  Icon(FluentIcons.lock, size: 16, color: Colors.green),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      l10n.infoSslEnabled,
                      style: TextStyle(color: Colors.green, fontWeight: FontWeight.bold),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        Button(
          onPressed: () => Navigator.of(context).pop(null),
          child: Text(l10n.buttonCancel),
        ),
        FilledButton(
          onPressed: _addAccount,
          child: Text(l10n.buttonAddAccount),
        ),
      ],
    );
  }
}
