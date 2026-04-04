import 'package:fluent_ui/fluent_ui.dart';
import '../utils/l10n_helper.dart';

/// First-run consent dialog for auto-update and logging
class FirstRunConsentDialog extends StatefulWidget {
  const FirstRunConsentDialog({super.key});

  @override
  State<FirstRunConsentDialog> createState() => _FirstRunConsentDialogState();
}

class _FirstRunConsentDialogState extends State<FirstRunConsentDialog> {
  bool _autoUpdateEnabled = true;
  bool _loggingEnabled = true;
  bool _notificationsEnabled = true;

  void _continue() {
    Navigator.of(context).pop({
      'autoUpdate': _autoUpdateEnabled,
      'logging': _loggingEnabled,
      'notifications': _notificationsEnabled,
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);
    final currentYear = DateTime.now().year;

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 600
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // App title
            Center(
              child: Text(
                l10n.firstRunAppTitle,
                style: theme.typography.title?.copyWith(
                  fontWeight: FontWeight.bold,
                  fontSize: 32,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Center(
              child: Text(
                l10n.firstRunAppVersion,
                style: theme.typography.subtitle?.copyWith(
                  color: theme.inactiveColor,
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Welcome message
            Text(
              l10n.firstRunWelcomeTitle,
              style: theme.typography.subtitle?.copyWith(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            Text(
              l10n.firstRunWelcomeMessage,
              style: theme.typography.body,
            ),
            const SizedBox(height: 24),

            // Auto-update section
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: theme.inactiveBackgroundColor,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(FluentIcons.update_restore, size: 20),
                      const SizedBox(width: 8),
                      Text(
                        l10n.firstRunSectionAutoUpdate,
                        style: theme.typography.subtitle?.copyWith(fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    l10n.firstRunAutoUpdateDescription,
                    style: theme.typography.body,
                  ),
                  const SizedBox(height: 12),
                  Checkbox(
                    checked: _autoUpdateEnabled,
                    onChanged: (value) => setState(() => _autoUpdateEnabled = value ?? true),
                    content: Text(l10n.firstRunCheckboxAutoUpdate),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Logging section
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: theme.inactiveBackgroundColor,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(FluentIcons.diagnostic, size: 20),
                      const SizedBox(width: 8),
                      Text(
                        l10n.firstRunSectionLogging,
                        style: theme.typography.subtitle?.copyWith(fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    l10n.firstRunLoggingDescription,
                    style: theme.typography.body,
                  ),
                  const SizedBox(height: 12),
                  Checkbox(
                    checked: _loggingEnabled,
                    onChanged: (value) => setState(() => _loggingEnabled = value ?? true),
                    content: Text(l10n.firstRunCheckboxLogging),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Notifications section
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: theme.inactiveBackgroundColor,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(FluentIcons.ringer, size: 20),
                      const SizedBox(width: 8),
                      Text(
                        l10n.firstRunSectionNotifications,
                        style: theme.typography.subtitle?.copyWith(fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text(
                    l10n.firstRunNotificationsDescription,
                    style: theme.typography.body,
                  ),
                  const SizedBox(height: 12),
                  Checkbox(
                    checked: _notificationsEnabled,
                    onChanged: (value) => setState(() => _notificationsEnabled = value ?? true),
                    content: Text(l10n.firstRunCheckboxNotifications),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            // Privacy note
            InfoBar(
              title: Text(l10n.firstRunPrivacyTitle),
              content: Text(l10n.firstRunPrivacyMessage),
              severity: InfoBarSeverity.info,
            ),
            const SizedBox(height: 24),

            // Footer
            Center(
              child: Text(
                l10n.firstRunFooterCopyright(currentYear),
                style: theme.typography.caption?.copyWith(
                  color: theme.inactiveColor,
                ),
              ),
            ),
          ],
        ),
      ),
      actions: [
        FilledButton(
          onPressed: _continue,
          child: Text(l10n.firstRunButtonContinue),
        ),
      ],
    );
  }
}
