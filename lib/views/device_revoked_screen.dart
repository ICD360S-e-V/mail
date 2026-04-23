import 'package:fluent_ui/fluent_ui.dart';
import '../services/logger_service.dart';

/// Full-screen blocking view shown when admin revokes this device.
///
/// Cannot be dismissed — the only exit is "Request Access Again"
/// which triggers the Faza 3 re-enrollment flow, or "Exit App".
class DeviceRevokedScreen extends StatelessWidget {
  final String username;
  final VoidCallback onRequestAccess;
  final VoidCallback onExit;

  const DeviceRevokedScreen({
    super.key,
    required this.username,
    required this.onRequestAccess,
    required this.onExit,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return ScaffoldPage(
      content: Center(
        child: SizedBox(
          width: 420,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Semantics(
                label: 'Device revoked',
                child: Icon(
                  FluentIcons.blocked2,
                  size: 64,
                  color: Colors.red,
                ),
              ),
              const SizedBox(height: 24),
              Text(
                'Device Revoked',
                style: theme.typography.title?.copyWith(
                  color: Colors.red,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'This device has been revoked by the administrator '
                'for account $username.\n\n'
                'Your credentials have been removed from this device. '
                'No email data remains in memory.\n\n'
                'Contact your administrator to request access again.',
                style: theme.typography.body,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 32),
              FilledButton(
                onPressed: () {
                  LoggerService.log('REVOKED',
                      'User requesting re-access for $username');
                  onRequestAccess();
                },
                child: const Text('Request Access Again'),
              ),
              const SizedBox(height: 12),
              Button(
                onPressed: onExit,
                child: const Text('Exit App'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
