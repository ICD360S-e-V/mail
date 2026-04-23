import 'package:fluent_ui/fluent_ui.dart';
import 'package:url_launcher/url_launcher.dart';

import '../services/logger_service.dart';
import '../services/security_health_service.dart';

/// Modal dialog showing the result of all platform-aware security
/// health checks. Each check renders as a card with a traffic-light
/// icon, name, description, and (when applicable) a recommendation
/// for fixing the issue. A "Re-check" button at the bottom re-runs
/// the audit on demand.
///
/// Triggers:
///   - Manual: footer button in main_window
///   - Automatic: shown once at startup if any check is at
///     [SecurityStatus.critical] severity (handled by main_window)
class SecurityHealthDialog extends StatefulWidget {
  const SecurityHealthDialog({super.key});

  @override
  State<SecurityHealthDialog> createState() => _SecurityHealthDialogState();
}

class _SecurityHealthDialogState extends State<SecurityHealthDialog> {
  List<SecurityCheck>? _checks;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _runChecks();
  }

  Future<void> _runChecks() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final checks = await SecurityHealthService.runAllChecks();
      if (!mounted) return;
      setState(() {
        _checks = checks;
        _loading = false;
      });
    } catch (e, st) {
      LoggerService.logError('SECURITY_HEALTH_UI', e, st);
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _openMacFileVaultSettings() async {
    try {
      await launchUrl(Uri.parse(
          'x-apple.systempreferences:com.apple.preference.security?Privacy_FileVault'));
    } catch (e) {
      LoggerService.logWarning('SECURITY_HEALTH_UI',
          'Could not open FileVault settings: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 700
            ? 700
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.85,
      ),
      title: Row(
        children: const [
          Semantics(
            excludeSemantics: true,
            child: Icon(FluentIcons.shield, size: 22),
          ),
          SizedBox(width: 12),
          Text('Security Health'),
        ],
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: _buildBody(theme),
      ),
      actions: [
        Tooltip(
          message: 'Re-check security',
          child: Button(
            onPressed: _loading ? null : _runChecks,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: const [
                Semantics(
                  excludeSemantics: true,
                  child: Icon(FluentIcons.refresh, size: 14),
                ),
                SizedBox(width: 8),
                Text('Re-check'),
              ],
            ),
          ),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }

  Widget _buildBody(FluentThemeData theme) {
    if (_loading) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 40),
        child: Center(child: ProgressRing()),
      );
    }
    if (_error != null) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Semantics(
              label: 'Error',
              child: Icon(FluentIcons.error, size: 32, color: Colors.red),
            ),
            const SizedBox(height: 12),
            Text('Failed to run security checks'),
            const SizedBox(height: 8),
            Text(_error!, style: const TextStyle(fontSize: 12)),
          ],
        ),
      );
    }
    final checks = _checks ?? [];
    if (checks.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(24),
        child: Text('No security checks available on this platform.'),
      );
    }

    final critCount =
        checks.where((c) => c.status == SecurityStatus.critical).length;
    final warnCount =
        checks.where((c) => c.status == SecurityStatus.warning).length;
    final okCount = checks.where((c) => c.status == SecurityStatus.ok).length;

    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Summary banner
          Container(
            margin: const EdgeInsets.only(bottom: 16),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: critCount > 0
                  ? Colors.red.withValues(alpha: 0.12)
                  : warnCount > 0
                      ? Colors.orange.withValues(alpha: 0.12)
                      : Colors.green.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(6),
              border: Border.all(
                color: critCount > 0
                    ? Colors.red.withValues(alpha: 0.4)
                    : warnCount > 0
                        ? Colors.orange.withValues(alpha: 0.4)
                        : Colors.green.withValues(alpha: 0.4),
              ),
            ),
            child: Row(
              children: [
                Semantics(
                  label: critCount > 0
                      ? 'Critical security issues'
                      : warnCount > 0
                          ? 'Security warnings'
                          : 'All checks passed',
                  child: Icon(
                    critCount > 0
                        ? FluentIcons.shield_alert
                        : warnCount > 0
                            ? FluentIcons.warning
                            : FluentIcons.shield_solid,
                    size: 22,
                    color: critCount > 0
                        ? Colors.red
                        : warnCount > 0
                            ? Colors.orange
                            : Colors.green,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    critCount > 0
                        ? '$critCount critical issue${critCount > 1 ? "s" : ""} require attention'
                        : warnCount > 0
                            ? '$warnCount warning${warnCount > 1 ? "s" : ""} — '
                                'app secure but environment could improve'
                            : 'All $okCount checks passed — environment is secure',
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 14,
                    ),
                  ),
                ),
              ],
            ),
          ),

          // Per-check cards
          ...checks.map((check) => _buildCheckCard(theme, check)),
        ],
      ),
    );
  }

  Widget _buildCheckCard(FluentThemeData theme, SecurityCheck check) {
    final color = _statusColor(check.status);
    final icon = _statusIcon(check.status);
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Semantics(
                label: '${check.status.name}',
                child: Icon(icon, size: 18, color: color),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  check.name,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              Semantics(
                label: '${check.name} status: ${check.status.name}',
                child: Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.18),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Text(
                    check.status.name.toUpperCase(),
                    style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                      color: color,
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Padding(
            padding: const EdgeInsets.only(left: 28),
            child: Text(
              check.description,
              style: const TextStyle(fontSize: 12),
            ),
          ),
          if (check.platformDetail != null && check.platformDetail!.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(left: 28, top: 6),
              child: Text(
                check.platformDetail!,
                style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: theme.typography.body?.color
                      ?.withValues(alpha: 0.7),
                ),
              ),
            ),
          if (check.recommendation != null)
            Padding(
              padding: const EdgeInsets.only(left: 28, top: 8),
              child: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: theme.scaffoldBackgroundColor
                      .withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Semantics(
                      excludeSemantics: true,
                      child: Icon(FluentIcons.lightbulb,
                          size: 14, color: Colors.yellow),
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(
                        check.recommendation!,
                        style: const TextStyle(fontSize: 11),
                      ),
                    ),
                    if (check.id == 'macos_filevault' &&
                        check.status == SecurityStatus.critical)
                      Padding(
                        padding: const EdgeInsets.only(left: 8),
                        child: Tooltip(
                          message: 'Open settings',
                          child: Button(
                            onPressed: _openMacFileVaultSettings,
                            child: const Text('Open Settings',
                                style: TextStyle(fontSize: 11)),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Color _statusColor(SecurityStatus status) {
    switch (status) {
      case SecurityStatus.ok:
        return Colors.green;
      case SecurityStatus.info:
        return Colors.blue;
      case SecurityStatus.warning:
        return Colors.orange;
      case SecurityStatus.critical:
        return Colors.red;
      case SecurityStatus.unknown:
        return Colors.grey;
    }
  }

  IconData _statusIcon(SecurityStatus status) {
    switch (status) {
      case SecurityStatus.ok:
        return FluentIcons.completed_solid;
      case SecurityStatus.info:
        return FluentIcons.info;
      case SecurityStatus.warning:
        return FluentIcons.warning;
      case SecurityStatus.critical:
        return FluentIcons.shield_alert;
      case SecurityStatus.unknown:
        return FluentIcons.unknown;
    }
  }
}
