// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'dart:async';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:provider/provider.dart';
import '../providers/email_provider.dart';
import '../services/server_health_service.dart';
import '../services/connection_monitor.dart';

/// Server diagnostics dialog — shows connection status, health checks,
/// ping latency, and SPF/DKIM/blacklist state.
class ServerInfoDialog extends StatefulWidget {
  const ServerInfoDialog({super.key});

  @override
  State<ServerInfoDialog> createState() => _ServerInfoDialogState();
}

class _ServerInfoDialogState extends State<ServerInfoDialog> {
  static const String _serverHost = 'mail.icd360s.de';

  // Resolved IP (fetched once on open)
  String? _resolvedIp;
  bool _resolvingIp = true;

  // Ping measured via TCP connect to port 443
  int? _pingMs;
  bool _pingError = false;
  bool _measuringPing = true;

  // Refresh state — triggers re-check of health + ports via provider
  bool _refreshing = false;

  @override
  void initState() {
    super.initState();
    _resolveServerIp();
    _measurePing();
  }

  // ── IP resolution ──────────────────────────────────────────────────

  Future<void> _resolveServerIp() async {
    try {
      final addresses = await InternetAddress.lookup(_serverHost)
          .timeout(const Duration(seconds: 5));
      final ipv4 = addresses
          .where((a) => a.type == InternetAddressType.IPv4)
          .map((a) => a.address)
          .firstOrNull;
      if (mounted) {
        setState(() {
          _resolvedIp = ipv4 ?? addresses.firstOrNull?.address ?? 'Unknown';
          _resolvingIp = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _resolvedIp = 'Resolution failed';
          _resolvingIp = false;
        });
      }
    }
  }

  // ── Ping via TCP connect (no raw ICMP needed) ──────────────────────

  Future<void> _measurePing() async {
    setState(() => _measuringPing = true);
    try {
      final stopwatch = Stopwatch()..start();
      final socket = await Socket.connect(
        _serverHost,
        443,
        timeout: const Duration(seconds: 3),
      );
      stopwatch.stop();
      socket.destroy();
      if (mounted) {
        setState(() {
          _pingMs = stopwatch.elapsedMilliseconds;
          _pingError = false;
          _measuringPing = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _pingMs = null;
          _pingError = true;
          _measuringPing = false;
        });
      }
    }
  }

  // ── Refresh all diagnostics ────────────────────────────────────────

  Future<void> _refresh() async {
    if (_refreshing) return;
    setState(() => _refreshing = true);
    final provider = context.read<EmailProvider>();
    await Future.wait([
      provider.checkServerHealth(),
      provider.checkPortConnections(),
      _measurePing(),
    ]);
    if (mounted) setState(() => _refreshing = false);
  }

  // ── Build ──────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final provider = context.watch<EmailProvider>();

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 620
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          const ExcludeSemantics(child: Icon(FluentIcons.server, size: 22)),
          const SizedBox(width: 10),
          const Text('Server Diagnostics'),
          const Spacer(),
          _refreshing
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: ProgressRing(strokeWidth: 2.5),
                )
              : Tooltip(
                  message: 'Refresh diagnostics',
                  child: IconButton(
                    icon: const Icon(FluentIcons.refresh, size: 16),
                    onPressed: _refresh,
                  ),
                ),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildServerIdentitySection(theme),
            const SizedBox(height: 16),
            _buildConnectionSection(theme, provider.connectionStatus),
            const SizedBox(height: 16),
            _buildHealthSection(theme, provider.serverHealth),
          ],
        ),
      ),
      actions: [
        FilledButton(
          child: const Text('Close'),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ],
    );
  }

  // ── Section: Server identity (hostname + IP + ping) ────────────────

  Widget _buildServerIdentitySection(FluentThemeData theme) {
    return _buildCard(
      theme,
      title: 'Server',
      icon: FluentIcons.globe,
      children: [
        _buildRow(
          theme,
          icon: FluentIcons.server,
          label: 'Hostname',
          value: _serverHost,
        ),
        _buildRow(
          theme,
          icon: FluentIcons.field_filled,
          label: 'IP Address',
          value: _resolvingIp ? 'Resolving...' : (_resolvedIp ?? 'Unknown'),
          valueWidget: _resolvingIp
              ? const SizedBox(
                  width: 14,
                  height: 14,
                  child: ProgressRing(strokeWidth: 2),
                )
              : null,
        ),
        _buildRow(
          theme,
          icon: FluentIcons.timer,
          label: 'Latency',
          value: _buildPingLabel(),
          valueColor: _pingColor(theme),
          valueWidget: _measuringPing
              ? const SizedBox(
                  width: 14,
                  height: 14,
                  child: ProgressRing(strokeWidth: 2),
                )
              : null,
        ),
      ],
    );
  }

  String _buildPingLabel() {
    if (_measuringPing) return 'Measuring...';
    if (_pingError || _pingMs == null) return 'Unreachable';
    return '${_pingMs}ms';
  }

  Color? _pingColor(FluentThemeData theme) {
    if (_measuringPing) return null;
    if (_pingError || _pingMs == null) return Colors.red;
    if (_pingMs! <= 30) return Colors.green;
    if (_pingMs! <= 50) return const Color(0xFF57A64A);
    if (_pingMs! <= 100) return Colors.warningPrimaryColor;
    return Colors.red;
  }

  // ── Section: Port connectivity ─────────────────────────────────────

  Widget _buildConnectionSection(
      FluentThemeData theme, ConnectionStatus? status) {
    return _buildCard(
      theme,
      title: 'Connections',
      icon: FluentIcons.plug_connected,
      children: [
        _buildPortRow(theme, 'IMAP', 10993, status?.imapStatus),
        _buildPortRow(theme, 'SMTP', 465, status?.smtpStatus),
        _buildPortRow(theme, 'HTTPS', 443, status?.httpsStatus),
      ],
    );
  }

  Widget _buildPortRow(
      FluentThemeData theme, String protocol, int port, PortStatus? port_status) {
    final isChecked = port_status != null && port_status.status != 'UNKNOWN';
    final isOpen = port_status?.isConnected ?? false;
    final statusText = isChecked ? port_status!.status : 'Unknown';
    final dotColor = isChecked
        ? (isOpen ? Colors.green : _colorFromString(port_status!.color, theme))
        : theme.inactiveColor;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Semantics(
            label: '$protocol port $port status: $statusText',
            child: _statusDot(dotColor),
          ),
          const SizedBox(width: 8),
          SizedBox(
            width: 52,
            child: Text(
              protocol,
              style: theme.typography.bodyStrong,
            ),
          ),
          Text(
            ':$port',
            style: theme.typography.body?.copyWith(
              color: theme.inactiveColor,
            ),
          ),
          const Spacer(),
          Text(
            statusText,
            style: theme.typography.body?.copyWith(
              color: dotColor,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  // ── Section: SPF / DKIM / IP blacklists ───────────────────────────

  Widget _buildHealthSection(
      FluentThemeData theme, ServerHealthStatus? health) {
    return _buildCard(
      theme,
      title: 'Email Health',
      icon: FluentIcons.health_solid,
      children: [
        _buildHealthRow(theme, 'SPF', FluentIcons.shield_solid,
            health?.spfStatus),
        _buildHealthRow(theme, 'DKIM', FluentIcons.shield_solid,
            health?.dkimStatus),
        _buildHealthRow(theme, 'DMARC', FluentIcons.shield_solid,
            health?.dmarcStatus),
        _buildHealthRow(theme, 'MTA-STS', FluentIcons.shield_solid,
            health?.mtaStsStatus),
        _buildHealthRow(theme, 'TLS-RPT', FluentIcons.shield_solid,
            health?.tlsRptStatus),
        _buildHealthRow(theme, 'CAA', FluentIcons.shield_solid,
            health?.caaStatus),
        _buildHealthRow(theme, 'DNSSEC', FluentIcons.shield_solid,
            health?.dnssecStatus),
        _buildHealthRow(theme, 'DANE', FluentIcons.shield_solid,
            health?.daneStatus),
        _buildHealthRow(theme, 'IPv4 Blacklist', FluentIcons.warning,
            health?.ipv4Status),
        _buildHealthRow(theme, 'IPv6 Blacklist', FluentIcons.warning,
            health?.ipv6Status),
      ],
    );
  }

  Widget _buildHealthRow(FluentThemeData theme, String label,
      IconData icon, HealthCheckResult? result) {
    final hasResult = result != null && result.status.isNotEmpty;
    final dotColor = hasResult
        ? _colorFromString(result!.color, theme)
        : theme.inactiveColor;
    final statusText = hasResult ? result!.status : 'Pending';
    final checkedAt = result?.checkedAt;
    final checkedText = checkedAt != null
        ? '${checkedAt.year}-${checkedAt.month.toString().padLeft(2, '0')}-${checkedAt.day.toString().padLeft(2, '0')} '
          '${checkedAt.hour.toString().padLeft(2, '0')}:${checkedAt.minute.toString().padLeft(2, '0')}:${checkedAt.second.toString().padLeft(2, '0')}'
        : '';

    return Tooltip(
      message: '${result?.message ?? ''}${checkedText.isNotEmpty ? '\nChecked: $checkedText' : ''}',
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          children: [
            Semantics(
              label: '$label status: $statusText',
              child: _statusDot(dotColor),
            ),
            const SizedBox(width: 8),
            ExcludeSemantics(child: Icon(icon, size: 14, color: theme.inactiveColor)),
            const SizedBox(width: 6),
            Expanded(
              child: Text(label, style: theme.typography.body),
            ),
            if (checkedText.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(right: 8),
                child: Text(
                  checkedText,
                  style: TextStyle(fontSize: 10, color: theme.inactiveColor),
                ),
              ),
            Text(
              statusText,
              style: theme.typography.body?.copyWith(
                color: dotColor,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Shared UI helpers ──────────────────────────────────────────────

  /// Card with a section title and a list of child widgets
  Widget _buildCard(
    FluentThemeData theme, {
    required String title,
    required IconData icon,
    required List<Widget> children,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: theme.cardColor,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(
          color: theme.resources.controlStrokeColorDefault,
          width: 1,
        ),
      ),
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              ExcludeSemantics(child: Icon(icon, size: 16, color: theme.accentColor)),
              const SizedBox(width: 8),
              Text(
                title,
                style: theme.typography.bodyStrong,
              ),
            ],
          ),
          const SizedBox(height: 10),
          ...children,
        ],
      ),
    );
  }

  /// A simple label + value row used in the server identity card
  Widget _buildRow(
    FluentThemeData theme, {
    required IconData icon,
    required String label,
    required String value,
    Color? valueColor,
    Widget? valueWidget,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          ExcludeSemantics(child: Icon(icon, size: 14, color: theme.inactiveColor)),
          const SizedBox(width: 8),
          SizedBox(
            width: 90,
            child: Text(label, style: theme.typography.body),
          ),
          if (valueWidget != null) ...[
            valueWidget,
            const SizedBox(width: 6),
          ],
          Expanded(
            child: Text(
              value,
              style: theme.typography.body?.copyWith(
                color: valueColor,
                fontWeight: valueColor != null ? FontWeight.w600 : null,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  /// Solid circle used as a status indicator dot
  Widget _statusDot(Color color) {
    return Container(
      width: 10,
      height: 10,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
      ),
    );
  }

  /// Map service color strings to Flutter Colors
  Color _colorFromString(String colorName, FluentThemeData theme) {
    switch (colorName.toLowerCase()) {
      case 'green':
        return Colors.green;
      case 'orange':
        return Colors.warningPrimaryColor;
      case 'red':
        return Colors.red;
      default:
        return theme.inactiveColor;
    }
  }
}

/// Convenience function — show the dialog from any widget tree
Future<void> showServerInfoDialog(BuildContext context) {
  return showDialog<void>(
    context: context,
    builder: (_) => const ServerInfoDialog(),
  );
}
