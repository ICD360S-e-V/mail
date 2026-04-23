import 'package:fluent_ui/fluent_ui.dart';
import '../services/server_health_service.dart';
import '../utils/l10n_helper.dart';

/// DNS details window for SPF/DKIM records
class DnsDetailsWindow extends StatelessWidget {
  final String recordType; // 'SPF' or 'DKIM'
  final HealthCheckResult result;

  const DnsDetailsWindow({
    super.key,
    required this.recordType,
    required this.result,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);

    Color statusColor;
    switch (result.color.toLowerCase()) {
      case 'green':
        statusColor = Colors.green;
        break;
      case 'orange':
        statusColor = Colors.orange;
        break;
      case 'red':
        statusColor = Colors.red;
        break;
      default:
        statusColor = Colors.grey;
    }

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 700
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          Tooltip(
            message: 'DNS record status',
            child: Icon(FluentIcons.shield, size: 24, color: statusColor),
          ),
          const SizedBox(width: 12),
          Text(l10n.dnsDetailsTitle(recordType)),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Status
            _buildInfoRow(
              theme,
              l10n.dnsDetailsLabelStatus,
              result.status,
              valueColor: statusColor,
            ),
            const SizedBox(height: 12),

            // Record type
            _buildInfoRow(theme, l10n.dnsDetailsLabelRecordType, recordType),
            const SizedBox(height: 12),

            // Domain
            _buildInfoRow(theme, l10n.dnsDetailsLabelDomain, 'icd360s.de'),
            const SizedBox(height: 16),

            // DNS Record content
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF1E1E1E),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: theme.inactiveBackgroundColor),
              ),
              child: SelectableText(
                result.message.isEmpty
                    ? l10n.dnsDetailsNoRecord
                    : result.message,
                style: const TextStyle(
                  fontFamily: 'Consolas',
                  fontSize: 12,
                  color: Colors.white,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Explanation
            if (recordType == 'SPF')
              _buildExplanation(
                theme,
                l10n.dnsDetailsExplanationSpf,
              )
            else if (recordType == 'DKIM')
              _buildExplanation(
                theme,
                l10n.dnsDetailsExplanationDkim,
              ),
          ],
        ),
      ),
      actions: [
        FilledButton(
          child: Text(l10n.buttonClose),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ],
    );
  }

  Widget _buildInfoRow(FluentThemeData theme, String label, String value,
      {Color? valueColor}) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 120,
          child: Text(
            label,
            style: theme.typography.body?.copyWith(
              fontWeight: FontWeight.bold,
              color: theme.inactiveColor,
            ),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: theme.typography.body?.copyWith(
              color: valueColor,
              fontWeight: valueColor != null ? FontWeight.bold : null,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildExplanation(FluentThemeData theme, String text) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.micaBackgroundColor,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(
        children: [
          const Tooltip(
            message: 'Information',
            child: Icon(FluentIcons.info, size: 16),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: theme.typography.caption,
            ),
          ),
        ],
      ),
    );
  }
}
