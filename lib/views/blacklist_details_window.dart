import 'package:fluent_ui/fluent_ui.dart';
import '../services/server_health_service.dart';
import '../services/notification_service.dart';
import '../utils/l10n_helper.dart';

/// Blacklist details window for IP blacklist information
class BlacklistDetailsWindow extends StatelessWidget {
  final HealthCheckResult result;
  final String ipType; // 'IPv4' or 'IPv6'

  const BlacklistDetailsWindow({
    super.key,
    required this.result,
    required this.ipType,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);

    // Determine IP address based on type
    final ipAddress = ipType == 'IPv4'
        ? '49.13.174.172 (mail.icd360s.de)'
        : '2a01:4f8:c0c:fd22::1 (mail.icd360s.de)';

    final providerCount = ipType == 'IPv4' ? 29 : 14;

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
            ? 800
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          Tooltip(
            message: 'Blacklist status',
            child: Icon(FluentIcons.blocked2, size: 24, color: statusColor),
          ),
          const SizedBox(width: 12),
          Text(l10n.blacklistDetailsTitle(ipType)),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Status
            _buildInfoRow(
              theme,
              l10n.blacklistDetailsLabelStatus,
              result.status,
              valueColor: statusColor,
            ),
            const SizedBox(height: 12),

            // IP Address
            _buildInfoRow(theme, l10n.blacklistDetailsLabelIpAddress, ipAddress),
            const SizedBox(height: 16),

            // Blacklist check results
            Text(
              l10n.blacklistDetailsResultsTitle,
              style: theme.typography.subtitle?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),

            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.micaBackgroundColor,
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: theme.inactiveBackgroundColor),
              ),
              child: Text(
                result.message.isEmpty
                    ? l10n.blacklistDetailsNoCheck
                    : result.message,
                style: theme.typography.body,
              ),
            ),
            const SizedBox(height: 16),

            // Blacklist providers
            Text(
              l10n.blacklistDetailsProvidersTitle(providerCount),
              style: theme.typography.subtitle?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),

            ..._buildProviderList(theme),

            const SizedBox(height: 16),

            // Explanation
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: statusColor.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Row(
                children: [
                  Tooltip(
                    message: 'Information',
                    child: Icon(FluentIcons.info, size: 16, color: statusColor),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      l10n.blacklistDetailsExplanation,
                      style: theme.typography.caption,
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
          child: Text(l10n.blacklistDetailsButtonRefresh),
          onPressed: () {
            Navigator.of(context).pop();
            NotificationService.showInfoToast(
              l10n.blacklistDetailsNotificationRefresh,
              l10n.blacklistDetailsNotificationRefreshMessage,
            );
          },
        ),
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

  List<Widget> _buildProviderList(FluentThemeData theme) {
    final providers = ipType == 'IPv4'
        ? [
            'zen.spamhaus.org (Spamhaus ZEN)',
            'bl.spamcop.net (SpamCop)',
            'dnsbl.sorbs.net (SORBS)',
            'b.barracudacentral.org (Barracuda)',
            'cbl.abuseat.org (CBL)',
            'psbl.surriel.com (PSBL)',
            'dnsbl.dronebl.org (DroneBL)',
            'dnsbl-1.uceprotect.net (UCEPROTECT Level 1)',
            'dnsbl-2.uceprotect.net (UCEPROTECT Level 2)',
            'dnsbl-3.uceprotect.net (UCEPROTECT Level 3)',
            'ix.dnsbl.manitu.net (Manitu)',
            's5h.net (S5H)',
            'all.s5h.net (S5H All)',
            'dnsbl.abuse.ch (Abuse.ch)',
            'spam.dnsbl.anonmails.de (Anonmails)',
            'bl.blocklist.de (Blocklist.de)',
            'dnsbl.inps.de (INPS)',
            'dnsbl.kempt.net (Kempt)',
            'backscatterer.spamrats.com (SpamRATS Backscatterer)',
            'noptr.spamrats.com (SpamRATS NoPtr)',
            'spam.spamrats.com (SpamRATS Spam)',
            'dyna.spamrats.com (SpamRATS Dyna)',
            'bl.mailspike.net (MailSpike BL)',
            'z.mailspike.net (MailSpike Z)',
            'truncate.gbudb.net (Truncate)',
            'hostkarma.junkemailfilter.com (Hostkarma Black)',
            'wormrbl.imp.ch (IMP Worm)',
            'web.dnsbl.sorbs.net (SORBS Web)',
            'socks.dnsbl.sorbs.net (SORBS Socks)',
          ]
        : [
            'zen.spamhaus.org (Spamhaus ZEN - IPv6)',
            'bl.spamcop.net (SpamCop - IPv6)',
            'dnsbl.sorbs.net (SORBS - IPv6)',
            'ix.dnsbl.manitu.net (Manitu - IPv6)',
            'ipv6.blacklist.woody.ch (Woody - IPv6)',
            'dnsbl-2.uceprotect.net (UCEPROTECT Level 2 - IPv6)',
            'dnsbl-3.uceprotect.net (UCEPROTECT Level 3 - IPv6)',
            'bl.mailspike.net (MailSpike BL - IPv6)',
            'backscatterer.spamrats.com (SpamRATS Backscatterer - IPv6)',
            'noptr.spamrats.com (SpamRATS NoPtr - IPv6)',
            'spam.spamrats.com (SpamRATS Spam - IPv6)',
            'dyna.spamrats.com (SpamRATS Dyna - IPv6)',
            'web.dnsbl.sorbs.net (SORBS Web - IPv6)',
            'socks.dnsbl.sorbs.net (SORBS Socks - IPv6)',
          ];

    return providers
        .map((provider) => Padding(
              padding: const EdgeInsets.only(left: 16, bottom: 4),
              child: Row(
                children: [
                  const Tooltip(
                    message: 'Provider checked',
                    child: Icon(FluentIcons.checkbox_composite, size: 12),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(provider, style: theme.typography.body),
                  ),
                ],
              ),
            ))
        .toList();
  }
}
