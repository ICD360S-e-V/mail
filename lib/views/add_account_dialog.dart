// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:fluent_ui/fluent_ui.dart';

import '../models/models.dart';
import '../services/device_approval_service.dart';
import '../services/device_registration_service.dart';
import '../services/logger_service.dart';
import '../utils/l10n_helper.dart';
import 'awaiting_approval_view.dart';

/// Add account dialog (v2.27.0 — Faza 3 passwordless flow).
///
/// User enters ONLY the username. The dialog:
///   1. Submits an access request to /api/client/request-access.php
///   2. On success, opens [AwaitingApprovalDialog] which polls until
///      admin approves/rejects (or 5 minutes pass)
///   3. On approval, the cert is downloaded + stored automatically;
///      this dialog returns a fully-configured [EmailAccount] (with
///      no password — auth is via mTLS cert from now on)
///   4. On rejection / expiration / cancel, returns null
///
/// Backward compat: server `mail.icd360s.de` is hardcoded; ports
/// 10993 (IMAPS mTLS) and 465 (SMTPS mTLS) are locked. Adding
/// non-icd360s.de accounts is not supported in v2.27.0+ — those
/// users should run an older client until we add a generic
/// password-based path back (or, more likely, use a third-party
/// IMAP client and don't get our security model).
class AddAccountDialog extends StatefulWidget {
  const AddAccountDialog({super.key});

  @override
  State<AddAccountDialog> createState() => _AddAccountDialogState();
}

class _AddAccountDialogState extends State<AddAccountDialog> {
  final _usernameController = TextEditingController();
  bool _submitting = false;
  String? _errorMessage;

  static const String _allowedServer = 'mail.icd360s.de';
  static const int _imapPort = 10993;
  static const int _smtpPort = 465;

  @override
  void dispose() {
    _usernameController.dispose();
    super.dispose();
  }

  Future<void> _requestAccess() async {
    final username = _usernameController.text.trim();
    if (username.isEmpty) {
      setState(() => _errorMessage = 'Enter your username.');
      return;
    }
    // Strip "@icd360s.de" if user pasted the full address
    final bareUser = username.replaceAll('@icd360s.de', '');
    if (!RegExp(r'^[a-zA-Z0-9._\-]+$').hasMatch(bareUser)) {
      setState(() => _errorMessage = 'Invalid username format.');
      return;
    }
    final email = '$bareUser@icd360s.de';

    setState(() {
      _submitting = true;
      _errorMessage = null;
    });

    try {
      LoggerService.log('ADD_ACCOUNT', 'Submitting access request for $email');
      final info = await DeviceRegistrationService.gatherDeviceInfo();
      final result = await DeviceApprovalService.requestAccess(
        username: email,
        deviceId: info['device_id'] ?? '',
        deviceName: info['device_name'] ?? '',
        deviceType: info['device_type'] ?? 'unknown',
        osVersion: info['os_version'] ?? '',
        clientVersion: info['client_version'] ?? '',
        hostname: info['hostname'] ?? '',
      );

      if (!mounted) return;

      if (!result.success) {
        String msg;
        switch (result.error) {
          case 'unknown_user':
            msg = 'No account exists for "$bareUser". '
                'Ask the admin to create the account first.';
            break;
          case 'invalid_username':
            msg = 'Invalid username format.';
            break;
          case 'rate_limited':
            final wait = result.retryAfterSeconds ?? 300;
            msg = 'Too many requests. Try again in ${wait ~/ 60} minutes.';
            break;
          case 'network_error':
            msg = 'Cannot reach mail.icd360s.de. Check your internet '
                'connection and try again.';
            break;
          default:
            msg = result.message ?? 'Request failed: ${result.error}';
        }
        setState(() {
          _submitting = false;
          _errorMessage = msg;
        });
        return;
      }

      // Open the awaiting-approval modal — it pops with a result enum.
      LoggerService.log('ADD_ACCOUNT',
          'Request submitted (${result.requestId}), opening approval dialog');
      final approvalResult = await showDialog<AwaitingApprovalResult>(
        context: context,
        barrierDismissible: false,
        builder: (_) => AwaitingApprovalDialog(
          username: email,
          requestId: result.requestId!,
          isTransfer: result.isTransfer,
          expiresInSeconds: result.expiresInSeconds,
          pollIntervalSeconds: result.pollIntervalSeconds,
        ),
      );

      if (!mounted) return;

      switch (approvalResult) {
        case AwaitingApprovalResult.approvedAndStored:
          // Build the EmailAccount and pop with it. Password is empty
          // because auth is via cert (SASL EXTERNAL) from now on.
          final account = EmailAccount(
            username: email,
            mailServer: _allowedServer,
            imapPort: _imapPort,
            smtpPort: _smtpPort,
            useSsl: true,
          );
          LoggerService.log('ADD_ACCOUNT',
              'Account approved + cert stored, returning $email');
          Navigator.of(context).pop(account);
          return;
        case AwaitingApprovalResult.rejected:
          setState(() {
            _submitting = false;
            _errorMessage = 'Admin rejected your access request.';
          });
          return;
        case AwaitingApprovalResult.expired:
          setState(() {
            _submitting = false;
            _errorMessage =
                'Request expired (no admin response in 5 minutes). Try again.';
          });
          return;
        case AwaitingApprovalResult.certDownloadFailed:
          setState(() {
            _submitting = false;
            _errorMessage =
                'Could not download certificate after approval. Contact admin.';
          });
          return;
        case AwaitingApprovalResult.cancelled:
        case null:
          setState(() {
            _submitting = false;
            _errorMessage = null;
          });
          return;
      }
    } catch (e, st) {
      LoggerService.logError('ADD_ACCOUNT', e, st);
      if (mounted) {
        setState(() {
          _submitting = false;
          _errorMessage = 'Unexpected error: $e';
        });
      }
    }
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
          Semantics(
            excludeSemantics: true,
            child: Icon(FluentIcons.contact, size: 24),
          ),
          const SizedBox(width: 12),
          Text(l10n.dialogTitleAddAccount),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Explanation banner
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.blue.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(
                    color: Colors.blue.withValues(alpha: 0.4)),
              ),
              child: Row(
                children: [
                  Icon(FluentIcons.info, size: 18, color: Colors.blue),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'No password required. Your request will be sent '
                      'to an admin who must approve it from mail-admin '
                      'before this device can access your mail.',
                      style: TextStyle(fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Username with @icd360s.de suffix
            InfoLabel(
              label: l10n.labelEmailAddress,
              child: Row(
                children: [
                  Expanded(
                    child: TextBox(
                      controller: _usernameController,
                      placeholder: l10n.placeholderUsername,
                      enabled: !_submitting,
                      onSubmitted: (_) => _requestAccess(),
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

            if (_errorMessage != null) ...[
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.red.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: Colors.red),
                ),
                child: Row(
                  children: [
                    Icon(FluentIcons.error, size: 16, color: Colors.red),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _errorMessage!,
                        style: const TextStyle(fontSize: 12),
                      ),
                    ),
                  ],
                ),
              ),
            ],

            const SizedBox(height: 16),

            // Server info (LOCKED)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.green.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: Colors.green),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(FluentIcons.lock,
                          size: 16, color: Colors.green),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          l10n.infoSslEnabled,
                          style: TextStyle(
                              color: Colors.green,
                              fontWeight: FontWeight.bold),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Server: mail.icd360s.de\n'
                    'IMAP: 10993 (mTLS)\n'
                    'SMTP: 465 (mTLS)',
                    style: TextStyle(fontSize: 11),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        Button(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(null),
          child: Text(l10n.buttonCancel),
        ),
        FilledButton(
          onPressed: _submitting ? null : _requestAccess,
          child: _submitting
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: ProgressRing(strokeWidth: 2),
                )
              : const Text('Request access'),
        ),
      ],
    );
  }
}