import 'dart:async';

import 'package:fluent_ui/fluent_ui.dart';

import '../services/device_approval_service.dart';
import '../services/logger_service.dart';

/// Result returned by [AwaitingApprovalDialog] via Navigator.pop.
enum AwaitingApprovalResult {
  /// Admin approved AND we successfully downloaded + stored the cert.
  /// Caller should now construct an EmailAccount and persist it.
  approvedAndStored,

  /// Admin actively rejected the request.
  rejected,

  /// 5-minute window passed without admin action.
  expired,

  /// User clicked Cancel.
  cancelled,

  /// Cert download failed (token consumed elsewhere, network, etc.).
  certDownloadFailed,
}

/// Modal dialog shown to the user after they submit an access request
/// via [DeviceApprovalService.requestAccess]. Polls the server every
/// 5 seconds until a terminal status is reached, then either:
///
/// - On approved → automatically downloads the cert via the
///   one_time_token, persists it via [DeviceApprovalService.storeBundle],
///   and pops with [AwaitingApprovalResult.approvedAndStored]
/// - On rejected/expired/cert failure → pops with the matching status
/// - On cancel button → pops with [AwaitingApprovalResult.cancelled]
///
/// The countdown is purely cosmetic — the actual deadline is enforced
/// server-side. The dialog gives up at `expiresInSeconds` even if the
/// poll stream is somehow still pending (defense in depth).
class AwaitingApprovalDialog extends StatefulWidget {
  final String username;
  final String requestId;
  final bool isTransfer;
  final int expiresInSeconds;
  final int pollIntervalSeconds;

  const AwaitingApprovalDialog({
    super.key,
    required this.username,
    required this.requestId,
    required this.isTransfer,
    this.expiresInSeconds = 300,
    this.pollIntervalSeconds = 5,
  });

  @override
  State<AwaitingApprovalDialog> createState() => _AwaitingApprovalDialogState();
}

class _AwaitingApprovalDialogState extends State<AwaitingApprovalDialog> {
  StreamSubscription<StatusPoll>? _pollSub;
  Timer? _countdownTimer;
  int _secondsRemaining = 0;
  String _statusText = '';
  bool _isDownloadingCert = false;
  bool _terminated = false;

  @override
  void initState() {
    super.initState();
    _secondsRemaining = widget.expiresInSeconds;
    _statusText = 'Waiting for admin approval…';
    _startCountdown();
    _startPolling();
    LoggerService.log('APPROVAL_UI',
        'Dialog opened for ${widget.username} request=${widget.requestId}');
  }

  @override
  void dispose() {
    _pollSub?.cancel();
    _countdownTimer?.cancel();
    super.dispose();
  }

  void _startCountdown() {
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted || _terminated) return;
      setState(() {
        _secondsRemaining = (_secondsRemaining - 1).clamp(0, 999999);
      });
      if (_secondsRemaining <= 0 && !_terminated) {
        _finish(AwaitingApprovalResult.expired);
      }
    });
  }

  void _startPolling() {
    final stream = DeviceApprovalService.pollStatus(
      widget.requestId,
      pollInterval: Duration(seconds: widget.pollIntervalSeconds),
      maxDuration: Duration(seconds: widget.expiresInSeconds + 30),
    );
    _pollSub = stream.listen((poll) async {
      if (!mounted || _terminated) return;
      switch (poll.status) {
        case ApprovalStatus.pending:
          // Cosmetic: show a heartbeat indicator update
          setState(() => _statusText = 'Waiting for admin approval…');
          break;
        case ApprovalStatus.approved:
          await _handleApproved(poll);
          break;
        case ApprovalStatus.rejected:
          _finish(AwaitingApprovalResult.rejected);
          break;
        case ApprovalStatus.expired:
          _finish(AwaitingApprovalResult.expired);
          break;
        case ApprovalStatus.notFound:
          _finish(AwaitingApprovalResult.expired);
          break;
        case ApprovalStatus.unknown:
          // transient, ignore — stream will retry
          break;
      }
    });
  }

  Future<void> _handleApproved(StatusPoll poll) async {
    final token = poll.oneTimeToken;
    if (token == null || token.isEmpty) {
      LoggerService.logWarning('APPROVAL_UI',
          'Approved status without one_time_token — treating as expired');
      _finish(AwaitingApprovalResult.expired);
      return;
    }
    setState(() {
      _isDownloadingCert = true;
      _statusText = 'Approved! Downloading certificate…';
    });
    // v2.30.3: top-level try/catch around the download+store path. In
    // v2.30.2 a PlatformException from flutter_secure_storage during
    // CertificateService.storeBundle (caused by `:` and `@` chars in
    // the per-username key) propagated up through the stream.listen
    // callback (which has no onError) and was swallowed silently —
    // leaving this dialog stuck on "Approved! Downloading…" forever.
    // Catching here makes any future failure visible to the user
    // AND closes the dialog so they can retry.
    try {
      final bundle = await DeviceApprovalService.downloadCert(
        requestId: widget.requestId,
        oneTimeToken: token,
      );
      if (bundle == null) {
        LoggerService.logWarning('APPROVAL_UI', 'Cert download failed');
        _finish(AwaitingApprovalResult.certDownloadFailed);
        return;
      }
      await DeviceApprovalService.storeBundle(bundle);
      LoggerService.log('APPROVAL_UI',
          'Cert stored for ${bundle.username} — closing dialog');
      _finish(AwaitingApprovalResult.approvedAndStored);
    } catch (ex, st) {
      LoggerService.logError('APPROVAL_UI',
          'Cert install path threw — closing with error', st);
      LoggerService.logError('APPROVAL_UI', ex, st);
      if (mounted && !_terminated) {
        setState(() {
          _statusText = 'Cert install failed:\n$ex';
        });
      }
      // Give the user 1.5s to read the error before closing.
      await Future.delayed(const Duration(milliseconds: 1500));
      _finish(AwaitingApprovalResult.certDownloadFailed);
    }
  }

  void _finish(AwaitingApprovalResult result) {
    if (_terminated) return;
    _terminated = true;
    _pollSub?.cancel();
    _countdownTimer?.cancel();
    if (mounted) {
      Navigator.of(context).pop(result);
    }
  }

  String _formatRemaining() {
    final m = _secondsRemaining ~/ 60;
    final s = _secondsRemaining % 60;
    return '${m}:${s.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    return ContentDialog(
      constraints: const BoxConstraints(maxWidth: 480),
      title: Row(
        children: [
          Icon(
            widget.isTransfer
                ? FluentIcons.transition_effect
                : FluentIcons.contact_card,
            size: 22,
          ),
          const SizedBox(width: 12),
          Text(widget.isTransfer
              ? 'Transfer device approval'
              : 'Device approval'),
        ],
      ),
      content: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const ProgressRing(),
            const SizedBox(height: 24),
            Text(
              widget.username,
              style: const TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              _statusText,
              style: const TextStyle(fontSize: 14),
              textAlign: TextAlign.center,
            ),
            if (widget.isTransfer) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    color: Colors.orange.withValues(alpha: 0.4),
                  ),
                ),
                child: Row(
                  children: [
                    Icon(
                      FluentIcons.warning,
                      color: Colors.orange,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    const Expanded(
                      child: Text(
                        'You already have an approved device. '
                        'Approving this request will revoke the previous one.',
                        style: TextStyle(fontSize: 12),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 16),
            Text(
              'Expires in ${_formatRemaining()}',
              style: TextStyle(
                fontSize: 12,
                color: _secondsRemaining < 60
                    ? Colors.orange
                    : null,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'An admin must approve this request from mail-admin '
              'before you can access your account.',
              style: TextStyle(fontSize: 11),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
      actions: [
        Button(
          onPressed: _isDownloadingCert
              ? null
              : () => _finish(AwaitingApprovalResult.cancelled),
          child: const Text('Cancel'),
        ),
      ],
    );
  }
}
