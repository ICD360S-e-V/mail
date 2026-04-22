import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/material.dart' show showModalBottomSheet;
import 'package:file_picker/file_picker.dart';
import 'package:cunning_document_scanner/cunning_document_scanner.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../utils/l10n_helper.dart';
import '../models/models.dart';
import '../providers/email_provider.dart';
import '../services/device_registration_service.dart';
import '../services/notification_service.dart';
import '../services/logger_service.dart';
import '../services/email_history_service.dart';
import '../services/pgp_key_service.dart';
import '../services/secure_mail_service.dart';
import '../utils/pii_redactor.dart';

enum _AttachStatus { loading, ready, failed }

class _ComposeAttachment {
  final PlatformFile file;
  _AttachStatus status;
  String? errorMessage;

  _ComposeAttachment(this.file, {this.status = _AttachStatus.loading});

  bool get isImage {
    final ext = file.extension?.toLowerCase() ?? '';
    return ext == 'jpg' || ext == 'jpeg' || ext == 'png' || ext == 'gif' || ext == 'webp';
  }
}

/// Compose email window
class ComposeWindow extends StatefulWidget {
  final String? replyTo;
  final String? replySubject;
  final String? initialBody;

  const ComposeWindow({super.key, this.replyTo, this.replySubject, this.initialBody});

  @override
  State<ComposeWindow> createState() => _ComposeWindowState();
}

class _ComposeWindowState extends State<ComposeWindow> {
  late final TextEditingController _toController;
  late final TextEditingController _ccController;
  late final TextEditingController _bccController;
  late final TextEditingController _subjectController;
  late final TextEditingController _bodyController;

  EmailAccount? _selectedAccount;
  Timer? _autoSaveTimer;
  Timer? _uiRefreshTimer;
  DateTime? _lastAutoSave;
  bool _isSavingDraft = false;
  int? _lastDraftUid;

  // Attachments
  final List<_ComposeAttachment> _attachments = [];
  final FlyoutController _attachFlyout = FlyoutController();
  static const int maxAttachments = 20;
  static const int maxTotalSizeMB = 25; // 25MB raw limit

  // Target server info
  int? _targetServerMaxSizeMB;
  bool _checkingTargetServer = false;

  // Multiple recipients
  static const int maxRecipients = 25;

  // Auto-complete suggestions
  List<String> _toSuggestions = [];
  bool _showToSuggestions = false;

  // E2EE: per-recipient PGP key status
  final Map<String, bool> _recipientHasKey = {};
  bool _encryptionPossible = false;
  Timer? _keyLookupTimer;

  // Password-protected email for external recipients
  bool _secureMailEnabled = false;
  final TextEditingController _securePasswordController = TextEditingController();
  int _secureExpiryDays = 7;

  @override
  void initState() {
    super.initState();

    // Initialize email history service
    EmailHistoryService.initialize();

    LoggerService.log('COMPOSE', 'Compose window opened${widget.replyTo != null ? " (reply)" : ""}');

    _toController = TextEditingController(text: widget.replyTo ?? '');
    _ccController = TextEditingController();
    _bccController = TextEditingController();
    _subjectController = TextEditingController(
      text: widget.replySubject ?? '',
    );
    _bodyController = TextEditingController(text: widget.initialBody ?? '');

    // Set default account
    final emailProvider = context.read<EmailProvider>();
    _selectedAccount = emailProvider.currentAccount;
    LoggerService.log('COMPOSE', 'Default account: ${_selectedAccount != null ? piiEmail(_selectedAccount!.username) : "none"}');

    // Start auto-save timer (every 5 seconds)
    _autoSaveTimer = Timer.periodic(const Duration(seconds: 5), (_) => _autoSaveDraft());
    LoggerService.log('COMPOSE', 'Auto-save draft enabled (every 5 seconds)');

    // Start UI refresh timer (every 10 seconds to update "X seconds ago")
    _uiRefreshTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (_lastAutoSave != null && mounted) {
        setState(() {}); // Trigger rebuild to update timestamp
      }
    });
  }

  bool _isSending = false;
  String _sendingStatus = '';

  /// Show picker to choose attachment source (file vs camera).
  /// Follows Gmail/Outlook/WinUI3 conventions per platform:
  /// - Desktop: Fluent MenuFlyout anchored to the attach button
  /// - Mobile: Material showModalBottomSheet (industry standard)
  Future<void> _showAttachmentSourcePicker(BuildContext context) async {
    final l10n = l10nOf(context);
    final isMobile = Platform.isAndroid || Platform.isIOS;

    // Camera scanner supported on iOS (VisionKit, always works) and
    // Android (ML Kit — may require Play Services; on GrapheneOS the
    // _scanDocument call fails gracefully with a toast).
    final canScan = Platform.isIOS || Platform.isAndroid;

    if (isMobile) {
      // Mobile: Material modal bottom sheet (Gmail/Outlook pattern,
      // M3 guideline for "secondary actions requiring choice")
      final choice = await showModalBottomSheet<String>(
        context: context,
        builder: (ctx) => SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(FluentIcons.document),
                title: Text(l10n.attachSourceFile),
                onPressed: () => Navigator.pop(ctx, 'file'),
              ),
              if (canScan)
                ListTile(
                  leading: const Icon(FluentIcons.camera),
                  title: Text(l10n.attachSourceCamera),
                  onPressed: () => Navigator.pop(ctx, 'camera'),
                ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      );
      if (choice == 'file') await _addAttachments();
      if (choice == 'camera') await _scanDocument();
    } else {
      // Desktop: Fluent MenuFlyout (WinUI3/Outlook for Windows pattern).
      // MenuFlyoutItem closes the flyout automatically when pressed —
      // no Navigator.pop needed (that caused back-stack corruption).
      _attachFlyout.showFlyout(
        builder: (ctx) => MenuFlyout(
          items: [
            MenuFlyoutItem(
              leading: const Icon(FluentIcons.document),
              text: Text(l10n.attachSourceFile),
              onPressed: _addAttachments,
            ),
            if (canScan)
              MenuFlyoutItem(
                leading: const Icon(FluentIcons.camera),
                text: Text(l10n.attachSourceCamera),
                onPressed: _scanDocument,
              ),
          ],
        ),
      );
    }
  }

  /// Add attachment files (any file type allowed)
  Future<void> _addAttachments() async {
    try {
      // SECURITY: on macOS without App Sandbox (our build is ad-hoc
      // signed, not sandboxed), the system strips file-access
      // entitlements from the plist. file_picker 11.x checks for
      // them and throws ENTITLEMENT_NOT_FOUND if missing. This
      // call tells the plugin to skip that check and open
      // NSOpenPanel directly — works fine outside the sandbox.
      // Requires file_picker >= 11.0.0.
      if (Platform.isMacOS) {
        await FilePicker.skipEntitlementsChecks();
      }
      LoggerService.log('COMPOSE', 'Opening file picker dialog...');
      final result = await FilePicker.pickFiles(
        allowMultiple: true,
        type: FileType.any,
        withData: true,
      );

      if (!mounted) return;

      if (result != null) {
        // Check max attachments
        if (_attachments.length + result.files.length > maxAttachments) {
          final l10n = l10nOf(context);
          NotificationService.showErrorToast(l10n.errorTooManyFiles, l10n.errorTooManyFilesMessage(maxAttachments));
          return;
        }

        // Ensure all files have bytes loaded (macOS sometimes returns null bytes)
        final validFiles = <PlatformFile>[];
        for (final file in result.files) {
          if (file.bytes != null) {
            validFiles.add(file);
          } else if (file.path != null) {
            // Read bytes from file path on macOS
            try {
              final bytes = await File(file.path!).readAsBytes();
              validFiles.add(PlatformFile(
                name: file.name,
                size: bytes.length,
                bytes: bytes,
                path: file.path,
              ));
              LoggerService.log('COMPOSE', 'Read file from path: ${file.name} (${(bytes.length / 1024).round()} KB)');
            } catch (ex) {
              LoggerService.logWarning('COMPOSE', 'Failed to read file ${file.name}: $ex');
            }
          }
        }

        if (validFiles.isEmpty) {
          LoggerService.logWarning('COMPOSE', 'No valid files to attach');
          return;
        }

        // Calculate total size
        int totalSize = _attachments.fold(0, (sum, a) => sum + a.file.size);
        int newSize = validFiles.fold(0, (sum, file) => sum + file.size);
        int totalSizeMB = ((totalSize + newSize) / (1024 * 1024)).round();

        if (totalSizeMB > maxTotalSizeMB) {
          if (!mounted) return;
          final l10n = l10nOf(context);
          NotificationService.showErrorToast(l10n.errorFilesTooLarge, l10n.errorFilesTooLargeMessage(maxTotalSizeMB, totalSizeMB));
          return;
        }

        // Add files with loading status, then mark ready
        final newAttachments = validFiles.map((f) => _ComposeAttachment(f)).toList();
        setState(() {
          _attachments.addAll(newAttachments);
        });

        // Mark each as ready (bytes already loaded)
        for (final att in newAttachments) {
          att.status = _AttachStatus.ready;
        }
        if (mounted) setState(() {});

        LoggerService.log('COMPOSE', 'Added ${validFiles.length} attachments (${totalSizeMB}MB total)');
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('COMPOSE', ex, stackTrace);
      if (!mounted) return;
      final l10n = l10nOf(context);
      // Surface the underlying exception so user-reported bugs include
      // the real cause (macOS sandbox / NSOpenPanel error / plugin
      // crash etc.) instead of a generic "failed to pick files".
      final detail = ex.toString();
      NotificationService.showErrorToast(
        l10n.errorTitle,
        '${l10n.errorFailedToPickFiles}\n\n$detail',
      );
    }
  }

  /// Scan document with camera.
  /// iOS: VisionKit (on-device, no Google dependency, works perfectly).
  /// Android: ML Kit Document Scanner — requires Google Play Services.
  /// On GrapheneOS/CalyxOS without GMS this will throw — user should
  /// use "Choose File" option instead (or use Gallery import).
  Future<void> _scanDocument() async {
    if (!Platform.isIOS && !Platform.isAndroid) {
      final l10n = l10nOf(context);
      NotificationService.showErrorToast(
          l10n.errorTitle, 'Camera scanning requires iOS or Android.');
      return;
    }

    List<String>? imagePaths;

    try {
      LoggerService.log('COMPOSE', 'Opening document scanner...');
      imagePaths = await CunningDocumentScanner.getPictures(
        isGalleryImportAllowed: true,
      );
    } catch (ex) {
      LoggerService.logError('COMPOSE', ex, StackTrace.current);
      if (!mounted) return;
      final l10n = l10nOf(context);
      NotificationService.showErrorToast(l10n.errorTitle, l10n.errorScanFailed);
      return;
    }

    if (!mounted) return;

    if (imagePaths == null || imagePaths.isEmpty) {
      LoggerService.log('COMPOSE', 'Document scan cancelled by user');
      return;
    }

    // Check max attachments
    if (_attachments.length + imagePaths.length > maxAttachments) {
      final l10n = l10nOf(context);
      NotificationService.showErrorToast(l10n.errorTooManyFiles, l10n.errorTooManyFilesMessage(maxAttachments));
      return;
    }

    // Convert scanned images to PlatformFile objects
    final validFiles = <PlatformFile>[];
    final timestamp = DateFormat('yyyyMMdd_HHmmss').format(DateTime.now());

    for (var i = 0; i < imagePaths.length; i++) {
      try {
        final file = File(imagePaths[i]);
        final bytes = await file.readAsBytes();
        final ext = imagePaths[i].toLowerCase().endsWith('.png') ? 'png' : 'jpg';
        final name = 'Scan_${timestamp}_${i + 1}.$ext';

        validFiles.add(PlatformFile(
          name: name,
          size: bytes.length,
          bytes: bytes,
          path: imagePaths[i],
        ));
        LoggerService.log('COMPOSE', 'Scanned page ${i + 1}: $name (${(bytes.length / 1024).round()} KB)');
      } catch (ex) {
        LoggerService.logWarning('COMPOSE', 'Failed to read scanned image ${imagePaths[i]}: $ex');
      }
    }

    if (validFiles.isEmpty) {
      LoggerService.logWarning('COMPOSE', 'No valid scanned images');
      return;
    }

    // Calculate total size
    int totalSize = _attachments.fold(0, (sum, a) => sum + a.file.size);
    int newSize = validFiles.fold(0, (sum, file) => sum + file.size);
    int totalSizeMB = ((totalSize + newSize) / (1024 * 1024)).round();

    if (totalSizeMB > maxTotalSizeMB) {
      if (!mounted) return;
      final l10n = l10nOf(context);
      NotificationService.showErrorToast(l10n.errorFilesTooLarge, l10n.errorFilesTooLargeMessage(maxTotalSizeMB, totalSizeMB));
      return;
    }

    final newAttachments = validFiles.map((f) => _ComposeAttachment(f, status: _AttachStatus.ready)).toList();
    setState(() {
      _attachments.addAll(newAttachments);
    });

    LoggerService.log('COMPOSE', 'Added ${validFiles.length} scanned document(s) (${totalSizeMB}MB total)');
  }

  /// Remove attachment
  void _removeAttachment(int index) {
    setState(() {
      final att = _attachments.removeAt(index);
      LoggerService.log('COMPOSE', 'Removed attachment: ${att.file.name}');
    });
  }

  /// Get total attachments size in MB
  int get _totalAttachmentsSizeMB {
    int totalBytes = _attachments.fold(0, (sum, a) => sum + a.file.size);
    return (totalBytes / (1024 * 1024)).round();
  }

  /// Check if all attachments are ready to send
  bool get _allAttachmentsReady =>
      _attachments.every((a) => a.status == _AttachStatus.ready);

  /// Check target server max message size
  Future<void> _checkTargetServerSize(String email) async {
    if (email.isEmpty || !email.contains('@')) {
      setState(() {
        _targetServerMaxSizeMB = null;
        _checkingTargetServer = false;
      });
      return;
    }

    setState(() => _checkingTargetServer = true);

    try {
      final domain = email.split('@').last;
      final emailProvider = context.read<EmailProvider>();

      final maxSizeMB = await emailProvider.checkTargetServerSize(domain);

      setState(() {
        _targetServerMaxSizeMB = maxSizeMB;
        _checkingTargetServer = false;
      });

      if (maxSizeMB != null) {
        LoggerService.log('TARGET_SERVER', 'Server $domain accepts max $maxSizeMB MB');
      }
    } catch (ex) {
      setState(() {
        _targetServerMaxSizeMB = null;
        _checkingTargetServer = false;
      });
      LoggerService.logWarning('TARGET_SERVER', 'Could not check server size: $ex');
    }
  }

  /// Parse recipients from comma-separated string
  List<String> _getRecipientsList() {
    if (_toController.text.isEmpty) return [];
    return _toController.text
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  /// Parse CC recipients from comma-separated string
  List<String> _getCcList() {
    if (_ccController.text.isEmpty) return [];
    return _ccController.text
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  /// Parse BCC recipients from comma-separated string
  List<String> _getBccList() {
    if (_bccController.text.isEmpty) return [];
    return _bccController.text
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  Future<void> _autoSaveDraft() async {
    if (_isSavingDraft) return; // Prevent concurrent saves
    if (_toController.text.isEmpty && _ccController.text.isEmpty && _bccController.text.isEmpty && _subjectController.text.isEmpty && _bodyController.text.isEmpty) {
      return; // Don't save empty drafts
    }

    if (_selectedAccount == null) return;

    _isSavingDraft = true;
    try {
      final emailProvider = context.read<EmailProvider>();
      final uid = await emailProvider.saveDraft(
        _toController.text,
        _ccController.text,
        _bccController.text,
        _subjectController.text,
        _bodyController.text,
        account: _selectedAccount,
        previousDraftUid: _lastDraftUid,
      );
      _lastDraftUid = uid ?? _lastDraftUid;
      if (mounted) setState(() => _lastAutoSave = DateTime.now());
      LoggerService.log('COMPOSE', 'Draft auto-saved (UID: $_lastDraftUid)');
    } catch (ex) {
      LoggerService.logWarning('COMPOSE', 'Auto-save failed: $ex');
    } finally {
      _isSavingDraft = false;
    }
  }

  /// Look up PGP keys for all current recipients (debounced).
  void _scheduleKeyLookup() {
    _keyLookupTimer?.cancel();
    _keyLookupTimer = Timer(const Duration(milliseconds: 500), _lookupKeys);
  }

  Future<void> _lookupKeys() async {
    final allEmails = [
      ..._getRecipientsList(),
      ..._getCcList(),
      ..._getBccList(),
    ].where((e) => e.contains('@') && e.contains('.')).toList();
    if (allEmails.isEmpty) {
      setState(() => _encryptionPossible = false);
      return;
    }
    LoggerService.log('COMPOSE',
        'Looking up keys for ${allEmails.length} recipients (sender: ${_selectedAccount?.username})');
    final results = await PgpKeyService.lookupAllRecipients(
      allEmails,
      senderEmail: _selectedAccount?.username,
      forceRefresh: true,
    );
    if (!mounted) return;
    for (final entry in results.entries) {
      LoggerService.log('COMPOSE',
          'Key lookup: ${entry.key} → ${entry.value != null ? "FOUND" : "NOT FOUND"}');
    }
    setState(() {
      _recipientHasKey.clear();
      for (final entry in results.entries) {
        _recipientHasKey[entry.key] = entry.value != null;
      }
      _encryptionPossible = results.values.every((k) => k != null) &&
          allEmails.every((e) => e.endsWith('@icd360s.de'));
    });
  }

  @override
  void dispose() {
    _keyLookupTimer?.cancel();
    LoggerService.log('COMPOSE', 'Compose window closed');
    _autoSaveTimer?.cancel();
    _uiRefreshTimer?.cancel();
    _toController.dispose();
    _ccController.dispose();
    _bccController.dispose();
    _subjectController.dispose();
    _bodyController.dispose();
    _attachFlyout.dispose();
    super.dispose();
  }

  Future<void> _sendEmail() async {
    final l10n = l10nOf(context);

    // CRITICAL: in-flight guard must be FIRST. A slow send (5MB attachment
    // on Android = UI freeze for several seconds) lets the user tap the
    // Send button multiple times before _isSending is flipped later. Each
    // tap spawned a parallel _sendEmail() which authenticated separately
    // and relayed the SAME 5MB message 3 times to the MX (seen in
    // submission logs: 3 identical 'Successfully relayed' lines within
    // the same second).
    if (_isSending) {
      LoggerService.log('COMPOSE', 'Send already in progress, ignoring duplicate tap');
      return;
    }
    // Claim the flag synchronously, before any await, so the next tap
    // sees isSending=true even if our UI hasn't rebuilt yet.
    _isSending = true;
    if (mounted) setState(() {});

    if (_selectedAccount == null) {
      _isSending = false;
      if (mounted) setState(() {});
      NotificationService.showErrorToast(l10n.errorTitle, l10n.errorPleaseSelectAccount);
      return;
    }

    final emailProvider = context.read<EmailProvider>();
    final recipients = _getRecipientsList();

    // Helper to reset in-flight guard before returning on validation errors
    void resetSending() {
      _isSending = false;
      if (mounted) setState(() {});
    }

    if (recipients.isEmpty) {
      resetSending();
      NotificationService.showErrorToast(l10n.errorTitle, l10n.errorAtLeastOneRecipient);
      return;
    }

    if (recipients.length > maxRecipients) {
      resetSending();
      NotificationService.showErrorToast(l10n.errorTitle, l10n.errorMaxRecipientsExceeded(maxRecipients));
      return;
    }

    // Validate email format for all recipients
    final emailRegex = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$');
    for (final email in recipients) {
      if (!emailRegex.hasMatch(email)) {
        resetSending();
        NotificationService.showErrorToast(l10n.errorInvalidEmail, l10n.errorInvalidEmailFormat(email));
        return;
      }
    }

    // Validate CC recipients if present
    final ccRecipients = _getCcList();
    for (final email in ccRecipients) {
      if (!emailRegex.hasMatch(email)) {
        resetSending();
        NotificationService.showErrorToast(l10n.errorInvalidCcEmail, l10n.errorInvalidCcEmailFormat(email));
        return;
      }
    }

    // Validate BCC recipients if present
    final bccRecipients = _getBccList();
    for (final email in bccRecipients) {
      if (!emailRegex.hasMatch(email)) {
        resetSending();
        NotificationService.showErrorToast(l10n.errorInvalidBccEmail, l10n.errorInvalidBccEmailFormat(email));
        return;
      }
    }

    // Check total recipients (TO + CC + BCC) doesn't exceed limit
    final totalRecipients = recipients.length + ccRecipients.length + bccRecipients.length;
    if (totalRecipients > maxRecipients) {
      resetSending();
      NotificationService.showErrorToast(l10n.errorTitle, l10n.errorTotalRecipientsExceeded(maxRecipients));
      return;
    }

    // ── mail-admin pre-flight: check sending quota ──
    final canSendResult = await DeviceRegistrationService.canSend(
      username: _selectedAccount!.username,
    );
    if (!canSendResult.allowed) {
      resetSending();
      NotificationService.showErrorToast(
        'Sending limit reached',
        canSendResult.message ??
            'You have reached your sending limit. Please try again later.',
      );
      LoggerService.logWarning('COMPOSE',
          'Send blocked by mail-admin: ${canSendResult.message}');
      return;
    }
    if (canSendResult.isLowQuota) {
      // Soft warning, but allow the send
      final hourLeft = canSendResult.remainingHour ?? -1;
      final dayLeft = canSendResult.remainingDay ?? -1;
      NotificationService.showInfoToast(
        'Quota warning',
        'Only $hourLeft sends left this hour, $dayLeft today.',
      );
    }

    // Verify all attachments are ready
    if (!_allAttachmentsReady) {
      resetSending();
      NotificationService.showErrorToast(l10n.errorTitle, 'Attachments are still being prepared. Please wait.');
      return;
    }

    // Calculate total size for progress display
    int totalSizeBytes = _bodyController.text.length;
    for (final att in _attachments) {
      totalSizeBytes += att.file.size;
    }
    final totalSizeMB = (totalSizeBytes / (1024 * 1024)).toStringAsFixed(1);

    // _isSending already claimed at top of function (in-flight guard).
    // Just update the status text for the spinner.
    setState(() {
      _sendingStatus = _attachments.isNotEmpty
          ? '${l10n.buttonSending} ($totalSizeMB MB, ${_attachments.length} ${_attachments.length == 1 ? "file" : "files"})...'
          : '${l10n.buttonSending}...';
    });

    try {
      LoggerService.log('COMPOSE', 'Sending email from ${piiEmail(_selectedAccount!.username)} to:${recipients.length} cc:${ccRecipients.length} bcc:${bccRecipients.length} attachments:${_attachments.length} (${totalSizeMB}MB)');

      // Password-protected secure mail for external recipients
      if (_secureMailEnabled && _securePasswordController.text.isNotEmpty) {
        try {
          final result = await SecureMailService.encryptAndUpload(
            body: _bodyController.text,
            password: _securePasswordController.text,
            senderEmail: _selectedAccount!.username,
            expiryDays: _secureExpiryDays,
          );

          // Replace body with notification text containing the link
          final senderName = _selectedAccount!.username.split('@').first;
          final notificationBody = SecureMailService.buildNotificationEmail(
            senderName: senderName,
            senderEmail: _selectedAccount!.username,
            secureUrl: result.url,
            expiresAt: result.expiresAt,
          );

          // Override body and subject for the notification email
          _bodyController.text = notificationBody;
          _subjectController.text =
              'Verschlüsselte Nachricht / Encrypted message';

          // Clear password from memory
          _securePasswordController.clear();

          LoggerService.log('SECURE_MAIL',
              '✓ Encrypted and uploaded, sending notification link');
        } catch (ex) {
          NotificationService.showErrorToast(
              'Secure mail failed', ex.toString());
          setState(() { _isSending = false; _sendingStatus = ''; });
          return;
        }
      }

      // Send using selected account with attachments.
      // Pass _lastDraftUid so the just-sent draft can be deleted by UID
      // (avoids the previous SUBJECT search, which was vulnerable to IMAP injection).
      await emailProvider.sendEmailFromAccountWithAttachments(
        _selectedAccount!,
        _toController.text,
        _ccController.text,
        _bccController.text,
        _subjectController.text,
        _bodyController.text,
        _attachments.map((a) => a.file).toList(),
        draftUid: _lastDraftUid,
      );

      if (mounted) {
        final msg = recipients.length > 1
            ? l10n.successEmailSentMultiple(recipients.length)
            : l10n.successEmailSent;
        NotificationService.showSuccessToast(l10n.successTitle, msg);
        Navigator.of(context).pop();
      }
    } catch (ex) {
      NotificationService.showErrorToast(l10n.errorSendFailed, ex.toString());
    } finally {
      if (mounted) {
        setState(() {
          _isSending = false;
          _sendingStatus = '';
        });
      }
    }
  }

  Future<void> _saveDraft() async {
    final l10n = l10nOf(context);
    final emailProvider = context.read<EmailProvider>();

    LoggerService.log('COMPOSE', 'User clicked Save Draft button${_attachments.isNotEmpty ? ' (${_attachments.length} attachments)' : ''}');

    try {
      final uid = await emailProvider.saveDraft(
        _toController.text,
        _ccController.text,
        _bccController.text,
        _subjectController.text,
        _bodyController.text,
        account: _selectedAccount,
        attachments: _attachments.map((a) => a.file).toList(),
        previousDraftUid: _lastDraftUid,
      );
      _lastDraftUid = uid ?? _lastDraftUid;
      NotificationService.showSuccessToast(l10n.successDraftTitle, l10n.successDraftSaved);
      LoggerService.log('COMPOSE', '✓ Draft saved manually (UID: $_lastDraftUid)${_attachments.isNotEmpty ? ' with ${_attachments.length} attachment(s)' : ''}');
    } catch (ex, stackTrace) {
      NotificationService.showErrorToast(l10n.errorDraft, ex.toString());
      LoggerService.logError('COMPOSE', ex, stackTrace);
    }
  }

  /// Get icon for file type (only PDF and images)
  IconData _getFileIcon(String extension) {
    switch (extension.toLowerCase()) {
      case 'pdf':
        return FluentIcons.document;
      case 'jpg':
      case 'jpeg':
      case 'png':
        return FluentIcons.photo2;
      default:
        return FluentIcons.page;
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = l10nOf(context);

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 800
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Text(l10n.dialogTitleCompose),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Account selector
            Consumer<EmailProvider>(
              builder: (context, emailProvider, child) {
                return InfoLabel(
                  label: l10n.labelFromAccount,
                  child: ComboBox<EmailAccount>(
                  value: _selectedAccount,
                  items: emailProvider.accounts.map((account) {
                    return ComboBoxItem<EmailAccount>(
                      value: account,
                      child: Text(account.username),
                    );
                  }).toList(),
                  onChanged: _isSending ? null : (account) {
                    setState(() {
                      _selectedAccount = account;
                      LoggerService.log('COMPOSE', 'Account changed to: ${account != null ? piiEmail(account.username) : "none"}');
                    });
                  },
                    placeholder: Text(l10n.placeholderSelectAccount),
                  ),
                );
              },
            ),
            const SizedBox(height: 12),

              // To field - Primary recipients
            InfoLabel(
              label: l10n.labelTo,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l10n.infoTooltip,
                    style: const TextStyle(fontSize: 10, color: Colors.grey, fontStyle: FontStyle.italic),
                  ),
                  const SizedBox(height: 4),
                  TextBox(
                    controller: _toController,
                    placeholder: l10n.placeholderRecipients,
                    enabled: !_isSending,
                    onChanged: (value) {
                      // Update suggestions based on input
                      final lastEmail = value.split(',').last.trim();
                      if (lastEmail.length >= 3) {
                        final suggestions = EmailHistoryService.getSuggestions(lastEmail);
                        setState(() {
                          _toSuggestions = suggestions;
                          _showToSuggestions = suggestions.isNotEmpty;
                        });
                      } else {
                        setState(() {
                          _toSuggestions = [];
                          _showToSuggestions = false;
                        });
                      }

                      // Check target server when user types email
                      final firstEmail = _getRecipientsList().firstOrNull;
                      if (firstEmail != null && firstEmail.contains('@') && firstEmail.split('@').last.contains('.')) {
                        _checkTargetServerSize(firstEmail);
                      }

                      // E2EE: look up PGP keys for recipients
                      _scheduleKeyLookup();
                    },
                  ),
                  // E2EE encryption status indicator
                  if (_recipientHasKey.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Row(
                        children: [
                          Icon(
                            _encryptionPossible
                                ? FluentIcons.lock_solid
                                : FluentIcons.unlock,
                            size: 12,
                            color: _encryptionPossible
                                ? const Color(0xFF107C10)
                                : FluentTheme.of(context).inactiveColor,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            _encryptionPossible
                                ? 'End-to-end encrypted'
                                : 'Some recipients have no encryption key',
                            style: TextStyle(
                              fontSize: 11,
                              color: _encryptionPossible
                                  ? const Color(0xFF107C10)
                                  : FluentTheme.of(context).inactiveColor,
                            ),
                          ),
                        ],
                      ),
                    ),
                  // Auto-complete suggestions dropdown
                  if (_showToSuggestions && _toSuggestions.isNotEmpty)
                    Container(
                      margin: const EdgeInsets.only(top: 4),
                      decoration: BoxDecoration(
                        color: FluentTheme.of(context).acrylicBackgroundColor,
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Colors.grey),
                      ),
                      constraints: const BoxConstraints(maxHeight: 150),
                      child: ListView.builder(
                        shrinkWrap: true,
                        itemCount: _toSuggestions.length,
                        itemBuilder: (context, index) {
                          final suggestion = _toSuggestions[index];
                          return ListTile(
                            title: Text(suggestion, style: const TextStyle(fontSize: 12)),
                            onPressed: () {
                              // Insert suggestion
                              final current = _toController.text;
                              final parts = current.split(',');
                              parts[parts.length - 1] = suggestion;
                              _toController.text = '${parts.join(', ')}, ';

                              setState(() {
                                _showToSuggestions = false;
                                _toSuggestions = [];
                              });

                              LoggerService.log('COMPOSE', 'Auto-complete: Selected ${piiEmail(suggestion)}');
                            },
                          );
                        },
                      ),
                    ),
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Row(
                      children: [
                        Text(
                          l10n.infoRecipientCount(_getRecipientsList().length),
                          style: TextStyle(
                            fontSize: 11,
                            color: _getRecipientsList().length > maxRecipients ? Colors.red : Colors.grey,
                          ),
                        ),
                        if (_checkingTargetServer) ...[
                          const SizedBox(width: 12),
                          Text(
                            l10n.infoCheckingServer,
                            style: const TextStyle(fontSize: 11, color: Colors.grey),
                          ),
                        ],
                        if (!_checkingTargetServer && _targetServerMaxSizeMB != null) ...[
                          const SizedBox(width: 12),
                          Text(
                            l10n.infoServerMax(_targetServerMaxSizeMB!),
                            style: TextStyle(fontSize: 11, color: _targetServerMaxSizeMB! >= 25 ? Colors.green : Colors.orange),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),

            // CC field - Carbon Copy (visible to all)
            InfoLabel(
              label: l10n.labelCc,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l10n.infoCcTooltip,
                    style: const TextStyle(fontSize: 10, color: Colors.grey, fontStyle: FontStyle.italic),
                  ),
                  const SizedBox(height: 4),
                  TextBox(
                    controller: _ccController,
                    placeholder: l10n.placeholderRecipientsOptional,
                    enabled: !_isSending,
                    onChanged: (value) {
                      setState(() {});
                      _scheduleKeyLookup();
                    },
                  ),
                  if (_getCcList().isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        l10n.infoCcCount(_getCcList().length),
                        style: const TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(height: 12),

            // BCC field - Blind Carbon Copy (hidden from others)
            InfoLabel(
              label: l10n.labelBcc,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l10n.infoBccTooltip,
                    style: const TextStyle(fontSize: 10, color: Colors.grey, fontStyle: FontStyle.italic),
                  ),
                  const SizedBox(height: 4),
                  TextBox(
                    controller: _bccController,
                    placeholder: l10n.placeholderRecipientsOptional,
                    enabled: !_isSending,
                    onChanged: (value) {
                      setState(() {});
                      _scheduleKeyLookup();
                    },
                  ),
                  if (_getBccList().isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        l10n.infoBccCount(_getBccList().length),
                        style: const TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(height: 8),

            // Total recipients info
            Text(
              l10n.infoTotalRecipients(_getRecipientsList().length + _getCcList().length + _getBccList().length, maxRecipients),
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w500,
                color: (_getRecipientsList().length + _getCcList().length + _getBccList().length) > maxRecipients ? Colors.red : Colors.grey,
              ),
            ),
            const SizedBox(height: 12),

            // Password-protected email toggle (for external recipients)
            if (!_encryptionPossible && _getRecipientsList().isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    ToggleSwitch(
                      checked: _secureMailEnabled,
                      onChanged: (v) => setState(() => _secureMailEnabled = v),
                      content: const Text('Password-protected email'),
                    ),
                    if (_secureMailEnabled) ...[
                      const SizedBox(height: 8),
                      TextBox(
                        controller: _securePasswordController,
                        placeholder: 'Password for recipient',
                        obscureText: true,
                        enabled: !_isSending,
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          const Text('Expires in: ', style: TextStyle(fontSize: 12)),
                          ComboBox<int>(
                            value: _secureExpiryDays,
                            items: const [
                              ComboBoxItem(value: 1, child: Text('1 day')),
                              ComboBoxItem(value: 3, child: Text('3 days')),
                              ComboBoxItem(value: 7, child: Text('7 days')),
                              ComboBoxItem(value: 14, child: Text('14 days')),
                            ],
                            onChanged: (v) => setState(() => _secureExpiryDays = v ?? 7),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'The recipient will receive a link. Share the password separately (phone, Signal).',
                        style: TextStyle(fontSize: 11, color: FluentTheme.of(context).inactiveColor),
                      ),
                    ],
                  ],
                ),
              ),

            // Subject field
            InfoLabel(
              label: l10n.labelSubject,
              child: TextBox(
                controller: _subjectController,
                placeholder: l10n.placeholderSubject,
                enabled: !_isSending,
              ),
            ),
            const SizedBox(height: 12),

            // Body field
            InfoLabel(
              label: l10n.labelMessage,
              child: TextBox(
                controller: _bodyController,
                placeholder: l10n.placeholderMessage,
                maxLines: 10,
                minLines: 10,
                enabled: !_isSending,
              ),
            ),
            const SizedBox(height: 8),

            // Auto-save status
            if (_lastAutoSave != null)
              Text(
                l10n.infoLastAutoSaved(DateTime.now().difference(_lastAutoSave!).inSeconds),
                style: const TextStyle(fontSize: 11, color: Colors.grey),
              ),
            const SizedBox(height: 12),

            // Attachments section
            Wrap(
              spacing: 8,
              runSpacing: 8,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                FlyoutTarget(
                  controller: _attachFlyout,
                  child: FilledButton(
                    onPressed: _isSending ? null : () => _showAttachmentSourcePicker(context),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(FluentIcons.attach, size: 16),
                        const SizedBox(width: 8),
                        Text(l10n.buttonAddAttachments),
                        const SizedBox(width: 4),
                        const Icon(FluentIcons.chevron_down, size: 10),
                      ],
                    ),
                  ),
                ),
                if (_attachments.isNotEmpty)
                  Text(
                    l10n.infoAttachmentsCount(_attachments.length, maxAttachments, _totalAttachmentsSizeMB, maxTotalSizeMB),
                    style: const TextStyle(fontSize: 11, color: Colors.grey),
                  ),
              ],
            ),

            // Attachments list
            if (_attachments.isNotEmpty) ...[
              const SizedBox(height: 8),
              ...List.generate(_attachments.length, (index) {
                final att = _attachments[index];
                final file = att.file;
                final sizeMB = (file.size / (1024 * 1024)).toStringAsFixed(2);
                final isLoading = att.status == _AttachStatus.loading;
                final isFailed = att.status == _AttachStatus.failed;
                return Container(
                  margin: const EdgeInsets.only(bottom: 4),
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    border: Border.all(
                      color: isFailed
                          ? Colors.red
                          : isLoading
                              ? Colors.orange
                              : Colors.grey[60],
                    ),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Row(
                    children: [
                      // Thumbnail for images, icon for others
                      if (att.isImage && file.bytes != null)
                        ClipRRect(
                          borderRadius: BorderRadius.circular(4),
                          child: Image.memory(
                            file.bytes!,
                            width: 40,
                            height: 40,
                            fit: BoxFit.cover,
                            cacheWidth: 80,
                            errorBuilder: (_, __, ___) =>
                                Icon(_getFileIcon(file.extension ?? ''), size: 16),
                          ),
                        )
                      else
                        Icon(_getFileIcon(file.extension ?? ''), size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              '${file.name} ($sizeMB MB)',
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(fontSize: 12),
                            ),
                            if (isLoading)
                              const Padding(
                                padding: EdgeInsets.only(top: 4),
                                child: SizedBox(
                                  height: 2,
                                  child: ProgressBar(),
                                ),
                              ),
                            if (isFailed)
                              Text(
                                att.errorMessage ?? 'Failed',
                                style: const TextStyle(fontSize: 10, color: Colors.red),
                              ),
                          ],
                        ),
                      ),
                      // Status indicator
                      if (att.status == _AttachStatus.ready)
                        const Padding(
                          padding: EdgeInsets.only(right: 4),
                          child: Icon(FluentIcons.check_mark, size: 12, color: Color(0xFF107C10)),
                        ),
                      if (isLoading)
                        const Padding(
                          padding: EdgeInsets.only(right: 4),
                          child: SizedBox(
                            width: 12,
                            height: 12,
                            child: ProgressRing(strokeWidth: 2),
                          ),
                        ),
                      IconButton(
                        icon: const Icon(FluentIcons.cancel, size: 14),
                        onPressed: _isSending ? null : () => _removeAttachment(index),
                      ),
                    ],
                  ),
                );
              }),
            ],
          ],
        ),
      ),
      actions: [
        // Save Draft button
        Button(
          onPressed: _isSending ? null : _saveDraft,
          child: Text(l10n.buttonSaveDraft),
        ),

        // Cancel button
        Button(
          onPressed: _isSending ? null : () => Navigator.of(context).pop(),
          child: Text(l10n.buttonCancel),
        ),

        // Send button
        FilledButton(
          onPressed: _isSending ? null : _sendEmail,
          child: _isSending
              ? Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(
                      width: 16,
                      height: 16,
                      child: ProgressRing(strokeWidth: 2),
                    ),
                    const SizedBox(width: 8),
                    Flexible(child: Text(_sendingStatus, overflow: TextOverflow.ellipsis)),
                  ],
                )
              : Text(l10n.buttonSend),
        ),
      ],
    );
  }
}

