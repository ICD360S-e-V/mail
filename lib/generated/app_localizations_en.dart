// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get dialogTitleAddAccount => 'Add Email Account';

  @override
  String get dialogTitleCompose => 'Compose Email';

  @override
  String get labelEmailAddress => 'Email Address:';

  @override
  String get placeholderUsername => 'username';

  @override
  String get labelPassword => 'Password:';

  @override
  String get placeholderPassword => 'Enter password...';

  @override
  String get labelMailServer => 'Mail Server (locked):';

  @override
  String get labelImapPort => 'IMAP Port (locked):';

  @override
  String get labelSmtpPort => 'SMTP Port (locked):';

  @override
  String get labelFromAccount => 'From Account:';

  @override
  String get labelTo => 'To (Primary Recipients):';

  @override
  String get labelCc => 'CC (Carbon Copy):';

  @override
  String get labelBcc => 'BCC (Blind Carbon Copy - Hidden):';

  @override
  String get labelSubject => 'Subject:';

  @override
  String get labelMessage => 'Message:';

  @override
  String get placeholderSelectAccount => 'Select account...';

  @override
  String get placeholderRecipients => 'email1@example.com, email2@example.com';

  @override
  String get placeholderRecipientsOptional =>
      'Optional: email1@example.com, email2@example.com';

  @override
  String get placeholderSubject => 'Enter subject...';

  @override
  String get placeholderMessage => 'Type your message here...';

  @override
  String get infoSslEnabled =>
      'SSL/TLS Encryption: ENABLED (locked for security)';

  @override
  String get infoTooltip =>
      'Primary recipients of the email - everyone will see this address';

  @override
  String get infoCcTooltip =>
      'Receive a copy and ALL recipients see who is in CC';

  @override
  String get infoBccTooltip =>
      'Receive a copy but NOBODY sees they received it (hidden)';

  @override
  String infoRecipientCount(int count) {
    return '$count recipient(s)';
  }

  @override
  String infoCcCount(int count) {
    return '$count CC recipient(s)';
  }

  @override
  String infoBccCount(int count) {
    return '$count BCC recipient(s) (hidden)';
  }

  @override
  String infoTotalRecipients(int total, int max) {
    return 'Total: $total/$max recipients (TO + CC + BCC)';
  }

  @override
  String get infoCheckingServer => 'Checking server...';

  @override
  String infoServerMax(int size) {
    return 'Server max: $size MB';
  }

  @override
  String infoLastAutoSaved(int seconds) {
    return 'Last auto-saved: $seconds seconds ago';
  }

  @override
  String infoAttachmentsCount(int count, int max, int used, int total) {
    return '$count/$max files ($used/$total MB)';
  }

  @override
  String get buttonAddAccount => 'Add Account';

  @override
  String get buttonAddAttachments => 'Add Attachments';

  @override
  String get buttonScanDocument => 'Scan Document';

  @override
  String get buttonSaveDraft => 'Save Draft';

  @override
  String get buttonCancel => 'Cancel';

  @override
  String get buttonSend => 'Send';

  @override
  String get buttonSending => 'Sending...';

  @override
  String get buttonClose => 'Close';

  @override
  String get errorTitle => 'Error';

  @override
  String get errorTooManyFiles => 'Too Many Files';

  @override
  String errorTooManyFilesMessage(int max) {
    return 'Maximum $max attachments allowed';
  }

  @override
  String get errorFilesTooLarge => 'Files Too Large';

  @override
  String errorFilesTooLargeMessage(int max, int current) {
    return 'Total attachment size must be under $max MB (currently ${current}MB)';
  }

  @override
  String get errorFailedToPickFiles => 'Failed to pick files';

  @override
  String get errorScanFailed => 'Failed to scan document';

  @override
  String get errorPleaseSelectAccount => 'Please select an account';

  @override
  String get errorAtLeastOneRecipient =>
      'At least one recipient email is required';

  @override
  String errorMaxRecipientsExceeded(int max) {
    return 'Maximum $max recipients allowed';
  }

  @override
  String get errorInvalidEmail => 'Invalid Email';

  @override
  String errorInvalidEmailFormat(String email) {
    return 'Invalid email format: $email';
  }

  @override
  String get errorInvalidCcEmail => 'Invalid CC Email';

  @override
  String errorInvalidCcEmailFormat(String email) {
    return 'Invalid CC email format: $email';
  }

  @override
  String get errorInvalidBccEmail => 'Invalid BCC Email';

  @override
  String errorInvalidBccEmailFormat(String email) {
    return 'Invalid BCC email format: $email';
  }

  @override
  String errorTotalRecipientsExceeded(int max) {
    return 'Total recipients (TO + CC + BCC) cannot exceed $max';
  }

  @override
  String get errorSendFailed => 'Send Failed';

  @override
  String get errorDraft => 'Draft Error';

  @override
  String get successTitle => 'Success';

  @override
  String successEmailSentMultiple(int count) {
    return 'Email sent to $count recipients!';
  }

  @override
  String get successEmailSent => 'Email sent successfully!';

  @override
  String get successDraftTitle => 'Draft';

  @override
  String get successDraftSaved => 'Draft saved successfully';

  @override
  String get appTitle => 'ICD360S Mail Client';

  @override
  String appVersion(String version) {
    return 'v$version';
  }

  @override
  String get labelToRecipients => 'To (Primary Recipients):';

  @override
  String get labelCcFull => 'CC (Carbon Copy):';

  @override
  String get labelBccFull => 'BCC (Blind Carbon Copy - Hidden):';

  @override
  String get infoTooltipRecipients =>
      'Primary recipients of the email - everyone will see this address';

  @override
  String get infoCcTooltipFull =>
      'Receive a copy and ALL recipients see who is in CC';

  @override
  String get infoBccTooltipFull =>
      'Receive a copy but NOBODY sees they received it (hidden)';

  @override
  String infoRecipientsSimple(int count) {
    return '$count recipient(s)';
  }

  @override
  String infoCcSimple(int count) {
    return '$count CC recipient(s)';
  }

  @override
  String infoBccSimple(int count) {
    return '$count BCC recipient(s) (hidden)';
  }

  @override
  String infoTotalDestinatari(int total, int max) {
    return 'Total: $total/$max recipients (TO + CC + BCC)';
  }

  @override
  String get infoLoadingHtml => 'Loading HTML email...';

  @override
  String get labelFrom => 'From:';

  @override
  String get labelDate => 'Date:';

  @override
  String get labelThreat => 'Threat:';

  @override
  String infoAttachmentsTitle(int count) {
    return 'Attachments ($count)';
  }

  @override
  String get infoForwardedMessage => '---------- Forwarded message ---------';

  @override
  String get buttonReply => 'Reply';

  @override
  String get buttonForward => 'Forward';

  @override
  String get buttonDelete => 'Delete';

  @override
  String get buttonPrint => 'Print';

  @override
  String get buttonCopy => 'Copy';

  @override
  String get buttonSpam => 'Mark as Spam';

  @override
  String get successDeleted => 'Deleted';

  @override
  String get successEmailMovedToTrash => 'Email moved to Trash';

  @override
  String get successSpam => 'Spam';

  @override
  String get successEmailMarkedAsSpam => 'Email marked as spam';

  @override
  String get successPrint => 'Print';

  @override
  String get successPrintDialogOpened => 'Print dialog opened';

  @override
  String get successCopied => 'Copied';

  @override
  String get successEmailCopiedToClipboard =>
      'Email content copied to clipboard';

  @override
  String get successDownloaded => 'Downloaded';

  @override
  String successSavedTo(String path) {
    return 'Saved to: $path';
  }

  @override
  String get errorPrint => 'Print Error';

  @override
  String get errorCopy => 'Copy Error';

  @override
  String get errorView => 'View Error';

  @override
  String get errorDownload => 'Download Error';

  @override
  String get mainWindowTitle => 'ICD360S Mail Client';

  @override
  String get mainWindowComposeButton => 'Compose Email';

  @override
  String get mainWindowAccountsHeader => '📬 Accounts';

  @override
  String get mainWindowAddAccount => 'Add Account';

  @override
  String get mainWindowFolderInbox => 'Inbox';

  @override
  String get mainWindowFolderSent => 'Sent';

  @override
  String get mainWindowFolderDrafts => 'Drafts';

  @override
  String get mainWindowFolderTrash => 'Trash';

  @override
  String get mainWindowFolderJunk => 'Junk';

  @override
  String get mainWindowSwitchAccount => 'Switch Account';

  @override
  String get mainWindowInboxMessages => 'messages in Inbox';

  @override
  String get mainWindowStatusConnected => 'Connected';

  @override
  String mainWindowStatusAuthError(String error) {
    return 'Authentication failed: $error';
  }

  @override
  String mainWindowStatusNetworkError(String error) {
    return 'Connection error: $error';
  }

  @override
  String get mainWindowStatusChecking => 'Checking connection...';

  @override
  String mainWindowTooltipQuota(String used, String limit, String percentage) {
    return 'Storage: $used MB / $limit MB ($percentage%)';
  }

  @override
  String get mainWindowDialogDeleteAccountTitle => 'Delete Account';

  @override
  String mainWindowDialogDeleteAccountMessage(String username) {
    return 'Remove $username from the app?\n\nThis will ONLY remove it from the app, NOT from the server.';
  }

  @override
  String get mainWindowButtonDeleteFromApp => 'Delete from App';

  @override
  String mainWindowEmailsCount(int count) {
    return '$count emails';
  }

  @override
  String mainWindowNoEmails(String folder) {
    return 'No emails in $folder';
  }

  @override
  String mainWindowTooltipAutoDelete(int days) {
    return 'Se va șterge automat în $days zile';
  }

  @override
  String get mainWindowTooltipAutoDeleteToday =>
      'Se va șterge la următoarea pornire';

  @override
  String mainWindowBadgeDaysShort(int days) {
    return '🗑️ ${days}z';
  }

  @override
  String get mainWindowBadgeToday => '⚠️ Azi';

  @override
  String get mainWindowStatusReady => 'Ready - All systems operational';

  @override
  String mainWindowStatusCheckingEmails(String account) {
    return 'Checking for new emails from server ($account)...';
  }

  @override
  String mainWindowStatusError(String error) {
    return 'Error: $error';
  }

  @override
  String mainWindowFooterCopyright(int year) {
    return '© 2025-$year ICD360S e.V. | All Rights Reserved';
  }

  @override
  String mainWindowVersion(String version) {
    return 'v$version';
  }

  @override
  String get mainWindowLegalImpressum => 'Impressum';

  @override
  String get mainWindowLegalPrivacy => 'Datenschutz';

  @override
  String get mainWindowLegalWithdrawal => 'Widerrufsrecht';

  @override
  String get mainWindowLegalCancellation => 'Kündigung';

  @override
  String get mainWindowLegalConstitution => 'Satzung';

  @override
  String get mainWindowDialogLockedTitle => 'Application Locked';

  @override
  String get mainWindowDialogLockedEnterPassword =>
      'Enter your master password to unlock:';

  @override
  String get mainWindowPlaceholderMasterPassword => 'Master Password';

  @override
  String get mainWindowButtonUnlock => 'Unlock';

  @override
  String get mainWindowLockedTitle => 'Application Locked';

  @override
  String get mainWindowLockedSubtitle =>
      'Auto-locked after 15 minutes of inactivity';

  @override
  String get mainWindowLockedNotification =>
      'Windows notifications continue to work in background';

  @override
  String get mainWindowNotificationUpdateAvailable => 'Actualizare disponibilă';

  @override
  String mainWindowNotificationDownloading(String version) {
    return 'Se descarcă v$version...';
  }

  @override
  String get mainWindowNotificationUpdateInProgress => 'Actualizare în curs';

  @override
  String mainWindowUnreadCount(int count) {
    return '$count unread';
  }

  @override
  String get masterPasswordDialogTitle => 'Master Password';

  @override
  String get masterPasswordDialogAppTitle => 'Client Mail';

  @override
  String get masterPasswordDialogFirstTimeMessage =>
      'This is your first time using ICD360S Mail Client.\nPlease set a master password to protect your email accounts.';

  @override
  String get masterPasswordDialogLoginMessage =>
      'Enter your master password to access email accounts.';

  @override
  String get masterPasswordLabelPassword => 'Password:';

  @override
  String get masterPasswordPlaceholderPassword => 'Enter master password...';

  @override
  String get masterPasswordLabelConfirm => 'Confirm Password:';

  @override
  String get masterPasswordPlaceholderConfirm => 'Confirm password...';

  @override
  String get masterPasswordErrorEmpty => 'Password cannot be empty';

  @override
  String get masterPasswordErrorMismatch => 'Passwords do not match';

  @override
  String get masterPasswordErrorIncorrect => 'Incorrect password';

  @override
  String masterPasswordErrorGeneric(String error) {
    return 'Error: $error';
  }

  @override
  String masterPasswordErrorFailedToSet(String error) {
    return 'Failed to set password: $error';
  }

  @override
  String get masterPasswordButtonResetApp => 'Reset App';

  @override
  String get masterPasswordButtonExitApp => 'Exit App';

  @override
  String get masterPasswordButtonSetPassword => 'Set Password';

  @override
  String get masterPasswordButtonUnlock => 'Unlock';

  @override
  String get masterPasswordButtonVerifying => 'Verifying...';

  @override
  String get masterPasswordDialogResetTitle => 'Reset Application';

  @override
  String get masterPasswordDialogResetMessage =>
      'This will DELETE ALL data:\n\n• Master password\n• All email accounts\n• All saved passwords\n• All settings\n\nThe app will restart as NEW.\n\nAre you sure?';

  @override
  String get masterPasswordLegalImpressum => 'Impressum';

  @override
  String get masterPasswordLegalPrivacy => 'Datenschutz';

  @override
  String get masterPasswordLegalWithdrawal => 'Widerrufsrecht';

  @override
  String get masterPasswordLegalCancellation => 'Kündigung';

  @override
  String get masterPasswordLegalConstitution => 'Satzung';

  @override
  String masterPasswordFooterCopyright(int year) {
    return '© 2025-$year ICD360S e.V. | Alle Rechte vorbehalten';
  }

  @override
  String get firstRunAppTitle => 'Mail Client';

  @override
  String get firstRunAppVersion => 'v2.6.0';

  @override
  String get firstRunWelcomeTitle => 'Welcome to ICD360S Mail Client!';

  @override
  String get firstRunWelcomeMessage =>
      'Before you start, please configure your preferences:';

  @override
  String get firstRunSectionAutoUpdate => 'Automatic Updates';

  @override
  String get firstRunAutoUpdateDescription =>
      'The app will automatically check for new updates on mail.icd360s.de and notify you when a new version is available.';

  @override
  String get firstRunCheckboxAutoUpdate =>
      'Enable automatic updates (recommended)';

  @override
  String get firstRunSectionLogging => 'Diagnostic & Logging';

  @override
  String get firstRunLoggingDescription =>
      'Send diagnostic logs to the server to help us identify and resolve issues. Logs contain information about errors and usage, but DO NOT contain passwords or email content.';

  @override
  String get firstRunCheckboxLogging =>
      'Enable diagnostic logging (helps improve the app)';

  @override
  String get firstRunSectionNotifications => 'Windows Notifications';

  @override
  String get firstRunNotificationsDescription =>
      'Receive Windows Toast notifications when new emails arrive in INBOX. Notifications appear in Action Center and include the sender and subject of the email.';

  @override
  String get firstRunCheckboxNotifications =>
      'Enable notifications for new emails (recommended)';

  @override
  String get firstRunPrivacyTitle => 'Privacy';

  @override
  String get firstRunPrivacyMessage =>
      'Your data is protected. Logs are sent securely via HTTPS and never contain passwords or personal content.';

  @override
  String firstRunFooterCopyright(int year) {
    return '© 2025-$year ICD360S e.V. | All Rights Reserved';
  }

  @override
  String get firstRunButtonContinue => 'Continue';

  @override
  String get changelogDialogTitle => 'Changelog - ICD360S Mail Client';

  @override
  String get changelogButtonClose => 'Close';

  @override
  String get logViewerDialogTitle => 'Log Viewer';

  @override
  String get logViewerButtonClearLogs => 'Clear Logs';

  @override
  String get logViewerButtonCopyAll => 'Copy All';

  @override
  String get logViewerButtonClose => 'Close';

  @override
  String logViewerLogsCopied(int count) {
    return 'Logs copied to clipboard ($count entries)';
  }

  @override
  String get logViewerMetadataHeader => '=== ICD360S Mail Client Logs ===';

  @override
  String logViewerMetadataVersion(String version) {
    return 'Version: $version';
  }

  @override
  String logViewerMetadataPlatform(String platform, String version) {
    return 'Platform: $platform $version';
  }

  @override
  String logViewerMetadataTimestamp(String timestamp) {
    return 'Timestamp: $timestamp';
  }

  @override
  String logViewerMetadataTotalEntries(int count) {
    return 'Total Entries: $count';
  }

  @override
  String get logViewerMetadataSeparator =>
      '===================================';

  @override
  String get authWrapperLoading => 'Loading...';

  @override
  String get authWrapperAuthRequired => 'Authentication Required';

  @override
  String get authWrapperButtonExit => 'Exit Application';

  @override
  String get attachmentViewerButtonDownload => 'Download';

  @override
  String get attachmentViewerButtonPrint => 'Print';

  @override
  String get attachmentViewerButtonClose => 'Close';

  @override
  String get attachmentViewerLoadingPdf => 'Loading PDF...';

  @override
  String get attachmentViewerUnsupportedType => 'Unsupported file type';

  @override
  String get attachmentViewerSuccessDownloaded => 'Downloaded';

  @override
  String attachmentViewerSuccessSavedTo(String path) {
    return 'Saved to: $path';
  }

  @override
  String get attachmentViewerErrorDownload => 'Download Error';

  @override
  String get attachmentViewerSuccessPrint => 'Print';

  @override
  String get attachmentViewerSuccessPrintDialogOpened => 'Print dialog opened';

  @override
  String get attachmentViewerErrorPrint => 'Print Error';

  @override
  String blacklistDetailsTitle(String ipType) {
    return '$ipType Blacklist Check Results';
  }

  @override
  String get blacklistDetailsLabelStatus => 'Status:';

  @override
  String get blacklistDetailsLabelIpAddress => 'IP Address:';

  @override
  String get blacklistDetailsResultsTitle => 'Blacklist Check Results:';

  @override
  String get blacklistDetailsNoCheck => 'No blacklist check performed yet.';

  @override
  String blacklistDetailsProvidersTitle(int count) {
    return 'Checked Providers ($count):';
  }

  @override
  String get blacklistDetailsExplanation =>
      'DNS blacklist (DNSBL) checks verify if your mail server IP is listed as a spam source. Clean status ensures email deliverability.';

  @override
  String get blacklistDetailsButtonRefresh => 'Refresh Check';

  @override
  String get blacklistDetailsNotificationRefresh => 'Refresh';

  @override
  String get blacklistDetailsNotificationRefreshMessage =>
      'Re-checking blacklists...';

  @override
  String dnsDetailsTitle(String recordType) {
    return '$recordType Record Details';
  }

  @override
  String get dnsDetailsLabelStatus => 'Status:';

  @override
  String get dnsDetailsLabelRecordType => 'Record Type:';

  @override
  String get dnsDetailsLabelDomain => 'Domain:';

  @override
  String get dnsDetailsNoRecord =>
      'No DNS record found or check not implemented yet.';

  @override
  String get dnsDetailsExplanationSpf =>
      'SPF (Sender Policy Framework) validates that emails from your domain are sent from authorized servers. This prevents email spoofing.';

  @override
  String get dnsDetailsExplanationDkim =>
      'DKIM (DomainKeys Identified Mail) adds a digital signature to your emails to verify they haven\'t been tampered with in transit.';

  @override
  String get webBrowserDefaultTitle => 'Browser';

  @override
  String get webBrowserButtonClose => 'Close';

  @override
  String get updateDownloadingUpdate => 'Downloading update v';

  @override
  String get updateDownloadingProgress => 'Downloading: ';

  @override
  String get updateInstalling =>
      'Installing update... App will restart automatically.';

  @override
  String updateError(String error) {
    return 'Update error: $error';
  }

  @override
  String mailServiceSecurityViolationServer(
      String server, String allowedServer) {
    return 'SECURITY VIOLATION: Connection to $server is blocked. This client only connects to $allowedServer.';
  }

  @override
  String mailServiceSecurityViolationPorts(int imapPort, int smtpPort) {
    return 'SECURITY VIOLATION: Only standard ports are allowed (IMAP:$imapPort, SMTP:$smtpPort).';
  }

  @override
  String mailServiceAuthenticationFailed(String username) {
    return 'Authentication failed for $username: Wrong username or password';
  }

  @override
  String get mailServiceAtLeastOneRecipient =>
      'At least one recipient is required';

  @override
  String mailServiceMessageTooLarge(int messageSizeKB, int maxSizeKB) {
    return 'Message too large: $messageSizeKB KB (server max: $maxSizeKB KB)';
  }

  @override
  String get mailServiceEmailCorrupt =>
      'Email MessageId is missing. This email may be corrupt and cannot be moved.';

  @override
  String mailServiceEmailNotFound(String folder) {
    return 'Email not found in $folder. It may have been already moved or deleted.';
  }

  @override
  String accountServiceSecurityErrorServer(String allowedServer) {
    return 'Security Error: Only $allowedServer server is allowed. This client is locked to ICD360S mail server.';
  }

  @override
  String get accountServiceSecurityErrorPorts =>
      'Security Error: Only secure ports (IMAP:10993, SMTP:465) are allowed for mTLS.';

  @override
  String notificationNewEmailFrom(String from) {
    return 'New Email from $from';
  }

  @override
  String notificationEmailSubjectThreat(String subject, String threat) {
    return '$subject\nThreat: $threat';
  }

  @override
  String get certExpiryStatusUnknown => 'Certificate status unknown';

  @override
  String get certExpiryExpired =>
      'Certificate EXPIRED - Please re-login to renew';

  @override
  String certExpiryExpiresSoon(int days) {
    return 'Certificate expires in $days days - Re-login recommended';
  }

  @override
  String certExpiryValid(int days) {
    return 'Certificate valid for $days+ days';
  }
}
