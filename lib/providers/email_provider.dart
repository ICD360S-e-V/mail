import 'package:fluent_ui/fluent_ui.dart';
import 'dart:async';
import '../models/models.dart';
import '../services/services.dart';
import '../services/device_registration_service.dart';
import '../utils/pii_redactor.dart';

/// Email provider for managing email accounts and messages
class EmailProvider with ChangeNotifier {
  final MailService _mailService = MailService();
  final ServerHealthService _healthService = ServerHealthService();
  final AccountService _accountService = AccountService();
  final PerformanceMonitor _performanceMonitor = PerformanceMonitor();
  final ConnectionMonitor _connectionMonitor = ConnectionMonitor();

  // State
  List<EmailAccount> _accounts = [];
  List<Email> _emails = [];
  final Map<String, Set<String>> _accountEmailIds = {}; // Track email IDs per account INBOX
  EmailAccount? _currentAccount;
  String _currentFolder = 'INBOX';
  bool _isLoading = false;
  bool _isFetching = false; // Guard against concurrent fetchEmails
  bool _isCheckingServer = false; // For auto-refresh indicator
  String? _error;
  ServerHealthStatus? _serverHealth;
  ConnectionStatus? _connectionStatus;
  String _performanceStats = 'CPU: 0% | RAM: 0 MB';
  bool _disposed = false;

  // Mail-admin device registration state
  /// Set to the username when the backend rejects with `device_limit_reached`.
  /// UI shows a blocking dialog when this is non-null.
  String? _deviceLimitReachedFor;
  /// Heartbeat timer for the active account.
  Timer? _heartbeatTimer;

  // Getters
  List<EmailAccount> get accounts => _accounts;
  List<Email> get emails => _emails;
  EmailAccount? get currentAccount => _currentAccount;
  String get currentFolder => _currentFolder;
  bool get isLoading => _isLoading || _isCheckingServer;
  String? get error => _error;
  ServerHealthStatus? get serverHealth => _serverHealth;
  ConnectionStatus? get connectionStatus => _connectionStatus;
  String get performanceStats => _performanceStats;
  String? get deviceLimitReachedFor => _deviceLimitReachedFor;
  void clearDeviceLimitFlag() {
    _deviceLimitReachedFor = null;
    if (!_disposed) notifyListeners();
  }

  /// Initialize provider - load accounts from secure storage
  Future<void> initialize() async {
    LoggerService.log('PROVIDER', 'Initializing email provider...');

    // Initialize trash tracker for 30-day auto-delete feature
    await TrashTrackerService.initialize();

    // Load accounts from AccountService (JSON + secure storage)
    _accounts = await _accountService.loadAccountsAsync();
    LoggerService.log('PROVIDER', 'Loaded ${_accounts.length} accounts from storage');

    if (_accounts.isNotEmpty) {
      _currentAccount = _accounts.first;
      LoggerService.log('PROVIDER', 'Current account set to: ${_currentAccount!.username}');

      // Load folders for all accounts
      // Download per-user certificate before each account (SECURITY: no hardcoded certs)
      for (final account in _accounts) {
        // Download UNIQUE certificate for this user
        LoggerService.log('PROVIDER', 'Downloading per-user certificate for ${account.username}...');
        final certSuccess = await CertificateService.downloadCertificateForUser(account.username, password: account.password ?? '');

        if (!certSuccess) {
          LoggerService.log('PROVIDER',
              '❌ Certificate download failed for ${account.username} - connection will fail');
          continue; // Skip loading folders if certificate download failed
        }

        LoggerService.log('PROVIDER', 'Loading folders for ${account.username}...');
        await _loadFoldersForAccount(account);
        LoggerService.log('PROVIDER', '✓ Account ${account.username} has ${account.folders.length} folders: ${account.folders.join(", ")}');
      }

      // Restore certificate for current account (last one loaded)
      if (_currentAccount != null) {
        await CertificateService.downloadCertificateForUser(_currentAccount!.username, password: _currentAccount!.password ?? '');
        LoggerService.log('PROVIDER', '✓ Certificate active for: ${_currentAccount!.username}');
      }

      // Initialize email IDs cache to prevent false "new email" notifications on first check
      LoggerService.log('PROVIDER', 'Initializing email IDs cache...');
      for (final account in _accounts) {
        if (account.connectionStatus == AccountConnectionStatus.connected) {
          try {
            final inboxEmails = await _mailService.fetchEmailsAsync(account, 'INBOX');
            final accountKey = '${account.username}_INBOX';
            _accountEmailIds[accountKey] = inboxEmails.map((e) => e.messageId).toSet();
            LoggerService.log('PROVIDER',
                '✓ Cached ${inboxEmails.length} email IDs for ${account.username} (prevents false notifications)');
          } catch (ex) {
            LoggerService.log('PROVIDER', '⚠️ Could not cache email IDs for ${account.username}');
          }
        }
      }
    }

    // Start background checks (don't wait - async, with error handling)
    checkServerHealth().catchError((e) => LoggerService.logError('HEALTH_BG', e, StackTrace.current));
    checkPortConnections().catchError((e) => LoggerService.logError('PORTS_BG', e, StackTrace.current));
    updatePerformanceStats();
    cleanTrashForAllAccounts().catchError((e) => LoggerService.logError('TRASH_BG', e, StackTrace.current));

    LoggerService.log('PROVIDER', '✓ Email provider initialized successfully (background checks started)');
    notifyListeners();
  }

  /// Check server health (SPF/DKIM/IP blacklists)
  Future<void> checkServerHealth() async {
    try {
      _serverHealth = await _healthService.checkHealthAsync();
      LoggerService.log('DIAGNOSTICS',
          'SPF=${_serverHealth!.spfStatus.status}, '
          'DKIM=${_serverHealth!.dkimStatus.status}, '
          'IPv4=${_serverHealth!.ipv4Status.status}, '
          'IPv6=${_serverHealth!.ipv6Status.status}');
      notifyListeners();
    } catch (ex, stackTrace) {
      LoggerService.logError('HEALTH', ex, stackTrace);
    }
  }

  /// Update performance stats (CPU/RAM) - async to avoid blocking UI
  Future<void> updatePerformanceStats() async {
    _performanceStats = await _performanceMonitor.getFormattedStats();
    if (!_disposed) notifyListeners();
  }

  /// Check port connections and log diagnostics for server-side analysis
  Future<void> checkPortConnections() async {
    // Always check mail.icd360s.de (hardcoded server)
    try {
      _connectionStatus = await _connectionMonitor.checkAllPortsAsync('mail.icd360s.de');

      // Log comprehensive diagnostics summary (sent to server for remote diagnosis)
      LoggerService.log('DIAGNOSTICS',
          'HTTPS:443=${_connectionStatus!.httpsStatus.status}, '
          'SMTP:465=${_connectionStatus!.smtpStatus.status}, '
          'IMAP:10993=${_connectionStatus!.imapStatus.status}');
      notifyListeners();
    } catch (ex, stackTrace) {
      LoggerService.logError('PORTS', ex, stackTrace);
    }
  }

  /// Add new account
  Future<void> addAccount(EmailAccount account) async {
    try {
      LoggerService.log('PROVIDER', 'Adding account: ${account.username}');
      await _accountService.addAccount(account);
      _accounts = _accountService.accounts;

      // Download per-user certificate BEFORE connecting (SECURITY: unique cert per user)
      LoggerService.log('PROVIDER', 'Downloading per-user certificate for ${account.username}...');
      final certSuccess = await CertificateService.downloadCertificateForUser(account.username, password: account.password ?? '');

      if (!certSuccess) {
        LoggerService.log('PROVIDER', '❌ Certificate download failed for ${account.username}');
        account.connectionStatus = AccountConnectionStatus.networkError;
        account.connectionError = 'Certificate download failed - check server connection';
        notifyListeners();
        return;
      }
      LoggerService.log('PROVIDER', '✓ Certificate downloaded for ${account.username}');

      // Load folders for the new account
      LoggerService.log('PROVIDER', 'Loading folders for new account...');
      await _loadFoldersForAccount(account);
      LoggerService.log('PROVIDER', '✓ Account added successfully with ${account.folders.length} folders');

      // Set as current account if it's the first one
      _currentAccount ??= account;

      notifyListeners();
    } catch (ex, stackTrace) {
      LoggerService.logError('PROVIDER', ex, stackTrace);
      _error = 'Failed to add account: ${ex.toString()}';
      notifyListeners();
      rethrow;
    }
  }

  /// Remove account
  Future<void> removeAccount(EmailAccount account) async {
    await _accountService.removeAccount(account);
    _accounts = _accountService.accounts;

    // Fix dangling _currentAccount reference
    if (_currentAccount?.username == account.username) {
      _currentAccount = _accounts.isNotEmpty ? _accounts.first : null;
      _emails = [];
      _currentFolder = 'INBOX';
    }

    notifyListeners();
  }

  /// Load folders for an account
  Future<void> _loadFoldersForAccount(EmailAccount account) async {
    try {
      LoggerService.log('PROVIDER', 'Calling MailService.getFoldersAsync for ${account.username}...');
      final folders = await _mailService.getFoldersAsync(account);
      LoggerService.log('PROVIDER', 'Received ${folders.length} folders from server: ${folders.join(", ")}');

      // Sort folders in logical order: INBOX, Sent, Drafts, Trash, Junk, Spam, Archive, others
      final sortedFolders = _sortFolders(folders);
      account.folders = sortedFolders;
      LoggerService.log('PROVIDER', 'Sorted folders: ${sortedFolders.join(", ")}');

      // Load inbox count
      final inboxCount = await _mailService.getFolderCountAsync(account, 'INBOX');
      account.inboxCount = inboxCount;
      LoggerService.log('PROVIDER', 'INBOX count: $inboxCount');

      // Load counts for other folders
      for (final folder in folders) {
        final count = await _mailService.getFolderCountAsync(account, folder);
        account.folderCounts[folder] = count;
        LoggerService.log('PROVIDER', 'Folder "$folder" count: $count');
      }

      // Fetch quota information
      try {
        final quotaData = await _mailService.getQuotaAsync(account);
        if (quotaData != null) {
          account.quotaUsedKB = quotaData['usedKB'] as int?;
          account.quotaLimitKB = quotaData['limitKB'] as int?;
          account.quotaPercentage = quotaData['percentage'] as double?;
          LoggerService.log('PROVIDER',
              '📊 Quota: ${quotaData['usedMB']} MB / ${quotaData['limitMB']} MB (${account.quotaPercentage?.toStringAsFixed(1)}%)');
        }
      } catch (quotaEx) {
        // Quota fetch failed - not critical, continue
        LoggerService.log('PROVIDER', '⚠️ Could not fetch quota for ${account.username}');
      }

      // Mark account as connected successfully
      account.connectionStatus = AccountConnectionStatus.connected;
      account.connectionError = null;
      LoggerService.log('PROVIDER', '✅ Account ${account.username} - CONNECTION OK (status: connected)');

      LoggerService.log('PROVIDER', '✓ Loaded ${folders.length} folders for ${account.username}');
      LoggerService.log('PROVIDER', 'Final account.folders: ${account.folders}');
      LoggerService.log('PROVIDER', 'Final account.folderCounts: ${account.folderCounts}');

      // Register device with mail-admin backend (1-device-per-account
      // enforcement, active session tracking, etc). Fire-and-forget —
      // backend errors are logged but never block the UI.
      _registerDeviceForAccount(account);
    } on AuthenticationException catch (authEx) {
      // Authentication failed - wrong username or password
      account.connectionStatus = AccountConnectionStatus.authError;
      account.connectionError = authEx.message;
      LoggerService.log('AUTH_ERROR', '❌ Account ${account.username} - AUTHENTICATION FAILED');
      if (authEx.isLikelyPasswordError) {
        LoggerService.log('AUTH_ERROR', '   → Likely cause: WRONG PASSWORD');
      } else if (authEx.isLikelyUsernameError) {
        LoggerService.log('AUTH_ERROR', '   → Likely cause: WRONG USERNAME');
      } else {
        LoggerService.log('AUTH_ERROR', '   → Likely cause: Wrong username or password');
      }
    } catch (ex, stackTrace) {
      // Other errors (network, etc.)
      account.connectionStatus = AccountConnectionStatus.networkError;
      account.connectionError = ex.toString();
      LoggerService.logError('PROVIDER_LOAD_FOLDERS', ex, stackTrace);
      LoggerService.log('CONNECTION_ERROR', '❌ Account ${account.username} - NETWORK/CONNECTION ERROR');
    }
  }

  /// Sort folders in logical order: INBOX first, then Sent, Drafts, etc.
  List<String> _sortFolders(List<String> folders) {
    final order = {
      'INBOX': 0,
      'Sent': 1,
      'Drafts': 2,
      'Trash': 3,
      'Junk': 4,
      'Spam': 5,
      'Archive': 6,
    };

    final sorted = List<String>.from(folders);
    sorted.sort((a, b) {
      final orderA = order[a] ?? 999;
      final orderB = order[b] ?? 999;
      if (orderA != orderB) {
        return orderA.compareTo(orderB);
      }
      return a.compareTo(b); // Alphabetical for unknown folders
    });

    return sorted;
  }

  // ── Mail-admin backend integration ──────────────────────────

  /// Track device registrations we've already done this session
  /// (per username) to avoid hammering the endpoint on every reconnect.
  final Set<String> _devicesRegisteredThisSession = {};

  /// Fire-and-forget device registration. Catches all errors so they
  /// never block the connection flow.
  Future<void> _registerDeviceForAccount(EmailAccount account) async {
    final username = account.username;
    final password = account.password;
    if (password == null || password.isEmpty) return;

    // Skip if we already registered in this session — heartbeat will
    // keep the last_seen fresh. We re-register on app restart.
    if (_devicesRegisteredThisSession.contains(username)) {
      // Just bump heartbeat
      unawaited(DeviceRegistrationService.sendHeartbeat(username: username));
      return;
    }

    try {
      final result = await DeviceRegistrationService.registerDevice(
        username: username,
        password: password,
      );

      if (result.success) {
        _devicesRegisteredThisSession.add(username);
        // Start heartbeat timer if not already running
        _ensureHeartbeatTimer();
      } else if (result.isDeviceLimitReached) {
        _deviceLimitReachedFor = username;
        if (!_disposed) notifyListeners();
        LoggerService.logWarning('PROVIDER',
            'Device limit reached for $username — UI should show '
            'restriction dialog');
      }
      // Other failures (network, unauthorized, etc.) are silent —
      // they don't affect mail delivery via IMAP/SMTP, which uses
      // its own credentials path.
    } catch (ex) {
      LoggerService.logWarning('PROVIDER',
          'Device registration error (non-fatal): $ex');
    }
  }

  /// Start the 5-minute heartbeat timer if not already running.
  void _ensureHeartbeatTimer() {
    if (_heartbeatTimer != null) return;
    _heartbeatTimer = Timer.periodic(const Duration(minutes: 5), (_) {
      if (_disposed) return;
      // Send heartbeat for every account that has been registered
      // this session.
      for (final username in _devicesRegisteredThisSession) {
        unawaited(DeviceRegistrationService.sendHeartbeat(username: username));
      }
    });
    LoggerService.log('PROVIDER',
        'Started device heartbeat timer (every 5 min)');
  }

  /// Select account and folder
  Future<void> selectFolder(EmailAccount account, String folder) async {
    LoggerService.log('UI', 'User selected: ${account.username}/$folder');
    _currentAccount = account;
    _currentFolder = folder;
    notifyListeners();

    await fetchEmails();
  }

  @override
  void dispose() {
    _disposed = true;
    _heartbeatTimer?.cancel();
    _heartbeatTimer = null;
    super.dispose();
  }

  /// Fetch emails for current account and folder
  Future<void> fetchEmails() async {
    if (_currentAccount == null || _isFetching) return;

    _isFetching = true;
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final account = _currentAccount;
      if (account == null) return;

      // Ensure certificate is loaded for current account
      final certSuccess = await CertificateService.downloadCertificateForUser(account.username, password: account.password ?? '');
      if (!certSuccess) {
        _error = 'Certificate download failed';
        _isLoading = false;
        notifyListeners();
        return;
      }

      // Re-check after async gap
      if (_currentAccount?.username != account.username) return;

      LoggerService.log('PROVIDER', 'Fetching emails from ${account.username}/$_currentFolder...');

      final newEmails = await _mailService.fetchEmailsAsync(
        account,
        _currentFolder,
      );

      // Detect new emails (only in INBOX folder to avoid spam)
      // Use per-account cache to avoid false notifications when switching accounts
      final accountKey = '${account.username}_INBOX';
      final previousIds = _accountEmailIds[accountKey] ?? <String>{};

      if (_currentFolder == 'INBOX' && previousIds.isNotEmpty) {
        for (final email in newEmails) {
          if (!previousIds.contains(email.messageId)) {
            // New email detected - show Windows Toast notification
            await NotificationService.showNewEmailToast(email);
            LoggerService.log('NEW_EMAIL', '🔔 New email from ${piiEmail(email.from)} ${piiSubject(email.subject)}');
          }
        }
      }

      // Update per-account email IDs cache
      if (_currentFolder == 'INBOX') {
        _accountEmailIds[accountKey] = newEmails.map((e) => e.messageId).toSet();
      }
      _emails = newEmails;

      // Update folder count in sidebar
      account.folderCounts[_currentFolder] = _emails.length;

      _error = null;
      LoggerService.log('PROVIDER', '✓ Fetched ${_emails.length} emails');
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
      _emails = [];
    } finally {
      _isLoading = false;
      _isFetching = false;
      if (!_disposed) notifyListeners();
    }
  }

  /// Check for new emails in INBOX (background check for all accounts)
  Future<void> checkForNewEmails() async {
    // Quick network check before iterating all accounts
    if (CertificateService.isNetworkDown) {
      final available = await CertificateService.isNetworkAvailable();
      if (!available) {
        LoggerService.log('AUTO_CHECK', '⚠️ Network down, skipping email check cycle');
        return;
      }
      LoggerService.log('AUTO_CHECK', '✓ Network recovered, resuming email checks');
    }

    // Create a copy of accounts list to avoid ConcurrentModificationError
    // (user might delete account while checking emails)
    final accountsCopy = List<EmailAccount>.from(_accounts);

    for (final account in accountsCopy) {
      try {
        // Skip accounts with connection errors
        if (account.connectionStatus == AccountConnectionStatus.authError ||
            account.connectionStatus == AccountConnectionStatus.networkError) {
          continue;
        }

        // If network went down during this cycle, stop immediately
        if (CertificateService.isNetworkDown) {
          LoggerService.log('AUTO_CHECK', '⚠️ Network lost during check cycle, stopping');
          break;
        }

        // Download certificate for this account before checking
        final certSuccess = await CertificateService.downloadCertificateForUser(account.username, password: account.password ?? '');
        if (!certSuccess) {
          LoggerService.log('AUTO_CHECK', '⚠️ Certificate download failed for ${account.username}, skipping');
          // If network is now flagged as down, stop entire cycle
          if (CertificateService.isNetworkDown) {
            LoggerService.log('AUTO_CHECK', '⚠️ Network down detected, aborting remaining accounts');
            break;
          }
          continue;
        }

        // Fetch emails from INBOX silently
        final newEmails = await _mailService.fetchEmailsAsync(account, 'INBOX');

        // Get previous email IDs for this account
        final accountKey = '${account.username}_INBOX';
        final previousIds = _accountEmailIds[accountKey] ?? <String>{};

        // Detect new emails
        for (final email in newEmails) {
          if (!previousIds.contains(email.messageId)) {
            // New email detected - show Windows Toast notification
            await NotificationService.showNewEmailToast(email);
            LoggerService.log('NEW_EMAIL', '🔔 New email in ${account.username}: ${email.subject}');
          }
        }

        // Update stored email IDs for this account
        _accountEmailIds[accountKey] = newEmails.map((e) => e.messageId).toSet();

        // Update folder count
        account.folderCounts['INBOX'] = newEmails.length;
      } catch (ex, stackTrace) {
        LoggerService.logError('AUTO_CHECK', ex, stackTrace);
        // Check if it's a network error - abort remaining accounts
        final errStr = ex.toString();
        if (errStr.contains('Failed host lookup') || errStr.contains('errno = 8') ||
            errStr.contains('Network is unreachable')) {
          LoggerService.log('AUTO_CHECK', '⚠️ Network error detected, aborting cycle');
          break;
        }
      }
    }

    // Batch UI update: notify once after all accounts processed (not per-account)
    notifyListeners();
  }

  /// Send email
  Future<void> sendEmail(String to, String subject, String body) async {
    if (_currentAccount == null) return;

    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      await _mailService.sendEmailAsync(_currentAccount!, to, subject, body);
      _error = null;
      LoggerService.log('PROVIDER', '✓ Email sent to ${piiEmail(to)}');
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
      rethrow;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Send email from specific account
  Future<void> sendEmailFromAccount(EmailAccount account, String to, String subject, String body) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      await _mailService.sendEmailAsync(account, to, subject, body);
      _error = null;
      LoggerService.log('PROVIDER', '✓ Email sent from ${piiEmail(account.username)} to ${piiEmail(to)}');
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
      rethrow;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Send email from specific account with attachments
  Future<void> sendEmailFromAccountWithAttachments(
    EmailAccount account,
    String to,
    String cc,
    String bcc,
    String subject,
    String body,
    List<dynamic> attachments, {
    int? draftUid,
  }) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      await _mailService.sendEmailWithAttachmentsAsync(
        account, to, cc, bcc, subject, body, attachments,
        draftUid: draftUid,
      );
      _error = null;
      LoggerService.log('PROVIDER', '✓ Email sent from ${piiEmail(account.username)} to:${to.split(',').length} cc:${cc.isEmpty ? 0 : cc.split(',').length} bcc:${bcc.isEmpty ? 0 : bcc.split(',').length} attachments:${attachments.length}');
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
      rethrow;
    } finally {
      _isLoading = false;
      notifyListeners();
    }

    // Refresh folder counts in background (don't block UI)
    _refreshFolderCounts(account).catchError((e) {
      LoggerService.logError('PROVIDER', e, StackTrace.current);
    });
  }

  /// Save draft (with optional attachments)
  /// Returns the UID of the saved draft for deduplication on next save
  Future<int?> saveDraft(String to, String cc, String bcc, String subject, String body, {List<dynamic> attachments = const [], int? previousDraftUid}) async {
    if (_currentAccount == null) return null;

    try {
      final uid = await _mailService.saveDraftAsync(_currentAccount!, to, cc, bcc, subject, body, attachments: attachments, previousDraftUid: previousDraftUid);
      LoggerService.log('PROVIDER', '✓ Draft saved${uid != null ? ' (UID $uid)' : ''}${attachments.isNotEmpty ? ' with ${attachments.length} attachment(s)' : ''}');
      return uid;
    } catch (ex, stackTrace) {
      LoggerService.logError('PROVIDER', ex, stackTrace);
      rethrow;
    }
  }

  /// Refresh folder counts for an account (single IMAP connection for all folders)
  Future<void> _refreshFolderCounts(EmailAccount account) async {
    if (account.folders.isEmpty) {
      LoggerService.log('PROVIDER', 'No folders to refresh for ${account.username}');
      return;
    }

    try {
      for (final folder in account.folders) {
        try {
          final count = await _mailService.getFolderCountAsync(account, folder);
          account.folderCounts[folder] = count;
        } catch (ex) {
          LoggerService.logWarning('PROVIDER', 'Could not refresh count for $folder: $ex');
        }
      }
      LoggerService.log('PROVIDER', 'Refreshed folder counts for ${account.username}: ${account.folderCounts}');
      notifyListeners();
    } catch (ex) {
      LoggerService.logWarning('PROVIDER', 'Could not refresh folder counts: $ex');
    }
  }

  /// Delete email (permanent delete if in Trash folder)
  Future<void> deleteEmail(Email email) async {
    if (_currentAccount == null) return;

    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      // If already in Trash, delete permanently
      if (_currentFolder.toLowerCase() == 'trash') {
        await _mailService.permanentDeleteEmailAsync(
          _currentAccount!,
          email.messageId,
          _currentFolder,
          uid: email.uid,
        );
        // Remove from trash tracker
        await TrashTrackerService.removeTracking(email.messageId);
        LoggerService.log('PROVIDER', '✓ Email PERMANENTLY deleted from Trash');
      } else {
        // Move to Trash
        await _mailService.deleteEmailAsync(
          _currentAccount!,
          email.messageId,
          _currentFolder,
          uid: email.uid,
        );
        // Track when email was moved to Trash (for 30-day auto-delete)
        await TrashTrackerService.recordMovedToTrash(email.messageId);
        LoggerService.log('PROVIDER', '✓ Email moved to Trash');
      }

      // Remove from local list
      _emails.removeWhere((e) => e.messageId == email.messageId);

      // Refresh all folder counts
      await _refreshFolderCounts(_currentAccount!);
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Move email to folder
  Future<void> moveEmail(Email email, String toFolder) async {
    if (_currentAccount == null) return;

    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      await _mailService.moveEmailAsync(
        _currentAccount!,
        email.messageId,
        _currentFolder,
        toFolder,
        uid: email.uid,
      );

      // Track trash movements for 30-day auto-delete feature
      if (toFolder.toLowerCase() == 'trash') {
        await TrashTrackerService.recordMovedToTrash(email.messageId);
      } else if (_currentFolder.toLowerCase() == 'trash') {
        // Email restored from Trash - remove tracking
        await TrashTrackerService.removeTracking(email.messageId);
      }

      // Remove from local list
      _emails.removeWhere((e) => e.messageId == email.messageId);

      _error = null;
      LoggerService.log('PROVIDER', '✓ Email moved to $toFolder ${piiSubject(email.subject)}');

      // Refresh all folder counts (source and destination folders affected)
      await _refreshFolderCounts(_currentAccount!);
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Mark email as spam
  Future<void> markAsSpam(Email email) async {
    if (_currentAccount == null) return;

    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      await _mailService.markAsSpamAsync(
        _currentAccount!,
        email.messageId,
        _currentFolder,
      );

      // Remove from local list
      _emails.removeWhere((e) => e.messageId == email.messageId);

      _error = null;
      LoggerService.log('PROVIDER', '✓ Email marked as spam: ${email.subject}');

      // Refresh all folder counts (current folder and Spam folder affected)
      await _refreshFolderCounts(_currentAccount!);
    } catch (ex, stackTrace) {
      _error = ex.toString();
      LoggerService.logError('PROVIDER', ex, stackTrace);
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Send read receipt
  Future<void> sendReadReceipt(Email email) async {
    if (_currentAccount == null) return;

    try {
      final receiptTo = email.headers['Disposition-Notification-To'] ??
          email.headers['Return-Receipt-To'];

      if (receiptTo != null && receiptTo.isNotEmpty) {
        await _mailService.sendReadReceiptAsync(
          _currentAccount!,
          email,
          receiptTo,
        );
        LoggerService.log('PROVIDER', '✓ Read receipt sent for: ${email.subject}');
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('PROVIDER', ex, stackTrace);
    }
  }

  /// Refresh current folder
  Future<void> refresh() async {
    LoggerService.log('UI', 'User requested manual refresh');
    await fetchEmails();
  }

  /// Get folder count for an account (for auto-check timer)
  Future<int> getFolderCountAsync(EmailAccount account, String folder) async {
    try {
      // Set checking flag for Row 0 indicator
      _isCheckingServer = true;
      notifyListeners();

      final count = await _mailService.getFolderCountAsync(account, folder);

      _isCheckingServer = false;
      notifyListeners();

      return count;
    } catch (ex, stackTrace) {
      LoggerService.logError('PROVIDER', ex, stackTrace);
      _isCheckingServer = false;
      notifyListeners();
      return 0;
    }
  }

  /// Clear error
  void clearError() {
    _error = null;
    notifyListeners();
  }

  /// Check target server max message size (for attachments)
  Future<int?> checkTargetServerSize(String domain) async {
    try {
      return await _mailService.checkTargetServerMaxSize(domain);
    } catch (ex, stackTrace) {
      LoggerService.logError('PROVIDER', ex, stackTrace);
      return null;
    }
  }

  /// Clean Trash folder for all accounts - delete emails older than 30 days
  /// This runs automatically at startup and can be called manually
  Future<void> cleanTrashForAllAccounts({int olderThanDays = 30}) async {
    LoggerService.log('TRASH_CLEANUP', 'Starting automatic trash cleanup (older than $olderThanDays days)');

    int totalDeleted = 0;

    for (final account in _accounts) {
      // Skip accounts with connection errors
      if (account.connectionStatus == AccountConnectionStatus.authError ||
          account.connectionStatus == AccountConnectionStatus.networkError) {
        LoggerService.log('TRASH_CLEANUP', 'Skipping ${account.username} - connection error');
        continue;
      }

      try {
        final deleted = await _mailService.cleanTrashAsync(account, olderThanDays: olderThanDays);
        totalDeleted += deleted;
        if (deleted > 0) {
          LoggerService.log('TRASH_CLEANUP', '${account.username}: deleted $deleted old emails');
        }
      } catch (ex) {
        LoggerService.logWarning('TRASH_CLEANUP', 'Error cleaning trash for ${account.username}: $ex');
      }
    }

    if (totalDeleted > 0) {
      LoggerService.log('TRASH_CLEANUP', '✓ Total: permanently deleted $totalDeleted old emails from Trash');
      // Refresh if we're viewing Trash folder
      if (_currentFolder.toLowerCase() == 'trash') {
        await fetchEmails();
      }
    } else {
      LoggerService.log('TRASH_CLEANUP', '✓ No old emails to clean in Trash folders');
    }
  }
}
