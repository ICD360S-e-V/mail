import 'package:fluent_ui/fluent_ui.dart';
import 'dart:async';
import '../models/models.dart';
import '../services/services.dart';
import '../services/device_registration_service.dart';
import '../services/pgp_key_service.dart';
import '../services/pin_unlock_service.dart';
import '../services/master_vault.dart';
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

  // ── RAM-only session cache ────────────────────────────────────────
  //
  // SECURITY: Emails are NEVER written to disk. This cache exists only
  // in process memory and is wiped on lock/background/close. No forensic
  // artifact remains on the device after the app closes.
  //
  // Key: "account::folder" → LRU list of emails (most recent first).
  // Max entries per folder: _maxCachePerFolder.
  // Total memory cap: ~50 folders × 50 emails × ~5KB avg = ~12.5 MB.
  static const _maxCachePerFolder = 50;
  final Map<String, List<Email>> _sessionCache = {};

  /// Wipe all cached emails from RAM. Called on lock, background, close.
  void wipeSessionCache() {
    // Zero body strings (best-effort — Dart strings are immutable,
    // but reassigning removes our reference for GC collection).
    for (final emails in _sessionCache.values) {
      for (final email in emails) {
        email.body = '';
        email.threatDetails = '';
        for (final a in email.attachments) {
          a.data = null;
        }
      }
    }
    _sessionCache.clear();
    _emails = [];
    LoggerService.log('CACHE', 'Session cache wiped from RAM');
  }
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
        final certSuccess = await _ensureCertForAccount(account);

        // Initialize PGP key in background — don't block email loading
        unawaited(PgpKeyService.getOrCreatePrivateKey(account.username).catchError(
          (ex) => LoggerService.logWarning('PROVIDER', 'PGP key init failed: $ex'),
        ));

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
        await _ensureCertForAccount(_currentAccount!);
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

  /// Acquire the per-user mTLS certificate for [account]. Returns true
  /// when the cert is loaded into [CertificateService]'s in-memory cache.
  ///
  /// Two paths (added v2.28.2 to fix Faza 3 add-account flow):
  ///
  /// - **Legacy** — `account.password` is non-null/non-empty.
  ///   Calls `CertificateService.downloadCertificateForUser(...)` against
  ///   `/api/get-certificate.php` which authenticates by raw IMAP LOGIN.
  ///   Used by all accounts created with v2.26.x or earlier and any
  ///   account where the user explicitly set a password.
  ///
  /// - **Cert-only** — `account.password` is null/empty (Faza 3 flow,
  ///   v2.27.0+ add-account dialog never asks for a password). The cert
  ///   was already downloaded by [DeviceApprovalService] via the
  ///   one-time-token endpoint and persisted to PortableSecureStorage.
  ///   Calling the legacy `/api/get-certificate.php` here would 401 with
  ///   "Authentication required" (the bug observed in v2.28.0). Instead
  ///   we just call [CertificateService.restoreFromSecureStorage] which
  ///   loads the previously-persisted cert into the in-memory cache.
  ///   Verifies the loaded cert's CN matches the requested account.
  Future<bool> _ensureCertForAccount(EmailAccount account) async {
    final pwd = account.password;
    if (pwd != null && pwd.isNotEmpty) {
      // LEGACY path
      LoggerService.log('PROVIDER',
          'Downloading per-user certificate for ${account.username}...');
      return CertificateService.downloadCertificateForUser(
          account.username, password: pwd);
    }
    // FAZA 3 path: cert was stored by DeviceApprovalService.storeBundle()
    // before this account was added. Restore from secure storage instead
    // of re-downloading via password.
    //
    // v2.30.2: per-username keys — call restoreFromSecureStorageFor so
    // each account loads its OWN cert. The previous global-key layout
    // overwrote the first account's cert when a second account was
    // added (the in-memory cache was correct after add but the next
    // restore-after-unlock loaded whichever username was last written).
    LoggerService.log('PROVIDER',
        'Account ${account.username} has no password (Faza 3 cert-only) — '
        'restoring cert from secure storage');
    final restored =
        await CertificateService.restoreFromSecureStorageFor(account.username);
    if (!restored) {
      LoggerService.logWarning('PROVIDER',
          'Cert-only account ${account.username} but secure storage is empty');
      return false;
    }
    LoggerService.log('PROVIDER',
        '✓ Cert for ${account.username} restored from secure storage');
    return true;
  }

  /// Add new account
  Future<void> addAccount(EmailAccount account) async {
    try {
      LoggerService.log('PROVIDER', 'Adding account: ${account.username}');
      await _accountService.addAccount(account);
      _accounts = _accountService.accounts;

      // Download per-user certificate BEFORE connecting (SECURITY: unique cert per user)
      LoggerService.log('PROVIDER', 'Downloading per-user certificate for ${account.username}...');
      final certSuccess = await _ensureCertForAccount(account);

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

      // Load counts for other folders.
      //
      // v2.30.7: per-folder try/catch. Some servers (Dovecot in
      // particular) advertise folders in LIST that cannot actually
      // be SELECT-ed — common with phantom \NoSelect placeholders,
      // legacy Spam folders that were renamed to Junk but left in
      // the subscription list, or shared/virtual mailboxes that
      // disappear under the per-user namespace. Without this catch,
      // a SINGLE bogus folder would propagate up to the outer
      // catch block and mark the entire account as networkError —
      // even though INBOX and every real folder worked fine.
      //
      // Strategy: log a warning, drop the bad folder from
      // [account.folders] so the UI doesn't show a clickable item
      // that 404s, and continue with the next one.
      final liveFolders = <String>[];
      for (final folder in sortedFolders) {
        try {
          final count = await _mailService.getFolderCountAsync(account, folder);
          account.folderCounts[folder] = count;
          liveFolders.add(folder);
          LoggerService.log('PROVIDER', 'Folder "$folder" count: $count');
        } catch (ex) {
          final msg = ex.toString();
          if (msg.contains("Mailbox doesn't exist") ||
              msg.contains('NONEXISTENT') ||
              msg.contains('NO mailbox')) {
            LoggerService.logWarning('PROVIDER',
                'Skipping phantom folder "$folder" (server LIST'
                'ed it but SELECT failed): ${msg.split('\n').first}');
            // Don't add to liveFolders — UI will hide it.
          } else {
            // Unknown error on a single folder — log but keep going.
            // Don't fail the whole account.
            LoggerService.logWarning('PROVIDER',
                'Folder "$folder" count failed: ${msg.split('\n').first}');
            liveFolders.add(folder);
            account.folderCounts[folder] = 0;
          }
        }
      }
      // Replace the folder list with the live (selectable) ones.
      account.folders = liveFolders;

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

      // Reset the consecutive auth-fail counter on successful auth.
      _consecutiveAuthFailures.remove(account.username);

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

      // ── Locked-out detection ──
      // If IMAP auth fails repeatedly (>= 3 consecutive failures) for an
      // account whose password we know is correct (already worked once
      // this session OR was just set), it's likely the admin enabled
      // single-device mode on another device. Probe the backend to
      // confirm and trigger the same dialog as direct device_limit_reached.
      _checkForLockedOut(account);
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

  /// Consecutive IMAP authentication failures per username. Reset on
  /// successful auth. Used by [_checkForLockedOut] to detect when an
  /// admin has activated single-device mode on another device.
  final Map<String, int> _consecutiveAuthFailures = {};

  /// Threshold for locked-out detection: after this many consecutive
  /// IMAP auth failures, probe the mail-admin backend to confirm
  /// single-device lockout vs. plain wrong-password.
  static const int _lockoutDetectionThreshold = 3;

  /// Detect if repeated IMAP auth failures are due to single-device
  /// mode being enabled on another device. Probes the mail-admin
  /// backend with the user's known-good password. If the backend
  /// returns `device_limit_reached`, set the same flag that direct
  /// register-device rejection sets, so the UI shows the same dialog.
  Future<void> _checkForLockedOut(EmailAccount account) async {
    final username = account.username;
    final password = account.password;
    if (password == null || password.isEmpty) return;

    // Increment consecutive failure counter
    final count = (_consecutiveAuthFailures[username] ?? 0) + 1;
    _consecutiveAuthFailures[username] = count;

    if (count < _lockoutDetectionThreshold) {
      LoggerService.log('AUTH_ERROR',
          'Auth failure $count/$_lockoutDetectionThreshold for $username '
          '(below lockout-detection threshold)');
      return;
    }

    // Threshold reached — only probe ONCE (don't re-probe on every
    // subsequent failure). Reset to a sentinel that's >= threshold
    // but won't trigger again.
    if (count > _lockoutDetectionThreshold) return;

    LoggerService.log('AUTH_ERROR',
        'Auth failure threshold reached for $username '
        '— probing mail-admin for single-device lockout');

    try {
      final result = await DeviceRegistrationService.registerDevice(
        username: username,
        password: password,
      );

      if (result.isDeviceLimitReached) {
        LoggerService.logWarning('AUTH_ERROR',
            'Confirmed single-device lockout for $username '
            '— showing restriction dialog');
        _deviceLimitReachedFor = username;
        if (!_disposed) notifyListeners();
      } else if (result.success) {
        // Strange — register succeeded but IMAP didn't. Backend probably
        // doesn't share auth state with Dovecot in real-time. Reset
        // counter so the user can retry.
        LoggerService.log('AUTH_ERROR',
            'Backend register OK for $username but IMAP failed; '
            'resetting failure counter (race condition?)');
        _consecutiveAuthFailures.remove(username);
      } else {
        // result.error == "unauthorized" → password really is wrong.
        // Don't show the lockout dialog; let the existing wrong-password
        // UX handle it.
        LoggerService.log('AUTH_ERROR',
            'Backend confirms wrong password for $username '
            '(error: ${result.error}) — not a lockout');
      }
    } catch (ex) {
      LoggerService.logWarning('AUTH_ERROR',
          'Lockout probe failed (network?): $ex');
    }
  }

  /// Track register-device attempts that failed so we don't retry on
  /// every folder fetch. Holds the failure timestamp; we retry after
  /// _registerRetryCooldown elapses (next folder fetch after that).
  final Map<String, DateTime> _registerFailedAt = {};
  static const Duration _registerRetryCooldown = Duration(minutes: 15);

  /// Fire-and-forget device registration. Catches all errors so they
  /// never block the connection flow.
  Future<void> _registerDeviceForAccount(EmailAccount account) async {
    final username = account.username;
    final password = account.password;
    if (password == null || password.isEmpty) return;

    // Skip if we already registered in this session — heartbeat will
    // keep the last_seen fresh. We re-register on app restart.
    if (_devicesRegisteredThisSession.contains(username)) {
      // Just bump heartbeat — check for revocation
      DeviceRegistrationService.sendHeartbeat(username: username).then((result) {
        if (result == HeartbeatResult.revoked) _onDeviceRevoked(username);
      });
      return;
    }

    // Skip if we recently failed to register and the cooldown hasn't
    // expired. Without this, EVERY folder fetch (which happens on every
    // email check cycle) would retry the failed register endpoint and
    // spam warnings into the log.
    final lastFailure = _registerFailedAt[username];
    if (lastFailure != null &&
        DateTime.now().difference(lastFailure) < _registerRetryCooldown) {
      return;
    }

    try {
      final result = await DeviceRegistrationService.registerDevice(
        username: username,
        password: password,
      );

      if (result.success) {
        _devicesRegisteredThisSession.add(username);
        _registerFailedAt.remove(username);
        // Start heartbeat timer if not already running
        _ensureHeartbeatTimer();
      } else if (result.isDeviceLimitReached) {
        _deviceLimitReachedFor = username;
        // Mark as "tried" so we don't keep retrying — the user has
        // to acknowledge the dialog and retry manually.
        _registerFailedAt[username] = DateTime.now();
        if (!_disposed) notifyListeners();
        LoggerService.logWarning('PROVIDER',
            'Device limit reached for $username — UI should show '
            'restriction dialog');
      } else {
        // Any other failure (unauthorized, network, http_5xx, etc.)
        // — record cooldown so we don't spam the endpoint on every
        // folder fetch. Will retry after _registerRetryCooldown.
        _registerFailedAt[username] = DateTime.now();
      }
    } catch (ex) {
      LoggerService.logWarning('PROVIDER',
          'Device registration error (non-fatal): $ex');
      _registerFailedAt[username] = DateTime.now();
    }
  }

  // ── Remote revocation state ──────────────────────────────────────
  /// Non-null when this device has been revoked by the administrator.
  /// UI should show a blocking "Device Revoked" screen.
  String? _revokedUsername;
  String? get revokedUsername => _revokedUsername;

  /// Start the 5-minute heartbeat timer if not already running.
  void _ensureHeartbeatTimer() {
    if (_heartbeatTimer != null) return;
    _heartbeatTimer = Timer.periodic(const Duration(minutes: 5), (_) async {
      if (_disposed) return;
      for (final username in _devicesRegisteredThisSession.toList()) {
        final result = await DeviceRegistrationService.sendHeartbeat(
            username: username);
        if (result == HeartbeatResult.revoked) {
          await _onDeviceRevoked(username);
          return; // stop processing — app is locked
        }
      }
    });
    LoggerService.log('PROVIDER',
        'Started device heartbeat timer (every 5 min)');
  }

  /// Handle remote device revocation: wipe credentials, lock, notify UI.
  Future<void> _onDeviceRevoked(String username) async {
    LoggerService.logWarning('PROVIDER',
        '🔴 Device revoked for $username — wiping credentials');
    // Stop heartbeat
    _heartbeatTimer?.cancel();
    _heartbeatTimer = null;
    _devicesRegisteredThisSession.clear();
    // Wipe mTLS certificate + private key
    await CertificateService.clearCertificates();
    // Wipe PIN
    try {
      await PinUnlockService.invalidatePin();
    } catch (_) {}
    // Wipe RAM session cache
    wipeSessionCache();
    // Lock vault (zeros KEK, dataKey, cache in memory)
    MasterVault.instance.lock();
    // Signal UI to show revoked screen
    _revokedUsername = username;
    if (!_disposed) notifyListeners();
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

    final account = _currentAccount;
    if (account == null) return;
    final cacheKey = '${account.username}::$_currentFolder';

    // ── RAM cache hit → instant display, refresh in background ───
    final cached = _sessionCache[cacheKey];
    if (cached != null && cached.isNotEmpty) {
      _emails = cached;
      _error = null;
      _isLoading = false;
      notifyListeners();
      // Background refresh (non-blocking)
      _backgroundRefresh(account, cacheKey);
      return;
    }

    // ── Cache miss → full fetch ──────────────────────────────────
    _isFetching = true;
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final certSuccess = await _ensureCertForAccount(account);
      if (!certSuccess) {
        _error = 'Certificate download failed';
        _isLoading = false;
        notifyListeners();
        return;
      }

      if (_currentAccount?.username != account.username) return;

      LoggerService.log('PROVIDER', 'Fetching emails from ${account.username}/$_currentFolder...');

      final newEmails = await _mailService.fetchEmailsAsync(
        account,
        _currentFolder,
      );

      _detectAndNotifyNewEmails(account, newEmails);
      _emails = newEmails;

      // Store in RAM session cache (LRU capped)
      _sessionCache[cacheKey] = newEmails.length > _maxCachePerFolder
          ? newEmails.sublist(0, _maxCachePerFolder)
          : newEmails;

      account.folderCounts[_currentFolder] = _emails.length;

      _error = null;
      LoggerService.log('PROVIDER', '✓ Fetched ${_emails.length} emails (cached in RAM)');
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

  /// Background refresh: fetch from server and update cache + UI silently.
  Future<void> _backgroundRefresh(EmailAccount account, String cacheKey) async {
    if (_isFetching) return;
    _isFetching = true;
    _isCheckingServer = true;
    if (!_disposed) notifyListeners();

    try {
      final certSuccess = await _ensureCertForAccount(account);
      if (!certSuccess) return;
      if (_currentAccount?.username != account.username) return;

      final newEmails = await _mailService.fetchEmailsAsync(
        account,
        _currentFolder,
      );

      _detectAndNotifyNewEmails(account, newEmails);

      // Update cache + UI
      _sessionCache[cacheKey] = newEmails.length > _maxCachePerFolder
          ? newEmails.sublist(0, _maxCachePerFolder)
          : newEmails;
      _emails = newEmails;
      account.folderCounts[_currentFolder] = _emails.length;
      _error = null;

      LoggerService.log('PROVIDER', '✓ Background refresh: ${_emails.length} emails');
    } catch (ex, stackTrace) {
      // Silent failure — cached data still displayed
      LoggerService.logError('PROVIDER', 'Background refresh failed', stackTrace);
    } finally {
      _isFetching = false;
      _isCheckingServer = false;
      if (!_disposed) notifyListeners();
    }
  }

  /// Detect new emails and show notifications.
  void _detectAndNotifyNewEmails(EmailAccount account, List<Email> newEmails) {
    final accountKey = '${account.username}_INBOX';
    final previousIds = _accountEmailIds[accountKey] ?? <String>{};

    if (_currentFolder == 'INBOX' && previousIds.isNotEmpty) {
      for (final email in newEmails) {
        if (!previousIds.contains(email.messageId)) {
          NotificationService.showNewEmailToast(email);
          LoggerService.log('NEW_EMAIL',
              '🔔 New email from ${piiEmail(email.from)} ${piiSubject(email.subject)}');
        }
      }
    }

    if (_currentFolder == 'INBOX') {
      _accountEmailIds[accountKey] = newEmails.map((e) => e.messageId).toSet();
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
        final certSuccess = await _ensureCertForAccount(account);
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
