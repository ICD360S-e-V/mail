// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:fluent_ui/fluent_ui.dart';
import 'dart:async';
import 'dart:collection' show LinkedHashMap;
import 'dart:convert' show utf8;
import '../models/models.dart';
import '../services/services.dart';
import 'dart:io' show Platform;
import '../services/certificate_expiry_monitor.dart';
import '../services/device_approval_service.dart';
import '../services/device_registration_service.dart';
import '../services/pgp_key_service.dart';
import '../services/update_service.dart';
import '../services/master_vault.dart';
import '../services/startup_diagnostics.dart';
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
  DateTime? _lastSyncTime;

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

  // ── On-demand body LRU cache ──────────────────────────────────────
  //
  // Envelope-first fetch (PR #37) means Email.body is null on the list
  // path. When the user opens a viewer we call loadBody which fetches
  // from IMAP — and without a body cache, every reopen re-fetches. The
  // LRU here keeps the last N opened bodies so re-clicks are instant.
  //
  // Sizing: hard cap of _maxBodyCacheEntries × max body size. With 1MB
  // body cap (mail_service.dart) and 10 entries, worst-case RAM
  // contribution is bounded at ~10MB + attachments. Predictable ceiling,
  // no possibility of the 300MB/refresh regression we hit pre-PR #36.
  //
  // Key: messageId. LinkedHashMap insertion order = LRU order; evict
  // oldest from the head, touch by re-insert.
  static const _maxBodyCacheEntries = 10;
  final LinkedHashMap<String, _CachedBody> _bodyCache =
      LinkedHashMap<String, _CachedBody>();

  /// Wipe all cached emails from RAM. Called on lock, background, close.
  void wipeSessionCache() {
    for (final emails in _sessionCache.values) {
      _wipeBodies(emails);
    }
    _sessionCache.clear();
    // Also drop the LRU body cache — bodies are decrypted plaintext, must
    // not survive a lock or background transition.
    for (final cached in _bodyCache.values) {
      for (final a in cached.attachments) {
        a.data = null;
      }
    }
    _bodyCache.clear();
    _emails = [];
    LoggerService.log('CACHE', 'Session cache + body LRU wiped from RAM');
  }

  /// Release heavy body strings + attachment buffers before dropping the
  /// reference. Without this, GC tends to retain ~300MB/refresh because
  /// (1) String is immutable so each body lingers as its own object,
  /// (2) widgets that just rebuilt may briefly hold the old snapshot via
  /// closures, and (3) Dart GC is opportunistic. Wiping the fields cuts
  /// the heavy retention path even while the Email shell waits to be GC'd.
  /// Pattern mirrored from wipeSessionCache; see incident 2026-05-16
  /// where 60s auto-refresh leaked 300MB/cycle until first wipe was added.
  static void _wipeBodies(Iterable<Email> emails) {
    for (final email in emails) {
      // Reset body to null so bodyLoaded → false. Reopening the email
      // triggers another fetchFullBody from server. With envelope-first
      // fetch, most emails already have body == null and this is a no-op.
      email.body = null;
      email.bodyTruncated = false;
      email.threatDetails = '';
      for (final a in email.attachments) {
        a.data = null;
      }
      // Drop attachment metadata too — they were populated by the body
      // fetch path and will be repopulated on next loadBody.
      email.attachments.clear();
    }
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
  DateTime? get lastSyncTime => _lastSyncTime;
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

    // Load persisted re-approval flags so the account-picker UI shows
    // the orange badge immediately on launch, before the first heartbeat
    // tick. Cheap (one secure-storage readAll); fire-and-forget on
    // error so a storage hiccup never blocks startup.
    unawaited(loadReapprovalFlags());

    // Kick off the daily cert refresh sweep. The Timer.periodic and its
    // startup-delay run inside; calling it here is safe before
    // _accounts is loaded because the sweep guards on `_accounts` being
    // empty and re-reads it each pass.
    _ensureCertRefreshTimer();

    // Load accounts from AccountService (JSON + secure storage)
    _accounts = await _accountService.loadAccountsAsync();
    LoggerService.log('PROVIDER', 'Loaded ${_accounts.length} accounts from storage');

    if (_accounts.isNotEmpty) {
      _currentAccount = _accounts.first;
      LoggerService.log('PROVIDER', 'Current account set to: ${_currentAccount!.username}');
      // Bind user identity to the startup transcript so the next-boot
      // crash-recovery upload (and any in-session writes) carry the IMAP
      // username — same pattern as Sentry's `scope.setUser` post-login.
      StartupDiagnostics.setUsername(_currentAccount!.username);

      // IMPORTANT: Notify UI immediately so accounts appear in the
      // navigation pane while folders are still loading. Without this,
      // the sidebar stays empty for 30-60s until all 36 accounts finish
      // cert download + folder load. Users had to toggle dark mode to
      // force a rebuild and see the accounts.
      notifyListeners();

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

        // Update UI progressively as each account loads
        notifyListeners();
      }

      // Restore certificate for current account (last one loaded)
      if (_currentAccount != null) {
        await _ensureCertForAccount(_currentAccount!);
        LoggerService.log('PROVIDER', '✓ Certificate active for: ${_currentAccount!.username}');
      }

      // Kick off PGP blob sync + pubkey reconciliation EARLY, in parallel
      // with the (slow, sequential) email IDs cache init below. Otherwise
      // the user can open Compose or receive encrypted mail before the
      // reconciled pubkey is published and see "no encryption key" /
      // "Bad state: Decryption failed".
      unawaited(() async {
        try {
          if (_accounts.isNotEmpty) {
            await PgpKeyService.migrateExistingKeysToServer(_accounts);
          }
        } catch (ex) {
          LoggerService.logWarning(
              'PROVIDER', 'PGP blob sync failed (non-fatal): $ex');
        }
      }());

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

  /// Persist changes made to an [account] (e.g. `account.signature`)
  /// back to encrypted disk storage and notify UI listeners. Callers
  /// mutate the account in-place then call this; the account reference
  /// is already inside [_accounts] so no list mutation is needed.
  Future<void> persistAccount(EmailAccount account) async {
    await _accountService.updateAccount(account);
    if (!_disposed) notifyListeners();
  }

  /// Update performance stats (CPU/RAM) - async to avoid blocking UI.
  /// Does NOT call notifyListeners() — performanceStats is only used
  /// by log uploads, not by any widget. Calling notifyListeners() here
  /// caused full widget tree rebuilds every 10 seconds for no visible
  /// UI change.
  Future<void> updatePerformanceStats() async {
    _performanceStats = await _performanceMonitor.getFormattedStats();
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
  /// Restores the cert from secure storage (Keychain/DPAPI/Keystore).
  /// If not found, auto-submits a Faza 3 re-approval request.
  Future<bool> _ensureCertForAccount(EmailAccount account) async {
    // Cert-first strategy (v2.46.2): try secure storage BEFORE API.
    //
    // Why: many accounts have a stale password from pre-Faza-3 era
    // (when add-account stored a password) but ALSO have a valid cert
    // in Keychain (because they later went through Faza 3 approval).
    // The previous "password-first" path called the API with the stale
    // password and got 401 "Authentication required" 18× per startup.
    //
    // Local Keychain restore is free (no network, no server contention),
    // so we always prefer it. Password-based download is the fallback
    // only when the Keychain has no cert for this account.
    final restored =
        await CertificateService.restoreFromSecureStorageFor(account.username);
    if (restored) {
      // Don't trust the cache blindly — if the cached cert is expired or
      // about to expire (<7 days), fall through to the re-approval path
      // so we get a fresh one. Otherwise the app silently uses an expired
      // cert and HAProxy rejects the mTLS handshake = infinite spinner
      // with no actionable error (incident: 2026-05-15, affected all users
      // whose 90d certs lapsed the same day).
      final daysLeft = CertificateExpiryMonitor.getDaysUntilExpiry();
      if (daysLeft != null && daysLeft < 7) {
        LoggerService.logWarning('PROVIDER',
            'Cached cert for ${account.username} expires in $daysLeft days — '
            'discarding cache and re-requesting');
        await CertificateService.clearCertificatesFor(account.username);
      } else {
        LoggerService.log('PROVIDER',
            '✓ Cert for ${account.username} restored from secure storage');
        return true;
      }
    }

    // No cert in secure storage — request Faza 3 re-approval.
    // Cert-only account with no cert in storage. Instead of silently
    // failing (leaves the account stuck on spinning circle forever),
    // auto-submit a Faza 3 re-approval request so the admin gets
    // notified and can approve. The account stays disconnected until
    // approved, but at least progress is made automatically.
    LoggerService.logWarning('PROVIDER',
        'Cert-only account ${account.username} — secure storage empty, '
        'requesting Faza 3 re-approval automatically');
    try {
      final deviceId = await DeviceRegistrationService.getOrCreateDeviceId();
      final result = await DeviceApprovalService.requestAccess(
        username: account.username,
        deviceId: deviceId,
        deviceName: Platform.localHostname,
        deviceType: Platform.operatingSystem,
        osVersion: Platform.operatingSystemVersion,
        clientVersion: UpdateService.currentVersion,
        hostname: 'mail.icd360s.de',
      );
      if (result.success && result.autoApproved && result.oneTimeToken != null) {
        LoggerService.log('PROVIDER',
            '✓ Auto-approved (same device) for ${account.username} — downloading cert');
        try {
          final certBundle = await DeviceApprovalService.downloadCert(
            requestId: result.requestId!,
            oneTimeToken: result.oneTimeToken!,
          );
          if (certBundle == null) throw StateError('Cert download returned null');
          await CertificateService.storeBundle(
            username: account.username,
            clientCert: certBundle.clientCert,
            clientKey: certBundle.clientKey,
            caCert: certBundle.caCert,
          );
          LoggerService.log('PROVIDER',
              '✓ Cert auto-restored for ${account.username}');
          return true;
        } catch (certEx) {
          LoggerService.logWarning('PROVIDER',
              'Auto-approved but cert download failed for ${account.username}: $certEx');
        }
      } else if (result.success) {
        LoggerService.log('PROVIDER',
            '✓ Re-approval request submitted for ${account.username} '
            '(requestId: ${result.requestId})');
        account.connectionError = 'Awaiting admin re-approval (cert lost)';
        account.connectionStatus = AccountConnectionStatus.authError;
      } else {
        LoggerService.logWarning('PROVIDER',
            'Auto re-approval request failed for ${account.username}: '
            '${result.error}');
      }
    } catch (ex) {
      LoggerService.logWarning('PROVIDER',
          'Auto re-approval request error for ${account.username}: $ex');
    }
    return false;
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

  /// Load folders for an account (single IMAP connection via pool)
  Future<void> _loadFoldersForAccount(EmailAccount account) async {
    try {
      // v2.41.0: getFoldersAndCountsAsync uses ONE pooled connection
      // instead of N+1 separate connections (was: 1× getFolders + N×
      // getFolderCount = 8 connections per account × 36 accounts = 288
      // simultaneous connections → "Too many open files" errno 24).
      LoggerService.log('PROVIDER', 'Loading folders+counts for ${account.username} (single connection)...');
      final foldersAndCounts = await _mailService.getFoldersAndCountsAsync(account);
      LoggerService.log('PROVIDER', 'Received ${foldersAndCounts.length} folders from server');

      final sortedFolders = _sortFolders(foldersAndCounts.keys.toList());
      account.folders = sortedFolders;

      // Apply counts — phantom folders (count returned as 0 from pool
      // due to SELECT failure) are kept but harmless.
      for (final folder in sortedFolders) {
        account.folderCounts[folder] = foldersAndCounts[folder] ?? 0;
        LoggerService.log('PROVIDER', 'Folder "$folder" count: ${account.folderCounts[folder]}');
      }
      account.inboxCount = account.folderCounts['INBOX'] ?? 0;
      LoggerService.log('PROVIDER', 'INBOX count: ${account.inboxCount}');

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

      LoggerService.log('PROVIDER', '✓ Loaded ${account.folders.length} folders for ${account.username}');
      LoggerService.log('PROVIDER', 'Final account.folders: ${account.folders}');
      LoggerService.log('PROVIDER', 'Final account.folderCounts: ${account.folderCounts}');

      if (!_disposed) notifyListeners();

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

    LoggerService.logWarning('AUTH_ERROR',
        'Auth failure threshold reached for $username '
        '— possible cert issue or device lockout');
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
    // Cert past server-side grace period — heartbeat would fail at the
    // TLS handshake. Skip so we don't spam nginx with handshake errors.
    if (_accountsCertExpired.contains(username)) return;
    // Skip if we already registered in this session — heartbeat will
    // keep the last_seen fresh. We re-register on app restart.
    if (_devicesRegisteredThisSession.contains(username)) {
      // Just bump heartbeat — check for revocation
      DeviceRegistrationService.sendHeartbeat(username: username).then((result) {
        if (result == HeartbeatResult.revoked) _onDeviceRevoked(username);
        if (result == HeartbeatResult.notRegistered) _onNotRegistered(username);
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
      final hbResult = await DeviceRegistrationService.sendHeartbeat(
        username: username,
      );
      if (hbResult == HeartbeatResult.revoked) {
        _onDeviceRevoked(username);
        return;
      }
      if (hbResult == HeartbeatResult.notRegistered) {
        _onNotRegistered(username);
        return;
      }
      _devicesRegisteredThisSession.add(username);
      _registerFailedAt.remove(username);
      _ensureHeartbeatTimer();
    } catch (ex) {
      LoggerService.logWarning('PROVIDER',
          'Heartbeat error (non-fatal): $ex');
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
        if (result == HeartbeatResult.notRegistered) {
          _onNotRegistered(username);
        }
      }
    });
    LoggerService.log('PROVIDER',
        'Started device heartbeat timer (every 5 min)');
  }

  // ── Stale-registration state ─────────────────────────────────────
  /// Accounts that the server has told us aren't registered (HTTP 404
  /// device_not_registered). Heartbeat is paused for these and the UI
  /// shows a "needs re-approval" badge so the user can act.
  final Set<String> _accountsNeedingReapproval = <String>{};

  /// UI helper — snapshot of accounts currently flagged for re-approval.
  Set<String> get accountsNeedingReapproval =>
      Set<String>.unmodifiable(_accountsNeedingReapproval);

  /// True if [username] is currently flagged as needing re-approval.
  bool needsReapproval(String username) =>
      _accountsNeedingReapproval.contains(username);

  Future<void> _onNotRegistered(String username) async {
    // Stop bumping heartbeat for this account, surface to UI.
    _devicesRegisteredThisSession.remove(username);
    if (_accountsNeedingReapproval.add(username)) {
      LoggerService.logWarning('PROVIDER',
          '🔶 Account $username needs re-approval — paused');
      if (!_disposed) notifyListeners();
    }
  }

  /// Clear the re-approval flag for [username] and allow the heartbeat
  /// loop to resume on the next folder fetch. Call this after the user
  /// completes admin re-approval and the next registerDevice succeeds —
  /// the underlying service also clears its persistent flag.
  Future<void> clearReapprovalFlag(String username) async {
    await DeviceRegistrationService.clearNeedsReapproval(username);
    if (_accountsNeedingReapproval.remove(username)) {
      if (!_disposed) notifyListeners();
    }
  }

  /// Load persisted re-approval flags into the in-memory provider state
  /// at startup so the UI immediately shows the correct badges. Call
  /// once after providers initialize.
  ///
  /// The service stores bare usernames (without the @icd360s.de suffix),
  /// the provider keys by the full username — translate at the boundary
  /// so both the UI lookup and downstream service calls land on the
  /// same identifier.
  Future<void> loadReapprovalFlags() async {
    final flagged = await DeviceRegistrationService.snapshotNeedingReapproval();
    if (flagged.isEmpty) return;
    _accountsNeedingReapproval
      ..clear()
      ..addAll(flagged.map((bare) => '$bare@icd360s.de'));
    if (!_disposed) notifyListeners();
  }

  // ── Cert expiry / auto-refresh state (v2.146.7+) ────────────────
  /// Accounts whose mTLS cert is too far past expiry (or never trusted)
  /// for the mid-life refresh endpoint to accept. Heartbeat / IMAP /
  /// SMTP are paused for these and the UI shows a red "Certificate
  /// expired" badge so the user re-enrolls via add-account.
  final Set<String> _accountsCertExpired = <String>{};

  /// UI helper — snapshot of accounts flagged as cert-expired.
  Set<String> get accountsCertExpired =>
      Set<String>.unmodifiable(_accountsCertExpired);

  /// True if [username] is currently flagged as cert-expired.
  bool isCertExpired(String username) =>
      _accountsCertExpired.contains(username);

  Future<void> _onCertExpired(String username) async {
    _devicesRegisteredThisSession.remove(username);
    if (_accountsCertExpired.add(username)) {
      LoggerService.logWarning('PROVIDER',
          '🔴 Account $username cert expired beyond grace — paused');
      if (!_disposed) notifyListeners();
    }
  }

  /// Clear the cert-expired flag for [username]. Called by the auto-
  /// refresh sweep after a successful renew, and by the add-account
  /// flow after a fresh enrollment.
  void clearCertExpiredFlag(String username) {
    if (_accountsCertExpired.remove(username)) {
      if (!_disposed) notifyListeners();
    }
  }

  Timer? _certRefreshTimer;
  static const Duration _certRefreshInterval = Duration(hours: 24);
  static const int _certRefreshThresholdDays = 14;
  bool _certRefreshRunning = false;

  /// Daily sweep: parse the locally-cached expiry for every account
  /// with a cert in secure storage. For any cert that's within
  /// [_certRefreshThresholdDays] of expiry (or already past expiry but
  /// still within the server-side grace window), call the mid-life
  /// renew endpoint via mTLS and persist the fresh bundle.
  ///
  /// Aligns with the Mastercard / Cloudflare WARP pattern: renewal at
  /// 30/14 days, grace period after expiry, then block on permanent
  /// failure. Skips silently when no accounts qualify (saves syscalls
  /// for users whose certs are fresh).
  void _ensureCertRefreshTimer() {
    _certRefreshTimer?.cancel();
    _certRefreshTimer = Timer.periodic(_certRefreshInterval, (_) {
      if (_disposed) return;
      unawaited(_runCertRefreshSweep());
    });
    // Also run once on startup, after a short delay so the first
    // heartbeat round-trip isn't competing for the certificate locks.
    unawaited(Future<void>.delayed(const Duration(seconds: 30),
        () { if (!_disposed) _runCertRefreshSweep(); }));
    LoggerService.log('PROVIDER',
        'Started cert refresh timer (every 24h, threshold '
        '${_certRefreshThresholdDays}d)');
  }

  Future<void> _runCertRefreshSweep() async {
    if (_certRefreshRunning) return;
    _certRefreshRunning = true;
    try {
      // Load any persisted expiries we haven't seen yet this session so
      // the threshold check doesn't have to re-parse every PEM.
      await CertificateExpiryMonitor.loadAllPersistedExpiries(
          _accounts.map((a) => a.username).toList());

      for (final account in _accounts.toList()) {
        if (_disposed) return;
        final username = account.username;
        var days = CertificateExpiryMonitor.getDaysUntilExpiryFor(username);
        // Fallback: pre-v2.147.0 installs persisted only the singleton
        // expiry, so the per-account map can be empty for accounts that
        // haven't been (re)connected since the upgrade. Load the bundle
        // and parse the PEM on demand — this also primes the map for
        // the next pass.
        if (days == null) {
          final bundle = await CertificateService.loadBundleFor(username);
          if (bundle == null) continue;
          final pem = utf8.decode(bundle.clientCert);
          final notAfter = await CertificateExpiryMonitor
              .parseCertAndPersistExpiryFor(username, pem);
          if (notAfter == null) continue;
          days = notAfter.difference(DateTime.now().toUtc()).inDays;
        }
        if (days > _certRefreshThresholdDays) continue;

        // Already past notAfter — the renew-cert endpoint mTLS-authenticates
        // with the very cert we're trying to refresh, so calling it would
        // just produce a confusing nginx "400 SSL certificate error" each
        // sweep and hide the re-enrollment prompt from the user. Flag the
        // account immediately so the badge appears and heartbeat stops
        // hammering the server with a dead cert.
        if (days < 0) {
          LoggerService.logWarning('CERT-RENEW',
              'Account $username cert already expired ($days days) — '
              'flagging for re-enrollment without trying renew-cert');
          await _onCertExpired(username);
          continue;
        }

        LoggerService.log('CERT-RENEW',
            'Account $username cert expiring in $days days — refreshing');
        final outcome = await CertificateService.refreshFor(username);
        if (outcome == CertificateService.refreshOk) {
          // Re-enable heartbeat if it was suppressed by a previous
          // sweep that hit refreshExpired.
          clearCertExpiredFlag(username);
        } else if (outcome == CertificateService.refreshExpired) {
          await _onCertExpired(username);
        }
        // Other outcomes (unreachable, notFound, skipped) leave the
        // current state alone — we'll try again tomorrow.
      }
    } finally {
      _certRefreshRunning = false;
    }
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
    StartupDiagnostics.setUsername(account.username);
    // Set active PGP key for decrypt (per-account keys).
    // MUST await: fetchEmails decrypts incoming mail inline, so the
    // worker must hold THIS account's private key before we fetch.
    // The old unawaited() path raced: fetchEmails fired before the
    // worker switched keys → every encrypted mail failed with
    // "Bad state: Decryption failed".
    try {
      await PgpKeyService.setActiveAccount(account.username);
    } catch (ex) {
      LoggerService.logWarning('PGP', 'setActiveAccount failed: $ex');
    }
    notifyListeners();

    await fetchEmails();
  }

  @override
  void dispose() {
    _disposed = true;
    _heartbeatTimer?.cancel();
    _heartbeatTimer = null;
    _certRefreshTimer?.cancel();
    _certRefreshTimer = null;
    // Close all pooled IMAP connections on dispose
    ImapPool.instance.closeAll();
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
      // Release heavy fields on the outgoing list before dropping the ref.
      _wipeBodies(_emails);
      final previousCached = _sessionCache[cacheKey];
      if (previousCached != null && !identical(previousCached, newEmails)) {
        _wipeBodies(previousCached);
      }
      _emails = newEmails;

      // Store in RAM session cache (LRU capped)
      _sessionCache[cacheKey] = newEmails.length > _maxCachePerFolder
          ? newEmails.sublist(0, _maxCachePerFolder)
          : newEmails;

      account.folderCounts[_currentFolder] = _emails.length;

      _error = null;
      _lastSyncTime = DateTime.now();
      LoggerService.log('PROVIDER', '✓ Fetched \${_emails.length} emails (cached in RAM)');
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
      _wipeBodies(_emails);
      final previousCached = _sessionCache[cacheKey];
      if (previousCached != null && !identical(previousCached, newEmails)) {
        _wipeBodies(previousCached);
      }

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
    void Function(int bytesSent, int totalBytes)? onSendProgress,
    Map<String, String>? preEncodedBase64,
    bool requestReadReceipt = false,
  }) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      await _mailService.sendEmailWithAttachmentsAsync(
        account, to, cc, bcc, subject, body, attachments,
        draftUid: draftUid,
        onSendProgress: onSendProgress,
        preEncodedBase64: preEncodedBase64,
        requestReadReceipt: requestReadReceipt,
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

  /// Save draft to the sender account's Drafts folder.
  /// [account] — REQUIRED: the From account from compose window.
  /// Draft belongs to the sender identity, not the navigation selection.
  Future<int?> saveDraft(String to, String cc, String bcc, String subject, String body, {required EmailAccount? account, List<dynamic> attachments = const [], int? previousDraftUid}) async {
    final targetAccount = account;
    if (targetAccount == null) return null;

    try {
      final uid = await _mailService.saveDraftAsync(targetAccount, to, cc, bcc, subject, body, attachments: attachments, previousDraftUid: previousDraftUid);
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
      // Uses single pooled connection (getFolderCountAsync reuses via pool)
      for (final folder in account.folders) {
        try {
          final count = await _mailService.getFolderCountAsync(account, folder);
          account.folderCounts[folder] = count;
        } catch (ex) {
          LoggerService.logWarning('PROVIDER', 'Could not refresh count for $folder: $ex');
        }
      }
      account.inboxCount = account.folderCounts['INBOX'] ?? account.inboxCount;
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

  /// Load the full body for [email] (on-demand body fetch).
  ///
  /// The list/refresh path fetches envelopes only (no bodies). When the
  /// user opens the email viewer, this method is called to download the
  /// MIME body, decrypt PGP/MIME if applicable, and extract attachments.
  /// On success, [Email.body] becomes non-null and listeners are notified
  /// so the viewer rebuilds with the content.
  ///
  /// Idempotent: if `email.bodyLoaded` is already true, this is a no-op.
  ///
  /// Pass [forceFull] = true to bypass both the idempotent short-circuit
  /// and the cache, and to forward `forceFull` to [MailService.fetchFullBody]
  /// so the IMAP fetch ignores the 1 MB body cap. Used by the "Download full
  /// message" affordance in the viewer when [Email.bodyTruncated] is set.
  Future<void> loadBody(Email email, {bool forceFull = false}) async {
    // Already loaded on this Email instance — just touch the LRU.
    // Skip the early-return when forceFull is set so the user can
    // re-fetch a previously-truncated body without clearing it first.
    if (email.bodyLoaded && !forceFull) {
      _touchBodyCache(email.messageId);
      return;
    }

    // Cache hit on a different Email shell (same messageId, e.g. after
    // an envelope-only refresh replaced the list). Hydrate from cache,
    // skip the IMAP fetch entirely. Same forceFull skip rule applies.
    final cached = _bodyCache[email.messageId];
    if (cached != null && !forceFull) {
      email.body = cached.body;
      email.bodyTruncated = cached.bodyTruncated;
      email.isEncrypted = cached.isEncrypted;
      email.attachments
        ..clear()
        ..addAll(cached.attachments);
      _touchBodyCache(email.messageId);
      LoggerService.log('CACHE',
          '✓ Body cache HIT for ${email.messageId} (size=${_bodyCache.length})');
      if (!_disposed) notifyListeners();
      return;
    }

    // Cache miss — fetch from IMAP.
    final account = _currentAccount;
    if (account == null) {
      LoggerService.logWarning(
          'PROVIDER', 'loadBody called with no current account');
      return;
    }
    try {
      await _mailService.fetchFullBody(account, email,
          folder: _currentFolder, forceFull: forceFull);
      LoggerService.log('PROVIDER',
          '✓ Loaded body for ${email.messageId} (${email.body?.length ?? 0} chars, '
          '${email.attachments.length} attachments, '
          'encrypted=${email.isEncrypted}, truncated=${email.bodyTruncated})');
      // Insert into LRU on success only (don't pollute cache with errors).
      // On forceFull this overwrites the previously cached truncated body.
      if (email.bodyLoaded) {
        _putBodyCache(email);
      }
    } catch (ex, stackTrace) {
      // fetchFullBody already populated email.body with an error sentinel.
      LoggerService.logError('PROVIDER', ex, stackTrace);
    } finally {
      if (!_disposed) notifyListeners();
    }
  }

  /// Move existing entry to end (most-recently-used) without re-storing.
  void _touchBodyCache(String messageId) {
    final entry = _bodyCache.remove(messageId);
    if (entry != null) _bodyCache[messageId] = entry;
  }

  /// Store body+attachments in LRU; evict oldest if over capacity.
  void _putBodyCache(Email email) {
    _bodyCache[email.messageId] = _CachedBody(
      body: email.body!,
      bodyTruncated: email.bodyTruncated,
      isEncrypted: email.isEncrypted,
      attachments: List<EmailAttachment>.from(email.attachments),
    );
    while (_bodyCache.length > _maxBodyCacheEntries) {
      final evictId = _bodyCache.keys.first;
      final evicted = _bodyCache.remove(evictId);
      if (evicted != null) {
        for (final a in evicted.attachments) {
          a.data = null;
        }
      }
      LoggerService.log('CACHE',
          'Evicted body for $evictId (cache full at $_maxBodyCacheEntries)');
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

/// Snapshot of a loaded message body for the LRU cache. We don't keep a
/// reference to the original Email because the envelope-only refresh path
/// replaces the Email shell — the body would point to a dead instance.
/// Storing the raw fields lets us re-hydrate any future Email shell with
/// the same messageId.
class _CachedBody {
  final String body;
  final bool bodyTruncated;
  final bool isEncrypted;
  final List<EmailAttachment> attachments;

  _CachedBody({
    required this.body,
    required this.bodyTruncated,
    required this.isEncrypted,
    required this.attachments,
  });
}
