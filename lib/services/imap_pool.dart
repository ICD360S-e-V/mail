import 'dart:async';
import 'dart:collection';
import 'package:enough_mail/enough_mail.dart';
import '../models/models.dart';
import 'logger_service.dart';
import 'mail_service.dart';
import 'mtls_service.dart';

/// Global IMAP connection pool with concurrency throttling.
///
/// Problem: 36 accounts × 7+ operations each = 252+ simultaneous IMAP
/// connections, exceeding macOS file descriptor limit (~256).
///
/// Solution: reuse one IMAP connection per account and limit the number
/// of concurrent connections with a semaphore (max 5 at a time).
///
/// IMAP is a single-stream protocol — operations on the same connection
/// must be serialized. The pool uses a per-account lock to ensure this.
class ImapPool {
  ImapPool._();
  static final ImapPool instance = ImapPool._();

  /// Maximum number of IMAP connections open at the same time.
  static const int maxConcurrent = 5;

  /// How long an idle connection stays in the pool before being closed.
  static const Duration idleTimeout = Duration(minutes: 2);

  // ── Semaphore (manual, no extra package) ──────────────────────────
  int _activeCount = 0;
  final Queue<Completer<void>> _waiters = Queue();

  Future<void> _acquire() async {
    if (_activeCount < maxConcurrent) {
      _activeCount++;
      return;
    }
    final completer = Completer<void>();
    _waiters.add(completer);
    await completer.future;
  }

  void _release() {
    if (_waiters.isNotEmpty) {
      final next = _waiters.removeFirst();
      next.complete();
    } else {
      _activeCount--;
    }
  }

  // ── Per-account cached connections ────────────────────────────────
  final Map<String, _PooledConnection> _connections = {};

  // ── Per-account mutex (IMAP is single-stream) ────────────────────
  // Prevents two concurrent operations on the same account from
  // interleaving IMAP commands (e.g. draft-save EXPUNGE running
  // while save-to-Sent APPEND is in progress → deletes from wrong
  // mailbox). Operations on DIFFERENT accounts run concurrently.
  final Map<String, _AsyncMutex> _accountLocks = {};

  _AsyncMutex _lockFor(String key) =>
      _accountLocks.putIfAbsent(key, () => _AsyncMutex());

  /// Execute [operation] with an authenticated IMAP client for [account].
  ///
  /// The connection is reused if already open and healthy; otherwise a
  /// new one is created (throttled by the semaphore). If the operation
  /// fails with a connection error, the cached connection is discarded.
  ///
  /// **Thread-safe**: operations on the same account are serialized by
  /// a per-account mutex. This prevents IMAP command interleaving.
  Future<T> withClient<T>(
    EmailAccount account,
    Future<T> Function(ImapClient client) operation,
  ) async {
    final key = account.username;
    final mutex = _lockFor(key);

    // Serialize all operations for this account
    return mutex.run(() async {
      // Try to reuse an existing connection
      final existing = _connections[key];
      if (existing != null && existing.isAlive) {
        existing.touch();
        try {
          return await operation(existing.client);
        } catch (ex) {
          if (_isConnectionError(ex)) {
            LoggerService.log('IMAP_POOL',
                'Connection error for $key, discarding cached connection');
            await _closeAndRemove(key);
          } else {
            rethrow;
          }
        }
      }

      // Need a new connection — acquire semaphore slot
      await _acquire();
      try {
        // Double-check: connection may have been created while waiting
        final existing2 = _connections[key];
        if (existing2 != null && existing2.isAlive) {
          existing2.touch();
          try {
            return await operation(existing2.client);
          } catch (ex) {
            if (_isConnectionError(ex)) {
              await _closeAndRemove(key);
            } else {
              rethrow;
            }
          }
        }

        // Create fresh connection
        final client = await _connect(account);
        _connections[key] = _PooledConnection(client);
        LoggerService.log('IMAP_POOL',
            '✓ New connection for $key (${_connections.length} total, $_activeCount active)');

        try {
          return await operation(client);
        } catch (ex) {
          if (_isConnectionError(ex)) {
            await _closeAndRemove(key);
          }
          rethrow;
        }
      } finally {
        _release();
      }
    });
  }

  /// Create and authenticate a new IMAP connection.
  Future<ImapClient> _connect(EmailAccount account) async {
    final client = ImapClient(
      isLogEnabled: false,
      securityContext: MtlsService.getSecurityContext(),
      onBadCertificate: MtlsService.onBadCertificate,
    );

    final serverIp = await MailService.resolveServer();
    await client.connectToServer(
      serverIp,
      account.imapPort,
      isSecure: account.useSsl,
    );

    // Authenticate: same logic as MailService._authenticate
    final user = account.username.contains('@')
        ? account.username.split('@').first
        : account.username;
    if (client.serverInfo.supports('AUTH=EXTERNAL')) {
      await client.authenticateWithExternal();
    } else {
      await client.login(user, account.password ?? '');
    }

    return client;
  }

  /// Close a cached connection and remove it from the pool.
  Future<void> _closeAndRemove(String key) async {
    final conn = _connections.remove(key);
    if (conn != null) {
      try {
        await conn.client.disconnect();
      } catch (_) {
        // Ignore disconnect errors on already-broken connections
      }
    }
  }

  /// Close all connections (called on app lock / logout).
  Future<void> closeAll() async {
    LoggerService.log('IMAP_POOL',
        'Closing all ${_connections.length} pooled connections');
    final futures = <Future>[];
    for (final entry in _connections.entries) {
      futures.add(Future(() async {
        try {
          await entry.value.client.disconnect();
        } catch (_) {
          // Best-effort cleanup; connection may already be dead
        }
      }));
    }
    await Future.wait(futures);
    _connections.clear();
    _accountLocks.clear();
    _activeCount = 0;
    // Complete any pending waiters so they don't hang forever
    while (_waiters.isNotEmpty) {
      _waiters.removeFirst().complete();
    }
  }

  /// Close the connection for a specific account (e.g. on account removal).
  Future<void> closeForAccount(String username) async {
    await _closeAndRemove(username);
  }

  /// Evict idle connections (call periodically from a timer).
  Future<void> evictIdle() async {
    final now = DateTime.now();
    final expired = <String>[];
    for (final entry in _connections.entries) {
      if (now.difference(entry.value.lastUsed) > idleTimeout) {
        expired.add(entry.key);
      }
    }
    for (final key in expired) {
      LoggerService.log('IMAP_POOL', 'Evicting idle connection for $key');
      await _closeAndRemove(key);
    }
  }

  /// Check if an exception indicates a broken connection (vs. a logical error).
  static bool _isConnectionError(Object ex) {
    final msg = ex.toString().toLowerCase();
    return msg.contains('socketexception') ||
        msg.contains('connection closed') ||
        msg.contains('connection reset') ||
        msg.contains('broken pipe') ||
        msg.contains('too many open files') ||
        msg.contains('errno = 24') ||
        msg.contains('connection refused') ||
        msg.contains('timed out') ||
        msg.contains('not connected');
  }
}

/// Wrapper around an ImapClient with last-used timestamp.
class _PooledConnection {
  final ImapClient client;
  DateTime lastUsed;

  _PooledConnection(this.client) : lastUsed = DateTime.now();

  void touch() => lastUsed = DateTime.now();

  /// Best-effort liveness check — enough_mail's ImapClient exposes
  /// `isConnected` on some versions. We also check if it's been too
  /// long since last use (server may have closed the connection).
  bool get isAlive {
    try {
      return client.isConnected &&
          DateTime.now().difference(lastUsed) < ImapPool.idleTimeout;
    } catch (_) {
      return false;
    }
  }
}

/// Simple async mutex — serializes async operations without external packages.
///
/// IMAP is a single-stream protocol: if two operations run on the same
/// ImapClient concurrently, their commands interleave and corrupt state
/// (e.g. EXPUNGE runs on the wrong selected mailbox). This mutex ensures
/// only one operation at a time per account.
class _AsyncMutex {
  Future<void>? _last;

  /// Run [fn] after all previous [run] calls complete.
  Future<T> run<T>(Future<T> Function() fn) {
    final prev = _last;
    // Chain: wait for previous operation, then run this one.
    // Use a Completer so we can set _last before awaiting.
    final completer = Completer<void>();
    _last = completer.future;

    return () async {
      if (prev != null) {
        try {
          await prev;
        } catch (_) {
          // Previous operation failed — still run ours
        }
      }
      try {
        return await fn();
      } finally {
        completer.complete();
      }
    }();
  }
}
