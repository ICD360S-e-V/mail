import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// Master password service for app authentication (cross-platform).
///
/// SECURITY: Rate limiting state (`_failedAttempts`, `_lockoutUntil`) is
/// PERSISTED to disk so it survives app restarts. An attacker who can launch
/// the binary cannot bypass the lockout by killing/restarting the process.
///
/// Lockout schedule (exponential — gets progressively harsher):
///   attempts  1-5  → no lockout (free retries for typos)
///   attempts  6-10 → 60-second lockout per failed attempt
///   attempts 11-15 → 5-minute lockout
///   attempts 16-20 → 1-hour lockout
///   attempts 21+   → 24-hour lockout
class MasterPasswordService {
  static String? _passwordHashFilePath;
  static String? _rateLimitFilePath;

  // Rate limit state (persisted to disk in `.master_password_attempts`)
  static int _failedAttempts = 0;
  static DateTime? _lockoutUntil;

  /// Free attempts before lockouts kick in
  static const int _freeAttempts = 5;

  /// Initialize service and load persisted rate limit state
  static Future<void> initialize() async {
    if (_passwordHashFilePath != null) return;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    _passwordHashFilePath = p.join(appDataPath, '.master_password_hash');
    _rateLimitFilePath = p.join(appDataPath, '.master_password_attempts');

    // Create directory if it doesn't exist
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    // Load persisted rate limit state (defends against app-restart bypass)
    await _loadRateLimitState();
  }

  /// Load rate limit state from disk (called on initialize)
  static Future<void> _loadRateLimitState() async {
    try {
      final f = File(_rateLimitFilePath!);
      if (!await f.exists()) return;
      final raw = await f.readAsString();
      final json = jsonDecode(raw) as Map<String, dynamic>;
      _failedAttempts = (json['attempts'] as int?) ?? 0;
      final lockoutMs = json['lockoutUntil'] as int?;
      _lockoutUntil = lockoutMs != null
          ? DateTime.fromMillisecondsSinceEpoch(lockoutMs)
          : null;
      LoggerService.log('AUTH',
          'Rate limit state loaded: $_failedAttempts failed attempts, lockout=${_lockoutUntil ?? "none"}');
    } catch (ex, stackTrace) {
      LoggerService.logError('AUTH', ex, stackTrace);
      // Fall back to defaults — better to lose state than crash
      _failedAttempts = 0;
      _lockoutUntil = null;
    }
  }

  /// Persist rate limit state to disk
  static Future<void> _saveRateLimitState() async {
    try {
      final f = File(_rateLimitFilePath!);
      await f.writeAsString(jsonEncode({
        'attempts': _failedAttempts,
        'lockoutUntil': _lockoutUntil?.millisecondsSinceEpoch,
      }));
    } catch (ex, stackTrace) {
      LoggerService.logError('AUTH', ex, stackTrace);
      // Best effort — if we can't write, the rate limit becomes weaker but
      // we don't want to fail the whole verify call
    }
  }

  /// Compute the lockout duration for the next failed attempt based on
  /// total failed attempts so far. Returns Duration.zero for the first
  /// few "free" attempts.
  static Duration _computeLockoutDuration(int failedAttempts) {
    if (failedAttempts <= _freeAttempts) return Duration.zero;
    if (failedAttempts <= 10) return const Duration(seconds: 60);
    if (failedAttempts <= 15) return const Duration(minutes: 5);
    if (failedAttempts <= 20) return const Duration(hours: 1);
    return const Duration(hours: 24);
  }

  /// Check if master password is set
  static Future<bool> hasMasterPassword() async {
    await initialize();
    final file = File(_passwordHashFilePath!);
    return await file.exists();
  }

  /// Check if account is currently locked out
  static bool isLockedOut() {
    if (_lockoutUntil == null) return false;
    if (DateTime.now().isAfter(_lockoutUntil!)) {
      // Lockout expired — clear it but DO NOT reset the attempt counter.
      // The counter must persist so the next failed attempt uses the
      // correct (escalated) lockout duration.
      _lockoutUntil = null;
      _saveRateLimitState();
      return false;
    }
    return true;
  }

  /// Get remaining lockout seconds
  static int get remainingLockoutSeconds {
    if (_lockoutUntil == null) return 0;
    final remaining = _lockoutUntil!.difference(DateTime.now()).inSeconds;
    return remaining > 0 ? remaining : 0;
  }

  /// Set master password (first-time setup)
  static Future<void> setMasterPassword(String password) async {
    await initialize();
    final hash = _hashPassword(password);
    final file = File(_passwordHashFilePath!);
    await file.writeAsString(hash);
    // Reset rate limit when password is (re)set
    _failedAttempts = 0;
    _lockoutUntil = null;
    await _saveRateLimitState();
    LoggerService.log('AUTH', 'Master password set');
  }

  /// Verify master password with persistent rate limiting
  static Future<bool> verifyMasterPassword(String password) async {
    await initialize();

    // Check rate limiting (uses state loaded from disk)
    if (isLockedOut()) {
      LoggerService.log('AUTH',
          '✗ Account locked — try again in ${remainingLockoutSeconds}s (total failed: $_failedAttempts)');
      return false;
    }

    if (!await hasMasterPassword()) {
      return false;
    }

    try {
      final file = File(_passwordHashFilePath!);
      final savedHash = (await file.readAsString()).trim();

      // Check if it's a salted hash (contains ':') or legacy unsalted
      final salt = _extractSalt(savedHash);
      bool isValid;
      if (salt != null) {
        // Salted hash — use same salt to verify
        final inputHash = _hashPassword(password, salt: salt);
        isValid = savedHash == inputHash;
      } else {
        // Legacy unsalted SHA-256 — verify and migrate to salted
        final legacyBytes = utf8.encode(password);
        final legacyHash = sha256.convert(legacyBytes).toString();
        isValid = savedHash == legacyHash;
        if (isValid) {
          // Migrate to salted hash
          final newHash = _hashPassword(password);
          await file.writeAsString(newHash);
          LoggerService.log('AUTH', '✓ Migrated legacy hash to salted hash');
        }
      }

      if (isValid) {
        _failedAttempts = 0;
        _lockoutUntil = null;
        await _saveRateLimitState();
        LoggerService.log('AUTH', '✓ Password correct');
      } else {
        _failedAttempts++;
        final lockoutDuration = _computeLockoutDuration(_failedAttempts);
        if (lockoutDuration > Duration.zero) {
          _lockoutUntil = DateTime.now().add(lockoutDuration);
          LoggerService.log('AUTH',
              '✗ Password incorrect — account locked for ${lockoutDuration.inSeconds}s (attempt $_failedAttempts)');
        } else {
          LoggerService.log('AUTH',
              '✗ Password incorrect (${_freeAttempts - _failedAttempts} free attempts before lockouts begin)');
        }
        // Persist immediately so a process kill cannot bypass the lockout
        await _saveRateLimitState();
      }
      return isValid;
    } catch (ex, stackTrace) {
      LoggerService.logError('AUTH', ex, stackTrace);
      return false;
    }
  }

  /// Hash password using PBKDF2-like iterated SHA-256 with salt
  /// Uses 100,000 iterations for brute-force resistance
  static String _hashPassword(String password, {String? salt}) {
    final useSalt = salt ?? _generateSalt();
    final saltedPassword = '$useSalt:$password';
    List<int> bytes = utf8.encode(saltedPassword);

    // Iterate SHA-256 100,000 times for key stretching
    for (int i = 0; i < 100000; i++) {
      bytes = sha256.convert(bytes).bytes;
    }

    final hash = sha256.convert(bytes).toString();
    return '$useSalt:$hash';
  }

  /// Generate a cryptographically secure random salt
  static String _generateSalt() {
    final random = Random.secure();
    final saltBytes = List<int>.generate(16, (_) => random.nextInt(256));
    return sha256.convert(saltBytes).toString().substring(0, 16);
  }

  /// Extract salt from stored hash
  static String? _extractSalt(String storedHash) {
    final parts = storedHash.split(':');
    if (parts.length == 2) return parts[0];
    return null; // Legacy unsalted hash
  }
}
