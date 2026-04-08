import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'account_service.dart';
import 'aes_gcm_helpers.dart';
import 'certificate_service.dart';
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

  // Secure storage for the AES-GCM key that protects the persisted
  // rate-limit state file. The key is generated on first run and
  // bound to the OS keystore (Android Keystore TEE / iOS Keychain /
  // Windows Credential Manager / macOS Keychain / Linux libsecret).
  // An attacker with filesystem-only access cannot read or forge the
  // key, so they cannot reset _failedAttempts to bypass the lockout.
  static const FlutterSecureStorage _secureStorage = FlutterSecureStorage();
  static const String _rateLimitKeyName = 'icd360s_rate_limit_state_key_v2';
  static const int _rateLimitVersionByte = 0x02;
  static const Duration _tamperLockoutDuration = Duration(hours: 24);
  static Uint8List? _cachedRateLimitKey;

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
  /// Get-or-create the AES-GCM key used to seal the rate-limit state.
  ///
  /// FAIL-CLOSED: if the platform's secure storage is unavailable
  /// (e.g. Linux without libsecret), we throw rather than fall back
  /// to plain storage. Without an integrity-protected key the entire
  /// rate-limit defense is meaningless — an attacker with filesystem
  /// access could simply reset the counter. Throwing here forces the
  /// caller into the catch branch of _loadRateLimitState which puts
  /// the account into a 24 h lockout (defensive default).
  static Future<Uint8List> _getOrCreateRateLimitKey() async {
    if (_cachedRateLimitKey != null) return _cachedRateLimitKey!;
    String? existingB64;
    try {
      existingB64 = await _secureStorage.read(key: _rateLimitKeyName);
    } on PlatformException catch (e) {
      throw StateError(
          'Secure storage unavailable for rate-limit key: ${e.message}');
    }
    Uint8List key;
    if (existingB64 != null) {
      try {
        key = Uint8List.fromList(base64.decode(existingB64));
      } catch (_) {
        // Stored value is corrupt — regenerate. Old encrypted state
        // becomes unreadable, which trips the tamper-lockout path.
        key = _generateKeyBytes();
        await _secureStorage.write(
            key: _rateLimitKeyName, value: base64.encode(key));
      }
      if (key.length != 32) {
        key = _generateKeyBytes();
        await _secureStorage.write(
            key: _rateLimitKeyName, value: base64.encode(key));
      }
    } else {
      key = _generateKeyBytes();
      await _secureStorage.write(
          key: _rateLimitKeyName, value: base64.encode(key));
    }
    _cachedRateLimitKey = key;
    return key;
  }

  static Uint8List _generateKeyBytes() {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(32, (_) => r.nextInt(256)));
  }

  /// Force a 24 h lockout in response to detected tampering of the
  /// persisted rate-limit state. Saves the new state immediately so
  /// the lockout survives a process kill.
  static Future<void> _enforceTamperLockout(String reason) async {
    LoggerService.log('AUTH',
        '⚠ Rate-limit tamper / corruption detected ($reason) — forcing 24 h lockout');
    _failedAttempts = _freeAttempts + 10;
    _lockoutUntil = DateTime.now().add(_tamperLockoutDuration);
    await _saveRateLimitState();
  }

  static Future<void> _loadRateLimitState() async {
    try {
      final f = File(_rateLimitFilePath!);
      if (!await f.exists()) return;
      final raw = await f.readAsString();

      // Detect format. v1 (legacy) is plain JSON starting with `{`.
      // v2 (current) is base64 of `0x02 || iv || ct+tag`.
      if (raw.trimLeft().startsWith('{')) {
        // Legacy v1 — read directly, then re-save in v2 to upgrade.
        final json = jsonDecode(raw) as Map<String, dynamic>;
        _failedAttempts = (json['attempts'] as int?) ?? 0;
        final lockoutMs = json['lockoutUntil'] as int?;
        _lockoutUntil = lockoutMs != null
            ? DateTime.fromMillisecondsSinceEpoch(lockoutMs)
            : null;
        LoggerService.log('AUTH',
            'Rate limit state loaded (v1, upgrading): $_failedAttempts attempts, lockout=${_lockoutUntil ?? "none"}');
        // Upgrade to v2 in-place. If keystore is unavailable this
        // throws and we fall to the tamper branch below.
        await _saveRateLimitState();
        return;
      }

      // v2: encrypted blob
      final Uint8List key;
      try {
        key = await _getOrCreateRateLimitKey();
      } catch (e) {
        await _enforceTamperLockout('keystore unavailable: $e');
        return;
      }
      final blob = Uint8List.fromList(base64.decode(raw.trim()));
      final plaintext = AesGcmHelpers.decrypt(key, blob,
          expectedVersionByte: _rateLimitVersionByte);
      if (plaintext == null) {
        await _enforceTamperLockout('AES-GCM decrypt failed');
        return;
      }
      final json = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
      _failedAttempts = (json['attempts'] as int?) ?? 0;
      final lockoutMs = json['lockoutUntil'] as int?;
      _lockoutUntil = lockoutMs != null
          ? DateTime.fromMillisecondsSinceEpoch(lockoutMs)
          : null;
      LoggerService.log('AUTH',
          'Rate limit state loaded (v2): $_failedAttempts attempts, lockout=${_lockoutUntil ?? "none"}');
    } catch (ex, stackTrace) {
      // Anything unexpected (parse error, IO, etc.) is treated as
      // tampering — defensive default. Resetting the counter would
      // be exactly what an attacker wants.
      LoggerService.logError('AUTH', ex, stackTrace);
      try {
        await _enforceTamperLockout('unexpected exception: $ex');
      } catch (_) {
        // Last-resort: at least set in-memory lockout so this process
        // session is protected even if writing fails.
        _failedAttempts = _freeAttempts + 10;
        _lockoutUntil = DateTime.now().add(_tamperLockoutDuration);
      }
    }
  }

  /// Persist rate limit state to disk in v2 format (AES-GCM sealed).
  ///
  /// The plaintext is the same JSON the v1 path used. We then encrypt
  /// it with the keystore-bound key and write the base64 of
  /// `0x02 || iv || ct+tag`. An attacker with filesystem-only access
  /// cannot decrypt (no key), cannot forge a valid blob (no key) and
  /// cannot replay an old blob without us detecting at decrypt time
  /// because the IV is freshly generated on every save.
  static Future<void> _saveRateLimitState() async {
    try {
      final key = await _getOrCreateRateLimitKey();
      final plaintext = utf8.encode(jsonEncode({
        'attempts': _failedAttempts,
        'lockoutUntil': _lockoutUntil?.millisecondsSinceEpoch,
      }));
      final blob = AesGcmHelpers.encrypt(
          key, Uint8List.fromList(plaintext),
          versionByte: _rateLimitVersionByte);
      final f = File(_rateLimitFilePath!);
      await f.writeAsString(base64.encode(blob));
    } catch (ex, stackTrace) {
      LoggerService.logError('AUTH', ex, stackTrace);
      // Best effort — if we can't write the lockout becomes weaker
      // but we don't want to crash the verify call. The in-memory
      // counter still applies for the lifetime of this process.
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
    final hash = _hashPasswordPhc(password);
    final file = File(_passwordHashFilePath!);
    await file.writeAsString(hash);
    // Reset rate limit when password is (re)set
    _failedAttempts = 0;
    _lockoutUntil = null;
    await _saveRateLimitState();
    // Unlock the credential session: derives the AES key used to decrypt
    // fallback storage. Without this, fallback passwords are inaccessible.
    await AccountService.unlockSession(password);
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
      bool isValid = false;
      bool needsRehash = false;

      if (savedHash.startsWith(r'$pbkdf2-sha256$')) {
        // PHC format: $pbkdf2-sha256$<iter>$<salt_b64>$<hash_b64>
        final parts = savedHash.split(r'$');
        if (parts.length == 5) {
          final iter = int.tryParse(parts[2]) ?? 0;
          if (iter > 0) {
            try {
              final salt = _b64UrlDecodeNoPad(parts[3]);
              final expected = parts[4];
              final computed = _pbkdf2HashB64(password, salt, iter);
              isValid = _constantTimeEquals(expected, computed);
              if (isValid && iter < _pbkdf2Iterations) {
                needsRehash = true;
              }
            } catch (_) {
              isValid = false;
            }
          }
        }
      } else {
        final salt = _extractSalt(savedHash);
        if (salt != null) {
          // Legacy salted SHA-256 iterated 100k
          final inputHash = _hashPasswordLegacySha256(password, salt: salt);
          isValid = _constantTimeEquals(savedHash, inputHash);
          if (isValid) needsRehash = true;
        } else {
          // Super-legacy unsalted single SHA-256
          final legacyBytes = utf8.encode(password);
          final legacyHash = sha256.convert(legacyBytes).toString();
          isValid = _constantTimeEquals(savedHash, legacyHash);
          if (isValid) needsRehash = true;
        }
      }

      if (isValid && needsRehash) {
        final newHash = _hashPasswordPhc(password);
        await file.writeAsString(newHash);
        LoggerService.log('AUTH',
            '✓ Migrated password hash to PHC pbkdf2-sha256 ($_pbkdf2Iterations iterations)');
      }

      if (isValid) {
        _failedAttempts = 0;
        _lockoutUntil = null;
        await _saveRateLimitState();
        // Unlock the credential session: derives the AES key used to
        // encrypt/decrypt fallback storage. The key is held in memory only
        // until lockSession() is called (auto-lock or explicit logout).
        await AccountService.unlockSession(password);
        // SECURITY (M7): repopulate the in-memory mTLS cert cache
        // from platform secure storage. This narrows the heap-dump
        // window for the client private key from "the entire login
        // session" down to "between unlock and the next lock".
        await CertificateService.restoreFromSecureStorage();
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
  /// Constant-time string comparison.
  ///
  /// Defends against timing side-channel attacks when comparing secret
  /// values such as password hashes. Always inspects every byte of both
  /// inputs (when lengths match) to avoid early-exit timing leaks.
  static bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return diff == 0;
  }

  // ==========================================================================
  // PASSWORD HASHING (PHC pbkdf2-sha256, OWASP 2025 recommended)
  // ==========================================================================

  /// Iteration count for PBKDF2-HMAC-SHA256.
  ///
  /// Per OWASP Password Storage Cheat Sheet (2025), the minimum
  /// recommended iteration count for PBKDF2-SHA256 is 600,000. This
  /// targets ~600ms on modern desktop hardware and ~1-2s on entry-level
  /// mobile — slow enough to thwart offline brute-force, fast enough
  /// to be tolerable on unlock.
  static const int _pbkdf2Iterations = 600000;
  static const int _pbkdf2KeyLength = 32; // 256 bits
  static const int _pbkdf2SaltBytes = 16; // 128 bits

  /// Hash a password using PBKDF2-HMAC-SHA-256 and return a PHC string.
  ///
  /// Output format: `\$pbkdf2-sha256\$<iterations>\$<salt_b64>\$<hash_b64>`
  /// where both `salt_b64` and `hash_b64` are unpadded base64url.
  static String _hashPasswordPhc(String password) {
    final salt = _randomBytes(_pbkdf2SaltBytes);
    final hashB64 = _pbkdf2HashB64(password, salt, _pbkdf2Iterations);
    final saltB64 = _b64UrlEncodeNoPad(salt);
    return '\$pbkdf2-sha256\$$_pbkdf2Iterations\$$saltB64\$$hashB64';
  }

  /// Computes PBKDF2-HMAC-SHA-256 of `password` with `salt` and `iterations`,
  /// returning the unpadded base64url-encoded derived key.
  static String _pbkdf2HashB64(String password, Uint8List salt, int iterations) {
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, iterations, _pbkdf2KeyLength));
    final key = derivator.process(Uint8List.fromList(utf8.encode(password)));
    return _b64UrlEncodeNoPad(key);
  }

  static Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }

  static String _b64UrlEncodeNoPad(Uint8List bytes) {
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  static Uint8List _b64UrlDecodeNoPad(String s) {
    final mod = s.length % 4;
    final padded = mod == 0 ? s : s + ('=' * (4 - mod));
    return Uint8List.fromList(base64Url.decode(padded));
  }

  /// Legacy: SHA-256 iterated 100k with salt prefix `salt:hash`.
  /// Kept ONLY for verifying credentials stored before the PHC migration.
  /// New writes always use [_hashPasswordPhc].
  static String _hashPasswordLegacySha256(String password, {required String salt}) {
    final saltedPassword = '$salt:$password';
    List<int> bytes = utf8.encode(saltedPassword);
    for (int i = 0; i < 100000; i++) {
      bytes = sha256.convert(bytes).bytes;
    }
    final hash = sha256.convert(bytes).toString();
    return '$salt:$hash';
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

