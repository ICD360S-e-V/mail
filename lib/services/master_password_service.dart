import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/services.dart' show PlatformException;
import 'package:path/path.dart' as p;
import 'account_service.dart';
import 'aes_gcm_helpers.dart';
import 'certificate_service.dart';
import 'logger_service.dart';
import 'master_vault.dart';
import 'portable_secure_storage.dart';
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
  // PortableSecureStorage uses native storage on iOS/Android/Windows/
  // Linux and AES-GCM file backend on macOS (Keychain unavailable on
  // ad-hoc signed builds).
  static final _secureStorage = PortableSecureStorage.instance;
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

    // Legacy hash wrapping removed — app reset clears all old formats.
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

  /// Argon2id salt length — matches MasterVault parameters.
  static const int _argon2SaltBytes = 16;

  /// Set master password (first-time setup).
  ///
  /// Single-derivation pattern (Bitwarden architecture):
  ///   Argon2id(password, salt) → masterKey
  ///     ├── HKDF(info="auth-hash")  → authHash  (stored on disk)
  ///     └── HKDF(info="vault-kek")  → KEK       (MasterVault)
  static Future<void> setMasterPassword(String password) async {
    await initialize();

    // Generate fresh Argon2id salt for this account.
    final salt = _randomBytes(_argon2SaltBytes);

    // ONE Argon2id call — all sub-keys derived from masterKey.
    final vault = MasterVault.instance;
    final masterKey = await vault.deriveMasterKey(password, salt);

    // Derive auth hash via HKDF (cheap — one HMAC round).
    final authHash = await vault.deriveAuthHash(masterKey);

    // Store salt + authHash in Argon2id PHC format.
    final phc = _encodeArgon2idPhc(salt: salt, hash: authHash);
    final file = File(_passwordHashFilePath!);
    await file.writeAsString(phc);

    // Best-effort zero masterKey from our heap.
    for (var i = 0; i < masterKey.length; i++) {
      masterKey[i] = 0;
    }

    // Reset rate limit when password is (re)set.
    _failedAttempts = 0;
    _lockoutUntil = null;
    await _saveRateLimitState();

    // Unlock credential session + MasterVault.
    await AccountService.unlockSession(password);
    try {
      await vault.unlock(password);
    } catch (ex, st) {
      LoggerService.logError('AUTH', ex, st);
    }
    LoggerService.log('AUTH', 'Master password set (Argon2id)');
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

      bool isValid = false;

      if (savedHash.startsWith(r'$argon2id$')) {
        // Argon2id PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        final parsed = _parseArgon2idPhc(savedHash);
        if (parsed != null) {
          final vault = MasterVault.instance;
          final masterKey =
              await vault.deriveMasterKey(password, parsed.salt);
          final authHash = await vault.deriveAuthHash(masterKey);
          // Best-effort zero masterKey.
          for (var i = 0; i < masterKey.length; i++) {
            masterKey[i] = 0;
          }
          isValid = _constantTimeEqualsBytes(authHash, parsed.hash);
        }
      }
      // All legacy formats (PBKDF2, SHA-256, wrapped) are no longer
      // supported — app reset required for the Argon2id upgrade.

      if (isValid) {
        _failedAttempts = 0;
        _lockoutUntil = null;
        await _saveRateLimitState();
        // Unlock the credential session: derives the AES key used to
        // encrypt/decrypt fallback storage. The key is held in memory only
        // until lockSession() is called (auto-lock or explicit logout).
        await AccountService.unlockSession(password);
        // SECURITY (B5, v2.30.0): unlock the master vault. This derives
        // the per-vault KEK from the master password + IOPlatformUUID
        // via Argon2id+HKDF, decrypts the on-disk vault file, and runs
        // the one-time migration of legacy mTLS cert/key from
        // PortableSecureStorage to the password-locked MasterVault.
        // MUST run BEFORE CertificateService.restoreFromSecureStorage()
        // so that the cert is in the new vault before the cache pull.
        try {
          await MasterVault.instance.unlock(password);
        } catch (vaultEx, vaultSt) {
          LoggerService.logError('AUTH', vaultEx, vaultSt);
          // Don't fail the password verification on vault unlock errors
          // — the user might have just upgraded and have a corrupted
          // vault. The CertificateService fallback path will handle it.
        }
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


  // ==========================================================================
  // ARGON2ID PASSWORD HASHING (Bitwarden single-derivation pattern)
  // ==========================================================================
  //
  // Architecture: ONE Argon2id call per unlock → masterKey [32 bytes]
  //   ├── HKDF(info="auth-hash")  → authHash  (stored on disk for verification)
  //   └── HKDF(info="vault-kek")  → KEK       (MasterVault, via _deriveKEK)
  //
  // The expensive Argon2id runs once (~600ms desktop, ~1-2s mobile).
  // HKDF-Expand is one HMAC round — microseconds.
  //
  // Matches Bitwarden's dual-use pattern: a single KDF call fans out
  // into auth hash + encryption key via cheap secondary derivations.
  // See: https://bitwarden.com/help/bitwarden-security-white-paper/

  /// Encode salt + hash into standard Argon2id PHC string format.
  ///
  /// Output: `$argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>`
  /// Uses standard base64 (not url-safe) without padding, per PHC spec.
  static String _encodeArgon2idPhc({
    required Uint8List salt,
    required Uint8List hash,
  }) {
    final saltB64 = base64.encode(salt).replaceAll('=', '');
    final hashB64 = base64.encode(hash).replaceAll('=', '');
    // Parameters match MasterVault._argon2* constants.
    return '\$argon2id\$v=19\$m=65536,t=3,p=4\$$saltB64\$$hashB64';
  }

  /// Parse an Argon2id PHC string. Returns null if format is invalid.
  static ({Uint8List salt, Uint8List hash})? _parseArgon2idPhc(String phc) {
    // Expected: ['', 'argon2id', 'v=19', 'm=65536,t=3,p=4', salt, hash]
    final parts = phc.split(r'$');
    if (parts.length != 6 || parts[1] != 'argon2id') return null;
    try {
      final salt = _b64DecodeNoPad(parts[4]);
      final hash = _b64DecodeNoPad(parts[5]);
      return (salt: salt, hash: hash);
    } catch (_) {
      return null;
    }
  }

  /// Constant-time comparison for byte arrays.
  static bool _constantTimeEqualsBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  static Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }

  /// Standard base64 decode without padding (PHC spec uses standard, not url-safe).
  static Uint8List _b64DecodeNoPad(String s) {
    final mod = s.length % 4;
    final padded = mod == 0 ? s : s + ('=' * (4 - mod));
    return Uint8List.fromList(base64.decode(padded));
  }
}

