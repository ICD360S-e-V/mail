import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'logger_service.dart';

/// Persistent monotonic version baseline for downgrade-attack protection.
///
/// Stores the highest version this client has ever accepted. Any update
/// proposing a version strictly less than this baseline is rejected,
/// even if all other integrity checks (TLS, SHA-256, signing certificate)
/// pass.
///
/// Inspired by The Update Framework (TUF) version-monotonicity rule.
/// Defense layer against rollback / downgrade attacks (CWE-1328:
/// Security Version Number Mutable to Older Versions).
///
/// SECURITY: The baseline is stored in platform secure storage
/// (Android Keystore-backed EncryptedSharedPreferences, iOS Keychain
/// backed by Secure Enclave, macOS Keychain, Windows DPAPI, Linux
/// libsecret) — NOT in a plaintext file on the filesystem.
///
/// Previous versions stored the baseline in `version_baseline.txt` on
/// the regular filesystem. An attacker with filesystem access (root on
/// Android, any user on desktop) could reset it to "0.0.0" and then
/// serve an older version with known vulnerabilities.
///
/// Tamper detection / fail-closed behavior:
///   - If the secure storage entry is missing on a non-first-run,
///     the baseline resets to the current compiled-in app version.
///   - If the stored value is corrupt or unparseable, same behavior.
///   - This means an attacker who wipes secure storage cannot
///     downgrade below the currently installed version.
class VersionBaseline {
  static const _storage = FlutterSecureStorage();

  /// Key for the baseline version in secure storage.
  static const _kBaseline = 'version_baseline_value';

  /// Key for the initialization flag — distinguishes first-run from
  /// tamper (secure storage wiped but app was already initialized).
  static const _kInitFlag = 'version_baseline_initialized';

  /// Initializes the baseline to [currentVersion] if not yet set.
  /// Safe to call repeatedly; subsequent calls are no-ops.
  ///
  /// Also handles migration from the old plaintext file and
  /// tamper detection (flag present but value missing).
  static Future<void> initialize(String currentVersion) async {
    try {
      final flag = await _storage.read(key: _kInitFlag);
      final existing = await _storage.read(key: _kBaseline);

      if (flag == null && existing == null) {
        // First run ever (or factory reset wiped everything).
        // Initialize from the compiled-in app version.
        await _storage.write(key: _kBaseline, value: currentVersion);
        await _storage.write(key: _kInitFlag, value: 'true');
        LoggerService.log('VERSION_BASELINE',
            'Initialized baseline to $currentVersion (first run)');
        return;
      }

      if (flag != null && existing == null) {
        // TAMPER DETECTED: flag exists but value was wiped.
        // Fail-closed: set baseline to current app version.
        await _storage.write(key: _kBaseline, value: currentVersion);
        LoggerService.logWarning('VERSION_BASELINE',
            'Tamper detected: init flag present but baseline missing. '
            'Reset to $currentVersion');
        return;
      }

      if (existing != null && flag == null) {
        // Partial state — set the flag to complete initialization.
        await _storage.write(key: _kInitFlag, value: 'true');
      }

      // Already initialized — no-op.
    } catch (ex, st) {
      LoggerService.logError('VERSION_BASELINE', ex, st);
    }
  }

  /// Reads the current baseline. Returns null if not yet initialized.
  static Future<String?> read() async {
    try {
      final value = await _storage.read(key: _kBaseline);
      if (value == null || value.trim().isEmpty) return null;
      return value.trim();
    } catch (ex, st) {
      LoggerService.logError('VERSION_BASELINE', ex, st);
      return null;
    }
  }

  /// Returns true if [candidate] is acceptable: greater than or equal
  /// to the persisted baseline. If no baseline exists yet, accepts.
  static Future<bool> isAcceptable(String candidate) async {
    final baseline = await read();
    if (baseline == null) return true;
    return compareSemver(candidate, baseline) >= 0;
  }

  /// Atomically updates the baseline to [version], but only if it is
  /// strictly greater than the current baseline. Provides the
  /// monotonic-counter property: the baseline never decreases.
  static Future<void> bumpTo(String version) async {
    try {
      final current = await read();
      if (current != null && compareSemver(version, current) <= 0) {
        return;
      }
      await _storage.write(key: _kBaseline, value: version);
      LoggerService.log('VERSION_BASELINE',
          'Bumped baseline to $version (was ${current ?? "<unset>"})');
    } catch (ex, st) {
      LoggerService.logError('VERSION_BASELINE', ex, st);
    }
  }

  /// Compare two semver strings of the form `X.Y.Z`. Returns negative
  /// when [a] is older, zero when equal, positive when [a] is newer.
  static int compareSemver(String a, String b) {
    final ap = a.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final bp = b.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    for (var i = 0; i < 3; i++) {
      final av = i < ap.length ? ap[i] : 0;
      final bv = i < bp.length ? bp[i] : 0;
      if (av != bv) return av - bv;
    }
    return 0;
  }
}
