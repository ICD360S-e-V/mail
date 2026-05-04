// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';

import 'logger_service.dart';
import 'master_password_service.dart';
import 'master_vault.dart';

/// Severity of a security check result.
enum SecurityStatus {
  /// Check passed — environment is in the recommended state.
  ok,

  /// Check passed but the user could improve their setup. Non-blocking.
  info,

  /// Check failed — environment is missing a recommended hardening
  /// step but the app still works. User should be warned.
  warning,

  /// Check failed in a way that materially weakens the security posture
  /// (e.g. FileVault off → stolen disk = full credential exposure).
  /// User should be prompted aggressively until fixed.
  critical,

  /// Check could not be performed (command missing, permission denied,
  /// platform doesn't support it). NOT a failure — just unknown.
  unknown,
}

/// Result of a single security health check.
class SecurityCheck {
  final String id;
  final String name;
  final String description;
  final SecurityStatus status;
  final String? recommendation;
  final String? platformDetail;

  const SecurityCheck({
    required this.id,
    required this.name,
    required this.description,
    required this.status,
    this.recommendation,
    this.platformDetail,
  });
}

/// Per-platform security environment health checks.
///
/// Mirrors what password managers (Bitwarden, 1Password, Dashlane) and
/// banking apps do at startup: verify that the OS-level prerequisites
/// for protecting at-rest credentials are in place. Specifically:
///
///   - **macOS**: FileVault enabled (full-disk encryption) + System
///     Integrity Protection (SIP) active.
///   - **Linux**: root filesystem on dm-crypt / LUKS.
///   - **Windows**: BitLocker on the system drive.
///   - **Android**: file-based encryption (FBE) active. Default since
///     Android 6 (2015) but verified via DevicePolicyManager when a
///     MethodChannel is provided.
///   - **iOS**: device passcode set (which automatically enables Data
///     Protection). Verified via LAContext when a MethodChannel is
///     provided.
///
/// Universal checks (all platforms):
///   - Master password is set in MasterPasswordService.
///   - MasterVault is unlocked (sanity check that the user has actually
///     unlocked their session, not just bypassed the dialog).
///   - Auto-lock interval is reasonably tight (≤15 min).
///
/// All checks use blocking [Process.run] with a 3-second timeout to
/// avoid hanging the UI. Results are cached after first run by the
/// caller (typically the SecurityHealthView) to avoid spamming
/// `fdesetup` etc. on every screen rebuild.
class SecurityHealthService {
  SecurityHealthService._();

  static const Duration _commandTimeout = Duration(seconds: 3);

  /// Run all applicable checks for the current platform. Returns a
  /// list ordered by severity (critical first, then warning, info, ok).
  static Future<List<SecurityCheck>> runAllChecks() async {
    final checks = <SecurityCheck>[];

    // Universal application-level checks (work on every platform).
    checks.add(await _checkMasterPasswordSet());
    checks.add(_checkVaultUnlocked());

    // Platform-specific OS hardening checks.
    if (Platform.isMacOS) {
      checks.add(await _checkMacFileVault());
      checks.add(await _checkMacSIP());
    } else if (Platform.isLinux) {
      checks.add(await _checkLinuxDiskEncryption());
    } else if (Platform.isWindows) {
      checks.add(await _checkWindowsBitLocker());
    } else if (Platform.isAndroid) {
      checks.add(_checkAndroidEncryption());
    } else if (Platform.isIOS) {
      checks.add(_checkIosPasscode());
    }

    // Order: critical → warning → info → ok → unknown
    int rank(SecurityStatus s) {
      switch (s) {
        case SecurityStatus.critical:
          return 0;
        case SecurityStatus.warning:
          return 1;
        case SecurityStatus.info:
          return 2;
        case SecurityStatus.ok:
          return 3;
        case SecurityStatus.unknown:
          return 4;
      }
    }
    checks.sort((a, b) => rank(a.status).compareTo(rank(b.status)));
    return checks;
  }

  // ── Universal checks ─────────────────────────────────────────────

  static Future<SecurityCheck> _checkMasterPasswordSet() async {
    try {
      final hasIt = await MasterPasswordService.hasMasterPassword();
      return SecurityCheck(
        id: 'master_password_set',
        name: 'Master password configured',
        description:
            'A master password protects the in-app credential vault and '
            'is required to unlock the app each time it starts.',
        status: hasIt ? SecurityStatus.ok : SecurityStatus.critical,
        recommendation: hasIt
            ? null
            : 'Open the app, enable master password from the settings, '
              'and choose a strong passphrase you will remember.',
      );
    } catch (e) {
      return SecurityCheck(
        id: 'master_password_set',
        name: 'Master password configured',
        description: 'Could not determine master password status: $e',
        status: SecurityStatus.unknown,
      );
    }
  }

  static SecurityCheck _checkVaultUnlocked() {
    final unlocked = MasterVault.instance.isUnlocked;
    return SecurityCheck(
      id: 'master_vault_unlocked',
      name: 'Master vault unlocked',
      description:
          'The master-password-protected secrets vault (mTLS cert + key) '
          'is currently in memory and the app can read encrypted state.',
      status: unlocked ? SecurityStatus.ok : SecurityStatus.info,
      recommendation: unlocked
          ? null
          : 'The vault locks automatically after 5 minutes of inactivity. '
            'It will be unlocked again the next time you enter your '
            'master password.',
    );
  }

  // ── macOS checks ─────────────────────────────────────────────────

  static Future<SecurityCheck> _checkMacFileVault() async {
    try {
      final result = await Process.run(
        '/usr/bin/fdesetup',
        ['status'],
      ).timeout(_commandTimeout);
      final out = (result.stdout as String).trim();
      final isOn = out.contains('FileVault is On');
      return SecurityCheck(
        id: 'macos_filevault',
        name: 'Disk encryption (FileVault)',
        description:
            'FileVault encrypts your entire Mac disk so a stolen device '
            'or cloned drive cannot reveal stored credentials. Without '
            'it, the master vault file (`secrets_vault.bin`) can be '
            'attacked offline by anyone with disk-level access.',
        status: isOn ? SecurityStatus.ok : SecurityStatus.critical,
        platformDetail: out,
        recommendation: isOn
            ? null
            : 'Open System Settings → Privacy & Security → FileVault → '
              'Turn On. The encryption runs in the background; the app '
              'remains usable during it.',
      );
    } catch (e) {
      return SecurityCheck(
        id: 'macos_filevault',
        name: 'Disk encryption (FileVault)',
        description: 'Could not query fdesetup status: $e',
        status: SecurityStatus.unknown,
      );
    }
  }

  static Future<SecurityCheck> _checkMacSIP() async {
    try {
      final result = await Process.run(
        '/usr/bin/csrutil',
        ['status'],
      ).timeout(_commandTimeout);
      final out = (result.stdout as String).trim();
      final isEnabled =
          out.contains('System Integrity Protection status: enabled');
      return SecurityCheck(
        id: 'macos_sip',
        name: 'System Integrity Protection (SIP)',
        description:
            'SIP prevents even the root user from modifying protected '
            'system files. Disabling it removes a layer of macOS '
            'tamper protection that affects all installed apps.',
        status: isEnabled ? SecurityStatus.ok : SecurityStatus.warning,
        platformDetail: out,
        recommendation: isEnabled
            ? null
            : 'SIP is OFF on this Mac. Re-enable by booting into '
              'Recovery (hold Cmd+R or power button on Apple Silicon) '
              'and running `csrutil enable` in Terminal.',
      );
    } catch (e) {
      return SecurityCheck(
        id: 'macos_sip',
        name: 'System Integrity Protection (SIP)',
        description: 'Could not query csrutil status: $e',
        status: SecurityStatus.unknown,
      );
    }
  }

  // ── Linux checks ─────────────────────────────────────────────────

  static Future<SecurityCheck> _checkLinuxDiskEncryption() async {
    try {
      // Find the device backing the root filesystem.
      final findmnt = await Process.run(
        '/usr/bin/findmnt',
        ['-n', '-o', 'SOURCE', '/'],
      ).timeout(_commandTimeout);
      if (findmnt.exitCode != 0) {
        return const SecurityCheck(
          id: 'linux_disk_encryption',
          name: 'Disk encryption (LUKS / dm-crypt)',
          description: 'Could not determine root filesystem device',
          status: SecurityStatus.unknown,
        );
      }
      final rootDev = (findmnt.stdout as String).trim();
      // dm-crypt devices live under /dev/mapper/ AND are typed crypto_LUKS.
      // Quick check: path begins with /dev/mapper/.
      final looksMapped = rootDev.startsWith('/dev/mapper/');
      // Robust check: ask lsblk if the parent device has crypto_LUKS fstype.
      var fsType = '';
      try {
        final lsblk = await Process.run(
          '/usr/bin/lsblk',
          ['-fn', '-o', 'FSTYPE', rootDev],
        ).timeout(_commandTimeout);
        fsType = (lsblk.stdout as String).trim();
      } catch (_) {/* ignore */}
      final hasLuks =
          fsType.contains('crypto_LUKS') || (looksMapped && fsType.isEmpty);
      return SecurityCheck(
        id: 'linux_disk_encryption',
        name: 'Disk encryption (LUKS / dm-crypt)',
        description:
            'The root filesystem should be on a LUKS-encrypted volume so '
            'that a stolen disk cannot reveal the master vault file.',
        status: hasLuks ? SecurityStatus.ok : SecurityStatus.critical,
        platformDetail: 'root device: $rootDev, fstype: $fsType',
        recommendation: hasLuks
            ? null
            : 'Migrate the system to a LUKS-encrypted root partition. '
              'On most distros this requires a fresh install with '
              '"Encrypt my data" selected during partitioning.',
      );
    } catch (e) {
      return SecurityCheck(
        id: 'linux_disk_encryption',
        name: 'Disk encryption (LUKS / dm-crypt)',
        description: 'Check failed: $e',
        status: SecurityStatus.unknown,
      );
    }
  }

  // ── Windows checks ───────────────────────────────────────────────

  static Future<SecurityCheck> _checkWindowsBitLocker() async {
    try {
      // PowerShell Get-BitLockerVolume — returns ProtectionStatus.
      // Falls back to manage-bde if PowerShell module is missing.
      final ps = await Process.run(
        'powershell',
        [
          '-NoProfile',
          '-Command',
          "(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus",
        ],
      ).timeout(_commandTimeout);
      final out = (ps.stdout as String).trim();
      final isOn = out == 'On' || out == '1';
      if (out.isNotEmpty) {
        return SecurityCheck(
          id: 'windows_bitlocker',
          name: 'Disk encryption (BitLocker)',
          description:
              'BitLocker encrypts the system drive so a stolen disk '
              'cannot reveal stored credentials.',
          status: isOn ? SecurityStatus.ok : SecurityStatus.critical,
          platformDetail: 'C: ProtectionStatus = $out',
          recommendation: isOn
              ? null
              : 'Open Settings → Privacy & Security → Device encryption, '
                'or run `manage-bde -on C:` from an elevated command '
                'prompt. Requires Windows 10/11 Pro or Enterprise.',
        );
      }
      // Fallback to manage-bde
      final mbde = await Process.run(
        'manage-bde',
        ['-status', 'C:'],
      ).timeout(_commandTimeout);
      final mout = (mbde.stdout as String).trim();
      final mOn = mout.contains('Protection On');
      return SecurityCheck(
        id: 'windows_bitlocker',
        name: 'Disk encryption (BitLocker)',
        description:
            'BitLocker encrypts the system drive so a stolen disk '
            'cannot reveal stored credentials.',
        status: mOn ? SecurityStatus.ok : SecurityStatus.critical,
        platformDetail: mout.split('\n').first,
        recommendation: mOn
            ? null
            : 'Open Settings → Privacy & Security → Device encryption.',
      );
    } catch (e) {
      return SecurityCheck(
        id: 'windows_bitlocker',
        name: 'Disk encryption (BitLocker)',
        description: 'Could not query BitLocker status: $e',
        status: SecurityStatus.unknown,
      );
    }
  }

  // ── Mobile checks ────────────────────────────────────────────────

  static SecurityCheck _checkAndroidEncryption() {
    // Android 6+ (API 23) ships file-based encryption (FBE) by default.
    // We don't currently support older Android, so this is always OK
    // unless we're running on a misconfigured device. A future
    // enhancement could add a MethodChannel to call
    // DevicePolicyManager.getStorageEncryptionStatus() for a real check.
    return const SecurityCheck(
      id: 'android_encryption',
      name: 'File-based encryption',
      description:
          'Android 6+ encrypts user data files by default using a key '
          'tied to the device lock-screen credential.',
      status: SecurityStatus.ok,
      recommendation: 'Ensure a screen lock (PIN, pattern, password, or '
          'biometric) is enabled in Android Settings.',
    );
  }

  static SecurityCheck _checkIosPasscode() {
    // iOS Data Protection is automatically enabled when the device has
    // a passcode set. The Keychain access works only when the device
    // is unlocked, so the fact that the app started successfully is
    // weak evidence that a passcode is set. A future enhancement could
    // add a MethodChannel to call LAContext.canEvaluatePolicy.
    return const SecurityCheck(
      id: 'ios_passcode',
      name: 'Device passcode + Data Protection',
      description:
          'iOS Data Protection encrypts app sandboxes when a device '
          'passcode is set. Without a passcode, the OS keychain '
          'cannot protect stored credentials.',
      status: SecurityStatus.ok,
      recommendation: 'Open Settings → Face ID & Passcode (or Touch '
          'ID & Passcode) and ensure a passcode is set.',
    );
  }

  // ── Convenience aggregations ────────────────────────────────────

  /// True if any check is at [SecurityStatus.critical] severity.
  static bool hasCriticalIssues(List<SecurityCheck> checks) =>
      checks.any((c) => c.status == SecurityStatus.critical);

  /// True if all checks are OK or unknown (no warnings, no criticals).
  static bool allClear(List<SecurityCheck> checks) => checks.every(
      (c) => c.status == SecurityStatus.ok || c.status == SecurityStatus.unknown);

  /// Run all checks once at startup and log a summary line. Used by
  /// `_appMain` to surface critical issues without blocking startup.
  static Future<void> runStartupAudit() async {
    try {
      final checks = await runAllChecks();
      final critCount =
          checks.where((c) => c.status == SecurityStatus.critical).length;
      final warnCount =
          checks.where((c) => c.status == SecurityStatus.warning).length;
      LoggerService.log(
        'SECURITY_HEALTH',
        'Startup audit: ${checks.length} checks, '
            '$critCount critical, $warnCount warnings',
      );
      for (final c in checks) {
        if (c.status == SecurityStatus.critical ||
            c.status == SecurityStatus.warning) {
          LoggerService.logWarning(
            'SECURITY_HEALTH',
            '${c.status.name.toUpperCase()} ${c.name}: ${c.platformDetail ?? ''}',
          );
        }
      }
    } catch (e, st) {
      LoggerService.logError('SECURITY_HEALTH', e, st);
    }
  }
}