// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import 'certificate_service.dart';
import 'logger_service.dart';
import 'mtls_service.dart';
import 'pinned_security_context.dart';
import 'platform_service.dart';
import 'portable_secure_storage.dart';
import 'update_service.dart';

/// Result of a heartbeat call — used to detect remote device revocation
/// and stale registrations.
///
/// `notRegistered` is returned when the server replies with HTTP 404
/// `device_not_registered`. The client persists this state per-account in
/// secure storage and stops heartbeating for that account until the user
/// re-approves the device — matches the Netflix Eureka / Cloudflare WARP
/// pattern where 404 means "stop polling, re-enroll" instead of retrying
/// forever (RFC: 404 is not a transient error).
enum HeartbeatResult { ok, revoked, error, notRegistered }

/// Client API for the mail-admin backend on mail.icd360s.de.
///
/// Four endpoints:
///   1. POST /api/client/register-device.php  — call on login + after update
///   2. POST /api/client/heartbeat.php        — call every 5 minutes
///   3. GET  /api/client/can-send.php         — call before sending an email
///   4. (no endpoint) detect locked-out via repeated IMAP auth failures
///
/// The backend uses these to:
/// - Restrict accounts to a single device (1 device per username)
/// - Track active sessions for the admin UI
/// - Enforce per-day / per-hour send rate limits
/// - Compute statistics
///
/// The `device_id` is generated once on first run and persisted via
/// PortableSecureStorage so it survives reinstalls within the same OS
/// user account.
class DeviceRegistrationService {
  static const String _registerEndpoint =
      'https://mail.icd360s.de/api/client/register-device.php';
  static const String _heartbeatEndpoint =
      'https://mail.icd360s.de/api/client/heartbeat.php';
  static const String _canSendEndpoint =
      'https://mail.icd360s.de/api/client/can-send.php';

  static const String _kDeviceId = 'icd360s_device_id_v1';
  static const String _kNeedsReapprovalPrefix = 'icd360s_needs_reapproval_';

  static final _storage = PortableSecureStorage.instance;

  /// In-memory cache so we don't hit secure storage on every heartbeat tick.
  /// Loaded lazily on first access via [needsReapproval].
  static final Set<String> _needsReapprovalCache = <String>{};
  static bool _needsReapprovalCacheReady = false;

  /// Returns true if the given account is currently flagged as needing
  /// admin re-approval (server returned 404 device_not_registered on the
  /// last heartbeat attempt). Heartbeat is suppressed for flagged
  /// accounts until [clearNeedsReapproval] is called — typically by the
  /// successful [registerDevice] following an admin approval.
  static Future<bool> needsReapproval(String username) async {
    final clean = username.replaceAll('@icd360s.de', '');
    if (!_needsReapprovalCacheReady) await _loadNeedsReapprovalCache();
    return _needsReapprovalCache.contains(clean);
  }

  /// Snapshot of the in-memory flagged set (loads on first call). Useful
  /// for UI that needs to render all flagged accounts in one pass.
  static Future<Set<String>> snapshotNeedingReapproval() async {
    if (!_needsReapprovalCacheReady) await _loadNeedsReapprovalCache();
    return Set<String>.from(_needsReapprovalCache);
  }

  /// Flag [username] as needing re-approval. Persists across restarts via
  /// secure storage. Idempotent.
  static Future<void> markNeedsReapproval(String username) async {
    final clean = username.replaceAll('@icd360s.de', '');
    if (!_needsReapprovalCacheReady) await _loadNeedsReapprovalCache();
    if (_needsReapprovalCache.add(clean)) {
      await _storage.write(key: '$_kNeedsReapprovalPrefix$clean', value: '1');
    }
  }

  /// Clear the re-approval flag for [username]. Called by [registerDevice]
  /// on success, or by the user after manually re-approving via admin
  /// panel and triggering a fresh registration.
  static Future<void> clearNeedsReapproval(String username) async {
    final clean = username.replaceAll('@icd360s.de', '');
    if (!_needsReapprovalCacheReady) await _loadNeedsReapprovalCache();
    if (_needsReapprovalCache.remove(clean)) {
      await _storage.delete(key: '$_kNeedsReapprovalPrefix$clean');
    }
  }

  /// Best-effort load — secure-storage cursor APIs differ per backend, so
  /// we lazy-load on first access. On any unexpected error, the cache is
  /// left empty and we re-try at the next call; this fails open
  /// (heartbeat continues normally rather than silently suppressing).
  static Future<void> _loadNeedsReapprovalCache() async {
    _needsReapprovalCacheReady = true;
    try {
      final all = await _storage.readAll();
      for (final entry in all.entries) {
        if (entry.key.startsWith(_kNeedsReapprovalPrefix) && entry.value == '1') {
          _needsReapprovalCache
              .add(entry.key.substring(_kNeedsReapprovalPrefix.length));
        }
      }
    } catch (_) {
      // Leave cache empty and silently retry on next call.
    }
  }

  /// Get the persistent device ID, generating one on first call.
  ///
  /// Format: UUID v4 (e.g. `f47ac10b-58cc-4372-a567-0e02b2c3d479`).
  /// Generated using `Random.secure()` so it's cryptographically random.
  static Future<String> getOrCreateDeviceId() async {
    final existing = await _storage.read(key: _kDeviceId);
    if (existing != null && existing.isNotEmpty) {
      return existing;
    }
    final newId = _generateUuidV4();
    await _storage.write(key: _kDeviceId, value: newId);
    LoggerService.log('DEVICE_REG', 'Generated new device ID');
    return newId;
  }

  /// Force-regenerate the device ID. Use sparingly — calling this on a
  /// device that's already registered will cause the backend to see it
  /// as a NEW device, which may trigger the 1-device-per-account
  /// restriction.
  static Future<void> resetDeviceId() async {
    await _storage.delete(key: _kDeviceId);
    LoggerService.logWarning('DEVICE_REG', 'Device ID reset');
  }

  /// Register this device for [username] with [password].
  ///
  /// Called from EmailProvider after a successful authentication.
  /// Returns true on success.
  ///
  /// The backend may return:
  /// - 200 OK with `{"success": true}` — registration accepted
  /// - 200 OK with `{"success": false, "error": "device_limit_reached"}`
  ///   — too many devices on this account
  /// - 401 Unauthorized — wrong password
  /// - other errors — network or server issues
  static Future<DeviceRegistrationResult> registerDevice({
    required String username,
    required String password,
  }) async {
    IOClient? client;
    HttpClient? ioClient;
    try {
      final deviceId = await getOrCreateDeviceId();
      final cleanUsername = username.replaceAll('@icd360s.de', '');
      final platform = PlatformService.instance;

      final payload = <String, dynamic>{
        'username': cleanUsername,
        'password': password,
        'device_id': deviceId,
        'device_name': await _deviceName(),
        'device_type': _deviceType(),
        'os_version': await _osVersion(),
        'hostname': platform.computerName,
        'client_version': UpdateService.currentVersion,
      };

      ioClient = PinnedSecurityContext.createHttpClient()
        ..connectionTimeout = const Duration(seconds: 10)
        ..idleTimeout = const Duration(seconds: 1);
      ioClient.badCertificateCallback = _validateCertificate;
      client = IOClient(ioClient);

      LoggerService.log('DEVICE_REG',
          'Registering device for $cleanUsername (${_deviceType()})...');

      final response = await client
          .post(
            Uri.parse(_registerEndpoint),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 15));

      if (response.statusCode == 401) {
        LoggerService.logWarning('DEVICE_REG',
            'Authentication failed for $cleanUsername (HTTP 401)');
        return DeviceRegistrationResult(
          success: false,
          error: 'unauthorized',
          message: 'Wrong password',
        );
      }

      if (response.statusCode != 200) {
        LoggerService.logWarning('DEVICE_REG',
            'Registration failed: HTTP ${response.statusCode}');
        return DeviceRegistrationResult(
          success: false,
          error: 'http_${response.statusCode}',
          message: 'Server error',
        );
      }

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final ok = data['success'] == true;

      if (ok) {
        // Successful registration clears the needs-reapproval flag so
        // the regular heartbeat loop resumes for this account.
        await clearNeedsReapproval(username);
        LoggerService.log('DEVICE_REG',
            'Device registered successfully for $cleanUsername');
        return DeviceRegistrationResult(success: true);
      }

      final errCode = (data['error'] as String?) ?? 'unknown';
      final errMsg = (data['message'] as String?) ?? 'Registration rejected';
      LoggerService.logWarning('DEVICE_REG',
          'Backend rejected: $errCode — $errMsg');
      return DeviceRegistrationResult(
        success: false,
        error: errCode,
        message: errMsg,
      );
    } catch (ex, stackTrace) {
      LoggerService.logError('DEVICE_REG', ex, stackTrace);
      return DeviceRegistrationResult(
        success: false,
        error: 'exception',
        message: ex.toString(),
      );
    } finally {
      try {
        client?.close();
      } catch (_) {}
      try {
        ioClient?.close(force: true);
      } catch (_) {}
    }
  }

  /// Send a heartbeat to the backend so it knows this device is still
  /// active. Should be called every 5 minutes while the app is open.
  ///
  /// Fire-and-forget: errors are logged but never surfaced to the user.
  /// Returns true on success.
  ///
  /// In v2.28.0+ this prefers the mTLS path: if a per-user client cert
  /// is loaded into [CertificateService], the request is sent via
  /// [MtlsService.createMtlsHttpClient] (cert presented at TLS
  /// handshake) and the body carries `timestamp` + `nonce` for replay
  /// protection. The server uses the cert CN as the authoritative
  /// username and ignores any username field in the body.
  ///
  /// If the cert is not yet available (e.g., before login completes),
  /// falls back to the legacy v2.27.x path with `username` in the body
  /// and no replay protection. The server-side endpoint accepts both
  /// during the v2.27 → v2.28 transition.
  /// Serializing queue so heartbeats fired from multiple call-sites
  /// (initial registration loop + the 5-min Timer.periodic) chain
  /// instead of racing into nginx's `limit_req zone=api burst=10`. Each
  /// heartbeat waits for the previous to complete, then sleeps 200 ms
  /// before starting — 5 req/s sustained, well under the limit even
  /// with a 50-account session.
  static Future<void> _heartbeatChain = Future<void>.value();
  static const _heartbeatSpacing = Duration(milliseconds: 200);

  static Future<HeartbeatResult> sendHeartbeat({required String username}) async {
    // Suppress heartbeat for accounts the server has already told us are
    // not registered (HTTP 404 device_not_registered). Retrying every 5
    // min spams the server and the client log without doing anything
    // useful — re-registration is the only path back. The flag clears
    // automatically on a successful registerDevice().
    if (await needsReapproval(username)) {
      return HeartbeatResult.notRegistered;
    }
    final previous = _heartbeatChain;
    final ticket = Completer<void>();
    _heartbeatChain = ticket.future;
    try {
      await previous;
      await Future<void>.delayed(_heartbeatSpacing);
      return await _doSendHeartbeat(username: username);
    } finally {
      ticket.complete();
    }
  }

  static Future<HeartbeatResult> _doSendHeartbeat({required String username}) async {
    IOClient? client;
    HttpClient? ioClient;
    try {
      final deviceId = await getOrCreateDeviceId();
      final cleanUsername = username.replaceAll('@icd360s.de', '');

      // Per-account mTLS: load the matching cert from secure storage
      // into a cached SecurityContext (no mutation of the singleton
      // "current user"). If the bundle is missing, fall through to the
      // legacy username-in-body path — the server still accepts it
      // during the v2.27 → v3.0 transition.
      ioClient = await MtlsService.createMtlsHttpClientFor(username: username);
      final useMtls = ioClient != null;

      final payload = <String, dynamic>{
        'device_id': deviceId,
      };
      if (useMtls) {
        // NEW PATH: server takes username from cert CN, body has freshness
        payload['timestamp'] = DateTime.now().toUtc().toIso8601String();
        payload['nonce'] = _randomHex16();
      } else {
        // LEGACY PATH: server accepts username from body
        payload['username'] = cleanUsername;
        payload['last_seen'] = DateTime.now().toUtc().toIso8601String();
      }

      if (ioClient == null) {
        ioClient = PinnedSecurityContext.createHttpClient()
          ..connectionTimeout = const Duration(seconds: 5)
          ..idleTimeout = const Duration(seconds: 1);
        ioClient.badCertificateCallback = _validateCertificate;
      }
      client = IOClient(ioClient);

      final response = await client
          .post(
            Uri.parse(_heartbeatEndpoint),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 8));

      if (response.statusCode == 200) {
        // Parse response body for revocation signal
        try {
          final body = jsonDecode(response.body) as Map<String, dynamic>;
          if (body['status'] == 'revoked') {
            LoggerService.logWarning('DEVICE_REG',
                '🔴 DEVICE REVOKED by administrator for $cleanUsername');
            return HeartbeatResult.revoked;
          }
        } catch (_) {/* non-JSON or old server — treat as ok */}
        if (useMtls) {
          LoggerService.logDebug('DEVICE_REG', 'Heartbeat OK (mTLS)');
        }
        return HeartbeatResult.ok;
      }

      // 404 device_not_registered: this account never had a device
      // record on the server, or it was deleted. Treat as permanent
      // (404 ≠ transient per RFC 7231) — flag for re-approval and stop
      // heartbeating until the user re-registers.
      if (response.statusCode == 404) {
        String? errCode;
        try {
          final body = jsonDecode(response.body) as Map<String, dynamic>;
          errCode = body['error'] as String?;
        } catch (_) {/* non-JSON */}
        if (errCode == 'device_not_registered') {
          await markNeedsReapproval(username);
          LoggerService.logWarning('DEVICE_REG',
              '🔶 Account $cleanUsername needs re-approval — heartbeat paused (mtls=$useMtls)');
          return HeartbeatResult.notRegistered;
        }
      }

      LoggerService.logWarning('DEVICE_REG',
          'Heartbeat failed for $cleanUsername: HTTP ${response.statusCode} (mtls=$useMtls)');
      return HeartbeatResult.error;
    } catch (ex) {
      LoggerService.logWarning('DEVICE_REG', 'Heartbeat error: $ex');
      return HeartbeatResult.error;
    } finally {
      try {
        client?.close();
      } catch (_) {}
      try {
        ioClient?.close(force: true);
      } catch (_) {}
    }
  }

  /// Generate 16 bytes of cryptographically secure random hex (32 chars).
  /// Used as the nonce for replay protection on cert-authenticated API
  /// calls (heartbeat, can-send) in v2.28.0+.
  static String _randomHex16() {
    final r = Random.secure();
    return List<int>.generate(16, (_) => r.nextInt(256))
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  /// Check whether the given user is allowed to send an email right now.
  ///
  /// Called from compose flow before SMTP send. Returns the current
  /// allowance + remaining counters so the UI can show:
  /// - Hard block if `allowed == false`
  /// - Yellow warning if `remainingHour < 2` or `remainingDay < 5`
  ///
  /// On any network/server error, fail OPEN (return allowed=true with
  /// unknown counters) — we don't want a server outage to block users
  /// from sending mail. The IMAP/SMTP layer is the real authority.
  static Future<CanSendResult> canSend({required String username}) async {
    IOClient? client;
    HttpClient? ioClient;
    try {
      final cleanUsername = username.replaceAll('@icd360s.de', '');
      final useMtls = CertificateService.hasCertificates &&
          CertificateService.currentUsername == username;

      // NEW PATH (v2.28.0+, B1 from audit): POST + mTLS + freshness.
      // LEGACY PATH (v2.27.x): GET ?username=
      http.Response response;
      if (useMtls) {
        ioClient = MtlsService.createMtlsHttpClient();
      }
      if (ioClient == null) {
        ioClient = PinnedSecurityContext.createHttpClient()
          ..connectionTimeout = const Duration(seconds: 5)
          ..idleTimeout = const Duration(seconds: 1);
        ioClient.badCertificateCallback = _validateCertificate;
      }
      client = IOClient(ioClient);

      if (useMtls) {
        final body = <String, dynamic>{
          'timestamp': DateTime.now().toUtc().toIso8601String(),
          'nonce': _randomHex16(),
        };
        response = await client
            .post(
              Uri.parse(_canSendEndpoint),
              headers: {'Content-Type': 'application/json'},
              body: jsonEncode(body),
            )
            .timeout(const Duration(seconds: 8));
      } else {
        final uri = Uri.parse(_canSendEndpoint).replace(queryParameters: {
          'username': cleanUsername,
        });
        response = await client.get(uri).timeout(const Duration(seconds: 8));
      }

      if (response.statusCode != 200) {
        LoggerService.logWarning('DEVICE_REG',
            'can-send check failed: HTTP ${response.statusCode} (mtls=$useMtls, failing open)');
        return const CanSendResult.unknown();
      }

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      return CanSendResult(
        allowed: data['allowed'] == true,
        remainingDay: (data['remaining_today'] as num?)?.toInt(),
        remainingHour: (data['remaining_hour'] as num?)?.toInt(),
        message: data['message'] as String?,
      );
    } catch (ex) {
      LoggerService.logWarning('DEVICE_REG',
          'can-send error (failing open): $ex');
      return const CanSendResult.unknown();
    } finally {
      try {
        client?.close();
      } catch (_) {}
      try {
        ioClient?.close(force: true);
      } catch (_) {}
    }
  }

  // ── helpers ──────────────────────────────────────────────────

  /// Validate server certificate against trusted Let's Encrypt issuers.
  /// Same pattern as certificate_service / log_upload_service.
  static bool _validateCertificate(
      X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    return MtlsService.onBadCertificate(cert, host);
  }

  /// Generate a UUID v4 using Random.secure().
  /// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
  /// where y is one of [8,9,a,b].
  static String _generateUuidV4() {
    final r = Random.secure();
    final bytes = List<int>.generate(16, (_) => r.nextInt(256));
    // Set version (4) and variant (RFC 4122) bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10xx

    String hex(int b) => b.toRadixString(16).padLeft(2, '0');
    final h = bytes.map(hex).toList();
    return '${h[0]}${h[1]}${h[2]}${h[3]}-'
        '${h[4]}${h[5]}-'
        '${h[6]}${h[7]}-'
        '${h[8]}${h[9]}-'
        '${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}';
  }

  /// Human-readable device name from hardware model (no PII).
  ///
  /// GDPR Article 25 — data minimization: hostname often contains the
  /// user's real name (e.g. "MacBook-de-Marcel.local"). Industry
  /// standard (Proton, Tuta, 1Password, Bitwarden) is to show hardware
  /// model instead. The admin sees "MacBook Pro" not "Marcel's MacBook".
  static Future<String> _deviceName() async {
    try {
      if (Platform.isMacOS) {
        final r = await Process.run('/usr/sbin/sysctl', ['-n', 'hw.model'])
            .timeout(const Duration(seconds: 2));
        if (r.exitCode == 0) {
          final model = (r.stdout as String).trim();
          if (model.isNotEmpty) return _friendlyMacModel(model);
        }
      } else if (Platform.isLinux) {
        final f = File('/sys/class/dmi/id/product_name');
        if (await f.exists()) {
          final v = (await f.readAsString()).trim();
          if (v.isNotEmpty && !v.startsWith('To Be Filled')) return v;
        }
      } else if (Platform.isWindows) {
        final r = await Process.run('wmic', ['csproduct', 'get', 'name'])
            .timeout(const Duration(seconds: 2));
        if (r.exitCode == 0) {
          final lines = (r.stdout as String).split('\n')
              .map((l) => l.trim())
              .where((l) => l.isNotEmpty && l != 'Name')
              .toList();
          if (lines.isNotEmpty) return lines.first;
        }
      }
    } catch (_) {/* fall through */}
    return _deviceType();
  }

  /// Convert macOS sysctl model ID to friendly name.
  static String _friendlyMacModel(String sysctl) {
    // e.g. "MacBookPro18,3" → "MacBook Pro"
    //      "Macmini9,1"     → "Mac mini"
    //      "MacBookAir10,1" → "MacBook Air"
    //      "Mac14,2"        → "Mac"
    if (sysctl.startsWith('MacBookPro')) return 'MacBook Pro';
    if (sysctl.startsWith('MacBookAir')) return 'MacBook Air';
    if (sysctl.startsWith('MacBook')) return 'MacBook';
    if (sysctl.startsWith('Macmini')) return 'Mac mini';
    if (sysctl.startsWith('MacPro')) return 'Mac Pro';
    if (sysctl.startsWith('iMac')) return 'iMac';
    if (sysctl.startsWith('Mac')) return 'Mac';
    return sysctl; // fallback: raw model ID
  }

  /// Device type identifier matching what the backend expects.
  static String _deviceType() {
    if (Platform.isMacOS) return 'macos';
    if (Platform.isWindows) return 'windows';
    if (Platform.isLinux) return 'linux';
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    return 'unknown';
  }

  /// Public helper that gathers all device-identification fields the
  /// server expects, in one structured object. Used by both the legacy
  /// password-based [registerDevice] flow and the v2.27.0+ passwordless
  /// approval flow ([DeviceApprovalService.requestAccess]).
  ///
  /// Fields:
  ///  - `device_id`     — UUID v4, persisted in PortableSecureStorage
  ///  - `device_name`   — hardware model (no PII) or platform string
  ///  - `device_type`   — macos / windows / linux / android / ios
  ///  - `os_version`    — best-effort OS version string
  ///  - `hostname`      — raw hostname (admin security audit — detect device changes)
  ///  - `client_version`— current app version from UpdateService
  static Future<Map<String, String>> gatherDeviceInfo() async {
    final platform = PlatformService.instance;
    return {
      'device_id': await getOrCreateDeviceId(),
      'device_name': await _deviceName(),
      'device_type': _deviceType(),
      'os_version': await _osVersion(),
      'hostname': platform.computerName,
      'client_version': UpdateService.currentVersion,
    };
  }

  /// Best-effort OS version string. Uses platform-specific commands
  /// where available, falls back to `Platform.operatingSystemVersion`.
  static Future<String> _osVersion() async {
    try {
      if (Platform.isMacOS) {
        final result =
            await Process.run('/usr/bin/sw_vers', ['-productVersion']).timeout(
          const Duration(seconds: 2),
        );
        if (result.exitCode == 0) {
          final v = (result.stdout as String).trim();
          return 'macOS $v';
        }
      } else if (Platform.isLinux) {
        final result = await Process.run('/usr/bin/uname', ['-rs']).timeout(
          const Duration(seconds: 2),
        );
        if (result.exitCode == 0) {
          return (result.stdout as String).trim();
        }
      }
    } catch (_) {/* fall through */}
    return Platform.operatingSystemVersion;
  }
}

/// Result of a device registration attempt.
class DeviceRegistrationResult {
  final bool success;
  final String? error;
  final String? message;

  const DeviceRegistrationResult({
    required this.success,
    this.error,
    this.message,
  });

  /// True if the failure was due to the 1-device-per-account limit.
  bool get isDeviceLimitReached =>
      !success &&
      (error == 'device_limit_reached' || error == 'too_many_devices');
}

/// Result of a can-send check. When the server is unreachable we
/// "fail open" — `allowed=true` with unknown counters — so a server
/// outage cannot prevent users from sending mail.
class CanSendResult {
  final bool allowed;
  final int? remainingDay;
  final int? remainingHour;
  final String? message;
  final bool isUnknown;

  const CanSendResult({
    required this.allowed,
    this.remainingDay,
    this.remainingHour,
    this.message,
  }) : isUnknown = false;

  const CanSendResult.unknown()
      : allowed = true,
        remainingDay = null,
        remainingHour = null,
        message = null,
        isUnknown = true;

  /// True if the user is approaching their daily/hourly limit.
  /// UI should show a yellow warning.
  bool get isLowQuota =>
      allowed &&
      ((remainingHour != null && remainingHour! < 2) ||
          (remainingDay != null && remainingDay! < 5));
}