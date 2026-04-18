import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/io_client.dart';

import 'certificate_service.dart';
import '../services/le_issuer_check.dart';
import 'logger_service.dart';
import 'pinned_security_context.dart';

/// Status returned by the polling endpoint.
enum ApprovalStatus {
  /// Admin has not yet acted on the request.
  pending,

  /// Admin approved — `oneTimeToken` is set, ready to download cert.
  approved,

  /// Admin actively rejected the request.
  rejected,

  /// 5-minute window passed without admin action.
  expired,

  /// Server doesn't know this request_id (404).
  notFound,

  /// Network or parsing failure — caller should retry the poll.
  unknown,
}

/// Result of submitting an access request.
class AccessRequestResult {
  final bool success;
  final String? requestId;
  final String? error;
  final String? message;

  /// True if the user already has at least one approved device on the
  /// server. The admin will see a "TRANSFER" badge in mail-admin and
  /// approving will revoke the old device's cert (per the design in
  /// CLAUDE.md §11 A3 phase 3).
  final bool isTransfer;

  /// How often the client should poll `check-device-status.php`.
  final int pollIntervalSeconds;

  /// How long until the request auto-expires server-side.
  final int expiresInSeconds;

  /// If `error == "rate_limited"`, seconds until the user may retry.
  final int? retryAfterSeconds;

  /// Set when the server auto-approved (same device_id already registered).
  final bool autoApproved;
  final String? oneTimeToken;

  AccessRequestResult({
    required this.success,
    this.requestId,
    this.error,
    this.message,
    this.isTransfer = false,
    this.pollIntervalSeconds = 5,
    this.expiresInSeconds = 300,
    this.retryAfterSeconds,
    this.autoApproved = false,
    this.oneTimeToken,
  });

  bool get isRateLimited => error == 'rate_limited';
  bool get isUnknownUser => error == 'unknown_user';
  bool get isInvalidUsername => error == 'invalid_username';
}

/// Result of polling for status updates.
class StatusPoll {
  final ApprovalStatus status;
  final String? oneTimeToken;
  final int? tokenExpiresInSeconds;
  StatusPoll(this.status, {this.oneTimeToken, this.tokenExpiresInSeconds});
}

/// Cert payload returned by `download-cert.php`.
class CertBundle {
  final String username;
  final String clientCert;
  final String clientKey;
  final String caCert;
  CertBundle({
    required this.username,
    required this.clientCert,
    required this.clientKey,
    required this.caCert,
  });
}

/// Faza 3 — passwordless device enrollment via admin push approval.
///
/// This service handles the client side of the new add-account flow:
///
///   1. [requestAccess] — submit username + device info, get request_id
///   2. [pollStatus] — Stream<StatusPoll> emitted every 5s until terminal
///      state (approved/rejected/expired/notFound) or [stop] is called
///   3. [downloadCert] — fetch the cert+key with the one_time_token
///      returned alongside an approved status
///
/// After [downloadCert] returns a [CertBundle], the caller (add-account
/// UI) writes it to [PortableSecureStorage] using the same keys as
/// [CertificateService] so the rest of the app can use the cert
/// transparently.
///
/// **No password ever** crosses any of these endpoints. The only auth
/// from client → server is:
///   - For request submission: nothing (the admin's manual approval is
///     the trust anchor)
///   - For status polling: the request_id (a UUID v4 unguessable in
///     practice, returned only to the original requester)
///   - For cert download: the one_time_token (32-byte random hex,
///     single-use, expires 10 min after approval)
///
/// Server endpoints (deployed on mail.icd360s.de):
///   - POST /api/client/request-access.php
///   - GET  /api/client/check-device-status.php?request_id=...
///   - GET  /api/client/download-cert.php?request_id=...&token=...
class DeviceApprovalService {
  DeviceApprovalService._();

  static const String _baseUrl = 'https://mail.icd360s.de/api/client';
  static const Duration _httpTimeout = Duration(seconds: 15);

  static IOClient _newClient() {
    final http = PinnedSecurityContext.createHttpClient()
      ..connectionTimeout = const Duration(seconds: 10)
      ..idleTimeout = const Duration(seconds: 5);
    http.badCertificateCallback = (cert, host, port) =>
        host == 'mail.icd360s.de' && isTrustedLetsEncryptIssuer(cert.issuer);
    return IOClient(http);
  }

  /// Submit a passwordless access request to the server.
  ///
  /// On success the returned [AccessRequestResult.requestId] should be
  /// passed to [pollStatus] and (eventually) [downloadCert].
  ///
  /// On `isRateLimited == true`, the user is being throttled — typically
  /// the UI should show "wait X seconds" with a countdown derived from
  /// [AccessRequestResult.retryAfterSeconds].
  ///
  /// [username] must be the full email (`<user>@icd360s.de`); the
  /// server validates the domain and rejects anything else.
  static Future<AccessRequestResult> requestAccess({
    required String username,
    required String deviceId,
    required String deviceName,
    required String deviceType,
    required String osVersion,
    required String clientVersion,
    required String hostname,
  }) async {
    LoggerService.log('APPROVAL',
        'Submitting access request for $username (device $deviceId)');
    final client = _newClient();
    try {
      final response = await client.post(
        Uri.parse('$_baseUrl/request-access.php'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'username': username,
          'device_id': deviceId,
          'device_name': deviceName,
          'device_type': deviceType,
          'os_version': osVersion,
          'client_version': clientVersion,
          'hostname': hostname,
        }),
      ).timeout(_httpTimeout);

      if (response.statusCode == 400) {
        final body = jsonDecode(response.body) as Map<String, dynamic>;
        final err = body['error']?.toString() ?? 'bad_request';
        LoggerService.logWarning('APPROVAL', 'Server rejected request: $err');
        return AccessRequestResult(success: false, error: err);
      }
      if (response.statusCode == 404) {
        LoggerService.logWarning('APPROVAL', 'Unknown user $username');
        return AccessRequestResult(success: false, error: 'unknown_user');
      }
      if (response.statusCode != 200) {
        LoggerService.logWarning('APPROVAL',
            'HTTP ${response.statusCode}: ${response.body}');
        return AccessRequestResult(
            success: false,
            error: 'http_${response.statusCode}',
            message: response.body);
      }

      final body = jsonDecode(response.body) as Map<String, dynamic>;
      if (body['success'] == true) {
        final requestId = body['request_id']?.toString();
        if (requestId == null || requestId.isEmpty) {
          return AccessRequestResult(
              success: false, error: 'no_request_id');
        }
        final isAutoApproved = body['auto_approved'] == true;
        final token = body['one_time_token']?.toString();
        LoggerService.log('APPROVAL',
            'Request accepted: $requestId (transfer=${body['is_transfer']}'
            '${isAutoApproved ? ", auto-approved" : ""})');
        return AccessRequestResult(
          success: true,
          requestId: requestId,
          isTransfer: body['is_transfer'] == true,
          pollIntervalSeconds:
              (body['poll_interval_seconds'] as num?)?.toInt() ?? 5,
          expiresInSeconds:
              (body['expires_in_seconds'] as num?)?.toInt() ?? 300,
          autoApproved: isAutoApproved,
          oneTimeToken: token,
        );
      }

      final err = body['error']?.toString() ?? 'unknown';
      LoggerService.logWarning('APPROVAL', 'Request denied: $err');
      return AccessRequestResult(
        success: false,
        error: err,
        message: body['message']?.toString(),
        retryAfterSeconds: (body['retry_after'] as num?)?.toInt(),
      );
    } catch (e, st) {
      LoggerService.logError('APPROVAL', e, st);
      return AccessRequestResult(success: false, error: 'network_error');
    } finally {
      client.close();
    }
  }

  /// Poll the server every [pollInterval] seconds until a terminal
  /// state is reached or [maxDuration] elapses. Yields each [StatusPoll]
  /// so the UI can show "still waiting..." vs final state.
  ///
  /// The stream completes naturally on terminal status (approved /
  /// rejected / expired / notFound) or on [maxDuration] timeout (which
  /// emits an [ApprovalStatus.expired] poll and closes).
  static Stream<StatusPoll> pollStatus(
    String requestId, {
    Duration pollInterval = const Duration(seconds: 5),
    Duration maxDuration = const Duration(minutes: 5, seconds: 30),
  }) async* {
    final deadline = DateTime.now().add(maxDuration);
    var consecutiveFailures = 0;
    while (true) {
      if (DateTime.now().isAfter(deadline)) {
        LoggerService.log('APPROVAL', 'Polling deadline reached, expiring');
        yield StatusPoll(ApprovalStatus.expired);
        return;
      }
      final poll = await _pollOnce(requestId);
      yield poll;
      switch (poll.status) {
        case ApprovalStatus.approved:
        case ApprovalStatus.rejected:
        case ApprovalStatus.expired:
        case ApprovalStatus.notFound:
          // Terminal — caller will react and stop the stream.
          return;
        case ApprovalStatus.unknown:
          consecutiveFailures++;
          if (consecutiveFailures >= 6) {
            LoggerService.logWarning('APPROVAL',
                '6 consecutive poll failures — giving up');
            yield StatusPoll(ApprovalStatus.expired);
            return;
          }
          break;
        case ApprovalStatus.pending:
          consecutiveFailures = 0;
          break;
      }
      await Future.delayed(pollInterval);
    }
  }

  static Future<StatusPoll> _pollOnce(String requestId) async {
    final client = _newClient();
    try {
      final response = await client
          .get(Uri.parse(
              '$_baseUrl/check-device-status.php?request_id=$requestId'))
          .timeout(_httpTimeout);
      if (response.statusCode == 404) {
        return StatusPoll(ApprovalStatus.notFound);
      }
      if (response.statusCode != 200) {
        return StatusPoll(ApprovalStatus.unknown);
      }
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      if (body['success'] != true) {
        return StatusPoll(ApprovalStatus.unknown);
      }
      final status = (body['status'] ?? '').toString();
      switch (status) {
        case 'pending':
          return StatusPoll(ApprovalStatus.pending);
        case 'approved':
          return StatusPoll(
            ApprovalStatus.approved,
            oneTimeToken: body['one_time_token']?.toString(),
            tokenExpiresInSeconds:
                (body['token_expires_in_seconds'] as num?)?.toInt(),
          );
        case 'rejected':
          return StatusPoll(ApprovalStatus.rejected);
        case 'expired':
          return StatusPoll(ApprovalStatus.expired);
        default:
          return StatusPoll(ApprovalStatus.unknown);
      }
    } catch (e) {
      LoggerService.logDebug('APPROVAL', 'Poll failed (transient): $e');
      return StatusPoll(ApprovalStatus.unknown);
    } finally {
      client.close();
    }
  }

  /// Download the cert+key+CA bundle using the one_time_token returned
  /// alongside an approved status. Single-use: the server invalidates
  /// the token immediately after this returns, so the caller MUST
  /// persist the bundle right away.
  ///
  /// Returns null if the token is invalid, expired, consumed, or the
  /// server can't read the cert files.
  static Future<CertBundle?> downloadCert({
    required String requestId,
    required String oneTimeToken,
  }) async {
    LoggerService.log('APPROVAL', 'Downloading cert for $requestId');
    final client = _newClient();
    try {
      final response = await client
          .get(Uri.parse('$_baseUrl/download-cert.php'
              '?request_id=$requestId'
              '&token=$oneTimeToken'))
          .timeout(_httpTimeout);
      if (response.statusCode != 200) {
        LoggerService.logWarning('APPROVAL',
            'download-cert HTTP ${response.statusCode}: ${response.body}');
        return null;
      }
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      if (body['success'] != true) {
        LoggerService.logWarning('APPROVAL',
            'download-cert error: ${body['error']}');
        return null;
      }
      final cert = body['client_cert']?.toString();
      final key = body['client_key']?.toString();
      final ca = body['ca_cert']?.toString();
      final username = body['username']?.toString();
      if (cert == null || key == null || ca == null || username == null) {
        LoggerService.logWarning('APPROVAL',
            'download-cert response missing fields');
        return null;
      }
      LoggerService.log('APPROVAL',
          'Cert downloaded: ${cert.length} bytes cert, ${key.length} bytes key');
      return CertBundle(
        username: username,
        clientCert: cert,
        clientKey: key,
        caCert: ca,
      );
    } catch (e, st) {
      LoggerService.logError('APPROVAL', e, st);
      return null;
    } finally {
      client.close();
    }
  }

  /// Persist the [bundle] via [CertificateService.storeBundle] which
  /// writes the per-username keys (v2.30.2+) into [MasterVault]
  /// (B5, v2.30.0+) and registers the user in the known-users list.
  /// The vault must already be unlocked — typically the case because
  /// Faza 3 add-account is invoked from the main UI which is gated
  /// by the master password dialog (which unlocks the vault as a
  /// side effect).
  ///
  /// On non-macOS this is a thin pass-through to PortableSecureStorage.
  static Future<void> storeBundle(CertBundle bundle) async {
    await CertificateService.storeBundle(
      username: bundle.username,
      clientCert: bundle.clientCert,
      clientKey: bundle.clientKey,
      caCert: bundle.caCert,
    );
    LoggerService.log('APPROVAL',
        'Cert bundle persisted via CertificateService for ${bundle.username}');
  }
}
