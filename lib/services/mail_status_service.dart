import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'mtls_client_pool.dart';
import 'mtls_service.dart';
import 'pinned_security_context.dart';

/// Delivery status for a sent/received email.
enum MailDeliveryStatus {
  sent,       // 250 ok — delivered to remote MX
  deferred,   // retrying (temporary failure)
  bounced,    // permanent failure
  expired,    // gave up retrying
  pending,    // in queue, no final status yet
  notFound,   // no matching log entry (too old, or never went through our server)
  forbidden,  // this message wasn't sent by the authenticated user
  unknown,    // API error / unexpected response
}

class MailStatusResult {
  final MailDeliveryStatus status;
  final String? relay;      // e.g. "mx00.ionos.de"
  final String? timestamp;  // e.g. "Apr 14 09:57:29"

  MailStatusResult({required this.status, this.relay, this.timestamp});

  factory MailStatusResult.fromJson(Map<String, dynamic> json) {
    final s = json['status'] as String? ?? 'unknown';
    MailDeliveryStatus status;
    switch (s) {
      case 'sent':
        status = MailDeliveryStatus.sent;
        break;
      case 'deferred':
        status = MailDeliveryStatus.deferred;
        break;
      case 'bounced':
        status = MailDeliveryStatus.bounced;
        break;
      case 'expired':
        status = MailDeliveryStatus.expired;
        break;
      case 'pending':
        status = MailDeliveryStatus.pending;
        break;
      case 'not_found':
        status = MailDeliveryStatus.notFound;
        break;
      case 'forbidden':
        status = MailDeliveryStatus.forbidden;
        break;
      default:
        status = MailDeliveryStatus.unknown;
    }
    return MailStatusResult(
      status: status,
      relay: json['relay'] as String?,
      timestamp: json['timestamp'] as String?,
    );
  }
}

/// Fetches delivery status from the server for a batch of message IDs.
///
/// Uses mTLS client cert — the server authenticates per-user and only
/// returns status for mail sent by the authenticated user.
class MailStatusService {
  static const String _endpoint =
      'https://mail.icd360s.de/api/mail-status.php';

  /// In-memory cache: messageId → result. Invalidated on app lock.
  static final Map<String, MailStatusResult> _cache = {};
  static final Set<String> _inFlight = {};

  /// Clear cached results (on app lock / account switch).
  static void clearCache() {
    _cache.clear();
    _inFlight.clear();
  }

  /// Get cached result (null if not yet fetched).
  static MailStatusResult? getCached(String messageId) => _cache[messageId];

  /// Fetch delivery status for a batch of message IDs. Results are cached.
  /// IDs already in the cache or currently being fetched are skipped.
  /// [senderUsername] selects the per-account mTLS cert so the server
  /// sees the correct CN and matches from=<user@icd360s.de> in maillog.
  static Future<void> fetchBatch(List<String> messageIds, {String? senderUsername}) async {
    final toFetch = messageIds
        .where((id) => !_cache.containsKey(id) && !_inFlight.contains(id))
        .toSet()
        .toList();
    if (toFetch.isEmpty) return;

    _inFlight.addAll(toFetch);

    try {
      HttpClient client;
      bool poolOwned = false;
      if (senderUsername != null) {
        try {
          client = await MtlsClientPool.instance.get(senderUsername);
          poolOwned = true;
        } catch (_) {
          client = MtlsService.createMtlsHttpClient() ??
              (PinnedSecurityContext.createHttpClient()
                ..badCertificateCallback = (cert, host, port) {
                  if (host != 'mail.icd360s.de') return false;
                  return isTrustedLetsEncryptIssuer(cert.issuer);
                });
        }
      } else {
        client = MtlsService.createMtlsHttpClient() ??
            (PinnedSecurityContext.createHttpClient()
              ..badCertificateCallback = (cert, host, port) {
                if (host != 'mail.icd360s.de') return false;
                return isTrustedLetsEncryptIssuer(cert.issuer);
              });
      }

      try {
        final request = await client
            .postUrl(Uri.parse(_endpoint))
            .timeout(const Duration(seconds: 10));
        request.headers.set('Content-Type', 'application/json');
        request.write(jsonEncode({'message_ids': toFetch}));

        final response = await request.close().timeout(const Duration(seconds: 10));
        final body = await response.transform(utf8.decoder).join();

        if (response.statusCode != 200) {
          LoggerService.logWarning('MAIL_STATUS',
              'HTTP ${response.statusCode}: $body');
          return;
        }

        final json = jsonDecode(body) as Map<String, dynamic>;
        final results = json['results'] as Map<String, dynamic>? ?? {};

        for (final entry in results.entries) {
          final result = MailStatusResult.fromJson(entry.value as Map<String, dynamic>);
          _cache[entry.key] = result;
        }
        LoggerService.log('MAIL_STATUS',
            '✓ Fetched ${results.length} statuses (cert: ${senderUsername ?? "global"})');
      } finally {
        if (!poolOwned) client.close();
      }
    } catch (ex) {
      LoggerService.logWarning('MAIL_STATUS', 'Fetch failed: $ex');
    } finally {
      _inFlight.removeAll(toFetch);
    }
  }
}
