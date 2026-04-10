import 'dart:convert';
import 'dart:io';

import 'logger_service.dart';
import 'pinned_security_context.dart';
import 'le_issuer_check.dart';

/// DNS-over-HTTPS (DoH) client for cross-platform DNS lookups.
///
/// Replaces `Process.run('nslookup', ...)` which only works on desktop.
/// Uses HTTPS GET requests — works on all platforms including Android,
/// iOS, and GrapheneOS.
///
/// Primary endpoint: self-hosted DoH on mail.icd360s.de (queries
/// forwarded to Quad9/DNS0.eu/Mullvad via DNS-over-TLS — all
/// non-Five-Eyes, zero-logging, unfiltered).
///
/// Fallback: Cloudflare DoH (in case our server is unreachable).
class DnsChecker {
  static const _primaryEndpoint = 'https://mail.icd360s.de/dns-query';
  static const _fallbackEndpoint = 'https://cloudflare-dns.com/dns-query';
  static const _apiKey = '/mYr5bIvhAcJxOLToUABpSi3RMvBthYf';
  static const _timeout = Duration(seconds: 10);

  /// Look up TXT records for [domain].
  /// Tries our own DoH first, falls back to Cloudflare.
  static Future<List<String>> lookupTxt(String domain) async {
    try {
      return await _queryDoH(_primaryEndpoint, domain, 'TXT',
          apiKey: _apiKey);
    } catch (ex) {
      LoggerService.log('DNS', 'Primary DoH failed, trying fallback: $ex');
      try {
        return await _queryDoH(_fallbackEndpoint, domain, 'TXT');
      } catch (ex2) {
        LoggerService.logWarning('DNS', 'Fallback DoH also failed: $ex2');
        return [];
      }
    }
  }

  /// Look up A records for [domain].
  static Future<List<String>> lookupA(String domain) async {
    try {
      return await _queryDoH(_primaryEndpoint, domain, 'A', apiKey: _apiKey);
    } catch (_) {
      try {
        return await _queryDoH(_fallbackEndpoint, domain, 'A');
      } catch (_) {
        return [];
      }
    }
  }

  /// Check SPF record for a domain.
  /// Returns the SPF string or null if not configured.
  static Future<String?> lookupSpf(String domain) async {
    final records = await lookupTxt(domain);
    for (final r in records) {
      if (r.toLowerCase().startsWith('v=spf1')) {
        return r;
      }
    }
    return null;
  }

  /// Check DKIM record for a domain with the given [selector].
  /// Returns the DKIM record or null.
  static Future<String?> lookupDkim(
    String domain, {
    String selector = 'default',
  }) async {
    final dkimDomain = '$selector._domainkey.$domain';
    final records = await lookupTxt(dkimDomain);
    for (final r in records) {
      final lower = r.toLowerCase();
      if (lower.contains('v=dkim1') || lower.contains('k=rsa') ||
          lower.contains('k=ed25519') || lower.contains('p=')) {
        return r;
      }
    }
    return null;
  }

  /// Perform a DoH JSON API query.
  static Future<List<String>> _queryDoH(
    String endpoint,
    String domain,
    String type, {
    String? apiKey,
  }) async {
    final uri = Uri.parse(endpoint).replace(queryParameters: {
      'name': domain,
      'type': type,
    });

    final client = PinnedSecurityContext.createHttpClient()
      ..badCertificateCallback = (cert, host, port) {
        // For our own server, validate LE issuer
        if (host == 'mail.icd360s.de') {
          return isTrustedLetsEncryptIssuer(cert.issuer);
        }
        // For Cloudflare fallback, accept system-validated certs
        return false;
      };

    try {
      final request = await client.getUrl(uri).timeout(_timeout);
      request.headers.set('Accept', 'application/dns-json');
      if (apiKey != null) {
        request.headers.set('X-DNS-Key', apiKey);
      }

      final response = await request.close().timeout(_timeout);
      final body = await response.transform(utf8.decoder).join();

      if (response.statusCode != 200) {
        throw DnsException('HTTP ${response.statusCode}', response.statusCode);
      }

      final json = jsonDecode(body) as Map<String, dynamic>;
      final status = json['Status'] as int? ?? -1;

      // Status 3 = NXDOMAIN (domain doesn't exist — not an error)
      if (status == 3) return [];
      if (status != 0) {
        throw DnsException('DNS error status $status', status);
      }

      final answers = json['Answer'] as List<dynamic>?;
      if (answers == null) return [];

      return answers
          .map((a) => _unquoteTxt(a['data'] as String? ?? ''))
          .where((s) => s.isNotEmpty)
          .toList();
    } finally {
      client.close();
    }
  }

  /// DoH returns TXT data with surrounding quotes and potentially
  /// split into multiple quoted strings. Reassemble them.
  static String _unquoteTxt(String raw) {
    final buffer = StringBuffer();
    final regex = RegExp(r'"([^"]*)"');
    for (final match in regex.allMatches(raw)) {
      buffer.write(match.group(1));
    }
    final result = buffer.toString();
    return result.isNotEmpty ? result : raw.replaceAll('"', '');
  }
}

/// Exception for DNS lookup failures.
class DnsException implements Exception {
  final String message;
  final int statusCode;
  DnsException(this.message, this.statusCode);

  @override
  String toString() => 'DnsException($statusCode): $message';
}
