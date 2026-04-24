// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'logger_service.dart';
import 'mtls_service.dart';
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
  // Quad9: non-Five-Eyes (Switzerland), zero-logging, DNSSEC-validating.
  // Uses RFC 8484 wireformat (binary), NOT JSON API.
  static const _quad9Endpoint = 'https://dns.quad9.net/dns-query';
  static const _timeout = Duration(seconds: 10);

  /// Look up TXT records for [domain].
  /// Tries our own DoH (mTLS-authenticated) first, falls back to Cloudflare.
  static Future<List<String>> lookupTxt(String domain) async {
    try {
      return await _queryDoH(_primaryEndpoint, domain, 'TXT');
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
      return await _queryDoH(_primaryEndpoint, domain, 'A');
    } catch (_) {
      try {
        return await _queryDoH(_fallbackEndpoint, domain, 'A');
      } catch (_) {
        return [];
      }
    }
  }

  /// Resolve the mail server's own hostname via EXTERNAL DoH only.
  ///
  /// This avoids the circular dependency: resolving `mail.icd360s.de`
  /// via `mail.icd360s.de/dns-query` would require resolving
  /// `mail.icd360s.de` first (via system resolver), defeating the
  /// purpose.
  ///
  /// Chain: Quad9 (Switzerland, RFC 8484 wireformat) → Cloudflare
  /// (JSON API fallback). Two distinct providers, distinct protocols.
  static Future<List<String>> lookupServerA(String domain) async {
    try {
      return await _queryDoHWireformat(_quad9Endpoint, domain, _qTypeA);
    } catch (ex) {
      LoggerService.logWarning('DNS',
          'Quad9 DoH failed for $domain: $ex');
      return [];
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

  /// Check DMARC record for a domain.
  /// Returns the DMARC record or null.
  static Future<String?> lookupDmarc(String domain) async {
    final dmarcDomain = '_dmarc.$domain';
    final records = await lookupTxt(dmarcDomain);
    for (final r in records) {
      if (r.toLowerCase().startsWith('v=dmarc1')) {
        return r;
      }
    }
    return null;
  }

  /// Check MTA-STS record for a domain.
  /// Returns the MTA-STS TXT record or null.
  static Future<String?> lookupMtaSts(String domain) async {
    final stsDomain = '_mta-sts.$domain';
    final records = await lookupTxt(stsDomain);
    for (final r in records) {
      if (r.toLowerCase().startsWith('v=stsv1')) {
        return r;
      }
    }
    return null;
  }

  /// Check TLS-RPT record for a domain.
  /// Returns the TLS-RPT TXT record or null.
  static Future<String?> lookupTlsRpt(String domain) async {
    final rptDomain = '_smtp._tls.$domain';
    final records = await lookupTxt(rptDomain);
    for (final r in records) {
      if (r.toLowerCase().startsWith('v=tlsrptv1')) {
        return r;
      }
    }
    return null;
  }

  /// Perform a DoH JSON API query.
  ///
  /// For the primary endpoint (mail.icd360s.de), authenticates via mTLS
  /// client certificate — no hardcoded API key needed. The per-user cert
  /// is available after login (when threat intelligence lookups happen).
  /// For external endpoints (Cloudflare, Quad9), uses the OS system trust
  /// store — these providers use DigiCert/Cloudflare certs, NOT Let's
  /// Encrypt, so the ISRG-pinned context must NOT be used for them.
  static Future<List<String>> _queryDoH(
    String endpoint,
    String domain,
    String type,
  ) async {
    final uri = Uri.parse(endpoint).replace(queryParameters: {
      'name': domain,
      'type': type,
    });

    // Use mTLS client for our own server; plain system-trust client for
    // external DoH providers (Cloudflare, Quad9 use non-ISRG certs).
    final isOwnServer = endpoint.contains('mail.icd360s.de');
    HttpClient client;
    if (isOwnServer) {
      client = MtlsService.createMtlsHttpClient() ??
          (PinnedSecurityContext.createHttpClient()
            ..badCertificateCallback = (cert, host, port) {
              return isTrustedLetsEncryptIssuer(cert.issuer);
            });
    } else {
      // External DoH (Cloudflare, Quad9): use system trust store.
      // PinnedSecurityContext (ISRG-only) would reject their DigiCert /
      // Cloudflare certs, causing "Connection refused" on the ephemeral
      // source port — the TLS failure surfaces as a SocketException.
      client = HttpClient()
        ..connectionTimeout = _timeout
        ..idleTimeout = const Duration(seconds: 5);
    }

    try {
      final request = await client.getUrl(uri).timeout(_timeout);
      request.headers.set('Accept', 'application/dns-json');

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

  // ────────────────────────────────────────────────────────────────
  //  RFC 8484 wireformat DoH (for Quad9 and other binary-only DoH)
  // ────────────────────────────────────────────────────────────────

  static const int _qTypeA = 1;
  // ignore: unused_field
  static const int _qTypeTxt = 16;
  static const int _qClassIn = 1;

  /// Build a minimal DNS query message (RFC 1035 §4.1).
  static Uint8List _buildDnsQuery(String domain, int qtype) {
    final buf = BytesBuilder();
    // Header: ID (random), flags (RD=1), QDCOUNT=1, rest=0
    final id = Random.secure().nextInt(0xFFFF);
    buf.addByte(id >> 8);
    buf.addByte(id & 0xFF);
    buf.addByte(0x01); // QR=0, Opcode=0, AA=0, TC=0, RD=1
    buf.addByte(0x00); // RA=0, Z=0, RCODE=0
    buf.addByte(0x00); buf.addByte(0x01); // QDCOUNT = 1
    buf.addByte(0x00); buf.addByte(0x00); // ANCOUNT = 0
    buf.addByte(0x00); buf.addByte(0x00); // NSCOUNT = 0
    buf.addByte(0x00); buf.addByte(0x00); // ARCOUNT = 0
    // QNAME: each label prefixed with length byte, terminated by 0x00
    for (final label in domain.split('.')) {
      final bytes = utf8.encode(label);
      buf.addByte(bytes.length);
      buf.add(bytes);
    }
    buf.addByte(0x00); // root label
    // QTYPE + QCLASS
    buf.addByte(qtype >> 8); buf.addByte(qtype & 0xFF);
    buf.addByte(_qClassIn >> 8); buf.addByte(_qClassIn & 0xFF);
    return buf.toBytes();
  }

  /// Parse A records from a DNS wireformat response.
  static List<String> _parseARecords(Uint8List data) {
    if (data.length < 12) return [];
    // Header: check RCODE (last 4 bits of byte 3)
    final rcode = data[3] & 0x0F;
    if (rcode == 3) return []; // NXDOMAIN
    if (rcode != 0) throw DnsException('DNS RCODE $rcode', rcode);

    final ancount = (data[6] << 8) | data[7];
    if (ancount == 0) return [];

    // Skip question section: jump past header (12 bytes), then skip
    // QDCOUNT questions (each is a name + 4 bytes QTYPE/QCLASS).
    final qdcount = (data[4] << 8) | data[5];
    var offset = 12;
    for (var q = 0; q < qdcount; q++) {
      offset = _skipName(data, offset);
      offset += 4; // QTYPE(2) + QCLASS(2)
    }

    // Parse answer RRs — extract A records (type 1, rdlength 4).
    final results = <String>[];
    for (var a = 0; a < ancount && offset < data.length; a++) {
      offset = _skipName(data, offset);
      if (offset + 10 > data.length) break;
      final rrtype = (data[offset] << 8) | data[offset + 1];
      final rdlength = (data[offset + 8] << 8) | data[offset + 9];
      offset += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
      if (rrtype == _qTypeA && rdlength == 4 && offset + 4 <= data.length) {
        results.add('${data[offset]}.${data[offset + 1]}.'
            '${data[offset + 2]}.${data[offset + 3]}');
      }
      offset += rdlength;
    }
    return results;
  }

  /// Skip a DNS name at [offset] (handles compression pointers).
  static int _skipName(Uint8List data, int offset) {
    while (offset < data.length) {
      final len = data[offset];
      if (len == 0) return offset + 1; // root label
      if ((len & 0xC0) == 0xC0) return offset + 2; // compression pointer
      offset += 1 + len;
    }
    return offset;
  }

  /// RFC 8484 DoH query via HTTP POST with binary wireformat body.
  ///
  /// Quad9 (and many other DoH servers) require POST with
  /// `Content-Type: application/dns-message`. GET with `?dns=`
  /// base64url is optional per RFC 8484 and not universally supported.
  ///
  /// Uses the OS system trust store — Quad9 uses a DigiCert certificate,
  /// not a Let's Encrypt cert.  PinnedSecurityContext (ISRG roots only)
  /// must NOT be used here or TLS validation fails, manifesting as
  /// SocketException("Connection refused") on the local ephemeral port.
  static Future<List<String>> _queryDoHWireformat(
    String endpoint,
    String domain,
    int qtype,
  ) async {
    final query = _buildDnsQuery(domain, qtype);
    final uri = Uri.parse(endpoint);

    // Plain HttpClient() uses the OS/Flutter trust store (system CAs),
    // which correctly validates Quad9's DigiCert certificate.
    final client = HttpClient()
      ..connectionTimeout = _timeout
      ..idleTimeout = const Duration(seconds: 5);

    try {
      final request = await client.postUrl(uri).timeout(_timeout);
      request.headers.set('Content-Type', 'application/dns-message');
      request.headers.set('Accept', 'application/dns-message');
      request.add(query);

      final response = await request.close().timeout(_timeout);
      if (response.statusCode != 200) {
        await response.drain<void>();
        throw DnsException('HTTP ${response.statusCode}', response.statusCode);
      }

      final bytes = await response.fold<BytesBuilder>(
        BytesBuilder(),
        (builder, chunk) => builder..add(chunk),
      ).then((b) => b.toBytes());

      return _parseARecords(bytes);
    } finally {
      client.close();
    }
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