import 'dart:io';
import '../models/models.dart';
import 'logger_service.dart';

/// Threat intelligence service for spam/phishing detection
class ThreatIntelligenceService {
  static final List<String> _dnsBlacklists = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
  ];

  /// Trusted domains — only whitelisted when DMARC passes.
  static const _trustedDomains = {'icd360s.de', 'mail.icd360s.de'};

  /// Analyze email for threats and return (level, score, details)
  static ThreatAnalysis analyzeEmail(Email email) {
    int score = 0;
    final indicators = <String>[];

    // --- Step 1: Parse authentication results (RFC 8601) ---
    final authResults = _parseAuthResults(email);

    final dmarcPass = authResults['dmarc'] == 'pass';
    final dkimPass = authResults['dkim'] == 'pass';
    final spfPass = authResults['spf'] == 'pass';

    // --- Step 2: Extract sender domain properly (RFC 5322) ---
    final fromDomain = _extractFromDomain(email.from);

    // --- Step 3: Authenticated trusted-domain whitelist ---
    // Only whitelist if DMARC passes AND the From domain is trusted.
    // A spoofed From: admin@icd360s.de with DMARC=fail will NOT be
    // whitelisted — this is the key fix.
    if (dmarcPass &&
        fromDomain != null &&
        _trustedDomains.contains(fromDomain)) {
      LoggerService.log('THREAT',
          'Authenticated trusted email: $fromDomain (DMARC=pass) - score=0');
      return ThreatAnalysis(
        level: 'Safe',
        score: 0,
        details: '✅ Authenticated trusted email (DMARC=pass, '
            'domain=$fromDomain)',
      );
    }

    // --- Step 4: MDN / read receipt detection (RFC 8098) ---
    // Detect by Content-Type header, NOT by subject prefix.
    if (_isAuthenticatedMdn(email, dmarcPass: dmarcPass)) {
      LoggerService.log('THREAT',
          'Authenticated MDN from $fromDomain - score=0');
      return ThreatAnalysis(
        level: 'Safe',
        score: 0,
        details: '✅ Read receipt (Content-Type=disposition-notification, '
            'DMARC=${dmarcPass ? "pass" : "unchecked"})',
      );
    }

    // --- Step 5: Score based on authentication ---
    if (!dkimPass) {
      if (authResults['dkim'] == 'fail') {
        score += 25;
        indicators.add('DKIM: fail');
      } else {
        score += 15;
        indicators.add('DKIM: missing');
      }
    } else {
      indicators.add('DKIM: pass');
    }

    if (spfPass) {
      indicators.add('SPF: pass');
    } else if (authResults['spf'] == 'fail' ||
        authResults['spf'] == 'softfail') {
      score += 30;
      indicators.add('SPF: ${authResults['spf']}');
    } else {
      score += 10;
      indicators.add('SPF: missing');
    }

    if (!dmarcPass) {
      if (authResults['dmarc'] == 'fail') {
        score += 30;
        indicators.add('DMARC: fail');
      } else {
        score += 10;
        indicators.add('DMARC: missing');
      }
    } else {
      indicators.add('DMARC: pass');
    }

    // --- Step 6: Extract sender IP from Received headers ---
    final senderIp = _extractSenderIp(email);
    if (senderIp != null) {
      indicators.add('IP $senderIp: detected');
    }

    // --- Step 7: Suspicious keywords in subject ---
    final suspiciousKeywords = [
      'urgent',
      'verify',
      'suspended',
      'click here',
      'confirm',
      'password'
    ];

    for (final keyword in suspiciousKeywords) {
      if (email.subject.toLowerCase().contains(keyword)) {
        score += 10;
        indicators.add('Keyword: $keyword');
      }
    }

    // --- Step 8: Sender domain mismatch (From vs Return-Path) ---
    if (fromDomain != null) {
      final returnPath =
          email.headers['Return-Path'] ?? email.headers['return-path'];

      if (returnPath != null) {
        final rpDomain = _extractFromDomain(returnPath);
        if (rpDomain != null && rpDomain != fromDomain) {
          score += 25;
          indicators.add('Domain mismatch: From=$fromDomain '
              'Return-Path=$rpDomain');
        }
      }
    }

    // Determine threat level
    final level = switch (score) {
      >= 70 => 'Critical',
      >= 50 => 'High',
      >= 30 => 'Medium',
      >= 10 => 'Low',
      _ => 'Safe',
    };

    final details = indicators.join(' | ');

    return ThreatAnalysis(level: level, score: score, details: details);
  }

  /// Parse Authentication-Results header (RFC 8601).
  ///
  /// Returns a map of method → result, e.g. {'dkim': 'pass', 'spf': 'fail'}.
  static Map<String, String> _parseAuthResults(Email email) {
    final header = email.headers['Authentication-Results'] ??
        email.headers['authentication-results'] ??
        '';
    final results = <String, String>{};
    if (header.isEmpty) return results;

    // The header format is: authserv-id; method=result ...; method=result ...
    // Strip authserv-id (everything before first ';')
    final semiIdx = header.indexOf(';');
    if (semiIdx < 0) return results;
    final methodsPart = header.substring(semiIdx + 1);

    // Split on ';' to get individual method results
    final methods = methodsPart.split(';');
    final methodRegex = RegExp(r'(\w+)\s*=\s*(\w+)');

    for (final method in methods) {
      final trimmed = method.trim();
      if (trimmed.isEmpty) continue;

      final match = methodRegex.firstMatch(trimmed);
      if (match != null) {
        final name = match.group(1)!.toLowerCase();
        final result = match.group(2)!.toLowerCase();
        // Only store known authentication methods
        if (name == 'dkim' || name == 'spf' || name == 'dmarc') {
          results[name] = result;
        }
      }
    }

    // Also check the legacy Received-SPF header as fallback
    if (!results.containsKey('spf')) {
      final receivedSpf =
          email.headers['Received-SPF'] ?? email.headers['received-spf'];
      if (receivedSpf != null) {
        final lower = receivedSpf.toLowerCase().trim();
        if (lower.startsWith('pass')) {
          results['spf'] = 'pass';
        } else if (lower.startsWith('fail')) {
          results['spf'] = 'fail';
        } else if (lower.startsWith('softfail')) {
          results['spf'] = 'softfail';
        }
      }
    }

    return results;
  }

  /// Extract the domain from a From header value (RFC 5322).
  ///
  /// Handles formats: `"Name" <user@domain>`, `<user@domain>`, `user@domain`,
  /// `user@domain (comment)`.
  static String? _extractFromDomain(String from) {
    final trimmed = from.trim();
    if (trimmed.isEmpty) return null;

    String? address;

    // Case 1: angle brackets — extract content of last <...>
    final angleBracket = RegExp(r'<([^>]+)>');
    final match = angleBracket.firstMatch(trimmed);
    if (match != null) {
      address = match.group(1)!.trim();
    } else {
      // Case 2: bare address — strip any trailing (comment)
      address = trimmed.replaceAll(RegExp(r'\(.*?\)'), '').trim();
    }

    if (!address.contains('@')) return null;

    final domain = address.split('@').last.toLowerCase().trim();
    if (domain.isEmpty || !domain.contains('.')) return null;

    return domain;
  }

  /// Detect legitimate MDN read receipts (RFC 8098).
  ///
  /// MDNs are identified by Content-Type, not by subject prefix. Subject
  /// prefixes like "Read:" vary by locale and client and are trivially
  /// spoofable.
  static bool _isAuthenticatedMdn(Email email, {required bool dmarcPass}) {
    final contentType =
        (email.headers['Content-Type'] ?? email.headers['content-type'] ?? '')
            .toLowerCase();

    // RFC 8098: MDN uses Content-Type: multipart/report;
    //   report-type=disposition-notification
    final isMdn = contentType.contains('multipart/report') &&
        contentType.contains('disposition-notification');

    if (!isMdn) return false;

    // Also accept if Auto-Submitted header is present (RFC 3834)
    // — confirms it's machine-generated, not a human-crafted fake.
    final autoSubmitted = (email.headers['Auto-Submitted'] ??
            email.headers['auto-submitted'] ??
            '')
        .toLowerCase();
    final isMachineGenerated = autoSubmitted.contains('auto-replied') ||
        autoSubmitted.contains('auto-generated');

    // Whitelist the MDN if DMARC passes OR if it is machine-generated
    // from a multipart/report. Both conditions confirm legitimacy.
    return dmarcPass || isMachineGenerated;
  }

  /// Extract sender IP from Received headers
  static String? _extractSenderIp(Email email) {
    final received = email.headers['Received'] ?? email.headers['received'];

    if (received != null) {
      // Extract IPv4 from "Received: from ... [1.2.3.4]"
      final ipv4Regex =
          RegExp(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]');
      final match = ipv4Regex.firstMatch(received);
      if (match != null && match.groupCount >= 1) {
        return match.group(1);
      }

      // Extract IPv6 from "Received: from ... [IPv6:2001:db8::1]"
      final ipv6Regex = RegExp(r'\[IPv6:([^\]]+)\]', caseSensitive: false);
      final ipv6Match = ipv6Regex.firstMatch(received);
      if (ipv6Match != null && ipv6Match.groupCount >= 1) {
        return ipv6Match.group(1);
      }
    }

    return null;
  }

  /// Analyze email with full async blacklist checking
  static Future<ThreatAnalysis> analyzeEmailAsync(Email email) async {
    // Start with synchronous analysis
    final basicAnalysis = analyzeEmail(email);

    // If authenticated trusted email or MDN, return immediately
    if (basicAnalysis.level == 'Safe' && basicAnalysis.score == 0) {
      return basicAnalysis;
    }

    // Add async blacklist check
    int score = basicAnalysis.score;
    final indicators = basicAnalysis.details.split(' | ').toList();

    final senderIp = _extractSenderIp(email);
    if (senderIp != null) {
      final isBlacklisted = await _checkBlacklistsAsync(senderIp);
      if (isBlacklisted) {
        score += 50;
        indicators.removeWhere((i) => i.startsWith('IP $senderIp'));
        indicators.add('IP $senderIp: BLACKLISTED');
      } else {
        indicators.removeWhere((i) => i.startsWith('IP $senderIp'));
        indicators.add('IP $senderIp: clean');
      }
    }

    // Recalculate threat level with blacklist data
    final level = switch (score) {
      >= 70 => 'Critical',
      >= 50 => 'High',
      >= 30 => 'Medium',
      >= 10 => 'Low',
      _ => 'Safe',
    };

    return ThreatAnalysis(
      level: level,
      score: score,
      details: indicators.join(' | '),
    );
  }

  /// Check if IP is in DNS blacklists
  static Future<bool> _checkBlacklistsAsync(String ip) async {
    try {
      final octets = ip.split('.');
      // Only reverse-lookup IPv4 addresses for DNSBL
      if (octets.length != 4) return false;

      final reversedIp =
          '${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}';

      for (final blacklist in _dnsBlacklists) {
        try {
          final query = '$reversedIp.$blacklist';
          final addresses = await InternetAddress.lookup(query);

          if (addresses.isNotEmpty) {
            LoggerService.log('THREAT', 'IP $ip blacklisted on $blacklist');
            return true;
          }
        } on SocketException {
          // NXDOMAIN = not listed (good)
          continue;
        } catch (_) {
          continue;
        }
      }

      return false;
    } catch (_) {
      return false;
    }
  }
}

/// Threat analysis result
class ThreatAnalysis {
  final String level;
  final int score;
  final String details;

  ThreatAnalysis({
    required this.level,
    required this.score,
    required this.details,
  });
}
