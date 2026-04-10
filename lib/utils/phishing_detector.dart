import 'dart:convert';
import 'dart:io';

import '../services/logger_service.dart';

/// Multi-layer phishing URL detector.
///
/// **Layer 1** (implemented in email_viewer.dart):
///   Display text vs href domain mismatch detection.
///
/// **Layer 2** (this file, local heuristics — no network, instant):
///   - Homograph / mixed-script detection (Cyrillic/Greek in Latin domain)
///   - Known URL shortener warning (bit.ly, tinyurl, t.co, etc.)
///   - IP address URLs (http://185.234.12.1/login)
///   - Suspicious TLDs (.tk, .ml, .ga, .cf, .gq — top phishing TLDs)
///   - Excessive subdomains (paypal.com.secure.login.evil.com)
///   - Data URI links (data:text/html,...)
///   - Punycode / xn-- domains (IDN encoded)
///
/// **Layer 3** (Google Safe Browsing v4 Lookup API — opt-in, network):
///   Checks URL against Google's 1.6M+ threat database. Disabled by
///   default for privacy (URL is sent to Google). Enable by providing
///   an API key via [safeBrowsingApiKey].
class PhishingDetector {
  /// Google Safe Browsing API key. Set to enable Layer 3.
  /// Get one free at https://console.cloud.google.com/apis/credentials
  /// then enable "Safe Browsing API" in the API Library.
  static String? safeBrowsingApiKey;

  /// Known URL shorteners that hide the real destination.
  static const Set<String> _urlShorteners = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'db.tt',
    'qr.ae', 'cur.lv', 'lnkd.in', 'youtu.be', 'rb.gy', 'cutt.ly',
    'short.io', 'rebrand.ly', 'bl.ink', 'shorturl.at', 'tinu.be',
    'tiny.cc', 'v.gd', 'clck.ru', 'shrinkme.io', 'ouo.io',
  };

  /// TLDs disproportionately used for phishing / free domain abuse.
  static const Set<String> _suspiciousTlds = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.top', '.xyz',
    '.club', '.work', '.date', '.racing', '.stream', '.download',
    '.win', '.bid', '.trade', '.webcam', '.loan', '.party',
  };

  /// Cyrillic characters that look identical to Latin.
  static const Map<int, String> _cyrillicHomoglyphs = {
    0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p',
    0x0441: 'c', 0x0443: 'y', 0x0445: 'x', 0x0456: 'i',
    0x0455: 's', 0x044C: 'b', 0x0457: 'i', 0x0491: 'r',
    0x04BB: 'h', 0x043D: 'H', 0x043A: 'K',
  };

  /// Run all Layer 2 heuristic checks on a URL. Returns a list of
  /// warnings (empty = no issues detected).
  static List<PhishingWarning> checkLocal(String url) {
    final warnings = <PhishingWarning>[];
    final uri = Uri.tryParse(url);
    if (uri == null) return warnings;

    final host = uri.host.toLowerCase();
    final scheme = uri.scheme.toLowerCase();

    // Data URI — can execute HTML/JS in browser
    if (scheme == 'data') {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.high,
        message: 'Data URI link detected — may execute code in your browser',
      ));
      return warnings;
    }

    // IP address URL
    if (RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').hasMatch(host)) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.medium,
        message: 'URL uses an IP address instead of a domain name',
      ));
    }

    // URL shortener
    if (_urlShorteners.contains(host)) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.medium,
        message: 'URL shortener detected — real destination is hidden',
      ));
    }

    // Suspicious TLD
    for (final tld in _suspiciousTlds) {
      if (host.endsWith(tld)) {
        warnings.add(PhishingWarning(
          severity: WarningSeverity.low,
          message: 'Domain uses suspicious TLD ($tld) — commonly abused for phishing',
        ));
        break;
      }
    }

    // Punycode (xn--) — IDN encoded domain
    if (host.contains('xn--')) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.medium,
        message: 'Internationalized domain name (Punycode) — may be a homograph attack',
      ));
    }

    // Homograph / mixed script detection
    if (_containsMixedScript(host)) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.high,
        message: 'Domain contains mixed Unicode scripts (possible homograph attack)',
      ));
    }

    // Excessive subdomains (more than 3 dots in host)
    if (host.split('.').length > 4) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.low,
        message: 'URL has excessive subdomains — real domain may be hidden at the end',
      ));
    }

    // Non-HTTPS
    if (scheme == 'http') {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.low,
        message: 'Unencrypted HTTP connection — data sent in cleartext',
      ));
    }

    return warnings;
  }

  /// Check if a domain string contains characters from multiple
  /// Unicode scripts that could be a homograph attack. Specifically
  /// detects Cyrillic or Greek characters mixed into Latin-looking
  /// domains.
  static bool _containsMixedScript(String domain) {
    // Only check the part before TLD (strip last segment)
    final parts = domain.split('.');
    if (parts.length < 2) return false;
    final label = parts.sublist(0, parts.length - 1).join('.');

    bool hasLatin = false;
    bool hasCyrillic = false;
    bool hasGreek = false;

    for (final rune in label.runes) {
      if ((rune >= 0x0041 && rune <= 0x007A)) {
        hasLatin = true;
      } else if (rune >= 0x0400 && rune <= 0x04FF) {
        hasCyrillic = true;
      } else if (rune >= 0x0370 && rune <= 0x03FF) {
        hasGreek = true;
      }
    }

    return hasLatin && (hasCyrillic || hasGreek);
  }

  /// Layer 3: Check URL against Google Safe Browsing v4 Lookup API.
  ///
  /// Returns threat type string if URL is flagged, null if safe or
  /// if the API is not configured / unreachable.
  ///
  /// PRIVACY: This sends the URL to Google's servers. Only called
  /// when [safeBrowsingApiKey] is set (opt-in).
  static Future<String?> checkSafeBrowsing(String url) async {
    final apiKey = safeBrowsingApiKey;
    if (apiKey == null || apiKey.isEmpty) return null;

    try {
      final client = HttpClient();
      final request = await client.postUrl(Uri.parse(
        'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$apiKey',
      ));
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode({
        'client': {
          'clientId': 'icd360s-mail-client',
          'clientVersion': '2.22',
        },
        'threatInfo': {
          'threatTypes': [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          'platformTypes': ['ANY_PLATFORM'],
          'threatEntryTypes': ['URL'],
          'threatEntries': [
            {'url': url},
          ],
        },
      }));

      final response = await request.close().timeout(
        const Duration(seconds: 5),
      );
      final body = await response.transform(utf8.decoder).join();

      if (response.statusCode == 200) {
        final data = jsonDecode(body) as Map<String, dynamic>;
        final matches = data['matches'] as List<dynamic>?;
        if (matches != null && matches.isNotEmpty) {
          final threat = matches[0]['threatType'] as String? ?? 'UNKNOWN';
          LoggerService.log('PHISHING',
              '⚠ Google Safe Browsing flagged URL: $url as $threat');
          return threat;
        }
      }

      client.close(force: true);
      return null;
    } catch (ex) {
      LoggerService.log('PHISHING',
          'Safe Browsing API error (non-fatal): $ex');
      return null;
    }
  }

  /// Run ALL layers and return combined result.
  static Future<PhishingResult> analyze(String url, {String? displayText}) async {
    // Layer 2: local heuristics
    final localWarnings = checkLocal(url);

    // Layer 1: display text mismatch (if provided)
    if (displayText != null && displayText.trim().isNotEmpty) {
      final textLower = displayText.trim().toLowerCase();
      if (_looksLikeUrl(textLower)) {
        final textDomain = _extractDomain(
          textLower.startsWith('http') ? textLower : 'https://$textLower',
        );
        final actualDomain = _extractDomain(url);
        if (textDomain != null &&
            actualDomain != null &&
            textDomain != actualDomain) {
          localWarnings.insert(0, PhishingWarning(
            severity: WarningSeverity.critical,
            message: 'Link text shows "$textDomain" but actual destination is "$actualDomain"',
          ));
        }
      }
    }

    // Layer 3: Google Safe Browsing (opt-in)
    String? safeBrowsingThreat;
    if (safeBrowsingApiKey != null) {
      safeBrowsingThreat = await checkSafeBrowsing(url);
      if (safeBrowsingThreat != null) {
        localWarnings.insert(0, PhishingWarning(
          severity: WarningSeverity.critical,
          message: 'Google Safe Browsing: flagged as $safeBrowsingThreat',
        ));
      }
    }

    final maxSeverity = localWarnings.isEmpty
        ? WarningSeverity.none
        : localWarnings
            .map((w) => w.severity)
            .reduce((a, b) => a.index > b.index ? a : b);

    return PhishingResult(
      url: url,
      warnings: localWarnings,
      maxSeverity: maxSeverity,
      safeBrowsingThreat: safeBrowsingThreat,
    );
  }

  static String? _extractDomain(String url) {
    try {
      return Uri.parse(url).host.toLowerCase();
    } catch (_) {
      return null;
    }
  }

  static bool _looksLikeUrl(String text) {
    final t = text.trim().toLowerCase();
    return t.startsWith('http://') ||
        t.startsWith('https://') ||
        RegExp(r'^[a-z0-9.-]+\.[a-z]{2,}(/|$)').hasMatch(t);
  }
}

enum WarningSeverity { none, low, medium, high, critical }

class PhishingWarning {
  final WarningSeverity severity;
  final String message;
  const PhishingWarning({required this.severity, required this.message});
}

class PhishingResult {
  final String url;
  final List<PhishingWarning> warnings;
  final WarningSeverity maxSeverity;
  final String? safeBrowsingThreat;

  const PhishingResult({
    required this.url,
    required this.warnings,
    required this.maxSeverity,
    this.safeBrowsingThreat,
  });

  bool get isSafe => warnings.isEmpty;
  bool get isDangerous =>
      maxSeverity == WarningSeverity.high ||
      maxSeverity == WarningSeverity.critical;
}
