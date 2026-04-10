import 'package:crypto/crypto.dart';
import 'dart:typed_data';
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
  // Layer 3 is now fully offline — no API key needed on the client.
  // The server (mail.icd360s.de) syncs hash prefixes from Google
  // every 6 hours via /opt/icd360s/safebrowsing/sync.py.

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

  // =========================================================================
  // Layer 3: Offline Safe Browsing (local hash prefix database)
  // =========================================================================
  //
  // PRIVACY: ZERO URLs are sent to Google. A cron on mail.icd360s.de
  // downloads hash prefixes from Google Safe Browsing Update API every
  // 6 hours and writes them to /updates/safebrowsing.bin. The client
  // downloads this file periodically and does a local binary search.
  //
  // File format: "SBv1" (4) | version (u32 LE) | count (u32 LE) |
  //              prefix_size (u32 LE) | sorted 4-byte prefixes
  // =========================================================================

  static const String _safeBrowsingUrl =
      'https://mail.icd360s.de/updates/safebrowsing.bin';

  /// In-memory sorted prefix list (loaded from downloaded file).
  static List<int>? _prefixDatabase;

  /// Last time the database was refreshed.
  static DateTime? _lastDbRefresh;

  /// Refresh interval (6 hours matches server cron).
  static const Duration _dbRefreshInterval = Duration(hours: 6);

  /// Path to the cached database file on disk.
  static String? _dbCachePath;

  /// Initialize the database cache path. Call once at app startup.
  static void setCachePath(String appDataPath) {
    _dbCachePath = '$appDataPath/safebrowsing.bin';
  }

  /// Load or refresh the local hash prefix database.
  static Future<void> _ensureDatabase() async {
    // Skip if recently refreshed
    if (_prefixDatabase != null &&
        _lastDbRefresh != null &&
        DateTime.now().difference(_lastDbRefresh!) < _dbRefreshInterval) {
      return;
    }

    // Try loading from cache first
    if (_prefixDatabase == null && _dbCachePath != null) {
      final cached = File(_dbCachePath!);
      if (cached.existsSync()) {
        _loadFromBytes(cached.readAsBytesSync());
      }
    }

    // Download fresh copy in background
    try {
      final client = HttpClient();
      final request = await client.getUrl(Uri.parse(_safeBrowsingUrl));
      final response = await request.close().timeout(
        const Duration(seconds: 30),
      );
      if (response.statusCode == 200) {
        final bytes = <int>[];
        await for (final chunk in response) {
          bytes.addAll(chunk);
        }
        final data = Uint8List.fromList(bytes);
        _loadFromBytes(data);

        // Cache to disk
        if (_dbCachePath != null) {
          await File(_dbCachePath!).writeAsBytes(data);
        }
        _lastDbRefresh = DateTime.now();
      }
      client.close(force: true);
    } catch (ex) {
      LoggerService.log('PHISHING',
          'Safe Browsing DB download failed (non-fatal, using cache): $ex');
    }
  }

  /// Parse the binary file into a sorted list of 4-byte prefix ints.
  static void _loadFromBytes(Uint8List data) {
    if (data.length < 16) return;
    // Verify magic
    if (data[0] != 0x53 || data[1] != 0x42 ||
        data[2] != 0x76 || data[3] != 0x31) {
      // Not "SBv1"
      return;
    }
    final count = data.buffer.asByteData().getUint32(8, Endian.little);
    final prefixSize = data.buffer.asByteData().getUint32(12, Endian.little);
    if (prefixSize != 4 || data.length < 16 + count * 4) return;

    _prefixDatabase = List<int>.generate(count, (i) {
      final offset = 16 + i * 4;
      return data.buffer.asByteData().getUint32(offset, Endian.big);
    });
    LoggerService.log('PHISHING',
        'Safe Browsing DB loaded: ${_prefixDatabase!.length} prefixes');
  }

  /// Check a URL against the local prefix database using binary search.
  ///
  /// Returns true if the URL's SHA-256 hash prefix matches any known
  /// threat. False positive rate: ~1 in 16 million (acceptable for
  /// warning-only use — we never block, just warn).
  static Future<bool> checkSafeBrowsingOffline(String url) async {
    await _ensureDatabase();
    final db = _prefixDatabase;
    if (db == null || db.isEmpty) return false;

    // Canonicalize URL (lowercase host, strip fragment)
    final uri = Uri.tryParse(url);
    if (uri == null) return false;
    final canonical = uri.replace(fragment: '').toString().toLowerCase();

    // SHA-256 hash → extract first 4 bytes as uint32 big-endian
    final hash = sha256.convert(utf8.encode(canonical)).bytes;
    final prefix = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];

    // Binary search in sorted prefix list
    int lo = 0, hi = db.length - 1;
    while (lo <= hi) {
      final mid = (lo + hi) ~/ 2;
      if (db[mid] == prefix) return true;
      if (db[mid] < prefix) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return false;
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

    // Layer 3: Offline Safe Browsing (local hash prefix DB — no URLs sent to Google)
    bool safeBrowsingMatch = false;
    try {
      safeBrowsingMatch = await checkSafeBrowsingOffline(url);
      if (safeBrowsingMatch) {
        localWarnings.insert(0, PhishingWarning(
          severity: WarningSeverity.critical,
          message: 'URL matches known threat in Safe Browsing database',
        ));
      }
    } catch (_) {
      // Non-fatal — Layer 2 still provides protection
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
      safeBrowsingMatch: safeBrowsingMatch,
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
  final bool safeBrowsingMatch;

  const PhishingResult({
    required this.url,
    required this.warnings,
    required this.maxSeverity,
    this.safeBrowsingMatch = false,
  });

  bool get isSafe => warnings.isEmpty;
  bool get isDangerous =>
      maxSeverity == WarningSeverity.high ||
      maxSeverity == WarningSeverity.critical;
}
