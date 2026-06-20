// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:crypto/crypto.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

import '../services/logger_service.dart';
import '../services/portable_secure_storage.dart';

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
  // Layer 3 is fully offline — no API key needed on the client. The
  // blocklist comes from a community-maintained feed updated twice a
  // day (curbengh/phishing-filter, aggregating OpenPhish + IPThreat +
  // PhishTank), reduced to 4-byte SHA-256 hash prefixes locally.

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

  /// Cyrillic letters that visually resemble ASCII Latin letters.
  /// Used for whole-script-confusable detection (UTS #39 + Chromium).
  /// If a label is 100% Cyrillic AND every character is in this set,
  /// the label is a confusable (e.g. аррӏе → apple).
  static const Set<int> _cyrillicLatinLookalikes = {
    0x0430, 0x0441, 0x0435, 0x043E, 0x0440, 0x0445, 0x0443, // a c e o p x y
    0x0456, 0x0458, 0x04CF, 0x0501, 0x050D, 0x04BB, 0x051B, // i j ӏ ԁ ԍ һ ԛ
    0x0455, 0x051D, 0x044C, 0x044A, 0x04BD, 0x043F, 0x0433, // s ԝ ь ъ ҽ п г
    0x0475, 0x0461, 0x044B, 0x044E, 0x043A,                  // ѵ ѡ ы ю к
  };

  /// Greek letters that visually resemble ASCII Latin letters.
  /// Used for whole-script-confusable detection.
  static const Set<int> _greekLatinLookalikes = {
    0x03B1, 0x03BF, 0x03C1, 0x03F2, 0x03F3, // α ο ρ ϲ ϳ
    0x03BD, 0x03C4, 0x03C5, 0x03C7, 0x03B9, // ν τ υ χ ι
  };

  /// ccTLDs where Cyrillic script is legitimate — don't flag whole-script
  /// Cyrillic labels as confusable when ending in these.
  static const Set<String> _cyrillicTlds = {
    'ru', 'by', 'bg', 'kz', 'ua', 'su', 'uz', 'mk', 'rs', 'mn',
    'рф', 'бел', 'укр', 'мкд', 'срб', 'бг', 'қаз',
  };

  /// ccTLDs where Greek script is legitimate.
  static const Set<String> _greekTlds = {'gr', 'cy', 'ελ'};

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

    // Homograph detection — UTS #39 Highly Restrictive + whole-script
    // confusable check (catches both pаypal.com and аррӏе.com).
    final spoofVerdict = _checkIdnSpoof(host);
    if (spoofVerdict == _IdnVerdict.mixedScript) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.high,
        message: 'Domain mixes incompatible Unicode scripts '
            '(Latin + Cyrillic/Greek) — possible homograph attack',
      ));
    } else if (spoofVerdict == _IdnVerdict.wholeScriptConfusable) {
      warnings.add(PhishingWarning(
        severity: WarningSeverity.high,
        message: 'Domain uses non-Latin characters that look like Latin '
            'letters — almost certainly a phishing attempt',
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

  /// Per-label IDN spoof check based on UTS #39 Highly Restrictive
  /// profile + whole-script confusable detection (Chromium-style).
  ///
  /// Returns the worst verdict across all labels in the hostname.
  static _IdnVerdict _checkIdnSpoof(String hostname) {
    final parts = hostname.split('.');
    if (parts.isEmpty) return _IdnVerdict.safe;
    final tld = parts.last;

    var worst = _IdnVerdict.safe;
    for (final label in parts) {
      final v = _checkLabelSpoof(label, tld);
      if (v.index > worst.index) worst = v;
    }
    return worst;
  }

  static _IdnVerdict _checkLabelSpoof(String label, String tld) {
    if (label.isEmpty) return _IdnVerdict.safe;
    // Pure ASCII = safe
    if (label.codeUnits.every((c) => c < 0x80)) return _IdnVerdict.safe;

    final codepoints = label.runes.toList();

    // Collect scripts used (Common/Inherited excluded).
    final scripts = <_Script>{};
    for (final cp in codepoints) {
      final s = _scriptOf(cp);
      if (s != _Script.common && s != _Script.inherited) scripts.add(s);
    }

    // UTS #39 Highly Restrictive — reject mixed Latin + non-CJK.
    if (!_isHighlyRestrictive(scripts)) return _IdnVerdict.mixedScript;

    // Whole-script confusable: Cyrillic
    if (scripts.length == 1 && scripts.contains(_Script.cyrillic)) {
      final allLookalike =
          codepoints.every(_cyrillicLatinLookalikes.contains);
      if (allLookalike && !_cyrillicTlds.contains(tld)) {
        return _IdnVerdict.wholeScriptConfusable;
      }
    }

    // Whole-script confusable: Greek
    if (scripts.length == 1 && scripts.contains(_Script.greek)) {
      final allLookalike =
          codepoints.every(_greekLatinLookalikes.contains);
      if (allLookalike && !_greekTlds.contains(tld)) {
        return _IdnVerdict.wholeScriptConfusable;
      }
    }

    return _IdnVerdict.safe;
  }

  /// UTS #39 Highly Restrictive: single script, or one of the three
  /// fixed CJK + Latin combinations.
  static bool _isHighlyRestrictive(Set<_Script> s) {
    if (s.isEmpty || s.length == 1) return true;
    // Japanese: Latin + Han + Hiragana + Katakana
    if (s.difference({_Script.latin, _Script.han, _Script.hiragana,
        _Script.katakana}).isEmpty) return true;
    // Traditional Chinese: Latin + Han + Bopomofo
    if (s.difference({_Script.latin, _Script.han, _Script.bopomofo})
        .isEmpty) return true;
    // Korean: Latin + Han + Hangul
    if (s.difference({_Script.latin, _Script.han, _Script.hangul})
        .isEmpty) return true;
    return false;
  }

  /// Minimal Unicode script classifier — covers blocks relevant to
  /// hostname spoofing detection. For full coverage we'd need ICU,
  /// but the Identifier Profile already excludes most exotic ranges.
  static _Script _scriptOf(int cp) {
    if (cp < 0x80) {
      if ((cp >= 0x61 && cp <= 0x7A) || (cp >= 0x41 && cp <= 0x5A)) {
        return _Script.latin;
      }
      return _Script.common;
    }
    // Latin Extended-A/B/IPA
    if (cp >= 0x0080 && cp <= 0x024F) return _Script.latin;
    if (cp >= 0x1E00 && cp <= 0x1EFF) return _Script.latin;
    // Greek + Coptic
    if (cp >= 0x0370 && cp <= 0x03FF) return _Script.greek;
    if (cp >= 0x1F00 && cp <= 0x1FFF) return _Script.greek;
    // Cyrillic
    if (cp >= 0x0400 && cp <= 0x052F) return _Script.cyrillic;
    // Armenian
    if (cp >= 0x0530 && cp <= 0x058F) return _Script.armenian;
    // Hebrew
    if (cp >= 0x0590 && cp <= 0x05FF) return _Script.hebrew;
    // Arabic
    if (cp >= 0x0600 && cp <= 0x06FF) return _Script.arabic;
    // Hiragana
    if (cp >= 0x3040 && cp <= 0x309F) return _Script.hiragana;
    // Katakana
    if (cp >= 0x30A0 && cp <= 0x30FF) return _Script.katakana;
    if (cp >= 0xFF65 && cp <= 0xFF9F) return _Script.katakana;
    // Bopomofo
    if (cp >= 0x3100 && cp <= 0x312F) return _Script.bopomofo;
    // Hangul
    if (cp >= 0xAC00 && cp <= 0xD7AF) return _Script.hangul;
    if (cp >= 0x1100 && cp <= 0x11FF) return _Script.hangul;
    // Han (CJK Unified)
    if (cp >= 0x4E00 && cp <= 0x9FFF) return _Script.han;
    if (cp >= 0x3400 && cp <= 0x4DBF) return _Script.han;
    // Combining marks
    if (cp >= 0x0300 && cp <= 0x036F) return _Script.inherited;
    return _Script.unknown;
  }

  // =========================================================================
  // Layer 3: Offline domain-based phishing blocklist
  // =========================================================================
  //
  // PRIVACY: ZERO URLs are sent to Google or any other party. The
  // blocklist itself is downloaded from a public, community-maintained
  // feed and reduced to 4-byte hash prefixes locally. URL lookups
  // happen entirely in-memory against the sorted prefix list.
  //
  // Source: `phishing-filter` by malware-filter/curben (mirror at
  // curbengh.github.io), aggregating OpenPhish + IPThreat + PhishTank.
  // Updated twice a day. The AdGuard Home (`-agh.txt`) format is one
  // domain per line, prefixed `||` and suffixed `^`, with `!` comments.
  // We hash the *domain* (not the full URL) since AGH entries are
  // domain-scoped.
  //
  // Trust model:
  //   - TLS to GitHub Pages (DigiCert chain via OS trust store)
  //   - Mandatory minimum count (anti-emptying)
  //   - Per-update shrinkage cap of 50% vs the previously loaded count
  //   - 7-day max cache age — past this, the cache is discarded and
  //     a fresh download is required before lookups will match
  //
  // What we dropped vs the pre-2026-06-17 SBv2 design: ECDSA P-256
  // signature on the file. The signing key only ever lived on the
  // mail host that we've now retired as a binary-distribution channel;
  // its only attacker model was "compromised CDN serves tampered
  // file", which is now covered by GitHub Pages TLS + the per-update
  // sanity checks above. Forging a useful tampered list also requires
  // padding it to >=50% of the legitimate size, which makes the
  // attack significantly more expensive than just serving an empty
  // file.
  // =========================================================================

  static const String _blocklistUrl =
      'https://curbengh.github.io/phishing-filter/phishing-filter-agh.txt';

  /// In-memory sorted prefix list (loaded from downloaded file).
  static List<int>? _prefixDatabase;

  /// Last time the database was refreshed.
  static DateTime? _lastDbRefresh;

  /// Refresh interval — upstream updates twice a day, so 6 hours keeps
  /// us close to fresh without hammering the feed.
  static const Duration _dbRefreshInterval = Duration(hours: 6);

  /// Hard freshness limit — reject databases older than this.
  static const Duration _maxDbAge = Duration(days: 7);

  /// Minimum absolute prefix count — reject suspiciously small DBs.
  static const int _minPrefixCount = 1000;

  /// Maximum allowed shrinkage between updates (50%).
  static const double _maxShrinkageRatio = 0.5;

  /// Path to the cached database file on disk.
  static String? _dbCachePath;

  /// Persistent state for anti-emptying check (last accepted count).
  /// PortableSecureStorage uses native storage on iOS/Android/Windows/
  /// Linux and AES-GCM file backend on macOS.
  static final _storage = PortableSecureStorage.instance;
  static const _kLastCount = 'sb_last_count';

  // Cache binary layout (little-endian):
  //   bytes  0..3   magic "PFv1" (Phishing Filter v1)
  //   bytes  4..11  int64 download time (ms since UNIX epoch)
  //   bytes 12..15  uint32 count
  //   bytes 16..    count * uint32 big-endian sorted prefixes
  static const _cacheMagic = 0x50467631; // "PFv1" big-endian
  static const _cacheHeaderSize = 16;

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

    // Try loading from on-disk cache first. The cache is our own
    // binary format (PFv1), produced by [_writeCache] after a
    // successful download. We re-check freshness here because a
    // device may have been offline for days.
    if (_prefixDatabase == null && _dbCachePath != null) {
      final cached = File(_dbCachePath!);
      if (cached.existsSync()) {
        try {
          _loadFromCache(cached.readAsBytesSync());
        } catch (ex) {
          LoggerService.log('PHISHING', 'Cache load skipped: $ex');
        }
      }
    }

    // Download fresh copy from the community blocklist. Plain
    // HttpClient because GitHub Pages uses DigiCert, outside the
    // ISRG-only [PinnedSecurityContext] used for our own services.
    try {
      final client = HttpClient()
        ..userAgent = 'ICD360S-Mail-Client/Phishing-Filter';
      try {
        final request = await client.getUrl(Uri.parse(_blocklistUrl));
        request.headers.set('Accept', 'text/plain');
        final response = await request.close().timeout(
          const Duration(seconds: 30),
        );
        if (response.statusCode != 200) {
          LoggerService.log('PHISHING',
              'Blocklist HTTP ${response.statusCode} — keeping cache if any');
          return;
        }
        final text = await response.transform(utf8.decoder).join();
        final prefixes = _parseAghTextToPrefixes(text);

        // Anti-emptying — minimum absolute count.
        if (prefixes.length < _minPrefixCount) {
          throw StateError(
              'Blocklist count too low: ${prefixes.length} < $_minPrefixCount');
        }
        // Anti-shrinkage — refuse to accept a list that lost more than
        // half of what we previously had. Catches both a botched
        // upstream regeneration and an attacker pushing a near-empty
        // file to whitelist phishing domains.
        final lastCountStr = await _storage.read(key: _kLastCount);
        final lastCount = int.tryParse(lastCountStr ?? '') ?? 0;
        if (lastCount > 0 &&
            prefixes.length < lastCount * _maxShrinkageRatio) {
          throw StateError(
              'Blocklist shrunk too much: ${prefixes.length} < '
              '${(lastCount * _maxShrinkageRatio).toStringAsFixed(0)} '
              '(was $lastCount)');
        }

        _prefixDatabase = prefixes;
        _lastDbRefresh = DateTime.now();
        await _storage.write(
            key: _kLastCount, value: prefixes.length.toString());

        if (_dbCachePath != null) {
          await _writeCache(_dbCachePath!, prefixes, _lastDbRefresh!);
        }
        LoggerService.log('PHISHING',
            'Blocklist refreshed: ${prefixes.length} prefixes');
      } finally {
        client.close(force: true);
      }
    } catch (ex) {
      LoggerService.log('PHISHING',
          'Blocklist refresh failed (using cache if loaded): $ex');
    }
  }

  /// Parse the AdGuard Home text format and return a sorted list of
  /// 4-byte SHA-256 prefixes of the domains. Each accepted line looks
  /// like `||example.com^` — anything else (comments starting with
  /// `!`, blank lines, malformed entries) is skipped silently.
  static List<int> _parseAghTextToPrefixes(String text) {
    final prefixes = <int>{};
    for (final raw in const LineSplitter().convert(text)) {
      final line = raw.trim();
      if (line.isEmpty || line.startsWith('!')) continue;
      if (!line.startsWith('||') || !line.endsWith('^')) continue;
      final domain = line.substring(2, line.length - 1).toLowerCase();
      if (domain.isEmpty) continue;
      final hash = sha256.convert(utf8.encode(domain)).bytes;
      final prefix = ((hash[0] & 0xff) << 24) |
          ((hash[1] & 0xff) << 16) |
          ((hash[2] & 0xff) << 8) |
          (hash[3] & 0xff);
      prefixes.add(prefix);
    }
    final sorted = prefixes.toList()..sort();
    return sorted;
  }

  /// Read a cached PFv1 file into memory if it parses cleanly AND is
  /// not older than [_maxDbAge]. Throws otherwise so the caller can
  /// fall through to a fresh download.
  static void _loadFromCache(Uint8List data) {
    if (data.length < _cacheHeaderSize) {
      throw StateError('Cache too short (${data.length} bytes)');
    }
    final bd = data.buffer.asByteData();
    final magic = bd.getUint32(0, Endian.big);
    if (magic != _cacheMagic) {
      throw StateError('Bad cache magic');
    }
    final downloadedMs = bd.getInt64(4, Endian.little);
    final count = bd.getUint32(12, Endian.little);
    if (data.length < _cacheHeaderSize + count * 4) {
      throw StateError('Cache truncated');
    }
    if (count < _minPrefixCount) {
      throw StateError('Cache count too low: $count');
    }
    final cacheAge = DateTime.now()
        .difference(DateTime.fromMillisecondsSinceEpoch(downloadedMs));
    if (cacheAge > _maxDbAge) {
      throw StateError(
          'Cache too stale: ${cacheAge.inDays}d > ${_maxDbAge.inDays}d');
    }
    _prefixDatabase = List<int>.generate(count, (i) {
      return bd.getUint32(_cacheHeaderSize + i * 4, Endian.big);
    });
    _lastDbRefresh = DateTime.fromMillisecondsSinceEpoch(downloadedMs);
    LoggerService.log('PHISHING',
        'Cache loaded: $count prefixes, ${cacheAge.inHours}h old');
  }

  /// Serialize the prefix list to a PFv1 cache file. Atomic via temp
  /// + rename so a crash mid-write never leaves a half-baked cache.
  static Future<void> _writeCache(
      String path, List<int> prefixes, DateTime downloadedAt) async {
    final buf = Uint8List(_cacheHeaderSize + prefixes.length * 4);
    final bd = buf.buffer.asByteData();
    bd.setUint32(0, _cacheMagic, Endian.big);
    bd.setInt64(4, downloadedAt.millisecondsSinceEpoch, Endian.little);
    bd.setUint32(12, prefixes.length, Endian.little);
    for (var i = 0; i < prefixes.length; i++) {
      bd.setUint32(_cacheHeaderSize + i * 4, prefixes[i], Endian.big);
    }
    final tmp = File('$path.tmp');
    await tmp.writeAsBytes(buf, flush: true);
    await tmp.rename(path);
    try {
      if (!Platform.isWindows) {
        await Process.run('/bin/chmod', ['600', path]);
      }
    } catch (_) {/* best-effort */}
  }

  /// Check a URL against the local prefix database using binary search.
  /// Hashes the URL's host (lowercased) — the upstream feed is
  /// domain-scoped, so per-path lookups would never match.
  ///
  /// Returns true if the domain's SHA-256 hash prefix matches any
  /// known threat. False positive rate: ~1 in 4 billion (a single
  /// 32-bit prefix collision over a list of ~10k entries).
  static Future<bool> checkSafeBrowsingOffline(String url) async {
    await _ensureDatabase();
    final db = _prefixDatabase;
    if (db == null || db.isEmpty) return false;

    final uri = Uri.tryParse(url);
    if (uri == null) return false;
    final host = uri.host.toLowerCase();
    if (host.isEmpty) return false;

    final hash = sha256.convert(utf8.encode(host)).bytes;
    final prefix = ((hash[0] & 0xff) << 24) |
        ((hash[1] & 0xff) << 16) |
        ((hash[2] & 0xff) << 8) |
        (hash[3] & 0xff);

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

/// Internal verdict for IDN spoof detection (UTS #39 + whole-script
/// confusable). Order matters — `index` is used to compute "worst".
enum _IdnVerdict { safe, mixedScript, wholeScriptConfusable }

/// Internal Unicode script enum for spoof detection. Limited to scripts
/// relevant to hostname display — exotic scripts are filtered out
/// elsewhere.
enum _Script {
  common, inherited, unknown,
  latin, cyrillic, greek, armenian, hebrew, arabic,
  han, hiragana, katakana, bopomofo, hangul,
}

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