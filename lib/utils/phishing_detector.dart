import 'package:crypto/crypto.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/api.dart' as pc_api;

import '../services/le_issuer_check.dart';
import '../services/logger_service.dart';
import '../services/pinned_security_context.dart';

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
  // Layer 3: Offline Safe Browsing (signed local hash prefix database)
  // =========================================================================
  //
  // PRIVACY: ZERO URLs are sent to Google. A cron on alma-8gb-fsn1-1
  // downloads hash prefixes from Google Safe Browsing Update API,
  // packs them into SBv2 format, signs with ECDSA P-256, and uploads
  // both safebrowsing.bin and safebrowsing.bin.sig to mail.icd360s.de.
  //
  // SBv2 format:
  //   "SBv2" (4) | version (u32 LE) | timestamp (u64 LE) |
  //   count (u32 LE) | prefix_size (u32 LE) | sorted 4-byte prefixes
  //
  // Verification chain (all must pass before loading):
  //   1. Download both .bin and .sig over PinnedSecurityContext (TLS pin)
  //   2. ECDSA P-256 signature on SHA-256(file) verified against
  //      hardcoded _safeBrowsingPublicKey
  //   3. Magic = "SBv2"
  //   4. Freshness: timestamp not older than 7 days
  //   5. Anti-replay: timestamp >= last loaded timestamp
  //   6. Anti-emptying: count >= 1000 absolute, and >= 50% of last count
  // =========================================================================

  static const String _safeBrowsingUrl =
      'https://mail.icd360s.de/updates/safebrowsing.bin';
  static const String _safeBrowsingSigUrl =
      'https://mail.icd360s.de/updates/safebrowsing.bin.sig';

  /// ECDSA P-256 public key for Safe Browsing DB signature verification.
  /// 65 bytes raw uncompressed point: 0x04 || X (32) || Y (32).
  /// Generated by `openssl ecparam -genkey -name prime256v1` on the
  /// signing server (alma-8gb-fsn1-1, /root/.icd360s/release_signing/).
  /// Private key never leaves the signing server.
  static final Uint8List _safeBrowsingPublicKey = Uint8List.fromList([
    0x04, 0x57, 0x05, 0xcc, 0x46, 0xdd, 0x5d, 0x77, 0x3a, 0x42, 0x39, 0xa8,
    0x34, 0x25, 0x80, 0x67, 0x6a, 0x2c, 0xc6, 0xcd, 0xaf, 0xb2, 0x7e, 0x71,
    0x17, 0xdb, 0xb3, 0x9f, 0xb3, 0x7b, 0x66, 0x95, 0x8e, 0x30, 0x90, 0xba,
    0xcf, 0x8c, 0x4e, 0xec, 0x77, 0xf2, 0x90, 0x45, 0x06, 0x51, 0x67, 0x1b,
    0xde, 0x71, 0x06, 0xcd, 0x60, 0xec, 0xb7, 0x48, 0xe8, 0x8c, 0x08, 0x26,
    0xee, 0xaf, 0x5f, 0x70, 0xde,
  ]);

  /// In-memory sorted prefix list (loaded from downloaded file).
  static List<int>? _prefixDatabase;

  /// Last time the database was refreshed.
  static DateTime? _lastDbRefresh;

  /// Refresh interval (6 hours matches server cron).
  static const Duration _dbRefreshInterval = Duration(hours: 6);

  /// Hard freshness limit — reject databases older than this.
  static const Duration _maxDbAge = Duration(days: 7);

  /// Minimum absolute prefix count — reject suspiciously small DBs.
  static const int _minPrefixCount = 1000;

  /// Maximum allowed shrinkage between updates (50%).
  static const double _maxShrinkageRatio = 0.5;

  /// Path to the cached database file on disk.
  static String? _dbCachePath;

  /// Persistent state for anti-replay and anti-emptying checks.
  static const _storage = FlutterSecureStorage();
  static const _kLastTimestamp = 'sb_last_timestamp';
  static const _kLastCount = 'sb_last_count';

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

    // Try loading from cache first (cached data was already verified
    // when we wrote it, so we trust it)
    if (_prefixDatabase == null && _dbCachePath != null) {
      final cached = File(_dbCachePath!);
      if (cached.existsSync()) {
        try {
          await _verifyAndLoad(cached.readAsBytesSync(), null);
        } catch (_) {
          // Cache is corrupt — proceed to download
        }
      }
    }

    // Download fresh copy
    try {
      final client = PinnedSecurityContext.createHttpClient()
        ..badCertificateCallback = (cert, host, port) {
          if (host != 'mail.icd360s.de') return false;
          return isTrustedLetsEncryptIssuer(cert.issuer);
        };
      try {
        // Download .sig first, then .bin
        final sigBytes = await _downloadBytes(client, _safeBrowsingSigUrl);
        if (sigBytes == null) return;
        final dataBytes = await _downloadBytes(client, _safeBrowsingUrl);
        if (dataBytes == null) return;

        await _verifyAndLoad(dataBytes, sigBytes);

        // Cache verified data + sig to disk
        if (_dbCachePath != null) {
          await File(_dbCachePath!).writeAsBytes(dataBytes);
          await File('$_dbCachePath!.sig').writeAsBytes(sigBytes);
        }
        _lastDbRefresh = DateTime.now();
      } finally {
        client.close(force: true);
      }
    } catch (ex) {
      LoggerService.log('PHISHING',
          'Safe Browsing DB download/verify failed (using cache): $ex');
    }
  }

  static Future<Uint8List?> _downloadBytes(
      HttpClient client, String url) async {
    final request = await client.getUrl(Uri.parse(url));
    final response = await request.close().timeout(
      const Duration(seconds: 30),
    );
    if (response.statusCode != 200) return null;
    final bytes = <int>[];
    await for (final chunk in response) {
      bytes.addAll(chunk);
    }
    return Uint8List.fromList(bytes);
  }

  /// Verify signature, parse SBv2 header, run all sanity checks,
  /// then load the prefix database into memory.
  static Future<void> _verifyAndLoad(
      Uint8List data, Uint8List? signature) async {
    // Step 1: Verify signature (if provided — cached data has no .sig)
    if (signature != null) {
      if (!_verifySignature(data, signature)) {
        throw StateError('Safe Browsing DB signature verification failed');
      }
    }

    // Step 2: Validate SBv2 header
    if (data.length < 24) {
      throw StateError('SBv2 file too short (${data.length} bytes)');
    }
    // Magic check: "SBv2"
    if (data[0] != 0x53 || data[1] != 0x42 ||
        data[2] != 0x76 || data[3] != 0x32) {
      throw StateError('Bad SBv2 magic');
    }

    final bd = data.buffer.asByteData();
    final version = bd.getUint32(4, Endian.little);
    final timestamp = bd.getUint64(8, Endian.little);
    final count = bd.getUint32(16, Endian.little);
    final prefixSize = bd.getUint32(20, Endian.little);

    if (prefixSize != 4) {
      throw StateError('Unsupported prefix size: $prefixSize');
    }
    if (data.length < 24 + count * 4) {
      throw StateError('SBv2 file truncated');
    }

    // Step 3: Anti-emptying — minimum absolute count
    if (count < _minPrefixCount) {
      throw StateError('SBv2 count too low: $count < $_minPrefixCount');
    }

    // Step 4: Freshness check
    final dbTime = DateTime.fromMillisecondsSinceEpoch(
        timestamp * 1000, isUtc: true);
    final age = DateTime.now().toUtc().difference(dbTime);
    if (age > _maxDbAge) {
      throw StateError(
          'SBv2 too stale: ${age.inDays}d (max ${_maxDbAge.inDays}d)');
    }
    if (age.inHours > 72) {
      LoggerService.logWarning('PHISHING',
          'SBv2 is ${age.inHours}h old — server cron may be lagging');
    }

    // Step 5: Anti-replay + anti-emptying ratio (only if signature provided,
    // i.e. fresh download — cached data we trust unconditionally)
    if (signature != null) {
      final lastTsStr = await _storage.read(key: _kLastTimestamp);
      final lastCountStr = await _storage.read(key: _kLastCount);
      final lastTs = int.tryParse(lastTsStr ?? '') ?? 0;
      final lastCount = int.tryParse(lastCountStr ?? '') ?? 0;

      if (timestamp < lastTs) {
        throw StateError(
            'SBv2 replay attack: timestamp $timestamp < last $lastTs');
      }
      if (lastCount > 0 && count < lastCount * _maxShrinkageRatio) {
        throw StateError(
            'SBv2 emptying attack: count $count < ${lastCount * _maxShrinkageRatio}');
      }

      // Persist new state
      await _storage.write(key: _kLastTimestamp, value: timestamp.toString());
      await _storage.write(key: _kLastCount, value: count.toString());
    }

    // Step 6: Load prefixes into memory
    _prefixDatabase = List<int>.generate(count, (i) {
      final offset = 24 + i * 4;
      return bd.getUint32(offset, Endian.big);
    });

    LoggerService.log('PHISHING',
        'SBv2 loaded: v$version ts=$timestamp count=$count age=${age.inHours}h');
  }

  /// Verify ECDSA P-256 signature over SHA-256(data) using
  /// _safeBrowsingPublicKey.
  static bool _verifySignature(Uint8List data, Uint8List signature) {
    try {
      // Hash the data
      final hash = SHA256Digest().process(data);

      // Parse DER signature into (r, s)
      final asn1 = ASN1Parser(signature);
      final seq = asn1.nextObject() as ASN1Sequence;
      final r = (seq.elements![0] as ASN1Integer).integer!;
      final s = (seq.elements![1] as ASN1Integer).integer!;

      // Build EC public key from raw 65-byte point
      final params = ECCurve_secp256r1();
      final point = params.curve.decodePoint(_safeBrowsingPublicKey);
      if (point == null) return false;
      final pubKey = ECPublicKey(point, params);

      // Verify
      final signer = ECDSASigner();
      signer.init(false, pc_api.PublicKeyParameter<ECPublicKey>(pubKey));
      return signer.verifySignature(hash, ECSignature(r, s));
    } catch (ex) {
      LoggerService.logWarning('PHISHING', 'Signature parse error: $ex');
      return false;
    }
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
