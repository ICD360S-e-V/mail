import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import 'logger_service.dart';

/// Persistent monotonic version baseline for downgrade-attack protection.
///
/// Stores the highest version this client has ever accepted. Any update
/// proposing a version strictly less than this baseline is rejected,
/// even if all other integrity checks (TLS, SHA-256, signing certificate)
/// pass.
///
/// Inspired by The Update Framework (TUF) version-monotonicity rule.
/// Defense layer against rollback / downgrade attacks (CWE-1328:
/// Security Version Number Mutable to Older Versions).
///
/// Threat model: an attacker who controls or impersonates the update
/// server cannot push an older legitimate release that contains a known
/// vulnerability. Note that this complements — does not replace —
/// Android's own `versionCode` enforcement at PackageInstaller level.
class VersionBaseline {
  static const String _filename = 'version_baseline.txt';
  static String? _cachedPath;

  static Future<String> _path() async {
    if (_cachedPath != null) return _cachedPath!;
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    _cachedPath = p.join(dir.path, _filename);
    return _cachedPath!;
  }

  /// Initializes the baseline to [currentVersion] if no file exists.
  /// Safe to call repeatedly; subsequent calls are no-ops.
  static Future<void> initialize(String currentVersion) async {
    try {
      final path = await _path();
      final f = File(path);
      if (!await f.exists()) {
        await _writeAtomic(path, currentVersion);
        LoggerService.log('VERSION_BASELINE',
            'Initialized baseline to $currentVersion');
      }
    } catch (ex, st) {
      LoggerService.logError('VERSION_BASELINE', ex, st);
    }
  }

  /// Reads the current baseline. Returns null if not yet initialized
  /// (or if reading failed for any reason — caller should treat null
  /// as "no constraint").
  static Future<String?> read() async {
    try {
      final path = await _path();
      final f = File(path);
      if (!await f.exists()) return null;
      final content = (await f.readAsString()).trim();
      return content.isEmpty ? null : content;
    } catch (ex, st) {
      LoggerService.logError('VERSION_BASELINE', ex, st);
      return null;
    }
  }

  /// Returns true if [candidate] is acceptable: greater than or equal
  /// to the persisted baseline. If no baseline exists yet, accepts.
  static Future<bool> isAcceptable(String candidate) async {
    final baseline = await read();
    if (baseline == null) return true;
    return compareSemver(candidate, baseline) >= 0;
  }

  /// Atomically updates the baseline to [version], but only if it is
  /// strictly greater than the current baseline. Provides the
  /// monotonic-counter property: the baseline never decreases.
  static Future<void> bumpTo(String version) async {
    try {
      final current = await read();
      if (current != null && compareSemver(version, current) <= 0) {
        return;
      }
      final path = await _path();
      await _writeAtomic(path, version);
      LoggerService.log('VERSION_BASELINE',
          'Bumped baseline to $version (was ${current ?? "<unset>"})');
    } catch (ex, st) {
      LoggerService.logError('VERSION_BASELINE', ex, st);
    }
  }

  static Future<void> _writeAtomic(String path, String content) async {
    final tmp = File('$path.tmp');
    await tmp.writeAsString(content, flush: true);
    await tmp.rename(path);
  }

  /// Compare two semver strings of the form `X.Y.Z`. Returns negative
  /// when [a] is older, zero when equal, positive when [a] is newer.
  static int compareSemver(String a, String b) {
    final ap = a.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final bp = b.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    for (var i = 0; i < 3; i++) {
      final av = i < ap.length ? ap[i] : 0;
      final bv = i < bp.length ? bp[i] : 0;
      if (av != bv) return av - bv;
    }
    return 0;
  }
}
