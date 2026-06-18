import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:path_provider/path_provider.dart';

/// Encrypted startup diagnostics.
///
/// Opens an on-disk transcript in the app support dir at first call, wraps
/// every pre-runApp() init step with [stepWithTimeout] so a hang in one step
/// can't brick the whole boot, and 3 s after [runApp] uploads the whole
/// transcript AES-256-GCM-encrypted to the per-platform PHP endpoint family
/// at `https://mail.icd360s.de/api/logs/mail_<plat>.php`.
///
/// Key is read at build time from `--dart-define=STARTUP_DIAG_KEY=<hex>`.
/// Empty key → upload is skipped silently (local-mode `flutter run` is the
/// expected case). Per-app key isolation: the server side reads it from the
/// PHP-FPM env var `MAIL_STARTUP_DIAG_KEY` — the per-app prefix only lives in
/// CI / PHP-FPM / GH Secrets, the dart-define name stays generic.
class StartupDiagnostics {
  static const _appSlug = 'mail';
  static const _reportBase = 'https://mail.icd360s.de/api/logs';

  static const _keyHex = String.fromEnvironment(
    'STARTUP_DIAG_KEY',
    defaultValue: '',
  );

  static final List<Map<String, Object?>> _logs = [];
  static IOSink? _sink;
  static bool _initFailed = false;
  static String? _pendingRecovery;

  /// User identity (IMAP username). Empty at the T+3 s live upload — the
  /// vault is still locked then. Updated by the auth flow via [setUsername]
  /// the moment the master vault unlocks and accounts load. The disk
  /// transcript captures everything written after that, so the next-boot
  /// crash-recovery upload includes the user — same pattern Sentry uses
  /// with `scope.setUser`.
  static String? _currentUsername;

  /// Bind the current IMAP user to subsequent transcript writes. Called
  /// from EmailProvider once `_currentAccount` is set. Idempotent —
  /// passing null clears the binding (e.g. on logout).
  static void setUsername(String? username) {
    if (_currentUsername == username) return;
    _currentUsername = username;
    _writeLine(username == null
        ? 'session-user=<cleared>'
        : 'session-user=$username');
  }

  /// Sentinel written at the end of a clean upload so the next boot can
  /// distinguish a healthy session from a crashed/killed one.
  static const _cleanShutdownMarker = '__uploadToServer_status_200__';

  /// Open the on-disk transcript. Safe to call multiple times.
  /// Side-effect: if the previous transcript exists AND lacks the clean
  /// shutdown marker, its contents are buffered into [_pendingRecovery]
  /// for the next [uploadToServer] call (industry-standard "send on next
  /// launch" crash-recovery pattern, same as Sentry/Crashlytics).
  static Future<void> init() async {
    if (_sink != null || _initFailed) return;
    try {
      final dir = await getApplicationSupportDirectory();
      final current = File('${dir.path}${Platform.pathSeparator}startup.log');
      final prev = File('${dir.path}${Platform.pathSeparator}startup.log.prev');

      // Recovery check: if previous-prev file still exists from an earlier
      // unsynced session, take its contents.
      if (await prev.exists()) {
        try {
          final content = await prev.readAsString();
          if (!content.contains(_cleanShutdownMarker)) {
            _pendingRecovery = content;
          }
          await prev.delete();
        } catch (_) {/* swallow — recovery is best-effort */}
      }

      // Rotate current → prev so this boot starts fresh. If the upload at
      // T+3s succeeds, the marker is written and the next boot ignores it.
      if (await current.exists()) {
        try {
          // If we don't have a recovery yet, check the just-rotated file.
          final content = await current.readAsString();
          if (_pendingRecovery == null
              && !content.contains(_cleanShutdownMarker)) {
            _pendingRecovery = content;
          }
          await current.rename(prev.path);
        } catch (_) {/* swallow */}
      }

      _sink = current.openWrite(mode: FileMode.write);
      _writeLine('=== boot ${DateTime.now().toUtc().toIso8601String()} ===');
      _writeLine('platform=${_platformTag()} pid=$pid path=${current.path}');
      if (_pendingRecovery != null) {
        _writeLine('previous-session=unfinished '
            '(${_pendingRecovery!.length} bytes pending recovery upload)');
      }
    } catch (e, st) {
      _initFailed = true;
      // Best-effort fallback: keep in-memory log; transcript is optional.
      log('warn', 'STARTUP', 'transcript open failed: $e');
      log('warn', 'STARTUP', st.toString());
    }
  }

  /// Run [body] with a per-step [timeout]. Surfaces both the timing and a
  /// timeout signal in the transcript so a hung step is identifiable. The
  /// outer caller still gets the awaited value (or rethrown error) — this
  /// wrapper is transparent on the happy path.
  static Future<T> stepWithTimeout<T>(
    String name,
    Duration timeout,
    Future<T> Function() body,
  ) async {
    final sw = Stopwatch()..start();
    log('info', 'STARTUP', '→ START $name');
    try {
      final result = await body().timeout(timeout);
      sw.stop();
      log('info', 'STARTUP', '← DONE  $name (${_fmtDuration(sw)})');
      return result;
    } on TimeoutException {
      sw.stop();
      log('error', 'STARTUP',
          '✗ TIMEOUT $name after ${timeout.inSeconds}s');
      rethrow;
    } catch (e, st) {
      sw.stop();
      log('error', 'STARTUP',
          '✗ FAILED $name (${_fmtDuration(sw)}): $e');
      log('error', 'STARTUP', st.toString());
      rethrow;
    }
  }

  /// Sub-millisecond timings get the `µs` suffix; ≥ 1 ms uses `ms`.
  /// Native platforms give Stopwatch true microsecond precision — never
  /// round legitimate sub-ms work to `0ms` and lose the signal.
  static String _fmtDuration(Stopwatch sw) {
    final us = sw.elapsedMicroseconds;
    if (us >= 1000) return '${(us / 1000).toStringAsFixed(1)}ms';
    return '${us}µs';
  }

  /// Append a log line. Goes to in-memory list (uploaded later) and the
  /// on-disk transcript (for forensic recovery on the next boot).
  static void log(String level, String tag, String message) {
    final entry = {
      'ts': DateTime.now().toUtc().toIso8601String(),
      'level': level,
      'tag': tag,
      'message': message,
    };
    _logs.add(entry);
    _writeLine('[$level] [$tag] $message');
  }

  /// Upload the accumulated transcript to the per-platform endpoint.
  /// Silent no-op if the key is empty (local dev build). Never throws —
  /// upload failure must not crash the app.
  static Future<void> uploadToServer({
    required String appVersion,
    required String deviceId,
    String? username,
  }) async {
    if (_keyHex.isEmpty) {
      _writeLine('→ uploadToServer skipped (no STARTUP_DIAG_KEY at build time)');
      return;
    }
    if (_keyHex.length != 64) {
      _writeLine(
          '→ uploadToServer skipped (key length=${_keyHex.length}, expected 64)');
      return;
    }
    try {
      final keyBytes = _hexDecode(_keyHex);
      final aes = AesGcm.with256bits();
      final secretKey = SecretKey(keyBytes);

      final payload = jsonEncode({
        'platform': _platformTag(),
        'app_version': appVersion,
        'device_id': deviceId,
        'username': username ?? _currentUsername ?? '',
        'logs': _logs,
      });

      final nonce = aes.newNonce(); // 12 bytes
      final box = await aes.encrypt(
        utf8.encode(payload),
        secretKey: secretKey,
        nonce: nonce,
      );
      // PHP side concatenates ciphertext + tag and splits with substr(-16).
      final ctTag = <int>[...box.cipherText, ...box.mac.bytes];

      final envelope = jsonEncode({
        'v': 1,
        'iv': base64.encode(nonce),
        'data': base64.encode(ctTag),
      });

      final client = HttpClient();
      try {
        client.connectionTimeout = const Duration(seconds: 10);
        final req = await client.postUrl(Uri.parse(_reportUrl));
        req.headers.contentType = ContentType.json;
        req.add(utf8.encode(envelope));
        final res = await req.close().timeout(const Duration(seconds: 10));
        _writeLine('→ uploadToServer status=${res.statusCode}');
        if (res.statusCode == 200) {
          _writeLine(_cleanShutdownMarker);
        }
        await res.drain<void>();

        // Second envelope: if the previous session left a transcript
        // without the clean shutdown marker, ship it now. Best-effort —
        // a failure here doesn't affect the current session's upload.
        if (res.statusCode == 200 && _pendingRecovery != null) {
          try {
            await _sendRecovery(
              client: client,
              key: secretKey,
              appVersion: appVersion,
              deviceId: deviceId,
              username: username,
            );
          } catch (e) {
            _writeLine('→ recovery upload failed: $e');
          } finally {
            _pendingRecovery = null;
          }
        }
      } finally {
        client.close(force: true);
      }
    } catch (e, st) {
      _writeLine('→ uploadToServer failed: $e');
      _writeLine(st.toString());
    } finally {
      try {
        await _sink?.flush();
      } catch (_) {/* swallow */}
    }
  }

  /// Ship the previous-session transcript that lacked the clean shutdown
  /// marker. Sentry/Crashlytics call this the "next launch upload" pattern.
  static Future<void> _sendRecovery({
    required HttpClient client,
    required SecretKey key,
    required String appVersion,
    required String deviceId,
    String? username,
  }) async {
    final aes = AesGcm.with256bits();
    final body = jsonEncode({
      'platform': _platformTag(),
      'app_version': appVersion,
      'device_id': deviceId,
      'username': username ?? _currentUsername ?? '',
      'crash_recovery': true,
      'previous_transcript': _pendingRecovery,
    });
    final nonce = aes.newNonce();
    final box = await aes.encrypt(
      utf8.encode(body),
      secretKey: key,
      nonce: nonce,
    );
    final ctTag = <int>[...box.cipherText, ...box.mac.bytes];
    final envelope = jsonEncode({
      'v': 1,
      'iv': base64.encode(nonce),
      'data': base64.encode(ctTag),
    });
    final req = await client.postUrl(Uri.parse(_reportUrl));
    req.headers.contentType = ContentType.json;
    req.add(utf8.encode(envelope));
    final res = await req.close().timeout(const Duration(seconds: 10));
    _writeLine('→ recovery upload status=${res.statusCode}');
    await res.drain<void>();
  }

  // Per-platform endpoint. FLATPAK_ID is set by the flatpak runtime, not the
  // app — trust it as the routing signal. Filename is `_flatpack.php` with
  // "ck" — sibling convention from icd360sev, don't fight it.
  static String get _reportUrl {
    final tag = _platformTag();
    return '$_reportBase/${_appSlug}_$tag.php';
  }

  static String _platformTag() {
    if (Platform.environment.containsKey('FLATPAK_ID')) return 'flatpack';
    if (Platform.isLinux) return 'linux';
    if (Platform.isWindows) return 'windows';
    if (Platform.isMacOS) return 'macos';
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    return 'startup';
  }

  static void _writeLine(String line) {
    try {
      _sink?.writeln(line);
    } catch (_) {/* swallow */}
  }

  static List<int> _hexDecode(String hex) {
    final out = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      out.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return out;
  }
}
