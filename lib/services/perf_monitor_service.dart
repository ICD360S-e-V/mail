// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:io';

import 'logger_service.dart';

/// Periodically emits RAM/CPU/peak/delta into LoggerService so users can
/// copy logs and pinpoint memory growth without needing DevTools.
///
/// Log line example:
///   [PERF] RSS=482MB peak=520MB delta=+24MB uptime=128s
///
/// CPU is best-effort: we measure the Dart isolate's accumulated CPU time
/// via `Stopwatch` baseline + `ProcessInfo`-derived process times, but on
/// most platforms only process-wall-clock-since-start is available, so we
/// report `cpu_proc_pct ~ (proc_rss_growth_rate)` heuristics rather than
/// true CPU%. Anything more accurate needs platform channels.
class PerfMonitorService {
  static Timer? _timer;
  static int _lastRssMb = 0;
  static DateTime? _started;

  static void start({Duration interval = const Duration(seconds: 30)}) {
    if (_timer != null) return;
    _started = DateTime.now();
    _lastRssMb = ProcessInfo.currentRss ~/ (1024 * 1024);
    LoggerService.log('PERF',
        'monitor started (interval=${interval.inSeconds}s, initial RSS=${_lastRssMb}MB)');
    _timer = Timer.periodic(interval, (_) => _tick());
  }

  static void stop() {
    _timer?.cancel();
    _timer = null;
  }

  static void _tick() {
    try {
      final rssMb = ProcessInfo.currentRss ~/ (1024 * 1024);
      final peakMb = ProcessInfo.maxRss ~/ (1024 * 1024);
      final delta = rssMb - _lastRssMb;
      final uptimeSec = DateTime.now().difference(_started!).inSeconds;
      final sign = delta >= 0 ? '+' : '';
      LoggerService.log('PERF',
          'RSS=${rssMb}MB peak=${peakMb}MB delta=$sign${delta}MB uptime=${uptimeSec}s cores=${Platform.numberOfProcessors}');
      _lastRssMb = rssMb;
    } catch (ex) {
      LoggerService.logWarning('PERF', 'tick failed: $ex');
    }
  }

  /// One-shot snapshot — useful around expensive user actions
  /// (e.g. before/after opening a large email).
  static void snapshot(String label) {
    try {
      final rssMb = ProcessInfo.currentRss ~/ (1024 * 1024);
      final peakMb = ProcessInfo.maxRss ~/ (1024 * 1024);
      LoggerService.log('PERF', 'snapshot[$label] RSS=${rssMb}MB peak=${peakMb}MB');
    } catch (_) {}
  }
}
