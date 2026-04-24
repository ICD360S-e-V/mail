// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'logger_service.dart';

/// Performance monitor for CPU and RAM usage (cross-platform)
class PerformanceMonitor {
  double _lastCpuUsage = 0.0;
  int _lastRamUsage = 0;
  int _consecutiveErrors = 0;
  static const int _maxConsecutiveErrors = 3;

  /// Whether monitoring is temporarily disabled due to errors
  bool get _isDisabled => _consecutiveErrors >= _maxConsecutiveErrors;

  /// Get CPU usage percentage of current process
  double getCpuUsage() {
    if (_isDisabled) return _lastCpuUsage;
    // Use cached value from combined fetch
    return _lastCpuUsage;
  }

  /// Get memory usage in MB of current process
  int getMemoryUsageMB() {
    if (_isDisabled) return _lastRamUsage;
    // Use cached value from combined fetch
    return _lastRamUsage;
  }

  /// Fetch both CPU and RAM asynchronously (doesn't block UI thread)
  Future<void> updateStats() async {
    if (_isDisabled) return;

    try {
      if (Platform.isWindows) {
        await _updateStatsWindows();
      } else if (Platform.isMacOS) {
        await _updateStatsMacOS();
      } else if (Platform.isLinux) {
        await _updateStatsLinux();
      }
      // Reset error counter on success
      _consecutiveErrors = 0;
    } catch (ex, stackTrace) {
      _consecutiveErrors++;
      if (_consecutiveErrors == _maxConsecutiveErrors) {
        LoggerService.log('PERF', 'Disabled after $_maxConsecutiveErrors consecutive errors');
      }
      if (_consecutiveErrors <= _maxConsecutiveErrors) {
        LoggerService.logError('PERF', ex, stackTrace);
      }
    }
  }

  /// macOS: single ps call for both CPU and RSS (async)
  Future<void> _updateStatsMacOS() async {
    final result = await Process.run('ps', [
      '-p', '$pid',
      '-o', '%cpu,rss',
    ]);

    if (result.exitCode == 0) {
      final lines = result.stdout.toString().trim().split('\n');
      if (lines.length >= 2) {
        final parts = lines[1].trim().split(RegExp(r'\s+'));
        if (parts.isNotEmpty) {
          final cpu = double.tryParse(parts[0]);
          if (cpu != null) {
            _lastCpuUsage = cpu.clamp(0.0, 100.0);
          }
        }
        if (parts.length >= 2) {
          final rssKB = int.tryParse(parts[1]);
          if (rssKB != null && rssKB > 0) {
            _lastRamUsage = (rssKB / 1024).round();
          }
        }
      }
    }
  }

  /// Windows: separate calls (PowerShell + tasklist) (async)
  Future<void> _updateStatsWindows() async {
    // CPU
    final cpuResult = await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      '(Get-Process -Id $pid).CPU'
    ]);

    if (cpuResult.exitCode == 0) {
      final output = cpuResult.stdout.toString().trim();
      final cpu = double.tryParse(output);
      if (cpu != null && cpu > 0) {
        _lastCpuUsage = (cpu / 10).clamp(0.0, 100.0);
      }
    }

    // RAM
    final memResult = await Process.run('tasklist', [
      '/FI', 'PID eq $pid',
      '/FO', 'CSV',
      '/NH',
    ]);

    if (memResult.exitCode == 0) {
      final output = memResult.stdout.toString().trim();
      final parts = output.split(',');
      if (parts.length >= 5) {
        var memStr = parts[4].replaceAll('"', '').trim();
        memStr = memStr.replaceAll(RegExp(r'\s*K[B]?\s*$'), '');
        memStr = memStr.replaceAll(',', '').replaceAll('.', '');
        final memKB = int.tryParse(memStr) ?? 0;
        if (memKB > 0) {
          _lastRamUsage = (memKB / 1024).round();
        }
      }
    }
  }

  /// Linux: read /proc first, fallback to single ps call (async)
  Future<void> _updateStatsLinux() async {
    // Try /proc for RAM (no process spawn needed)
    try {
      final statusFile = File('/proc/$pid/status');
      if (await statusFile.exists()) {
        final content = await statusFile.readAsString();
        final vmRssMatch = RegExp(r'VmRSS:\s*(\d+)\s*kB').firstMatch(content);
        if (vmRssMatch != null) {
          final rssKB = int.tryParse(vmRssMatch.group(1) ?? '0') ?? 0;
          if (rssKB > 0) {
            _lastRamUsage = (rssKB / 1024).round();
          }
        }
      }
    } catch (e) {
      LoggerService.log('PERF', 'Failed to read /proc/$pid/status: $e');
    }

    // CPU via single ps call
    final result = await Process.run('ps', [
      '-p', '$pid',
      '-o', '%cpu,rss',
      '--no-headers',
    ]);

    if (result.exitCode == 0) {
      final parts = result.stdout.toString().trim().split(RegExp(r'\s+'));
      if (parts.isNotEmpty) {
        final cpu = double.tryParse(parts[0]);
        if (cpu != null) {
          _lastCpuUsage = cpu.clamp(0.0, 100.0);
        }
      }
      if (parts.length >= 2) {
        final rssKB = int.tryParse(parts[1]);
        if (rssKB != null && rssKB > 0) {
          _lastRamUsage = (rssKB / 1024).round();
        }
      }
    }
  }

  /// Get formatted stats string (async - doesn't block UI)
  Future<String> getFormattedStats() async {
    await updateStats();
    return 'CPU: ${_lastCpuUsage.toStringAsFixed(1)}% | RAM: $_lastRamUsage MB';
  }

  /// Get cached stats string (sync, no process spawn)
  String getCachedStats() {
    return 'CPU: ${_lastCpuUsage.toStringAsFixed(1)}% | RAM: $_lastRamUsage MB';
  }
}
