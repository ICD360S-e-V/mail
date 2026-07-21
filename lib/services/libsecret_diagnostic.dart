// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';

import 'logger_service.dart';

/// Runs a one-shot Linux Secret Service probe and streams the result
/// into [LoggerService] so it lands in the next log upload — no manual
/// file-copy from the sandbox required. Called from
/// [MasterPasswordService._getOrCreateRateLimitKey] when libsecret has
/// just failed with `PlatformException(KeyringLocked, ...)`, and again
/// from the Add Account catch block.
///
/// Everything is best-effort: any subprocess that isn't on PATH is
/// logged as "not available" and skipped. No throws.
class LibsecretDiagnostic {
  static bool _alreadyRan = false;

  static Future<void> dumpToLog({required String trigger}) async {
    if (!Platform.isLinux) return;
    if (_alreadyRan) {
      LoggerService.logWarning(
          'LIBSECRET_DIAG', 'skipped ($trigger) — already ran once this session');
      return;
    }
    _alreadyRan = true;

    LoggerService.log('LIBSECRET_DIAG', '=== BEGIN (trigger=$trigger) ===');

    final env = Platform.environment;
    for (final k in const [
      'DBUS_SESSION_BUS_ADDRESS',
      'GNOME_KEYRING_CONTROL',
      'SSH_AUTH_SOCK',
      'XDG_RUNTIME_DIR',
      'XDG_DATA_HOME',
      'FLATPAK_ID',
      'container',
    ]) {
      LoggerService.log('LIBSECRET_DIAG', 'env $k=${env[k] ?? "<unset>"}');
    }

    for (final path in const [
      '/app/bin/gnome-keyring-daemon',
      '/usr/bin/gnome-keyring-daemon',
    ]) {
      final exists = await File(path).exists();
      LoggerService.log('LIBSECRET_DIAG', 'file $path exists=$exists');
    }

    // launcher.sh log — if present it holds daemon-startup diagnostics
    // written by flatpak/launcher.sh (PR #166).
    final dataHome = env['XDG_DATA_HOME'] ??
        '${env['HOME'] ?? '/tmp'}/.var/app/de.icd360s.mailclient/data';
    final launcherLog = File('$dataHome/icd360s_mail_client/keyring-launcher.log');
    if (await launcherLog.exists()) {
      try {
        final content = await launcherLog.readAsString();
        final tail = content.length > 4096
            ? '…(truncated)…\n${content.substring(content.length - 4096)}'
            : content;
        LoggerService.log('LIBSECRET_DIAG', 'launcher.log:\n$tail');
      } catch (e) {
        LoggerService.logWarning(
            'LIBSECRET_DIAG', 'launcher.log read failed: $e');
      }
    } else {
      LoggerService.log('LIBSECRET_DIAG',
          'launcher.log NOT present at ${launcherLog.path} — launcher.sh did not run');
    }

    await _runAndLog('busctl-list',
        ['busctl', '--user', 'list', '--no-pager', '--no-legend']);
    await _runAndLog(
        'busctl-secrets',
        ['busctl', '--user', 'call', 'org.freedesktop.secrets',
          '/org/freedesktop/secrets', 'org.freedesktop.DBus.Peer', 'Ping']);
    await _runAndLog('secret-tool-ping',
        ['secret-tool', 'lookup', 'icd360s-diagnostic-ping', 'x']);

    LoggerService.log('LIBSECRET_DIAG', '=== END ===');
  }

  static Future<void> _runAndLog(String label, List<String> argv) async {
    try {
      final r = await Process.run(argv.first, argv.sublist(1),
          runInShell: false);
      final out = r.stdout.toString().trim();
      final err = r.stderr.toString().trim();
      final tail = (out.isEmpty && err.isEmpty)
          ? '<empty>'
          : [
              if (out.isNotEmpty)
                'stdout: ${out.length > 800 ? "${out.substring(0, 800)}…" : out}',
              if (err.isNotEmpty)
                'stderr: ${err.length > 800 ? "${err.substring(0, 800)}…" : err}',
            ].join('\n');
      LoggerService.log(
          'LIBSECRET_DIAG', '$label exit=${r.exitCode}\n$tail');
    } on ProcessException catch (e) {
      LoggerService.log(
          'LIBSECRET_DIAG', '$label not available: ${e.message}');
    } catch (e) {
      LoggerService.logWarning('LIBSECRET_DIAG', '$label threw: $e');
    }
  }
}
