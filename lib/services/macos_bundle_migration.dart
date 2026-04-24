// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'logger_service.dart';

/// One-time migration of macOS user data from the legacy
/// `com.example.icd360sMailClient` bundle directory to the new
/// reverse-DNS bundle `de.icd360s.mailclient`, introduced in v2.25.0.
///
/// ## Why this is needed
///
/// `path_provider`'s `getApplicationSupportDirectory()` on macOS
/// resolves to `~/Library/Application Support/<CFBundleIdentifier>/`
/// — the bundle ID is appended explicitly by the plugin. After the
/// rebrand, the new build looks at the new directory which is empty,
/// so the user would lose their AES-GCM encrypted credential blob
/// (`secure_store.bin`), the cached `device_id`, and any other
/// persistent state, forcing a full re-login + new device registration.
///
/// The encryption key for `secure_store.bin` is derived from the Mac's
/// IOPlatformUUID — independent of bundle ID — so the file decrypts
/// correctly after being moved.
///
/// ## v2.28.1 — narrowed scope + hard timeout
///
/// The original v2.25.0 implementation did a recursive copy of the
/// ENTIRE legacy bundle dir, which on Macs with months of accumulated
/// state could be hundreds of MB and take many seconds — long enough
/// to block the main isolate before `runApp()` and trip macOS's
/// "Application not responding" detector. Combined with App
/// Translocation (running from a randomized read-only path) it caused
/// a hard hang on first launch of v2.28.0.
///
/// v2.28.1 narrows the migration to **just `secure_store.bin`** (the
/// only file the app actually needs to keep), wraps the entire run in
/// a 3-second timeout, and runs all best-effort cleanup of the legacy
/// `Caches/`, `Logs/`, etc. as fire-and-forget background work that
/// can never block startup.
///
/// ## Strategy
///
/// 1. **Self-guarded**: if the new `secure_store.bin` already exists,
///    do nothing and return immediately.
/// 2. If the legacy `secure_store.bin` doesn't exist (fresh install),
///    do nothing and return.
/// 3. Copy ONLY the `secure_store.bin` file (`File.copy`, not a
///    directory walk). Verify with SHA-256.
/// 4. Delete the legacy `secure_store.bin` (NOT the whole directory —
///    leave anything else for the background cleanup).
/// 5. Schedule best-effort cleanup of stale legacy paths in the
///    background via [_scheduleBackgroundCleanup]. The cleanup runs
///    after `runApp()` so it can never block startup.
/// 6. Idempotent: safe to call on every launch. After successful
///    migration the legacy file is gone, so the second pass
///    short-circuits at step 2.
/// 7. **No-op on non-macOS platforms.**
/// 8. **Hard timeout**: the entire foreground phase is wrapped in
///    `Future.any` with a 3-second guard. If anything blocks for
///    longer the migration is abandoned, the legacy file is left
///    intact, and the app starts normally — the user will see an
///    empty credential store and need to re-enter the password once.
///    This is preferable to a permanent hang.
class MacOSBundleMigration {
  MacOSBundleMigration._();

  static const String _legacyBundleId = 'com.example.icd360sMailClient';
  static const String _newBundleId = 'de.icd360s.mailclient';
  static const String _secureStoreFileName = 'secure_store.bin';

  /// Hard wall on the foreground migration phase. The original v2.25.0
  /// recursive copy could take many seconds on a Mac with accumulated
  /// state and trip macOS "Application not responding" detection.
  static const Duration _foregroundTimeout = Duration(seconds: 3);

  /// Run the one-time migration. Safe to call on every launch.
  /// On non-macOS platforms this is a no-op.
  ///
  /// NEVER throws — all errors are logged and swallowed. The worst
  /// possible outcome is that the user has to re-enter the master
  /// password once, which is much better than the app refusing to
  /// start.
  static Future<void> runIfNeeded() async {
    if (!Platform.isMacOS) return;

    try {
      await _doForegroundMigration().timeout(_foregroundTimeout);
    } on TimeoutException {
      LoggerService.logWarning(
        'BUNDLE_MIGRATION',
        'Migration timed out after ${_foregroundTimeout.inSeconds}s — '
        'continuing without it. User may need to re-enter the master '
        'password. Legacy directory left intact for manual recovery.',
      );
    } catch (e, st) {
      LoggerService.logError('BUNDLE_MIGRATION', e, st);
    }
  }

  static Future<void> _doForegroundMigration() async {
    final home = Platform.environment['HOME'];
    if (home == null || home.isEmpty) {
      LoggerService.logWarning(
        'BUNDLE_MIGRATION',
        'HOME env var unset — cannot locate Application Support',
      );
      return;
    }

    final appSupportRoot = '$home/Library/Application Support';
    final legacyDir = Directory('$appSupportRoot/$_legacyBundleId');
    final newDir = Directory('$appSupportRoot/$_newBundleId');
    final newSecureStore = File('${newDir.path}/$_secureStoreFileName');
    final legacySecureStore = File('${legacyDir.path}/$_secureStoreFileName');

    // Self-guard: new store already in place → migration already done
    // (or was never needed). Cheapest possible no-op for the steady state.
    if (newSecureStore.existsSync()) {
      _scheduleBackgroundCleanup(home);
      return;
    }

    // Nothing to migrate — fresh install OR legacy file already removed.
    if (!legacySecureStore.existsSync()) {
      _scheduleBackgroundCleanup(home);
      return;
    }

    LoggerService.log(
      'BUNDLE_MIGRATION',
      'Legacy secure_store.bin detected — migrating just that one file',
    );

    // Compute source hash so we can verify byte-for-byte identity.
    final sourceBytes = await legacySecureStore.readAsBytes();
    final sourceHash = sha256.convert(sourceBytes).toString();

    // Ensure destination parent exists.
    if (!newDir.existsSync()) {
      await newDir.create(recursive: true);
    }

    // SINGLE FILE COPY — no directory walk. Anything else under the
    // legacy bundle dir is non-essential cache and gets deleted by the
    // background cleanup task.
    await legacySecureStore.copy(newSecureStore.path);

    // Verify
    if (!newSecureStore.existsSync()) {
      throw StateError(
        'Migration verify failed: $_secureStoreFileName missing at destination',
      );
    }
    final destBytes = await newSecureStore.readAsBytes();
    final destHash = sha256.convert(destBytes).toString();
    if (destHash != sourceHash) {
      throw StateError(
        'Migration verify failed: SHA-256 mismatch '
        '(expected $sourceHash, got $destHash)',
      );
    }

    LoggerService.log(
      'BUNDLE_MIGRATION',
      'Verify OK — copied ${sourceBytes.length} bytes, '
      'sha256=${sourceHash.substring(0, 16)}…',
    );

    // Only now is it safe to delete the legacy file. We do NOT delete
    // the entire legacy directory here — that's a recursive operation
    // that could be slow if the dir has accumulated MB of cache, and
    // we already moved the only file we care about. Background cleanup
    // takes care of the rest.
    try {
      await legacySecureStore.delete();
    } catch (e) {
      LoggerService.logWarning(
        'BUNDLE_MIGRATION',
        'Could not delete legacy secure_store.bin: $e',
      );
    }

    _scheduleBackgroundCleanup(home);
  }

  /// Fire-and-forget cleanup of stale legacy paths. Runs in the
  /// background after foreground migration finishes (or is skipped),
  /// and CANNOT block app startup. Each path is wrapped independently
  /// so a slow / failing delete on one doesn't affect the rest.
  static void _scheduleBackgroundCleanup(String home) {
    // Microtask so we don't tie up the current await chain. The
    // microtask itself awaits but its completion is not waited on
    // by anyone — runApp() is already running by then.
    scheduleMicrotask(() async {
      final paths = <String>[
        '$home/Library/Application Support/$_legacyBundleId',
        '$home/Library/Caches/$_legacyBundleId',
        '$home/Library/Saved Application State/$_legacyBundleId.savedState',
        '$home/Library/Logs/$_legacyBundleId',
        '$home/Library/HTTPStorages/$_legacyBundleId',
        '$home/Library/WebKit/$_legacyBundleId',
      ];
      for (final p in paths) {
        await _bestEffortDelete(p);
      }
      LoggerService.logDebug(
        'BUNDLE_MIGRATION',
        'Background cleanup of legacy paths complete',
      );
    });
  }

  /// Delete [path] if it exists, swallowing any error. Used for
  /// non-critical legacy directory cleanup.
  static Future<void> _bestEffortDelete(String path) async {
    try {
      final dir = Directory(path);
      if (dir.existsSync()) {
        await dir.delete(recursive: true);
        LoggerService.logDebug(
          'BUNDLE_MIGRATION',
          'Removed legacy path: $path',
        );
      }
    } catch (e) {
      LoggerService.logDebug(
        'BUNDLE_MIGRATION',
        'Best-effort delete skipped ($path): $e',
      );
    }
  }
}
