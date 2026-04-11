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
/// ## Strategy
///
/// 1. **Self-guarded**: if the new `secure_store.bin` already exists,
///    do nothing and return immediately.
/// 2. If the legacy directory doesn't exist either (fresh install),
///    do nothing and return.
/// 3. **Copy first, verify with SHA-256, then delete.** Never delete
///    the source until we are certain the destination is intact —
///    this is the only persistent state the user has.
/// 4. Best-effort cleanup of stale `Caches/`, `Saved Application
///    State/`, and `Logs/` directories under the legacy bundle ID.
///    Failures during cleanup are swallowed (silent) — they do not
///    affect functionality.
/// 5. Idempotent: safe to call on every launch. After successful
///    migration the legacy directory is gone, so the second pass
///    short-circuits at step 2.
/// 6. **No-op on non-macOS platforms.**
///
/// ## Error handling
///
/// On any failure during the copy/verify phase, the legacy directory
/// is left intact (so the user can retry by reopening the app or by
/// manually copying the files). The error is logged and rethrown so
/// that `main()` can surface a fatal dialog.
class MacOSBundleMigration {
  MacOSBundleMigration._();

  static const String _legacyBundleId = 'com.example.icd360sMailClient';
  static const String _newBundleId = 'de.icd360s.mailclient';
  static const String _secureStoreFileName = 'secure_store.bin';

  /// Run the one-time migration. Safe to call on every launch.
  /// On non-macOS platforms this is a no-op.
  ///
  /// Throws if the copy phase fails (callers should treat this as
  /// fatal — the user has no credentials).
  static Future<void> runIfNeeded() async {
    if (!Platform.isMacOS) return;

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
      return;
    }

    // Nothing to migrate — fresh install.
    if (!legacySecureStore.existsSync()) {
      return;
    }

    LoggerService.log(
      'BUNDLE_MIGRATION',
      'Legacy bundle dir detected — starting one-time migration',
    );

    try {
      // Compute source hash before copy so we can verify byte-for-byte
      // identity at the destination.
      final sourceBytes = await legacySecureStore.readAsBytes();
      final sourceHash = sha256.convert(sourceBytes).toString();

      // Ensure destination parent exists.
      if (!newDir.existsSync()) {
        await newDir.create(recursive: true);
      }

      // Copy every file under the legacy bundle dir (recursive). The
      // primary payload is `secure_store.bin` but the user may have
      // other persistent state we don't know about (logs, cached
      // certificates, etc.). Copy everything to be safe.
      await _copyDirectoryRecursive(legacyDir, newDir);

      // Verify the secure_store.bin survived the copy.
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

      // Only now is it safe to delete the legacy directory.
      await legacyDir.delete(recursive: true);

      // Best-effort cleanup of other legacy paths. Each is wrapped
      // independently so a failure in one doesn't block the rest.
      await _bestEffortDelete('$home/Library/Caches/$_legacyBundleId');
      await _bestEffortDelete(
        '$home/Library/Saved Application State/$_legacyBundleId.savedState',
      );
      await _bestEffortDelete('$home/Library/Logs/$_legacyBundleId');
      await _bestEffortDelete('$home/Library/HTTPStorages/$_legacyBundleId');
      await _bestEffortDelete('$home/Library/WebKit/$_legacyBundleId');

      LoggerService.log(
        'BUNDLE_MIGRATION',
        'Migration complete — legacy directories cleaned up',
      );
    } catch (e, st) {
      // Do NOT delete the legacy directory on error. The user can
      // retry by relaunching, or recover by manually copying the file.
      LoggerService.logError('BUNDLE_MIGRATION', e, st);
      rethrow;
    }
  }

  /// Recursively copy [src] into [dst]. [dst] must already exist.
  /// Files are copied with `File.copy`, which preserves byte content
  /// (we verify with SHA-256 afterwards anyway).
  static Future<void> _copyDirectoryRecursive(
    Directory src,
    Directory dst,
  ) async {
    await for (final entity in src.list(recursive: false, followLinks: false)) {
      final name = entity.uri.pathSegments.where((s) => s.isNotEmpty).last;
      if (entity is File) {
        final target = File('${dst.path}/$name');
        await entity.copy(target.path);
      } else if (entity is Directory) {
        final targetDir = Directory('${dst.path}/$name');
        if (!targetDir.existsSync()) {
          await targetDir.create();
        }
        await _copyDirectoryRecursive(entity, targetDir);
      }
      // Symlinks are skipped intentionally — none expected, and
      // following them could escape the bundle dir.
    }
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
