import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as path;
import 'package:url_launcher/url_launcher.dart';
import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'localization_service.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/api.dart' as pc_api;
import 'pinned_security_context.dart';
import 'version_baseline.dart';

/// Auto-update service for checking and installing updates
class UpdateService {
  static const String updateUrl = 'https://mail.icd360s.de/updates/version.json';
  static const String currentVersion = '2.21.5';

  // Progress callback for UI updates
  static Function(int downloaded, int total, String status)? onProgress;

  // In-flight deduplication for the two long-running update entry
  // points. Dart is single-threaded per isolate but async functions
  // can interleave at every `await`. Without these guards a periodic
  // timer + a manual user tap can launch two parallel downloads of
  // the same APK into the same temp file (corrupting it), or trigger
  // two PackageInstaller dialogs, or double-bump the version
  // baseline. The pattern: first caller starts the work and stores
  // its Future; subsequent callers while it is in-flight receive the
  // same Future, so they all complete with the same result instead
  // of racing.
  static Future<UpdateInfo?>? _inflightCheck;
  static Future<bool>? _inflightInstall;

  /// SHA-256 of the DER-encoded X.509 signing certificate used to sign all
  /// official ICD360S Mail Client APKs (the keystore lives in GitHub Secrets,
  /// alias `upload`, organization `ICD360S e.V.`).
  ///
  /// SECURITY: Before self-installing an Android update, MainActivity.kt
  /// extracts the signing cert from the downloaded APK via PackageManager
  /// and computes its SHA-256. If it does not match this value, the install
  /// is refused — even if the APK passed SHA-256 file integrity check.
  ///
  /// This defends against a scenario where the update server (or any
  /// intermediate) is compromised and serves a malicious APK signed by a
  /// different key: the file hash would match (attacker rewrites version.json),
  /// but the cert hash would NOT match this hardcoded value.
  ///
  /// To rotate this value: extract the new cert with
  ///   openssl x509 -in cert.pem -outform DER | sha256sum
  /// and update both this constant and a new release.
  /// Base64-encoded raw uncompressed ECDSA P-256 public key (65 bytes,
  /// format `0x04 || X || Y`) used to verify the detached signature on
  /// `version.json`.
  ///
  /// SECURITY: The matching private key is held offline at
  /// `/root/.icd360s/release_signing/version_signing_priv.pem` on the
  /// release-signing host (Claude Code dev server, NOT mail.icd360s.de).
  /// A compromise of `mail.icd360s.de` cannot forge update metadata
  /// because the attacker would need this offline private key.
  ///
  /// To rotate: generate a new keypair offline, ship a release that
  /// trusts BOTH the old and the new key, wait for adoption, ship a
  /// follow-up release that trusts only the new key.
  static const String _versionJsonPublicKey =
      'BOaKDVWITCwis2+9tVGNkeNPBsV0dO/ja3HheaaqVW6GZbb6Y6csarYVoMpCFH7FTprFSwfZP1JO72fRu2x6te0=';

  static const String _expectedApkCertSha256 =
      'ff9c4a92347693745a06a20cc15310e897145dad6b719cbe724eda093a6195b5';

  static const MethodChannel _apkVerifyChannel =
      MethodChannel('de.icd360s.mailclient/apk_verify');

  /// Verify an APK's signing certificate against the expected hash.
  /// Calls into MainActivity.kt via MethodChannel.
  /// Returns `true` only if the cert SHA-256 matches the hardcoded value.
  static Future<bool> _verifyApkCert(String apkPath) async {
    if (!Platform.isAndroid) return true; // not applicable
    try {
      final result = await _apkVerifyChannel.invokeMethod<Map<dynamic, dynamic>>(
        'verifyApkSignature',
        {
          'apkPath': apkPath,
          'expectedCertSha256': _expectedApkCertSha256,
        },
      );
      final verified = result?['verified'] == true;
      final actualHash = result?['actualHash'] as String?;
      final reason = result?['reason'] as String?;
      if (verified) {
        LoggerService.log('UPDATE', '✓ APK signature verified (cert SHA-256 match)');
      } else {
        LoggerService.log('UPDATE',
            '❌ APK signature verification FAILED — reason=$reason actual=$actualHash expected=$_expectedApkCertSha256');
      }
      return verified;
    } catch (ex, stackTrace) {
      LoggerService.logError('UPDATE', ex, stackTrace);
      return false;
    }
  }

  /// Validate server certificate — only accept trusted Let's Encrypt issuers.
  /// Uses the shared `isTrustedLetsEncryptIssuer` helper.
  /// Verify an ECDSA P-256 / SHA-256 detached signature against a
  /// message using the hardcoded `_versionJsonPublicKey`.
  ///
  /// Signature format: ASN.1 DER (the openssl `dgst -sha256 -sign`
  /// default). Pure Dart, no native code, no extra dependencies
  /// (pointycastle is already pulled in by other services).
  static bool _verifyVersionJsonSignature(
      Uint8List message, Uint8List derSignature) {
    try {
      final pubBytes = base64.decode(_versionJsonPublicKey);
      if (pubBytes.length != 65 || pubBytes[0] != 0x04) {
        LoggerService.log('UPDATE',
            '❌ version.json verify: malformed pinned public key');
        return false;
      }

      final curve = ECCurve_secp256r1();
      BigInt toBigInt(List<int> bytes) {
        final hex =
            bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        return BigInt.parse(hex, radix: 16);
      }

      final x = toBigInt(pubBytes.sublist(1, 33));
      final y = toBigInt(pubBytes.sublist(33, 65));
      final point = curve.curve.createPoint(x, y);
      final pubKey = ECPublicKey(point, curve);

      final parser = ASN1Parser(derSignature);
      final asn1 = parser.nextObject();
      if (asn1 is! ASN1Sequence ||
          asn1.elements == null ||
          asn1.elements!.length != 2) {
        LoggerService.log('UPDATE',
            '❌ version.json verify: signature is not an ASN.1 SEQUENCE of 2');
        return false;
      }
      final rEl = asn1.elements![0];
      final sEl = asn1.elements![1];
      if (rEl is! ASN1Integer || sEl is! ASN1Integer) {
        LoggerService.log('UPDATE',
            '❌ version.json verify: signature components not INTEGERs');
        return false;
      }
      final ecSig = ECSignature(rEl.integer!, sEl.integer!);

      // SHA-256 of the message, then ECDSA verify on the hash.
      final hash = SHA256Digest().process(message);

      final signer = ECDSASigner();
      signer.init(false, pc_api.PublicKeyParameter<ECPublicKey>(pubKey));
      return signer.verifySignature(hash, ecSig);
    } catch (ex, st) {
      LoggerService.logError('UPDATE', ex, st);
      return false;
    }
  }

  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    return isTrustedLetsEncryptIssuer(cert.issuer);
  }

  /// Verify that an update download URL is allowed: must be HTTPS and pointed
  /// at mail.icd360s.de.
  ///
  /// SECURITY: version.json is served from our server, but the `download_url`
  /// field inside it is JSON data that an attacker who compromised the server
  /// (or any future intermediate write path) could redirect to:
  ///   - http://attacker.com/...   — cleartext, leaks user IP, no TLS check
  ///   - https://github.com/.../release.exe — bypasses our domain pinning
  ///
  /// This check rejects both. Combined with the mandatory SHA-256 hash check
  /// after download (and APK cert verification on Android, see H4), this
  /// makes the update path defense-in-depth secure.
  static bool _isAllowedDownloadUrl(String url) {
    try {
      final uri = Uri.parse(url);
      return uri.scheme == 'https' && uri.host == 'mail.icd360s.de';
    } catch (_) {
      return false;
    }
  }

  /// Check if update is available
  static Future<UpdateInfo?> checkForUpdates() {
    if (_inflightCheck != null) {
      LoggerService.log('UPDATE', 'checkForUpdates: reusing in-flight call');
      return _inflightCheck!;
    }
    final fut = _checkForUpdatesInternal();
    _inflightCheck = fut.whenComplete(() {
      _inflightCheck = null;
    });
    return _inflightCheck!;
  }

  static Future<UpdateInfo?> _checkForUpdatesInternal() async {
    try {
      // Pin baseline to currentVersion on first run so any subsequent
      // proposal strictly below the currently installed build is rejected,
      // even before the first successful update bumps the baseline.
      await VersionBaseline.initialize(currentVersion);
      LoggerService.log('UPDATE', 'Checking for updates at $updateUrl');

      // Download version.json from server
      final client = PinnedSecurityContext.createHttpClient()
        ..badCertificateCallback = _validateCertificate;
      try {
        // Download version.json AND its detached ECDSA signature, then
        // verify before trusting any field. Defends against compromise
        // of mail.icd360s.de itself: an attacker who controls the
        // server can serve any JSON, but cannot forge a valid signature
        // without the offline private key.
        final request = await client.getUrl(Uri.parse(updateUrl));
        final response = await request.close();

        if (response.statusCode == 200) {
          final jsonBytes = Uint8List.fromList(
              await response.fold<List<int>>(<int>[], (acc, c) {
            acc.addAll(c);
            return acc;
          }));

          final sigUrl = '$updateUrl.sig';
          final sigReq = await client.getUrl(Uri.parse(sigUrl));
          final sigResp = await sigReq.close();
          if (sigResp.statusCode != 200) {
            LoggerService.log('UPDATE',
                '❌ REJECTED: $sigUrl returned ${sigResp.statusCode}');
            return null;
          }
          final sigBytes = Uint8List.fromList(
              await sigResp.fold<List<int>>(<int>[], (acc, c) {
            acc.addAll(c);
            return acc;
          }));

          if (!_verifyVersionJsonSignature(jsonBytes, sigBytes)) {
            LoggerService.log('UPDATE',
                '❌ REJECTED: version.json signature verification FAILED');
            return null;
          }
          LoggerService.log('UPDATE', '✓ version.json signature verified');

          final jsonString = utf8.decode(jsonBytes);
          final json = jsonDecode(jsonString) as Map<String, dynamic>;

          final latestVersion = json['version'] as String;
          final changelog = json['changelog'] as String?;

          // Pick the right download URL AND SHA-256 for the current platform.
          // Bug fix: previously the SHA-256 was always read from the
          // generic 'sha256' field (Windows). On macOS/Linux/Android the
          // hash mismatched the actual binary, causing every update to be
          // rejected as "file corrupted or tampered".
          String downloadUrl;
          String? sha256Hash;
          if (Platform.isAndroid) {
            downloadUrl = (json['download_url_android'] as String?) ?? json['download_url'] as String;
            sha256Hash = (json['sha256_android'] as String?) ?? json['sha256'] as String?;
          } else if (Platform.isIOS) {
            downloadUrl = (json['download_url_ios'] as String?) ?? json['download_url'] as String;
            sha256Hash = (json['sha256_ios'] as String?) ?? json['sha256'] as String?;
          } else if (Platform.isMacOS) {
            downloadUrl = (json['download_url_macos'] as String?) ?? json['download_url'] as String;
            sha256Hash = (json['sha256_macos'] as String?) ?? json['sha256'] as String?;
          } else if (Platform.isLinux) {
            downloadUrl = (json['download_url_linux'] as String?) ?? json['download_url'] as String;
            sha256Hash = (json['sha256_linux'] as String?) ?? json['sha256'] as String?;
          } else {
            // Windows / fallback — use the generic 'sha256' field
            downloadUrl = json['download_url'] as String;
            sha256Hash = json['sha256'] as String?;
          }

          LoggerService.log('UPDATE', 'Latest version: $latestVersion (current: $currentVersion)');

          // SECURITY: Reject any download_url that is not HTTPS to mail.icd360s.de.
          // Defense against a compromised version.json that points elsewhere.
          if (!_isAllowedDownloadUrl(downloadUrl)) {
            LoggerService.log('UPDATE',
                '❌ REJECTED: download_url is not HTTPS to mail.icd360s.de: $downloadUrl');
            return null;
          }

          // Compare versions
          // L2 anti-rollback: refuse to even surface a candidate
          // version that is below our persisted monotonic baseline.
          // See VersionBaseline / CWE-1328.
          if (!await VersionBaseline.isAcceptable(latestVersion)) {
            LoggerService.log('UPDATE',
                '❌ REJECTED candidate $latestVersion: below persisted baseline');
            return null;
          }
          if (_isNewerVersion(latestVersion, currentVersion)) {
            return UpdateInfo(
              version: latestVersion,
              downloadUrl: downloadUrl,
              changelog: changelog ?? '',
              sha256Hash: sha256Hash,
            );
          }
        }
      } finally {
        client.close();
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('UPDATE', ex, stackTrace);
    }

    return null;
  }

  /// Download and install update automatically with progress
  static Future<bool> downloadAndInstallAuto(UpdateInfo updateInfo) {
    if (_inflightInstall != null) {
      LoggerService.log('UPDATE',
          'downloadAndInstallAuto: reusing in-flight call');
      return _inflightInstall!;
    }
    final fut = _downloadAndInstallAutoInternal(updateInfo);
    _inflightInstall = fut.whenComplete(() {
      _inflightInstall = null;
    });
    return _inflightInstall!;
  }

  static Future<bool> _downloadAndInstallAutoInternal(
      UpdateInfo updateInfo) async {
    // L2 anti-rollback (defense in depth): re-check the baseline at the
    // entry point of the install pipeline so any code path that
    // constructs an UpdateInfo manually (deep link, UI button, retry)
    // also gets the protection. Bumps the baseline AFTER all integrity
    // checks pass and the platform-specific install path returns success.
    if (!await VersionBaseline.isAcceptable(updateInfo.version)) {
      LoggerService.log('UPDATE',
          '❌ REJECTED install of ${updateInfo.version}: below persisted baseline');
      onProgress?.call(0, 0, 'Update rejected: rollback blocked');
      return false;
    }

    // iOS: no self-update possible, open browser
    if (Platform.isIOS) {
      return _updateViaBrowser(updateInfo);
    }

    // Android: download APK then trigger system installer
    if (Platform.isAndroid) {
      final ok = await _installAndroid(updateInfo);
      if (ok) await VersionBaseline.bumpTo(updateInfo.version);
      return ok;
    }

    try {
      LoggerService.log('UPDATE', 'Auto-downloading update from ${updateInfo.downloadUrl}');
      final l10nService = LocalizationService.instance;
      onProgress?.call(0, 100, l10nService.getText(
        (l10n) => '${l10n.updateDownloadingUpdate}${updateInfo.version}...',
        'Downloading update v${updateInfo.version}...'
      ));

      // Download the update file
      final downloadedFile = await _downloadWithProgress(updateInfo, l10nService);
      if (downloadedFile == null) return false;

      // Notify installing
      onProgress?.call(100, 100, l10nService.getText(
        (l10n) => l10n.updateInstalling,
        'Installing update... App will restart automatically.'
      ));
      await Future.delayed(const Duration(seconds: 2));

      // Platform-specific install
      // Bump baseline BEFORE launching the installer: on Windows/macOS/
      // Linux the installer subprocess takes over and the current
      // process is killed before we could record success.
      await VersionBaseline.bumpTo(updateInfo.version);
      if (Platform.isWindows) {
        return _installWindows(downloadedFile);
      } else if (Platform.isMacOS) {
        return _installMacOS(downloadedFile);
      } else if (Platform.isLinux) {
        return _installLinux(downloadedFile);
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('UPDATE', ex, stackTrace);
      final l10nService = LocalizationService.instance;
      onProgress?.call(0, 0, l10nService.getText(
        (l10n) => l10n.updateError(ex.toString()),
        'Update error: $ex'
      ));
      return false;
    }

    return true;
  }

  /// Download update file with progress and mandatory SHA-256 verification
  static Future<File?> _downloadWithProgress(UpdateInfo updateInfo, LocalizationService l10nService) async {
    // SECURITY (defense in depth): re-validate the URL host even though
    // checkForUpdates already filtered it. Catches any code path that
    // constructs an UpdateInfo manually.
    if (!_isAllowedDownloadUrl(updateInfo.downloadUrl)) {
      LoggerService.log('UPDATE',
          '❌ REJECTED: download_url is not HTTPS to mail.icd360s.de: ${updateInfo.downloadUrl}');
      onProgress?.call(0, 0, 'Update rejected: invalid download URL');
      return null;
    }

    // SECURITY: SHA-256 hash is mandatory — reject updates without integrity verification
    if (updateInfo.sha256Hash == null || updateInfo.sha256Hash!.isEmpty) {
      LoggerService.log('UPDATE', '❌ REJECTED: No SHA-256 hash in version.json — cannot verify update integrity');
      onProgress?.call(0, 0, 'Update rejected: missing integrity hash');
      return null;
    }

    final client = PinnedSecurityContext.createHttpClient()
      ..badCertificateCallback = _validateCertificate;
    try {
      final request = await client.getUrl(Uri.parse(updateInfo.downloadUrl));
      final response = await request.close();

      if (response.statusCode != 200) return null;

      final contentLength = response.contentLength;
      final tempDir = Directory.systemTemp;

      // Determine file extension from URL
      final urlPath = Uri.parse(updateInfo.downloadUrl).path;
      final ext = path.extension(urlPath);
      final updateFile = File(path.join(tempDir.path, 'icd360s-mail-update$ext'));

      final sink = updateFile.openWrite();
      int downloaded = 0;
      final allBytes = <int>[];
      // Throttle progress callbacks: only notify when percent changes
      // (or every 250ms at most). Without this, the callback fires once
      // per network chunk (~4KB on most platforms), which on a 30 MB
      // download means ~7500 callbacks. Each one rebuilds the navigation
      // pane and floods the log with localization warnings.
      int lastPercent = -1;
      DateTime lastNotify = DateTime.fromMillisecondsSinceEpoch(0);

      try {
        await for (final chunk in response) {
          sink.add(chunk);
          allBytes.addAll(chunk);
          downloaded += chunk.length;

          final percent = contentLength > 0 ? (downloaded * 100 / contentLength).round() : 0;
          final now = DateTime.now();
          final percentChanged = percent != lastPercent;
          final timeElapsed = now.difference(lastNotify).inMilliseconds >= 250;
          if (percentChanged || timeElapsed) {
            lastPercent = percent;
            lastNotify = now;
            onProgress?.call(downloaded, contentLength, l10nService.getText(
              (l10n) => '${l10n.updateDownloadingProgress}$percent% (${(downloaded / 1024 / 1024).toStringAsFixed(1)} MB)',
              'Downloading: $percent% (${(downloaded / 1024 / 1024).toStringAsFixed(1)} MB)'
            ));
          }
        }
      } finally {
        await sink.close();
      }
      // Always notify final state
      onProgress?.call(downloaded, contentLength, l10nService.getText(
        (l10n) => '${l10n.updateDownloadingProgress}100% (${(downloaded / 1024 / 1024).toStringAsFixed(1)} MB)',
        'Downloading: 100% (${(downloaded / 1024 / 1024).toStringAsFixed(1)} MB)'
      ));

      LoggerService.log('UPDATE', 'Downloaded $downloaded bytes to ${updateFile.path}');

      // SHA-256 verification (mandatory)
      final fileHash = sha256.convert(allBytes).toString();
      if (fileHash != updateInfo.sha256Hash) {
        LoggerService.log('UPDATE', '❌ HASH MISMATCH! Expected: ${updateInfo.sha256Hash}, Got: $fileHash');
        await updateFile.delete();
        onProgress?.call(0, 0, 'Update verification failed - file corrupted or tampered');
        return null;
      }
      LoggerService.log('UPDATE', '✓ SHA-256 hash verified: $fileHash');

      return updateFile;
    } finally {
      client.close(force: true);
    }
  }

  /// Windows: Run Inno Setup silent installer
  static Future<bool> _installWindows(File updateFile) async {
    await Process.start(
      updateFile.path,
      ['/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CLOSEAPPLICATIONS'],
      mode: ProcessStartMode.detached,
    );
    LoggerService.log('UPDATE', 'Launched Windows silent installer');
    exit(0);
  }

  /// macOS: Mount DMG, copy .app to /Applications, relaunch
  static Future<bool> _installMacOS(File updateFile) async {
    final mountPoint = '/tmp/icd360s-update-mount';

    // Mount DMG
    await Process.run('hdiutil', ['attach', updateFile.path, '-mountpoint', mountPoint, '-nobrowse']);
    LoggerService.log('UPDATE', 'Mounted DMG at $mountPoint');

    // Find .app in mounted volume
    final mountDir = Directory(mountPoint);
    final apps = mountDir.listSync().where((e) => e.path.endsWith('.app')).toList();
    if (apps.isEmpty) {
      LoggerService.log('UPDATE', '❌ No .app found in DMG');
      await Process.run('hdiutil', ['detach', mountPoint]);
      return false;
    }

    // Determine install location (where current app is running from, or /Applications)
    final currentExe = Platform.resolvedExecutable;
    final appBundlePath = currentExe.contains('.app/')
        ? currentExe.substring(0, currentExe.indexOf('.app/') + 4)
        : '/Applications/${path.basename(apps.first.path)}';

    // Remove old app and copy new one
    final oldApp = Directory(appBundlePath);
    if (oldApp.existsSync()) {
      await Process.run('rm', ['-rf', appBundlePath]);
    }
    await Process.run('cp', ['-R', apps.first.path, appBundlePath]);
    LoggerService.log('UPDATE', 'Copied ${apps.first.path} → $appBundlePath');

    // Unmount DMG
    await Process.run('hdiutil', ['detach', mountPoint]);
    await updateFile.delete();

    // Relaunch app via a detached shell that waits for THIS process
    // to fully exit before calling `open`.
    //
    // SECURITY / CORRECTNESS: Without the delay, three things go
    // wrong simultaneously:
    //   1. macOS LaunchServices sees the existing process still
    //      running with the same bundle id, so `open` becomes a
    //      no-op "bring to front" instead of launching the new
    //      binary.
    //   2. Even after `exit(0)`, LaunchServices may have already
    //      cached the request and serve the old running PID, then
    //      see it die and never try again.
    //   3. The single-instance lock in main.dart blocks any second
    //      instance that races against the dying parent.
    //
    // Following the same pattern Sparkle uses on macOS: spawn a
    // detached child that polls until our PID is gone, then issues
    // `open` against the freshly-installed bundle. The 2-second
    // grace period covers normal Dart/Flutter shutdown teardown.
    final myPid = pid;
    // Single-quote-escape for sh: ' -> '\''
    final escapedPath =
        appBundlePath.replaceAll("'", r"'\''");
    await Process.start(
      'sh',
      [
        '-c',
        "while kill -0 $myPid 2>/dev/null; do sleep 0.2; done; "
            "sleep 1; open '$escapedPath'",
      ],
      mode: ProcessStartMode.detached,
    );
    LoggerService.log('UPDATE',
        'Scheduled detached relaunch (after PID $myPid exits) from $appBundlePath');
    exit(0);
  }

  /// Linux: Replace AppImage or open browser for .deb/.rpm
  static Future<bool> _installLinux(File updateFile) async {
    final ext = path.extension(updateFile.path).toLowerCase();

    if (ext == '.appimage') {
      final currentExe = Platform.resolvedExecutable;
      final appImagePath = Platform.environment['APPIMAGE'] ?? currentExe;

      await updateFile.copy(appImagePath);
      await Process.run('chmod', ['+x', appImagePath]);
      LoggerService.log('UPDATE', 'Replaced AppImage at $appImagePath');

      await Process.start(appImagePath, [], mode: ProcessStartMode.detached);
      LoggerService.log('UPDATE', 'Relaunching AppImage');
      exit(0);
    } else {
      return _updateViaBrowser(UpdateInfo(
        version: '', downloadUrl: updateFile.path, changelog: '',
      ));
    }
  }

  /// Android: Download APK to app-private cache, then install it via
  /// PackageInstaller.Session.
  ///
  /// SECURITY: Eliminates the TOCTOU window of the legacy
  /// `am start INSTALL_PACKAGE` flow:
  ///
  /// - The APK is written by `_downloadWithProgress` to
  ///   `Directory.systemTemp` which on Android is the app-private
  ///   `cacheDir` (`/data/data/de.icd360s.mailclient/cache/`). No other
  ///   app on the device can read or write this path on any supported
  ///   Android version (minSdk=24).
  /// - We do NOT copy the APK to public Downloads anymore.
  /// - The actual install runs through PackageInstaller.Session in
  ///   MainActivity.kt — bytes stream from the cache file directly into
  ///   a kernel-side install session, with no path that an attacker
  ///   could substitute between cert verification and install.
  /// - The signing-certificate hash is re-verified inside the Kotlin
  ///   helper immediately before commit, so the check and the install
  ///   reference the same on-disk bytes.
  static Future<bool> _installAndroid(UpdateInfo updateInfo) async {
    try {
      final l10nService = LocalizationService.instance;
      LoggerService.log('UPDATE',
          'Downloading APK for Android: ${updateInfo.downloadUrl}');

      final downloadedFile = await _downloadWithProgress(updateInfo, l10nService);
      if (downloadedFile == null) return false;

      onProgress?.call(100, 100, l10nService.getText(
        (l10n) => l10n.updateInstalling,
        'Opening installer... Please tap Install when prompted.',
      ));

      LoggerService.log('UPDATE',
          'Invoking PackageInstaller.Session for ${downloadedFile.path}');

      final result = await _apkVerifyChannel.invokeMethod<Map<dynamic, dynamic>>(
        'installApk',
        {
          'path': downloadedFile.path,
          'expectedCertSha256': _expectedApkCertSha256,
        },
      );
      final ok = result?['ok'] == true;
      if (ok) {
        LoggerService.log('UPDATE',
            '✓ Update installed via PackageInstaller.Session');
        return true;
      }
      final reason = result?['reason'] as String?;
      final message = result?['message'] as String?;
      LoggerService.log('UPDATE',
          '❌ PackageInstaller.Session failed: reason=$reason message=$message');
      onProgress?.call(0, 0,
          'Update install failed${reason != null ? ': $reason' : ''}');
      // Best-effort cleanup if Kotlin didn't already remove the file.
      try {
        if (await downloadedFile.exists()) {
          await downloadedFile.delete();
        }
      } catch (_) {}
      return false;
    } catch (ex, stackTrace) {
      LoggerService.logError('UPDATE', ex, stackTrace);
      return false;
    }
  }

  /// Update on iOS: open the download URL in browser (no self-update possible)
  static Future<bool> _updateViaBrowser(UpdateInfo updateInfo) async {
    try {
      LoggerService.log('UPDATE', 'Opening update URL in browser: ${updateInfo.downloadUrl}');
      final l10nService = LocalizationService.instance;
      onProgress?.call(0, 100, l10nService.getText(
        (l10n) => '${l10n.updateDownloadingUpdate}${updateInfo.version}...',
        'Opening download for v${updateInfo.version}...'
      ));

      final uri = Uri.parse(updateInfo.downloadUrl);
      if (await canLaunchUrl(uri)) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
        LoggerService.log('UPDATE', 'Opened APK download in browser');
        onProgress?.call(100, 100, l10nService.getText(
          (l10n) => l10n.updateInstalling,
          'Download opened in browser. Install the APK when ready.'
        ));
        return true;
      } else {
        LoggerService.log('UPDATE', 'Could not launch URL: ${updateInfo.downloadUrl}');
        return false;
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('UPDATE', ex, stackTrace);
      final l10nService = LocalizationService.instance;
      onProgress?.call(0, 0, l10nService.getText(
        (l10n) => l10n.updateError(ex.toString()),
        'Update error: $ex'
      ));
      return false;
    }
  }

  /// Download and install update (legacy - with manual confirmation)
  static Future<bool> downloadAndInstall(UpdateInfo updateInfo) async {
    return downloadAndInstallAuto(updateInfo);
  }

  /// Compare version strings (e.g., "2.0.1" > "2.0.0")
  static bool _isNewerVersion(String latest, String current) {
    final latestParts = latest.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final currentParts = current.split('.').map((e) => int.tryParse(e) ?? 0).toList();

    for (var i = 0; i < 3; i++) {
      final latestPart = i < latestParts.length ? latestParts[i] : 0;
      final currentPart = i < currentParts.length ? currentParts[i] : 0;

      if (latestPart > currentPart) return true;
      if (latestPart < currentPart) return false;
    }

    return false;
  }
}

/// Update information
class UpdateInfo {
  final String version;
  final String downloadUrl;
  final String changelog;
  final String? sha256Hash;

  UpdateInfo({
    required this.version,
    required this.downloadUrl,
    required this.changelog,
    this.sha256Hash,
  });
}






