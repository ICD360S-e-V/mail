import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as path;
import 'package:url_launcher/url_launcher.dart';
import 'logger_service.dart';
import 'localization_service.dart';

/// Auto-update service for checking and installing updates
class UpdateService {
  static const String updateUrl = 'https://mail.icd360s.de/updates/version.json';
  static const String currentVersion = '2.20.0';

  // Progress callback for UI updates
  static Function(int downloaded, int total, String status)? onProgress;

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

  // Trusted Let's Encrypt issuer DNs (same as MtlsService)
  static const _trustedIssuers = [
    'CN=R3,O=Let\'s Encrypt,C=US',
    'CN=R10,O=Let\'s Encrypt,C=US',
    'CN=R11,O=Let\'s Encrypt,C=US',
    'CN=R12,O=Let\'s Encrypt,C=US',
    'CN=E5,O=Let\'s Encrypt,C=US',
    'CN=E6,O=Let\'s Encrypt,C=US',
    'CN=E7,O=Let\'s Encrypt,C=US',
    'CN=E8,O=Let\'s Encrypt,C=US',
    'CN=ISRG Root X1,O=Internet Security Research Group,C=US',
    'CN=ISRG Root X2,O=Internet Security Research Group,C=US',
  ];

  /// Validate server certificate — only accept trusted Let's Encrypt issuers
  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    final issuer = cert.issuer;
    return _trustedIssuers.any(
      (trusted) => issuer == trusted || issuer.contains(trusted),
    );
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
  static Future<UpdateInfo?> checkForUpdates() async {
    try {
      LoggerService.log('UPDATE', 'Checking for updates at $updateUrl');

      // Download version.json from server
      final client = HttpClient()
        ..badCertificateCallback = _validateCertificate;
      try {
        final request = await client.getUrl(Uri.parse(updateUrl));
        final response = await request.close();

        if (response.statusCode == 200) {
          final jsonString = await response.transform(utf8.decoder).join();
          final json = jsonDecode(jsonString) as Map<String, dynamic>;

          final latestVersion = json['version'] as String;
          final changelog = json['changelog'] as String?;
          final sha256Hash = json['sha256'] as String?;

          // Pick the right download URL for the current platform
          String downloadUrl;
          if (Platform.isAndroid) {
            downloadUrl = (json['download_url_android'] as String?) ?? json['download_url'] as String;
          } else if (Platform.isIOS) {
            downloadUrl = (json['download_url_ios'] as String?) ?? json['download_url'] as String;
          } else if (Platform.isMacOS) {
            downloadUrl = (json['download_url_macos'] as String?) ?? json['download_url'] as String;
          } else if (Platform.isLinux) {
            downloadUrl = (json['download_url_linux'] as String?) ?? json['download_url'] as String;
          } else {
            downloadUrl = json['download_url'] as String;
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
  static Future<bool> downloadAndInstallAuto(UpdateInfo updateInfo) async {
    // iOS: no self-update possible, open browser
    if (Platform.isIOS) {
      return _updateViaBrowser(updateInfo);
    }

    // Android: download APK then trigger system installer
    if (Platform.isAndroid) {
      return _installAndroid(updateInfo);
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

    final client = HttpClient()
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

    // Relaunch app
    await Process.start('open', [appBundlePath], mode: ProcessStartMode.detached);
    LoggerService.log('UPDATE', 'Relaunching app from $appBundlePath');
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

  /// Android: Download APK to Downloads, verify signing cert, then open system installer
  static Future<bool> _installAndroid(UpdateInfo updateInfo) async {
    try {
      final l10nService = LocalizationService.instance;
      LoggerService.log('UPDATE', 'Downloading APK for Android: ${updateInfo.downloadUrl}');

      final downloadedFile = await _downloadWithProgress(updateInfo, l10nService);
      if (downloadedFile == null) return false;

      final downloadsDir = Directory('/storage/emulated/0/Download');
      final apkName = 'ICD360S_MailClient_v${updateInfo.version}.apk';
      final apkDest = File('${downloadsDir.path}/$apkName');
      await downloadedFile.copy(apkDest.path);
      await downloadedFile.delete();

      LoggerService.log('UPDATE', 'APK saved to ${apkDest.path}');

      // SECURITY: Verify the APK's signing certificate matches the expected
      // hash BEFORE handing it to the system installer. Even if the file SHA-256
      // matched (which is required upstream), the cert check ensures the APK
      // was signed by our keystore — defense against a compromised update server
      // serving a tampered (re-signed) APK with a matching version.json hash.
      final certVerified = await _verifyApkCert(apkDest.path);
      if (!certVerified) {
        await apkDest.delete();
        onProgress?.call(0, 0, 'Update rejected: signature verification failed');
        return false;
      }

      onProgress?.call(100, 100, l10nService.getText(
        (l10n) => l10n.updateInstalling,
        'Opening installer... Please tap Install when prompted.'
      ));

      await Process.run('am', [
        'start', '-a', 'android.intent.action.VIEW',
        '-t', 'application/vnd.android.package-archive',
        '-d', 'file://${apkDest.path}',
        '--grant-read-uri-permission',
      ]);

      LoggerService.log('UPDATE', 'Triggered APK installer for ${apkDest.path}');
      return true;
    } catch (ex, stackTrace) {
      LoggerService.logError('UPDATE', ex, stackTrace);
      return _updateViaBrowser(updateInfo);
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



