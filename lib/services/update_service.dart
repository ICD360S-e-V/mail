import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as path;
import 'package:url_launcher/url_launcher.dart';
import 'logger_service.dart';
import 'localization_service.dart';

/// Auto-update service for checking and installing updates
class UpdateService {
  static const String updateUrl = 'https://mail.icd360s.de/updates/version.json';
  static const String currentVersion = '2.17.11';

  // Progress callback for UI updates
  static Function(int downloaded, int total, String status)? onProgress;

  /// Check if update is available
  static Future<UpdateInfo?> checkForUpdates() async {
    try {
      LoggerService.log('UPDATE', 'Checking for updates at $updateUrl');

      // Download version.json from server
      final client = HttpClient()
        ..badCertificateCallback = (cert, host, port) =>
            host == 'mail.icd360s.de' && (cert.issuer.contains("Let's Encrypt") || cert.issuer.contains('ISRG Root'));
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

  // Progress message constants - removed (now using LocalizationService)

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

  /// Download update file with progress and SHA-256 verification
  static Future<File?> _downloadWithProgress(UpdateInfo updateInfo, LocalizationService l10nService) async {
    final client = HttpClient()
      ..badCertificateCallback = (cert, host, port) => host == 'mail.icd360s.de';
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

      try {
        await for (final chunk in response) {
          sink.add(chunk);
          allBytes.addAll(chunk);
          downloaded += chunk.length;

          final percent = contentLength > 0 ? (downloaded * 100 / contentLength).round() : 0;
          onProgress?.call(downloaded, contentLength, l10nService.getText(
            (l10n) => '${l10n.updateDownloadingProgress}$percent% (${(downloaded / 1024 / 1024).toStringAsFixed(1)} MB)',
            'Downloading: $percent% (${(downloaded / 1024 / 1024).toStringAsFixed(1)} MB)'
          ));
        }
      } finally {
        await sink.close();
      }

      LoggerService.log('UPDATE', 'Downloaded $downloaded bytes to ${updateFile.path}');

      // SHA-256 verification
      final fileHash = sha256.convert(allBytes).toString();
      if (updateInfo.sha256Hash != null && updateInfo.sha256Hash!.isNotEmpty) {
        if (fileHash != updateInfo.sha256Hash) {
          LoggerService.log('UPDATE', '❌ HASH MISMATCH! Expected: ${updateInfo.sha256Hash}, Got: $fileHash');
          await updateFile.delete();
          onProgress?.call(0, 0, 'Update verification failed - file corrupted');
          return null;
        }
        LoggerService.log('UPDATE', '✓ SHA-256 hash verified: $fileHash');
      } else {
        LoggerService.log('UPDATE', '⚠️ No hash in version.json, skipping verification (hash: $fileHash)');
      }

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
    // resolvedExecutable is like /Applications/icd360s_mail_client.app/Contents/MacOS/icd360s_mail_client
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
      // Replace current AppImage with new one
      final currentExe = Platform.resolvedExecutable;
      final isAppImage = Platform.environment.containsKey('APPIMAGE');
      final appImagePath = Platform.environment['APPIMAGE'] ?? currentExe;

      // Copy new AppImage over the old one
      await updateFile.copy(appImagePath);
      await Process.run('chmod', ['+x', appImagePath]);
      LoggerService.log('UPDATE', 'Replaced AppImage at $appImagePath');

      // Relaunch
      await Process.start(appImagePath, [], mode: ProcessStartMode.detached);
      LoggerService.log('UPDATE', 'Relaunching AppImage');
      exit(0);
    } else {
      // For .deb/.rpm, open in browser for manual install
      return _updateViaBrowser(UpdateInfo(
        version: '', downloadUrl: updateFile.path, changelog: '',
      ));
    }
  }

  /// Android: Download APK to Downloads, then open system installer via content URI
  static Future<bool> _installAndroid(UpdateInfo updateInfo) async {
    try {
      final l10nService = LocalizationService.instance;
      LoggerService.log('UPDATE', 'Downloading APK for Android: ${updateInfo.downloadUrl}');

      // Download APK
      final downloadedFile = await _downloadWithProgress(updateInfo, l10nService);
      if (downloadedFile == null) return false;

      // Move APK to a location accessible by the system installer
      // Use external storage Downloads directory
      final downloadsDir = Directory('/storage/emulated/0/Download');
      final apkName = 'ICD360S_MailClient_v${updateInfo.version}.apk';
      final apkDest = File('${downloadsDir.path}/$apkName');
      await downloadedFile.copy(apkDest.path);
      await downloadedFile.delete();

      LoggerService.log('UPDATE', 'APK saved to ${apkDest.path}');

      onProgress?.call(100, 100, l10nService.getText(
        (l10n) => l10n.updateInstalling,
        'Opening installer... Please tap Install when prompted.'
      ));

      // Open APK with system installer via content:// URI
      // Using url_launcher with file:// won't work on Android 7+ (needs FileProvider)
      // Instead, use intent via Process to trigger install
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
      // Fallback to browser download
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
