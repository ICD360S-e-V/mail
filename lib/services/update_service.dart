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
  static const String currentVersion = '2.17.4';

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
          } else if (Platform.isMacOS) {
            downloadUrl = (json['download_url_macos'] as String?) ?? json['download_url'] as String;
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
    // On mobile platforms, open download URL in browser for native install
    if (Platform.isAndroid || Platform.isIOS) {
      return _updateViaBrowser(updateInfo);
    }

    try {
      LoggerService.log('UPDATE', 'Auto-downloading update from ${updateInfo.downloadUrl}');
      final l10nService = LocalizationService.instance;
      onProgress?.call(0, 100, l10nService.getText(
        (l10n) => '${l10n.updateDownloadingUpdate}${updateInfo.version}...',
        'Downloading update v${updateInfo.version}...'
      ));

      final client = HttpClient()
        ..badCertificateCallback = (cert, host, port) => host == 'mail.icd360s.de';
      final request = await client.getUrl(Uri.parse(updateInfo.downloadUrl));
      final response = await request.close();

      if (response.statusCode == 200) {
        // Get content length for progress
        final contentLength = response.contentLength;

        // Save to temp directory
        final tempDir = Directory.systemTemp;
        final updateFileName = 'ICD360S_MailClient_Setup_v${updateInfo.version}.exe';
        final updateFile = File(path.join(tempDir.path, updateFileName));

        // Download with progress
        final sink = updateFile.openWrite();
        int downloaded = 0;
        final allBytes = <int>[];

        try {
          await for (final chunk in response) {
            sink.add(chunk);
            allBytes.addAll(chunk);
            downloaded += chunk.length;

            // Update progress
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

        // Verify file integrity via SHA-256 hash (if provided in version.json)
        final fileHash = sha256.convert(allBytes).toString();
        if (updateInfo.sha256Hash != null && updateInfo.sha256Hash!.isNotEmpty) {
          if (fileHash != updateInfo.sha256Hash) {
            LoggerService.log('UPDATE', '❌ HASH MISMATCH! Expected: ${updateInfo.sha256Hash}, Got: $fileHash');
            await updateFile.delete();
            onProgress?.call(0, 0, 'Update verification failed - file corrupted');
            return false;
          }
          LoggerService.log('UPDATE', '✓ SHA-256 hash verified: $fileHash');
        } else {
          LoggerService.log('UPDATE', '⚠️ No hash in version.json, skipping verification (hash: $fileHash)');
        }

        // Notify installing
        onProgress?.call(100, 100, l10nService.getText(
          (l10n) => l10n.updateInstalling,
          'Installing update... App will restart automatically.'
        ));

        // Small delay to show the message
        await Future.delayed(const Duration(seconds: 2));

        // Launch silent installer - it will auto-launch app after install
        await Process.start(
          updateFile.path,
          ['/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CLOSEAPPLICATIONS'],
          mode: ProcessStartMode.detached,
        );

        LoggerService.log('UPDATE', 'Launched silent installer - app will restart automatically');

        // Gracefully exit to allow update (SystemNavigator doesn't work for desktop)
        exit(0);
      }

      client.close();
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

  /// Update on Android/iOS: open the download URL in browser for native APK install
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
