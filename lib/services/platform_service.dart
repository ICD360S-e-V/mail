import 'dart:io';
import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';

/// Cross-platform service for handling platform-specific paths and operations.
class PlatformService {
  static PlatformService? _instance;
  String? _mobileAppDataPath;

  PlatformService._();

  static PlatformService get instance {
    _instance ??= PlatformService._();
    return _instance!;
  }

  /// Initialize platform-specific paths (must be called before using appDataPath on mobile)
  Future<void> initialize() async {
    if (isMobile) {
      final dir = await getApplicationDocumentsDirectory();
      _mobileAppDataPath = dir.path;
    }
  }

  /// Returns the application data directory path for the current platform.
  /// - Windows: %APPDATA%\ICD360S Mail Client
  /// - macOS: ~/Library/Application Support/ICD360S Mail Client
  /// - Linux: ~/.local/share/ICD360S Mail Client
  /// - Android/iOS: App documents directory (via path_provider)
  String get appDataPath {
    final appName = 'ICD360S Mail Client';

    if (Platform.isWindows) {
      final appData = Platform.environment['APPDATA'] ??
          Platform.environment['LOCALAPPDATA'] ??
          'C:\\Users\\${Platform.environment['USERNAME']}\\AppData\\Roaming';
      return path.join(appData, appName);
    } else if (Platform.isMacOS) {
      final home = Platform.environment['HOME'] ?? '/Users/${Platform.environment['USER']}';
      return path.join(home, 'Library', 'Application Support', appName);
    } else if (Platform.isLinux) {
      final home = Platform.environment['HOME'] ?? '/home/${Platform.environment['USER']}';
      final xdgData = Platform.environment['XDG_DATA_HOME'] ?? path.join(home, '.local', 'share');
      return path.join(xdgData, appName);
    } else if (_mobileAppDataPath != null) {
      return _mobileAppDataPath!;
    } else {
      return appName;
    }
  }

  /// Returns the downloads directory path for the current platform.
  String get downloadsPath {
    if (Platform.isWindows) {
      final userProfile = Platform.environment['USERPROFILE'] ??
          'C:\\Users\\${Platform.environment['USERNAME']}';
      return path.join(userProfile, 'Downloads');
    } else if (Platform.isMacOS || Platform.isLinux) {
      final home = Platform.environment['HOME'] ?? '/home/${Platform.environment['USER']}';
      if (Platform.isLinux) {
        final xdgDownload = Platform.environment['XDG_DOWNLOAD_DIR'];
        if (xdgDownload != null && xdgDownload.isNotEmpty) {
          return xdgDownload;
        }
      }
      return path.join(home, 'Downloads');
    } else if (_mobileAppDataPath != null) {
      return _mobileAppDataPath!;
    } else {
      return 'Downloads';
    }
  }

  /// Returns the computer/device name.
  /// On mobile (Android/iOS) returns OS name — Process.runSync is forbidden
  /// on GrapheneOS and other hardened ROMs.
  String get computerName {
    if (Platform.isWindows) {
      return Platform.environment['COMPUTERNAME'] ?? 'unknown';
    } else if (Platform.isAndroid || Platform.isIOS) {
      // Never call Process.runSync on mobile — GrapheneOS blocks it
      return Platform.operatingSystem;
    } else if (Platform.isMacOS || Platform.isLinux) {
      try {
        final result = Process.runSync('hostname', []);
        if (result.exitCode == 0) {
          return (result.stdout as String).trim();
        }
      } catch (_) {}
      return Platform.environment['HOSTNAME'] ??
             Platform.environment['HOST'] ??
             'unknown';
    }
    return Platform.operatingSystem;
  }

  /// Returns the current username.
  String get username {
    if (Platform.isWindows) {
      return Platform.environment['USERNAME'] ?? 'unknown';
    } else if (Platform.isMacOS || Platform.isLinux) {
      return Platform.environment['USER'] ??
             Platform.environment['LOGNAME'] ??
             'unknown';
    }
    return 'user';
  }

  /// Returns the platform name for logging/display purposes.
  String get platformName {
    if (Platform.isWindows) return 'Windows';
    if (Platform.isMacOS) return 'macOS';
    if (Platform.isLinux) return 'Linux';
    if (Platform.isAndroid) return 'Android';
    if (Platform.isIOS) return 'iOS';
    return Platform.operatingSystem;
  }

  /// Returns true if running on a desktop platform (Windows, macOS, Linux).
  bool get isDesktop {
    return Platform.isWindows || Platform.isMacOS || Platform.isLinux;
  }

  /// Returns true if running on a mobile platform (Android, iOS).
  bool get isMobile {
    return Platform.isAndroid || Platform.isIOS;
  }

  /// Ensures the app data directory exists. Creates it if not.
  Future<Directory> ensureAppDataDirectory() async {
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    return dir;
  }

  /// Returns a file path within the app data directory.
  String getAppDataFile(String filename) {
    return path.join(appDataPath, filename);
  }
}
