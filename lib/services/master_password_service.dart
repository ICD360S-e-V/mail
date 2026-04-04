import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// Master password service for app authentication (cross-platform)
class MasterPasswordService {
  static String? _passwordHashFilePath;

  /// Initialize service and get password hash file path
  static Future<void> initialize() async {
    if (_passwordHashFilePath != null) return;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    _passwordHashFilePath = p.join(appDataPath, '.master_password_hash');

    // Create directory if it doesn't exist
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
  }

  /// Check if master password is set
  static Future<bool> hasMasterPassword() async {
    await initialize();
    final file = File(_passwordHashFilePath!);
    return await file.exists();
  }

  /// Set master password (first-time setup)
  static Future<void> setMasterPassword(String password) async {
    await initialize();
    final hash = _hashPassword(password);
    final file = File(_passwordHashFilePath!);
    await file.writeAsString(hash);
    LoggerService.log('AUTH', 'Master password set');
  }

  /// Verify master password
  static Future<bool> verifyMasterPassword(String password) async {
    await initialize();

    if (!await hasMasterPassword()) {
      return false;
    }

    try {
      final file = File(_passwordHashFilePath!);
      final savedHash = (await file.readAsString()).trim();

      // Check if it's a salted hash (contains ':') or legacy unsalted
      final salt = _extractSalt(savedHash);
      if (salt != null) {
        // Salted hash — use same salt to verify
        final inputHash = _hashPassword(password, salt: salt);
        final isValid = savedHash == inputHash;
        LoggerService.log('AUTH', isValid ? '✓ Password correct' : '✗ Password incorrect');
        return isValid;
      } else {
        // Legacy unsalted SHA-256 — verify and migrate to salted
        final legacyBytes = utf8.encode(password);
        final legacyHash = sha256.convert(legacyBytes).toString();
        final isValid = savedHash == legacyHash;

        if (isValid) {
          // Migrate to salted hash
          final newHash = _hashPassword(password);
          await file.writeAsString(newHash);
          LoggerService.log('AUTH', '✓ Password correct + migrated to salted hash');
        } else {
          LoggerService.log('AUTH', '✗ Password incorrect');
        }
        return isValid;
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('AUTH', ex, stackTrace);
      return false;
    }
  }

  /// Hash password using PBKDF2-like iterated SHA-256 with salt
  /// Uses 100,000 iterations for brute-force resistance
  static String _hashPassword(String password, {String? salt}) {
    final useSalt = salt ?? _generateSalt();
    final saltedPassword = '$useSalt:$password';
    List<int> bytes = utf8.encode(saltedPassword);

    // Iterate SHA-256 100,000 times for key stretching
    for (int i = 0; i < 100000; i++) {
      bytes = sha256.convert(bytes).bytes;
    }

    final hash = sha256.convert(bytes).toString();
    return '$useSalt:$hash';
  }

  /// Generate a random salt
  static String _generateSalt() {
    final random = DateTime.now().microsecondsSinceEpoch;
    final bytes = utf8.encode('$random-icd360s-salt');
    return sha256.convert(bytes).toString().substring(0, 16);
  }

  /// Extract salt from stored hash
  static String? _extractSalt(String storedHash) {
    final parts = storedHash.split(':');
    if (parts.length == 2) return parts[0];
    return null; // Legacy unsalted hash
  }
}
