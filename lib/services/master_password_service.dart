import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// Master password service for app authentication (cross-platform)
class MasterPasswordService {
  static String? _passwordHashFilePath;

  // Rate limiting: max 5 attempts, then lockout for 60 seconds
  static int _failedAttempts = 0;
  static DateTime? _lockoutUntil;
  static const int _maxAttempts = 5;
  static const Duration _lockoutDuration = Duration(seconds: 60);

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

  /// Check if account is currently locked out
  static bool isLockedOut() {
    if (_lockoutUntil == null) return false;
    if (DateTime.now().isAfter(_lockoutUntil!)) {
      _lockoutUntil = null;
      _failedAttempts = 0;
      return false;
    }
    return true;
  }

  /// Get remaining lockout seconds
  static int get remainingLockoutSeconds {
    if (_lockoutUntil == null) return 0;
    final remaining = _lockoutUntil!.difference(DateTime.now()).inSeconds;
    return remaining > 0 ? remaining : 0;
  }

  /// Set master password (first-time setup)
  static Future<void> setMasterPassword(String password) async {
    await initialize();
    final hash = _hashPassword(password);
    final file = File(_passwordHashFilePath!);
    await file.writeAsString(hash);
    LoggerService.log('AUTH', 'Master password set');
  }

  /// Verify master password with rate limiting
  static Future<bool> verifyMasterPassword(String password) async {
    await initialize();

    // Check rate limiting
    if (isLockedOut()) {
      LoggerService.log('AUTH', '✗ Account locked — too many failed attempts');
      return false;
    }

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

        if (isValid) {
          _failedAttempts = 0;
          _lockoutUntil = null;
          LoggerService.log('AUTH', '✓ Password correct');
        } else {
          _failedAttempts++;
          if (_failedAttempts >= _maxAttempts) {
            _lockoutUntil = DateTime.now().add(_lockoutDuration);
            LoggerService.log('AUTH', '✗ Password incorrect — account locked for ${_lockoutDuration.inSeconds}s');
          } else {
            LoggerService.log('AUTH', '✗ Password incorrect (${_maxAttempts - _failedAttempts} attempts remaining)');
          }
        }
        return isValid;
      } else {
        // Legacy unsalted SHA-256 — verify and migrate to salted
        final legacyBytes = utf8.encode(password);
        final legacyHash = sha256.convert(legacyBytes).toString();
        final isValid = savedHash == legacyHash;

        if (isValid) {
          _failedAttempts = 0;
          _lockoutUntil = null;
          // Migrate to salted hash
          final newHash = _hashPassword(password);
          await file.writeAsString(newHash);
          LoggerService.log('AUTH', '✓ Password correct + migrated to salted hash');
        } else {
          _failedAttempts++;
          if (_failedAttempts >= _maxAttempts) {
            _lockoutUntil = DateTime.now().add(_lockoutDuration);
            LoggerService.log('AUTH', '✗ Password incorrect — account locked for ${_lockoutDuration.inSeconds}s');
          } else {
            LoggerService.log('AUTH', '✗ Password incorrect');
          }
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

  /// Generate a cryptographically secure random salt
  static String _generateSalt() {
    final random = Random.secure();
    final saltBytes = List<int>.generate(16, (_) => random.nextInt(256));
    return sha256.convert(saltBytes).toString().substring(0, 16);
  }

  /// Extract salt from stored hash
  static String? _extractSalt(String storedHash) {
    final parts = storedHash.split(':');
    if (parts.length == 2) return parts[0];
    return null; // Legacy unsalted hash
  }
}