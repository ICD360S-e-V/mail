import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import '../models/models.dart';
import 'logger_service.dart';
import 'localization_service.dart';
import 'platform_service.dart';

/// Account service for managing email accounts with secure password storage
/// Cross-platform: Uses Keychain (macOS/iOS), Credential Manager (Windows), encrypted storage (Linux/Android)
/// Fallback: If secure storage fails, passwords are stored locally (base64 obfuscated)
class AccountService {
  static String? _accountsFilePath;
  static String? _passwordsFallbackPath;
  static const _secureStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
    lOptions: LinuxOptions(),
    mOptions: MacOsOptions(),
    wOptions: WindowsOptions(),
  );

  List<EmailAccount> accounts = [];

  /// Initialize service
  Future<void> initialize() async {
    if (_accountsFilePath != null) return;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    _accountsFilePath = p.join(appDataPath, 'accounts.json');
    _passwordsFallbackPath = p.join(appDataPath, '.passwords');

    // Create directory if it doesn't exist
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
  }

  /// Get secure storage key for an account password
  String _getPasswordKey(String username) {
    return 'icd360s_mail_password_$username';
  }

  /// Encrypt value for fallback password storage using XOR with derived key
  String _obfuscate(String value) {
    final key = _deriveKey();
    final valueBytes = utf8.encode(value);
    final encrypted = List<int>.generate(
      valueBytes.length,
      (i) => valueBytes[i] ^ key[i % key.length],
    );
    return base64Encode(encrypted);
  }

  /// Decrypt value from fallback storage
  String? _deobfuscate(String value) {
    try {
      final key = _deriveKey();
      final encrypted = base64Decode(value);
      final decrypted = List<int>.generate(
        encrypted.length,
        (i) => encrypted[i] ^ key[i % key.length],
      );
      return utf8.decode(decrypted);
    } catch (_) {
      // Try legacy format (double base64 with icd360s_ prefix)
      try {
        final decoded = utf8.decode(base64Decode(value));
        if (decoded.startsWith('icd360s_')) {
          final inner = decoded.substring(8);
          return utf8.decode(base64Decode(inner));
        }
      } catch (_) {}
      return null;
    }
  }

  /// Derive encryption key from a per-installation random secret
  /// Falls back to machine info if secret doesn't exist yet (legacy compat)
  List<int> _deriveKey() {
    // Try to read stored random key
    final keyFile = File(p.join(p.dirname(_passwordsFallbackPath!), '.enc_key'));
    if (keyFile.existsSync()) {
      final storedKey = keyFile.readAsStringSync().trim();
      return sha256.convert(utf8.encode(storedKey)).bytes;
    }
    // First run or migration: generate random key and store it
    final random = Random.secure();
    final randomBytes = List<int>.generate(32, (_) => random.nextInt(256));
    final randomKey = base64Encode(randomBytes);
    keyFile.writeAsStringSync(randomKey);
    return sha256.convert(utf8.encode(randomKey)).bytes;
  }

  /// Save password to fallback file
  Future<void> _saveFallbackPassword(String username, String password) async {
    try {
      final file = File(_passwordsFallbackPath!);
      Map<String, dynamic> passwords = {};

      if (await file.exists()) {
        final content = await file.readAsString();
        passwords = jsonDecode(content) as Map<String, dynamic>;
      }

      passwords[username] = _obfuscate(password);
      await file.writeAsString(jsonEncode(passwords));
      LoggerService.log('ACCOUNTS', '✓ Password saved to fallback for $username');
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_FALLBACK', ex, stackTrace);
    }
  }

  /// Load password from fallback file
  Future<String?> _loadFallbackPassword(String username) async {
    try {
      final file = File(_passwordsFallbackPath!);
      if (await file.exists()) {
        final content = await file.readAsString();
        final passwords = jsonDecode(content) as Map<String, dynamic>;
        if (passwords.containsKey(username)) {
          final password = _deobfuscate(passwords[username] as String);
          if (password != null) {
            LoggerService.log('ACCOUNTS', 'Loaded password for $username from fallback');
          }
          return password;
        }
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_FALLBACK', ex, stackTrace);
    }
    return null;
  }

  /// Delete password from fallback file
  Future<void> _deleteFallbackPassword(String username) async {
    try {
      final file = File(_passwordsFallbackPath!);
      if (await file.exists()) {
        final content = await file.readAsString();
        final passwords = jsonDecode(content) as Map<String, dynamic>;
        passwords.remove(username);
        await file.writeAsString(jsonEncode(passwords));
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_FALLBACK', ex, stackTrace);
    }
  }

  /// Save password (secure storage + fallback)
  Future<void> _savePassword(String username, String password) async {
    // Always save to fallback (guaranteed to work)
    await _saveFallbackPassword(username, password);

    // Also try secure storage (Keychain/Credential Manager)
    try {
      final passwordKey = _getPasswordKey(username);
      await _secureStorage.write(key: passwordKey, value: password);
      LoggerService.log('ACCOUNTS', '✓ Password saved for $username (secure storage)');
    } catch (ex, stackTrace) {
      LoggerService.log('ACCOUNTS', 'Secure storage write failed for $username, using fallback');
      LoggerService.logError('ACCOUNTS_SECURE', ex, stackTrace);
    }
  }

  /// Load password (try secure storage first, then fallback)
  Future<String?> _loadPassword(String username) async {
    // Try secure storage first
    try {
      final passwordKey = _getPasswordKey(username);
      final password = await _secureStorage.read(key: passwordKey);
      if (password != null && password.isNotEmpty) {
        LoggerService.log('ACCOUNTS', 'Loaded password for $username: YES (secure storage)');
        return password;
      }
    } catch (ex, stackTrace) {
      LoggerService.log('ACCOUNTS', 'Secure storage read failed for $username, trying fallback');
      LoggerService.logError('ACCOUNTS_SECURE', ex, stackTrace);
    }

    // Fallback to local file
    final fallbackPassword = await _loadFallbackPassword(username);
    if (fallbackPassword != null) {
      // Try to migrate back to secure storage
      try {
        final passwordKey = _getPasswordKey(username);
        await _secureStorage.write(key: passwordKey, value: fallbackPassword);
        LoggerService.log('ACCOUNTS', 'Migrated $username password back to secure storage');
      } catch (_) {}
      return fallbackPassword;
    }

    LoggerService.log('ACCOUNTS', 'No password found for $username');
    return null;
  }

  /// Delete password from all storage
  Future<void> _deletePassword(String username) async {
    await _deleteFallbackPassword(username);
    try {
      final passwordKey = _getPasswordKey(username);
      await _secureStorage.delete(key: passwordKey);
      LoggerService.log('ACCOUNTS', '✓ Password deleted for $username');
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_SECURE', ex, stackTrace);
    }
  }

  /// Load accounts from JSON and passwords from secure storage
  Future<List<EmailAccount>> loadAccountsAsync() async {
    await initialize();

    try {
      final file = File(_accountsFilePath!);

      if (await file.exists()) {
        final json = await file.readAsString();
        final List<dynamic> jsonList = jsonDecode(json);

        accounts = jsonList
            .map((item) => EmailAccount.fromJson(item as Map<String, dynamic>))
            .toList();

        LoggerService.log('ACCOUNTS', 'Loaded ${accounts.length} accounts from JSON');

        // Load passwords (secure storage with fallback)
        for (final account in accounts) {
          account.password = await _loadPassword(account.username);
        }

        // AUTO-MIGRATION: Update ports for mTLS strict enforcement
        bool migrationNeeded = false;
        for (final account in accounts) {
          // SMTP: 587 (STARTTLS) → 465 (direct SSL/TLS)
          if (account.smtpPort == 587) {
            LoggerService.log('MIGRATION', '🔄 Migrating ${account.username}: SMTP port 587 → 465 (mTLS)');
            account.smtpPort = 465;
            migrationNeeded = true;
          }
          // IMAP: 993 (standard) → 10993 (dedicated mTLS-only port)
          if (account.imapPort == 993) {
            LoggerService.log('MIGRATION', '🔄 Migrating ${account.username}: IMAP port 993 → 10993 (mTLS strict)');
            account.imapPort = 10993;
            migrationNeeded = true;
          }
        }

        if (migrationNeeded) {
          LoggerService.log('MIGRATION', '✓ Auto-migration completed - saving updated accounts');
          await saveAccountsAsync();
        }
      } else {
        LoggerService.log('ACCOUNTS', 'No accounts file found, starting fresh');
        accounts = [];
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS', ex, stackTrace);
      accounts = [];
    }

    return accounts;
  }

  /// Save accounts to JSON (passwords go to secure storage + fallback)
  Future<void> saveAccountsAsync() async {
    await initialize();

    try {
      // Don't serialize passwords (they're in secure storage)
      final accountsToSave = accounts.map((a) {
        final json = a.toJson();
        // Remove password from JSON if present
        json.remove('password');
        return json;
      }).toList();

      final jsonString = const JsonEncoder.withIndent('  ').convert(accountsToSave);
      final file = File(_accountsFilePath!);
      await file.writeAsString(jsonString);

      LoggerService.log('ACCOUNTS', 'Saved ${accounts.length} accounts to JSON');
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS', ex, stackTrace);
    }
  }

  /// Add new account
  Future<void> addAccount(EmailAccount account) async {
    // SECURITY: Only allow mail.icd360s.de server
    const allowedServer = 'mail.icd360s.de';
    if (account.mailServer != allowedServer) {
      LoggerService.log('ACCOUNTS',
          '✗ BLOCKED: Unauthorized server ${account.mailServer} (only $allowedServer allowed)');
      final l10nService = LocalizationService.instance;
      throw Exception(l10nService.getText(
        (l10n) => l10n.accountServiceSecurityErrorServer(allowedServer),
        'Security Error: Only $allowedServer server is allowed. This client is locked to ICD360S mail server.'
      ));
    }

    // Validate ports (IMAP:10993 dedicated mTLS port, SMTP:465 for mTLS)
    if (account.imapPort != 10993 || account.smtpPort != 465) {
      LoggerService.log('ACCOUNTS',
          '✗ BLOCKED: Invalid ports IMAP:${account.imapPort} SMTP:${account.smtpPort}');
      final l10nService = LocalizationService.instance;
      throw Exception(l10nService.getText(
        (l10n) => l10n.accountServiceSecurityErrorPorts,
        'Security Error: Only secure ports (IMAP:10993, SMTP:465) are allowed for mTLS.'
      ));
    }

    // Save password to secure storage + fallback
    if (account.password != null && account.password!.isNotEmpty) {
      await _savePassword(account.username, account.password!);
    }

    accounts.add(account);
    await saveAccountsAsync();
    LoggerService.log('ACCOUNTS', '✓ Account added: ${account.username}');
  }

  /// Remove account
  Future<void> removeAccount(EmailAccount account) async {
    await _deletePassword(account.username);

    accounts.removeWhere((a) => a.username == account.username);
    await saveAccountsAsync();
    LoggerService.log('ACCOUNTS', '✓ Account removed: ${account.username}');
  }

  /// Update account
  Future<void> updateAccount(EmailAccount account) async {
    // SECURITY: Validate server and ports (same as addAccount)
    const allowedServer = 'mail.icd360s.de';
    if (account.mailServer != allowedServer) {
      LoggerService.log('ACCOUNTS',
          '✗ BLOCKED: Unauthorized server ${account.mailServer} (only $allowedServer allowed)');
      throw Exception('Security Error: Only $allowedServer server is allowed.');
    }
    if (account.imapPort != 10993 || account.smtpPort != 465) {
      LoggerService.log('ACCOUNTS',
          '✗ BLOCKED: Invalid ports IMAP:${account.imapPort} SMTP:${account.smtpPort}');
      throw Exception('Security Error: Only secure ports (IMAP:10993, SMTP:465) are allowed.');
    }

    // Update password if changed
    if (account.password != null && account.password!.isNotEmpty) {
      await _savePassword(account.username, account.password!);
    }

    await saveAccountsAsync();
    LoggerService.log('ACCOUNTS', '✓ Account updated: ${account.username}');
  }
}