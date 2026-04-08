import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import '../models/models.dart';
import 'logger_service.dart';
import 'localization_service.dart';
import 'platform_service.dart';

/// Account service for managing email accounts with secure password storage.
///
/// Storage strategy:
///
/// 1. **Primary**: `flutter_secure_storage`
///    - macOS/iOS: Keychain (login-protected)
///    - Windows: Credential Manager (DPAPI)
///    - Android: EncryptedSharedPreferences (Keystore)
///    - Linux: libsecret (gnome-keyring/KWallet)
///
/// 2. **Fallback**: `.passwords` JSON file in app data dir
///    - Used when secure storage is unavailable (Linux without libsecret, etc.)
///    - Encrypted with AES-256-GCM (NOT XOR — that was M4)
///    - Encryption key is derived from the master password via PBKDF2 (100k iterations)
///    - Key exists ONLY in memory while the session is unlocked
///    - On lock/logout, the key is wiped — fallback file becomes unreadable
///
/// SECURITY: Without the master password, the `.passwords` file is useless.
/// An attacker who reads the app data directory cannot decrypt anything.
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

  /// In-memory AES-256 key derived from the master password.
  /// `null` until the user unlocks via MasterPasswordService.verifyMasterPassword.
  /// Wiped on lock — fallback storage becomes unreadable.
  static Uint8List? _sessionKey;

  /// Salt used to derive the AES key from the master password (PBKDF2).
  /// Stored alongside the encrypted file (or generated on first save).
  static String? _saltFilePath;

  List<EmailAccount> accounts = [];

  /// Initialize service
  Future<void> initialize() async {
    if (_accountsFilePath != null) return;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    _accountsFilePath = p.join(appDataPath, 'accounts.json');
    _passwordsFallbackPath = p.join(appDataPath, '.passwords');
    _saltFilePath = p.join(appDataPath, '.passwords.salt');

    // Create directory if it doesn't exist
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
  }

  // ==========================================================================
  // SESSION KEY MANAGEMENT (M4 fix — AES-GCM with master-password-derived key)
  // ==========================================================================

  /// Derive a 256-bit AES key from the master password via PBKDF2 with 100k
  /// iterations of HMAC-SHA-256 (same iteration count as the auth hash, but a
  /// different salt so the two hashes can never match).
  static Uint8List _deriveSessionKey(String masterPassword, Uint8List salt) {
    // We implement PBKDF2 manually with SHA-256 to avoid pulling more deps.
    // 100k iterations on a modern device takes ~100ms — slow enough to thwart
    // brute force, fast enough to be tolerable on unlock.
    const iterations = 100000;
    const keyLength = 32; // 256 bits

    // PBKDF2-HMAC-SHA-256
    Uint8List hmacSha256(Uint8List key, Uint8List data) {
      return Uint8List.fromList(Hmac(sha256, key).convert(data).bytes);
    }

    final result = Uint8List(keyLength);
    int pos = 0;
    int blockNum = 1;
    while (pos < keyLength) {
      // INT(blockNum) — 4-byte big-endian
      final block = Uint8List(salt.length + 4);
      block.setRange(0, salt.length, salt);
      block[salt.length] = (blockNum >> 24) & 0xff;
      block[salt.length + 1] = (blockNum >> 16) & 0xff;
      block[salt.length + 2] = (blockNum >> 8) & 0xff;
      block[salt.length + 3] = blockNum & 0xff;

      final pwBytes = Uint8List.fromList(utf8.encode(masterPassword));
      var u = hmacSha256(pwBytes, block);
      final t = Uint8List.fromList(u);

      for (int i = 1; i < iterations; i++) {
        u = hmacSha256(pwBytes, u);
        for (int j = 0; j < t.length; j++) {
          t[j] ^= u[j];
        }
      }

      final remaining = keyLength - pos;
      final copyLen = remaining < t.length ? remaining : t.length;
      result.setRange(pos, pos + copyLen, t);
      pos += copyLen;
      blockNum++;
    }
    return result;
  }

  /// Load or create the salt file used to derive the session key.
  static Uint8List _loadOrCreateSalt() {
    final f = File(_saltFilePath!);
    if (f.existsSync()) {
      return Uint8List.fromList(f.readAsBytesSync());
    }
    // First-run: generate fresh 16-byte CSPRNG salt
    final random = Random.secure();
    final salt = Uint8List.fromList(List<int>.generate(16, (_) => random.nextInt(256)));
    f.writeAsBytesSync(salt);
    return salt;
  }

  /// Unlock the credential session.
  ///
  /// Called by MasterPasswordService after a successful master-password verify.
  /// Derives the AES session key from the password and holds it in memory.
  static Future<void> unlockSession(String masterPassword) async {
    // Make sure paths are initialized
    if (_saltFilePath == null) {
      final platform = PlatformService.instance;
      final appDataPath = platform.appDataPath;
      _saltFilePath = p.join(appDataPath, '.passwords.salt');
      _passwordsFallbackPath = p.join(appDataPath, '.passwords');
      final dir = Directory(appDataPath);
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
    }
    final salt = _loadOrCreateSalt();
    _sessionKey = _deriveSessionKey(masterPassword, salt);
    LoggerService.log('ACCOUNTS', 'Credential session unlocked');
  }

  /// Lock the credential session: wipe the AES key from memory.
  /// Called from auto-lock and explicit logout.
  static void lockSession() {
    if (_sessionKey != null) {
      // Best-effort zeroize
      for (int i = 0; i < _sessionKey!.length; i++) {
        _sessionKey![i] = 0;
      }
      _sessionKey = null;
      LoggerService.log('ACCOUNTS', 'Credential session locked (key wiped)');
    }
  }

  /// Whether the credential session is unlocked.
  static bool get isSessionUnlocked => _sessionKey != null;

  // ==========================================================================
  // AES-256-GCM ENCRYPTION (replaces XOR)
  // ==========================================================================

  /// Encrypt a value using AES-256-GCM with the in-memory session key.
  /// Returns base64(version | iv(12) | ciphertext+tag).
  /// Version byte 0x01 marks the new format vs legacy XOR (no version byte).
  String _encrypt(String value) {
    if (_sessionKey == null) {
      throw StateError('Cannot encrypt: session is locked. Call unlockSession() first.');
    }
    final random = Random.secure();
    final iv = Uint8List.fromList(List<int>.generate(12, (_) => random.nextInt(256)));
    final plaintext = Uint8List.fromList(utf8.encode(value));

    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(_sessionKey!), 128, iv, Uint8List(0)));
    final ciphertext = cipher.process(plaintext);

    // Output format: 0x01 (version) | 12-byte IV | ciphertext+tag
    final out = Uint8List(1 + iv.length + ciphertext.length);
    out[0] = 0x01;
    out.setRange(1, 1 + iv.length, iv);
    out.setRange(1 + iv.length, out.length, ciphertext);
    return base64Encode(out);
  }

  /// Decrypt a value previously stored by _encrypt().
  /// Returns null if decryption fails (wrong key, tampered data, locked session).
  String? _decrypt(String encoded) {
    if (_sessionKey == null) return null;
    try {
      final raw = base64Decode(encoded);
      if (raw.isEmpty || raw[0] != 0x01) return null;
      if (raw.length < 1 + 12 + 16) return null; // version + iv + min ciphertext+tag

      final iv = Uint8List.fromList(raw.sublist(1, 13));
      final ciphertext = Uint8List.fromList(raw.sublist(13));

      final cipher = GCMBlockCipher(AESEngine())
        ..init(false, AEADParameters(KeyParameter(_sessionKey!), 128, iv, Uint8List(0)));
      final plaintext = cipher.process(ciphertext);
      return utf8.decode(plaintext);
    } catch (ex) {
      LoggerService.log('ACCOUNTS', 'AES-GCM decrypt failed: $ex');
      return null;
    }
  }

  /// Decrypt legacy XOR-encrypted entries (for migration of existing installs).
  /// The legacy format had no version byte. Used only during one-shot migration.
  String? _decryptLegacyXor(String encoded) {
    try {
      // Legacy format (v2.17.x): random key from .enc_key
      final keyFile = File(p.join(p.dirname(_passwordsFallbackPath!), '.enc_key'));
      if (!keyFile.existsSync()) return null;
      final keyStr = keyFile.readAsStringSync().trim();
      final key = sha256.convert(utf8.encode(keyStr)).bytes;
      final encrypted = base64Decode(encoded);
      final decrypted = List<int>.generate(
        encrypted.length,
        (i) => encrypted[i] ^ key[i % key.length],
      );
      return utf8.decode(decrypted);
    } catch (_) {
      return null;
    }
  }

  /// Decrypt the OLDEST legacy format (v2.5.0 and earlier): XOR with a key
  /// derived from the host's computer name and OS user name. This format
  /// was replaced in v2.17.x by `_decryptLegacyXor` (random key) and then
  /// in v2.20.0 by AES-GCM (`_decrypt`).
  ///
  /// Without this final fallback, users upgrading directly from v2.5.x
  /// to v2.20.0 lose access to all stored passwords because their existing
  /// .passwords file is encrypted with this oldest scheme.
  String? _decryptVeryLegacyHostnameXor(String encoded) {
    try {
      final platform = PlatformService.instance;
      final seed = '${platform.computerName}-${platform.username}-icd360s-key';
      final key = sha256.convert(utf8.encode(seed)).bytes;
      final encrypted = base64Decode(encoded);
      final decrypted = List<int>.generate(
        encrypted.length,
        (i) => encrypted[i] ^ key[i % key.length],
      );
      final result = utf8.decode(decrypted);
      // Sanity check: a successful decryption should produce printable
      // ASCII (or at least valid UTF-8 with no control chars). Garbage
      // bytes from the wrong key will usually contain control characters.
      if (result.contains('\x00') ||
          result.runes.any((r) => r < 0x20 && r != 0x09 && r != 0x0a && r != 0x0d)) {
        return null;
      }
      return result;
    } catch (_) {
      return null;
    }
  }

  // ==========================================================================
  // PASSWORD STORAGE (fallback file)
  // ==========================================================================

  /// Get secure storage key for an account password
  String _getPasswordKey(String username) {
    return 'icd360s_mail_password_$username';
  }

  /// Save password to fallback file (AES-GCM encrypted with session key)
  Future<void> _saveFallbackPassword(String username, String password) async {
    if (_sessionKey == null) {
      LoggerService.log('ACCOUNTS',
          '⚠ Cannot save password to fallback: session is locked');
      return;
    }
    try {
      final file = File(_passwordsFallbackPath!);
      Map<String, dynamic> passwords = {};

      if (await file.exists()) {
        final content = await file.readAsString();
        passwords = jsonDecode(content) as Map<String, dynamic>;
      }

      passwords[username] = _encrypt(password);
      await file.writeAsString(jsonEncode(passwords));
      LoggerService.log('ACCOUNTS', '✓ Password saved to fallback for $username (AES-GCM)');
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_FALLBACK', ex, stackTrace);
    }
  }

  /// Load password from fallback file
  Future<String?> _loadFallbackPassword(String username) async {
    try {
      final file = File(_passwordsFallbackPath!);
      if (!await file.exists()) return null;

      final content = await file.readAsString();
      final passwords = jsonDecode(content) as Map<String, dynamic>;
      if (!passwords.containsKey(username)) return null;

      final stored = passwords[username] as String;

      // Try the new AES-GCM format first (v2.20.0+)
      var password = _decrypt(stored);
      if (password != null) {
        LoggerService.log('ACCOUNTS', 'Loaded password for $username from fallback (AES-GCM)');
        return password;
      }

      // Migration #1: try v2.17.x XOR (random key from .enc_key)
      password = _decryptLegacyXor(stored);
      if (password != null && _sessionKey != null) {
        LoggerService.log('ACCOUNTS',
            'Migrating $username password from v2.17 XOR to AES-GCM');
        passwords[username] = _encrypt(password);
        await file.writeAsString(jsonEncode(passwords));
        return password;
      }

      // Migration #2: try v2.5.x XOR (key derived from hostname + username)
      password = _decryptVeryLegacyHostnameXor(stored);
      if (password != null && _sessionKey != null) {
        LoggerService.log('ACCOUNTS',
            'Migrating $username password from v2.5 hostname-XOR to AES-GCM');
        passwords[username] = _encrypt(password);
        await file.writeAsString(jsonEncode(passwords));
        return password;
      }

      LoggerService.log('ACCOUNTS',
          '⚠ Could not decrypt fallback password for $username (session locked or data corrupt)');
      return null;
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_FALLBACK', ex, stackTrace);
      return null;
    }
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

