// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:path/path.dart' as p;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import '../models/models.dart';
import 'aes_gcm_helpers.dart';
import 'certificate_service.dart';
import 'logger_service.dart';
import 'localization_service.dart';
import 'platform_service.dart';
import 'portable_secure_storage.dart';

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
  // PortableSecureStorage uses native secure storage on iOS/Android/
  // Windows/Linux and an AES-GCM file backend on macOS — because
  // ad-hoc signed macOS builds cannot use Keychain at all
  // (errSecMissingEntitlement -34018 regardless of MacOsOptions
  // configuration). See PortableSecureStorage docs for empirical
  // evidence and threat model.
  static final _secureStorage = PortableSecureStorage.instance;

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

  /// Iteration count for PBKDF2-HMAC-SHA256, per OWASP 2025
  /// (Password Storage Cheat Sheet). Same value as
  /// MasterPasswordService._pbkdf2Iterations.
  static const int _pbkdf2Iterations = 600000;
  static const int _pbkdf2KeyLength = 32; // 256 bits
  static const int _pbkdf2SaltLength = 16; // 128 bits

  /// Derive a 256-bit AES key from the master password via
  /// PBKDF2-HMAC-SHA-256 with the given salt and iteration count.
  static Uint8List _deriveSessionKey(
      String masterPassword, Uint8List salt, int iterations) {
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, iterations, _pbkdf2KeyLength));
    return derivator.process(Uint8List.fromList(utf8.encode(masterPassword)));
  }

  static Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }

  /// Load the salt + iteration count from the salt file, or create a new
  /// one in v2 (text) format on first run.
  ///
  /// Salt file format:
  ///   - v2 (current): UTF-8 text `pbkdf2-sha256:<iter>:<salt_b64>`
  ///   - v1 (legacy):  raw 16 bytes; iteration count was hardcoded 100000
  ///
  /// Backward compatibility: a legacy raw-bytes file is detected and
  /// reported as 100000 iterations so unlockSession can derive the
  /// matching key and run the migration to v2 / 600k.
  static ({Uint8List salt, int iterations}) _loadOrCreateSaltAndIter() {
    final f = File(_saltFilePath!);
    if (f.existsSync()) {
      final raw = f.readAsBytesSync();
      try {
        final text = utf8.decode(raw);
        if (text.startsWith('pbkdf2-sha256:')) {
          final parts = text.split(':');
          if (parts.length == 3) {
            final iter = int.tryParse(parts[1]) ?? 0;
            if (iter > 0) {
              final saltB64 = parts[2];
              final mod = saltB64.length % 4;
              final padded = mod == 0 ? saltB64 : saltB64 + ('=' * (4 - mod));
              final salt = Uint8List.fromList(base64Url.decode(padded));
              return (salt: salt, iterations: iter);
            }
          }
        }
      } catch (_) {
        // Not valid UTF-8 → legacy raw bytes
      }
      // Legacy v1: raw bytes, 100k iterations
      return (salt: Uint8List.fromList(raw), iterations: 100000);
    }
    // First-run: write fresh v2 file
    final salt = _randomBytes(_pbkdf2SaltLength);
    _writeSaltFileV2Sync(salt, _pbkdf2Iterations);
    return (salt: salt, iterations: _pbkdf2Iterations);
  }

  static String _formatSaltFileV2(Uint8List salt, int iterations) {
    final saltB64 = base64Url.encode(salt).replaceAll('=', '');
    return 'pbkdf2-sha256:$iterations:$saltB64';
  }

  static void _writeSaltFileV2Sync(Uint8List salt, int iterations) {
    File(_saltFilePath!).writeAsStringSync(_formatSaltFileV2(salt, iterations));
  }

  static Future<void> _writeSaltFileV2(Uint8List salt, int iterations) async {
    await _atomicWriteString(
        _saltFilePath!, _formatSaltFileV2(salt, iterations));
  }

  static Future<void> _atomicWriteString(String path, String content) async {
    final tmp = File('$path.tmp');
    await tmp.writeAsString(content, flush: true);
    await tmp.rename(path);
  }

  /// AES-256-GCM encrypt with an explicit key, returning a v1 blob
  /// (`0x01 | iv(12) | ciphertext+tag`). Thin delegating wrapper around
  /// the shared [AesGcmHelpers] so the migration path keeps the same
  /// signature it had before the helpers were extracted.
  static Uint8List _aesGcmEncryptWithKey(Uint8List key, Uint8List plaintext) =>
      AesGcmHelpers.encrypt(key, plaintext, versionByte: 0x01);

  /// AES-256-GCM decrypt with an explicit key. Returns null on any failure.
  static Uint8List? _aesGcmDecryptWithKey(Uint8List key, Uint8List blob) =>
      AesGcmHelpers.decrypt(key, blob, expectedVersionByte: 0x01);

  /// Re-encrypt all entries in `.passwords` from `oldKey` to `newKey`.
  ///
  /// Entries that cannot be decrypted with `oldKey` are preserved
  /// untouched.
  static Future<void> _migrateFallbackPasswords(
      Uint8List oldKey, Uint8List newKey) async {
    if (_passwordsFallbackPath == null) return;
    final file = File(_passwordsFallbackPath!);
    if (!await file.exists()) return;
    Map<String, dynamic> data;
    try {
      final content = await file.readAsString();
      data = jsonDecode(content) as Map<String, dynamic>;
    } catch (ex) {
      LoggerService.log(
          'ACCOUNTS', '⚠ Migration: cannot parse .passwords ($ex)');
      return;
    }

    final updated = <String, dynamic>{};
    var migrated = 0;
    var preserved = 0;
    for (final entry in data.entries) {
      final stored = entry.value;
      if (stored is! String) {
        updated[entry.key] = stored;
        continue;
      }
      try {
        final blob = Uint8List.fromList(base64Decode(stored));
        final plain = _aesGcmDecryptWithKey(oldKey, blob);
        if (plain == null) {
          updated[entry.key] = stored;
          preserved++;
          continue;
        }
        final newBlob = _aesGcmEncryptWithKey(newKey, plain);
        updated[entry.key] = base64Encode(newBlob);
        migrated++;
      } catch (_) {
        updated[entry.key] = stored;
        preserved++;
      }
    }

    if (migrated > 0) {
      await _atomicWriteString(
          _passwordsFallbackPath!, jsonEncode(updated));
      LoggerService.log('ACCOUNTS',
          '✓ Re-encrypted $migrated fallback entries to PBKDF2-$_pbkdf2Iterations key (preserved $preserved legacy)');
    }
  }

  /// Unlock the credential session.
  ///
  /// Called by MasterPasswordService after a successful master-password
  /// verify. Derives the AES session key from the password and holds it
  /// in memory. If the salt file is in legacy v1 format (or its iteration
  /// count is below the current target), automatically migrates the salt
  /// file and re-encrypts all fallback entries to the new key.
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

    final saltInfo = _loadOrCreateSaltAndIter();
    final derivedKey = _deriveSessionKey(
        masterPassword, saltInfo.salt, saltInfo.iterations);

    if (saltInfo.iterations < _pbkdf2Iterations) {
      LoggerService.log('ACCOUNTS',
          'Migrating credential KDF from ${saltInfo.iterations} to $_pbkdf2Iterations iterations');
      final newSalt = _randomBytes(_pbkdf2SaltLength);
      final newKey = _deriveSessionKey(
          masterPassword, newSalt, _pbkdf2Iterations);
      // Re-encrypt the fallback file FIRST (in case of crash, the salt
      // file still matches the on-disk ciphertext).
      await _migrateFallbackPasswords(derivedKey, newKey);
      await _writeSaltFileV2(newSalt, _pbkdf2Iterations);
      // Wipe the old derived key
      for (var i = 0; i < derivedKey.length; i++) {
        derivedKey[i] = 0;
      }
      _sessionKey = newKey;
    } else {
      _sessionKey = derivedKey;
    }

    LoggerService.log('ACCOUNTS', 'Credential session unlocked');
  }

  /// Unlock session using raw key bytes (PIN unlock path).
  /// Avoids converting master key to String (immutable, can't be wiped).
  static Future<void> unlockSessionWithKey(Uint8List keyBytes) async {
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

    final saltInfo = _loadOrCreateSaltAndIter();
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(saltInfo.salt, saltInfo.iterations, _pbkdf2KeyLength));
    _sessionKey = derivator.process(keyBytes);
    LoggerService.log('ACCOUNTS', 'Credential session unlocked (key-based)');
  }

  /// Lock the credential session: wipe the AES key from memory.
  /// Called from auto-lock and explicit logout.
  static void lockSession() {
    if (_sessionKey != null) {
      final r = Random.secure();
      for (int i = 0; i < _sessionKey!.length; i++) {
        _sessionKey![i] = r.nextInt(256);
      }
      for (int i = 0; i < _sessionKey!.length; i++) {
        _sessionKey![i] = 0;
      }
      _sessionKey = null;
      LoggerService.log('ACCOUNTS', 'Credential session locked (key wiped)');
    }
    // SECURITY (M7): also clear the in-memory mTLS client certificate
    // cache. The persistent copy in platform secure storage is left
    // intact so the next unlock can re-restore without a network
    // download. Heap dump captured between sessions reveals nothing.
    CertificateService.lockCache();
  }

  /// Whether the credential session is unlocked.
  static bool get isSessionUnlocked => _sessionKey != null;

  // ==========================================================================
  // PASSWORD STORAGE (fallback file)
  // ==========================================================================

  /// Get secure storage key for an account password
  String _getPasswordKey(String username) {
    return 'icd360s_mail_password_$username';
  }

  /// Delete password from fallback file
  Future<void> _deleteFallbackPassword(String username) async {
    try {
      final file = File(_passwordsFallbackPath!);
      if (await file.exists()) {
        final content = await file.readAsString();
        final passwords = jsonDecode(content) as Map<String, dynamic>;
        passwords.remove(username);
        await _atomicWriteString(file.path, jsonEncode(passwords));
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('ACCOUNTS_FALLBACK', ex, stackTrace);
    }
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
      await _atomicWriteString(_accountsFilePath!, jsonString);

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

    await saveAccountsAsync();
    LoggerService.log('ACCOUNTS', '✓ Account updated: ${account.username}');
  }
}