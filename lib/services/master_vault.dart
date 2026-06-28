// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as old_crypto;
import 'package:path_provider/path_provider.dart';
import 'package:sodium/sodium_sumo.dart';

import 'logger_service.dart';
import 'master_vault_meta_service.dart';
import 'portable_secure_storage.dart';

/// Master-password-protected secrets vault (macOS only).
///
/// v0x04 format (sodium):
///   Argon2id(p=1) + BLAKE2b-KDF + XChaCha20-Poly1305
///   All keys stored in libsodium SecureKey (mlock + sodium_memzero).
///
/// v0x03 format (legacy, read-only for migration):
///   Argon2id(p=4) + HKDF-SHA256 + AES-256-GCM
///   Auto-migrated to v0x04 on first unlock.
///
/// On non-macOS: pass-through to PortableSecureStorage.
class MasterVault {
  MasterVault._();
  static final MasterVault instance = MasterVault._();

  /// Sodium instance — set by main.dart before unlock.
  static SodiumSumo? sodium;

  // ── Format constants ─────────────────────────────────────────────
  static const int _formatVersion = 0x04;
  static const int _legacyV3FormatVersion = 0x03;
  static const int _legacyBuggyFormatVersion = 0x02;
  static const String _fileName = 'secrets_vault.bin';

  // ── Argon2id parameters (sodium: p=1 hardcoded by libsodium) ────
  static const int _argon2MemoryKiB = 65536; // 64 MiB
  static const int _argon2MemoryBytes = _argon2MemoryKiB * 1024;
  static const int _argon2OpsLimit = 3;
  static const int _argon2SaltBytes = 16;
  static const int _hashLength = 32;
  static const int _dataKeyBytes = 32;

  // ── XChaCha20-Poly1305 constants ────────────────────────────────
  static const int _xNonceBytes = 24;
  static const int _xTagBytes = 16;

  // ── Legacy AES-GCM constants (v0x03 migration only) ─────────────
  static const int _gcmNonceBytes = 12;
  static const int _gcmTagBytes = 16;

  // ── KDF context (BLAKE2b, exactly 8 ASCII chars) ────────────────
  static const String _kdfContextKek = 'VaultKEK';
  static const String _kdfContextAuth = 'VaultAut';

  // ── Legacy HKDF info labels (v0x03 only) ────────────────────────
  static const _legacyHkdfSalt = 'icd360s.macos.v2.master-vault.salt';
  static const _legacyHkdfInfoKek = 'icd360s.macos.v2.master-vault.kek';
  static const _legacyHkdfInfoAuth = 'icd360s.v1.auth-hash';

  // ── In-memory state (SecureKey with mlock) ──────────────────────
  SecureKey? _kek;
  SecureKey? _dataKey;
  SecureKey? _cachedMasterKey;
  Map<String, String>? _cache;
  Uint8List? _argon2Salt;
  String? _filePath;
  String? _machineSecretCache;
  bool _migrationDone = false;
  bool _unlocking = false;

  // ── Legacy crypto handles (lazy, only for v0x03 migration) ──────
  old_crypto.Argon2id? _legacyArgon2;
  old_crypto.AesGcm? _legacyAes;
  old_crypto.Hkdf? _legacyHkdf;

  // ── Public API ───────────────────────────────────────────────────

  bool get isUnlocked => _kek != null && _dataKey != null && _cache != null;

  Future<void> unlock(String masterPassword) async {
    if (isUnlocked) return;
    if (_unlocking) return;
    _unlocking = true;
    _assertSodium();
    LoggerService.log('MASTER_VAULT', 'Unlocking vault (format=v0x04, crypto=sodium)…');
    try {
      final path = await _path();
      final file = File(path);

      if (!await file.exists()) {
        await _createFreshVault(masterPassword);
        await _runMigrationFromLegacyStorage();
        await _persist();
        LoggerService.log('MASTER_VAULT',
            '✓ Fresh vault created and unlocked '
            '(${_cache!.length} entries after migration)');
        return;
      }

      final blob = await file.readAsBytes();
      if (blob.isEmpty || blob[0] == _legacyBuggyFormatVersion) {
        LoggerService.logWarning('MASTER_VAULT',
            'Detected corrupt/buggy vault file — deleting and recreating');
        await file.delete();
        _wipeKeys();
        _cache = null;
        _argon2Salt = null;
        await _createFreshVault(masterPassword);
        await _runMigrationFromLegacyStorage();
        await _persist();
        LoggerService.log('MASTER_VAULT',
            '✓ Fresh vault recreated after corruption recovery');
        return;
      }

      if (blob[0] == _legacyV3FormatVersion) {
        await _migrateFromV3(blob, masterPassword);
        return;
      }

      if (blob[0] == _formatVersion) {
        await _loadAndDecryptV4(blob, masterPassword);
      } else {
        throw StateError('Unknown vault format: 0x${blob[0].toRadixString(16)}');
      }

      if (!_migrationDone) {
        await _runMigrationFromLegacyStorage();
        if (_migrationDone) await _persist();
      }
      LoggerService.log('MASTER_VAULT',
          '✓ Vault unlocked (${_cache!.length} entries)');
    } catch (ex, st) {
      _wipeKeys();
      _cache = null;
      _argon2Salt = null;
      LoggerService.logError('MASTER_VAULT', ex, st);
      rethrow;
    } finally {
      _unlocking = false;
    }
  }

  /// Same contract as [unlock], but threads through a [boundEmail] used for
  /// server-side Argon2id salt sync (see [MasterVaultMetaService]).
  ///
  ///   - If the vault file does not exist, the fresh vault is created with
  ///     the salt that the server has bound for [boundEmail] (and binds the
  ///     locally-generated salt if no server-side salt exists yet).
  ///   - If the vault file does exist, the salt is loaded from disk as usual,
  ///     but we still attempt an opportunistic upload — first device of a
  ///     pre-existing vault gets its salt bound to the server so the next
  ///     fresh install of another device of the same user can align.
  ///
  /// Callers that do not yet know the account (e.g. the legacy first-boot
  /// path) should keep calling [unlock] — this method only adds value once
  /// at least one account is enrolled.
  Future<void> unlockBoundTo(String masterPassword, String boundEmail) async {
    if (isUnlocked) {
      // Already unlocked — still try to reconcile the salt in case this is
      // the first call since the salt-sync feature was added.
      await _reconcileSaltWithServer(boundEmail);
      return;
    }
    if (_unlocking) return;
    _unlocking = true;
    _assertSodium();
    LoggerService.log('MASTER_VAULT',
        'Unlocking vault (format=v0x04, crypto=sodium, boundEmail=$boundEmail)…');
    try {
      final path = await _path();
      final file = File(path);

      if (!await file.exists()) {
        await _createFreshVault(masterPassword, boundEmail: boundEmail);
        await _runMigrationFromLegacyStorage();
        await _persist();
        LoggerService.log('MASTER_VAULT',
            '✓ Fresh vault created and unlocked '
            '(${_cache!.length} entries after migration), boundEmail=$boundEmail');
        return;
      }

      final blob = await file.readAsBytes();
      if (blob.isEmpty || blob[0] == _legacyBuggyFormatVersion) {
        LoggerService.logWarning('MASTER_VAULT',
            'Detected corrupt/buggy vault file — deleting and recreating');
        await file.delete();
        _wipeKeys();
        _cache = null;
        _argon2Salt = null;
        await _createFreshVault(masterPassword, boundEmail: boundEmail);
        await _runMigrationFromLegacyStorage();
        await _persist();
        LoggerService.log('MASTER_VAULT',
            '✓ Fresh vault recreated after corruption recovery (boundEmail=$boundEmail)');
        return;
      }

      if (blob[0] == _legacyV3FormatVersion) {
        await _migrateFromV3(blob, masterPassword);
        await _reconcileSaltWithServer(boundEmail);
        return;
      }

      if (blob[0] == _formatVersion) {
        await _loadAndDecryptV4(blob, masterPassword);
      } else {
        throw StateError('Unknown vault format: 0x${blob[0].toRadixString(16)}');
      }

      if (!_migrationDone) {
        await _runMigrationFromLegacyStorage();
        if (_migrationDone) await _persist();
      }

      // Existing vault loaded — opportunistically push our salt to the server.
      await _reconcileSaltWithServer(boundEmail);

      LoggerService.log('MASTER_VAULT',
          '✓ Vault unlocked (${_cache!.length} entries), boundEmail=$boundEmail');
    } catch (ex, st) {
      _wipeKeys();
      _cache = null;
      _argon2Salt = null;
      LoggerService.logError('MASTER_VAULT', ex, st);
      rethrow;
    } finally {
      _unlocking = false;
    }
  }

  Future<void> unlockWithKey(Uint8List masterKey) async {
    if (isUnlocked) return;
    if (_unlocking) return;
    _unlocking = true;
    _assertSodium();
    try {
      final path = await _path();
      final file = File(path);
      if (!await file.exists()) {
        throw StateError('unlockWithKey: vault file not found');
      }
      final blob = await file.readAsBytes();
      if (blob[0] == _legacyV3FormatVersion) {
        throw StateError('unlockWithKey: vault needs migration, use full unlock');
      }
      if (blob[0] != _formatVersion) {
        throw StateError('Unknown vault format: 0x${blob[0].toRadixString(16)}');
      }
      await _loadAndDecryptV4WithKey(blob, masterKey);
      if (!_migrationDone) {
        await _runMigrationFromLegacyStorage();
        if (_migrationDone) await _persist();
      }
      LoggerService.log('MASTER_VAULT',
          '✓ Vault unlocked via cached key (${_cache!.length} entries)');
    } catch (ex, st) {
      _wipeKeys();
      _cache = null;
      _argon2Salt = null;
      LoggerService.logError('MASTER_VAULT', ex, st);
      rethrow;
    } finally {
      _unlocking = false;
    }
  }

  Future<void> deleteAndRecreate(String masterPassword,
      {String? boundEmail}) async {
    _assertSodium();
    final path = await _path();
    final file = File(path);
    if (await file.exists()) {
      await file.delete();
      LoggerService.log('MASTER_VAULT', 'Deleted stale vault file');
    }
    _wipeKeys();
    _cache = null;
    _argon2Salt = null;
    await _createFreshVault(masterPassword, boundEmail: boundEmail);
    await _persist();
    LoggerService.log('MASTER_VAULT',
        '✓ Fresh vault created after deleteAndRecreate (boundEmail=$boundEmail)');
  }

  void lock() {
    if (!isUnlocked && !_unlocking) return;
    _unlocking = false;
    _wipeKeys(wipeMasterKeyCache: true);
    if (_argon2Salt != null) {
      for (var i = 0; i < _argon2Salt!.length; i++) _argon2Salt![i] = 0;
    }
    _cache?.updateAll((_, __) => '');
    _cache = null;
    _argon2Salt = null;
    _machineSecretCache = null;
    _migrationDone = false;
    LoggerService.log('MASTER_VAULT', 'Vault locked, secure keys disposed');
  }

  Future<String?> read({required String key}) async {
    if (!isUnlocked) {
      LoggerService.logWarning('MASTER_VAULT',
          'read($key) before unlock — returning null');
      return null;
    }
    return _cache![key];
  }

  Future<void> write({required String key, required String? value}) async {
    if (!isUnlocked) {
      // Symmetric with [read]: when an async task is racing the auto-lock
      // timer (e.g. a heartbeat completes a write right after auto-lock
      // fires) we don't want a StateError stack trace bubbling up. The
      // auto-lock path has already zeroed the keys, so any write would
      // also lose its state — log a warning and bail gracefully instead.
      LoggerService.logWarning('MASTER_VAULT',
          'write($key) before unlock — dropping (likely a write racing '
          'the auto-lock timer)');
      return;
    }
    if (value == null) {
      _cache!.remove(key);
    } else {
      _cache![key] = value;
    }
    await _persist();
  }

  Future<void> delete({required String key}) => write(key: key, value: null);

  Future<bool> containsKey({required String key}) async =>
      (await read(key: key)) != null;

  Future<void> changeMasterPassword(String newMasterPassword) async {
    if (!isUnlocked) {
      throw StateError('changeMasterPassword called on locked vault');
    }
    LoggerService.log('MASTER_VAULT', 'Re-keying vault under new password…');
    _argon2Salt = _randomBytes(_argon2SaltBytes);
    _kek = await _deriveKEK(newMasterPassword, _argon2Salt!);
    await _persist();
    LoggerService.log('MASTER_VAULT',
        '✓ Vault re-encrypted under new password');
  }

  /// Derive master key (Argon2id via sodium, p=1).
  /// Returns Uint8List for backward compat with MasterPasswordService.
  /// Also caches in SecureKey for PIN setup.
  Future<Uint8List> deriveMasterKey(
    String masterPassword,
    Uint8List argonSalt,
  ) async {
    _assertSodium();
    final s = sodium!;
    final masterSecure = s.crypto.pwhash(
      outLen: _hashLength,
      password: Int8List.fromList(utf8.encode(masterPassword)),
      salt: argonSalt,
      opsLimit: _argon2OpsLimit,
      memLimit: _argon2MemoryBytes,
      alg: CryptoPwhashAlgorithm.argon2id13,
    );
    _cachedMasterKey?.dispose();
    _cachedMasterKey = masterSecure;
    final bytes = masterSecure.extractBytes();
    return Uint8List.fromList(bytes);
  }

  Future<Uint8List?> deriveMasterKeyFromCache() async {
    if (_cachedMasterKey == null) return null;
    final bytes = _cachedMasterKey!.extractBytes();
    return Uint8List.fromList(bytes);
  }

  /// Derive auth hash via BLAKE2b-KDF (sodium).
  /// For NEW vaults (v0x04). Returns 32 bytes.
  Future<Uint8List> deriveAuthHash(Uint8List masterKeyBytes) async {
    _assertSodium();
    final s = sodium!;
    final masterSecure = s.secureCopy(masterKeyBytes);
    final authKey = s.crypto.kdf.deriveFromKey(
      masterKey: masterSecure,
      context: _kdfContextAuth,
      subkeyId: BigInt.from(1),
      subkeyLen: _hashLength,
    );
    final bytes = authKey.extractBytes();
    authKey.dispose();
    masterSecure.dispose();
    return Uint8List.fromList(bytes);
  }

  /// Legacy auth hash for v0x03 migration (HKDF-SHA256).
  Future<Uint8List> deriveLegacyAuthHash(Uint8List masterKeyBytes) async {
    _initLegacyCrypto();
    final authKey = await _legacyHkdf!.deriveKey(
      secretKey: old_crypto.SecretKey(masterKeyBytes),
      nonce: utf8.encode(_legacyHkdfSalt),
      info: utf8.encode(_legacyHkdfInfoAuth),
    );
    final authBytes = await authKey.extractBytes();
    return Uint8List.fromList(authBytes);
  }


  /// Legacy master key derivation (Argon2id p=4, cryptography pkg).
  /// Used to verify passwords stored with the old format.
  Future<Uint8List> deriveLegacyMasterKey(
    String masterPassword,
    Uint8List argonSalt,
  ) async {
    _initLegacyCrypto();
    final masterKey = await _legacyArgon2!.deriveKey(
      secretKey: old_crypto.SecretKey(utf8.encode(masterPassword)),
      nonce: argonSalt,
    );
    final bytes = await masterKey.extractBytes();
    return Uint8List.fromList(bytes);
  }
  /// Get cached salt for external use (MasterPasswordService).
  Uint8List? get vaultArgon2Salt => _argon2Salt != null
      ? Uint8List.fromList(_argon2Salt!) : null;

  // ── Internals ────────────────────────────────────────────────────

  void _assertSodium() {
    if (sodium == null) {
      throw StateError('MasterVault: sodium not initialized (call SodiumSumoInit.init first)');
    }
  }

  void _initLegacyCrypto() {
    _legacyArgon2 ??= old_crypto.Argon2id(
      memory: _argon2MemoryKiB,
      iterations: 3,
      parallelism: 4,
      hashLength: _hashLength,
    );
    _legacyAes ??= old_crypto.AesGcm.with256bits();
    _legacyHkdf ??= old_crypto.Hkdf(
        hmac: old_crypto.Hmac.sha256(), outputLength: _hashLength);
  }

  Future<String> _path() async {
    if (_filePath != null) return _filePath!;
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) await dir.create(recursive: true);
    _filePath = '${dir.path}/$_fileName';
    return _filePath!;
  }

  Future<String> _machineSecret() async {
    // macOS: use hardware UUID from ioreg/system_profiler
    if (Platform.isMacOS) {
      try {
        final result = await Process.run(
          '/usr/sbin/ioreg',
          ['-rd1', '-c', 'IOPlatformExpertDevice'],
        );
        if (result.exitCode == 0) {
          final out = result.stdout as String;
          final uuidMatch =
              RegExp(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]+)"').firstMatch(out);
          if (uuidMatch != null) {
            final uuid = uuidMatch.group(1)!;
            final serialMatch =
                RegExp(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"').firstMatch(out);
            final serial = serialMatch?.group(1) ?? '';
            return '$uuid:$serial';
          }
        }
      } catch (_) {}
      try {
        final spResult = await Process.run(
          '/usr/sbin/system_profiler',
          ['SPHardwareDataType'],
        );
        if (spResult.exitCode == 0) {
          final out = spResult.stdout as String;
          final uuidMatch =
              RegExp(r'Hardware UUID:\s*([0-9A-Fa-f-]+)').firstMatch(out);
          if (uuidMatch != null) {
            LoggerService.logWarning('MASTER_VAULT',
                'ioreg failed, using system_profiler fallback');
            return uuidMatch.group(1)!;
          }
        }
      } catch (_) {}
      throw StateError('Cannot determine machine secret — '
          'both ioreg and system_profiler failed.');
    }

    // Linux: use /etc/machine-id (stable, unique per install)
    if (Platform.isLinux) {
      try {
        final file = File('/etc/machine-id');
        if (await file.exists()) {
          final id = (await file.readAsString()).trim();
          if (id.isNotEmpty) return 'linux:$id';
        }
      } catch (_) {}
    }

    // Windows: use MachineGuid from registry
    if (Platform.isWindows) {
      try {
        final result = await Process.run('reg', [
          'query', r'HKLM\SOFTWARE\Microsoft\Cryptography',
          '/v', 'MachineGuid',
        ]);
        if (result.exitCode == 0) {
          final match = RegExp(r'MachineGuid\s+REG_SZ\s+(\S+)')
              .firstMatch(result.stdout as String);
          if (match != null) return 'win:${match.group(1)}';
        }
      } catch (_) {}
    }

    // Android/iOS: use a randomly generated persistent ID stored
    // in app-private storage (survives reboots, not tied to KeyStore).
    // This is NOT the machine hardware ID — it is a per-install
    // random secret that adds entropy to the vault key derivation.
    final dir = await _vaultDir();
    final idFile = File('$dir/vault_device_id');
    if (await idFile.exists()) {
      final id = (await idFile.readAsString()).trim();
      if (id.length >= 32) return 'mobile:$id';
    }
    // Generate a new random device ID (first run)
    final rng = Random.secure();
    final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
    final newId = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    await idFile.writeAsString(newId);
    LoggerService.log('MASTER_VAULT',
        'Generated persistent vault device ID for mobile');
    return 'mobile:$newId';
  }

  Future<String> _vaultDir() async {
    final dir = await getApplicationSupportDirectory();
    return dir.path;
  }

  // ── v0x04 KEK derivation (sodium BLAKE2b) ──────────────────────

  Future<SecureKey> _deriveKEK(
    String masterPassword,
    Uint8List argonSalt,
  ) async {
    final s = sodium!;
    final masterKey = s.crypto.pwhash(
      outLen: _hashLength,
      password: Int8List.fromList(utf8.encode(masterPassword)),
      salt: argonSalt,
      opsLimit: _argon2OpsLimit,
      memLimit: _argon2MemoryBytes,
      alg: CryptoPwhashAlgorithm.argon2id13,
    );
    final kek = await _deriveKEKFromSecureKey(masterKey);
    masterKey.dispose();
    return kek;
  }

  Future<SecureKey> _deriveKEKFromSecureKey(SecureKey masterKey) async {
    final s = sodium!;
    final mkBytes = masterKey.extractBytes();
    _machineSecretCache ??= await _machineSecret();
    final machineBytes = utf8.encode(_machineSecretCache!);
    final combined = Uint8List.fromList(mkBytes + machineBytes);
    for (var i = 0; i < mkBytes.length; i++) mkBytes[i] = 0;
    final combinedKey = s.crypto.genericHash(
      message: combined,
      outLen: _hashLength,
    );
    for (var i = 0; i < combined.length; i++) combined[i] = 0;
    final kdfMaster = s.secureCopy(combinedKey);
    final kek = s.crypto.kdf.deriveFromKey(
      masterKey: kdfMaster,
      context: _kdfContextKek,
      subkeyId: BigInt.from(1),
      subkeyLen: _hashLength,
    );
    kdfMaster.dispose();
    return kek;
  }

  Future<SecureKey> _deriveKEKFromMasterKeyBytes(Uint8List masterKey) async {
    final s = sodium!;
    final secureKey = s.secureCopy(masterKey);
    final kek = await _deriveKEKFromSecureKey(secureKey);
    secureKey.dispose();
    return kek;
  }

  // ── v0x04 encrypt / decrypt ─────────────────────────────────────

  Future<void> _loadAndDecryptV4(Uint8List blob, String masterPassword) async {
    final s = sodium!;
    var off = 1;
    final memKiB = _readUint32(blob, off); off += 4;
    final opsLimit = blob[off++];
    /* parallelism stored but unused (sodium hardcodes 1) */
    off++;
    _argon2Salt = Uint8List.fromList(blob.sublist(off, off + _argon2SaltBytes));
    off += _argon2SaltBytes;
    final kekNonce = blob.sublist(off, off + _xNonceBytes); off += _xNonceBytes;
    final wrappedDataKey = blob.sublist(off, off + _dataKeyBytes + _xTagBytes);
    off += _dataKeyBytes + _xTagBytes;
    final vaultNonce = blob.sublist(off, off + _xNonceBytes); off += _xNonceBytes;
    final vaultCt = blob.sublist(off);

    final masterKey = s.crypto.pwhash(
      outLen: _hashLength,
      password: Int8List.fromList(utf8.encode(masterPassword)),
      salt: _argon2Salt!,
      opsLimit: opsLimit,
      memLimit: memKiB * 1024,
      alg: CryptoPwhashAlgorithm.argon2id13,
    );
    _cachedMasterKey?.dispose();
    _cachedMasterKey = masterKey;
    _kek = await _deriveKEKFromSecureKey(masterKey);

    final aead = s.crypto.aeadXChaCha20Poly1305IETF;
    final dataKeyPlain = aead.decrypt(
      cipherText: wrappedDataKey,
      nonce: kekNonce,
      key: _kek!,
    );
    _dataKey = s.secureCopy(Uint8List.fromList(dataKeyPlain));

    final vaultPlain = aead.decrypt(
      cipherText: vaultCt,
      nonce: vaultNonce,
      key: _dataKey!,
    );
    final json = jsonDecode(utf8.decode(vaultPlain)) as Map<String, dynamic>;
    _cache = {};
    json.forEach((k, v) {
      if (k == '__migration_v1_done') {
        _migrationDone = (v == '1' || v == 1 || v == true);
      } else {
        _cache![k] = v.toString();
      }
    });
  }

  Future<void> _loadAndDecryptV4WithKey(Uint8List blob, Uint8List masterKey) async {
    final s = sodium!;
    var off = 1 + 4 + 1 + 1;
    _argon2Salt = Uint8List.fromList(blob.sublist(off, off + _argon2SaltBytes));
    off += _argon2SaltBytes;
    final kekNonce = blob.sublist(off, off + _xNonceBytes); off += _xNonceBytes;
    final wrappedDataKey = blob.sublist(off, off + _dataKeyBytes + _xTagBytes);
    off += _dataKeyBytes + _xTagBytes;
    final vaultNonce = blob.sublist(off, off + _xNonceBytes); off += _xNonceBytes;
    final vaultCt = blob.sublist(off);

    _kek = await _deriveKEKFromMasterKeyBytes(masterKey);

    final aead = s.crypto.aeadXChaCha20Poly1305IETF;
    final dataKeyPlain = aead.decrypt(
      cipherText: wrappedDataKey,
      nonce: kekNonce,
      key: _kek!,
    );
    _dataKey = s.secureCopy(Uint8List.fromList(dataKeyPlain));

    final vaultPlain = aead.decrypt(
      cipherText: vaultCt,
      nonce: vaultNonce,
      key: _dataKey!,
    );
    final json = jsonDecode(utf8.decode(vaultPlain)) as Map<String, dynamic>;
    _cache = {};
    json.forEach((k, v) {
      if (k == '__migration_v1_done') {
        _migrationDone = (v == '1' || v == 1 || v == true);
      } else {
        _cache![k] = v.toString();
      }
    });
  }

  Future<void> _persist() async {
    if (_kek == null || _dataKey == null || _cache == null ||
        _argon2Salt == null) {
      throw StateError('_persist on locked vault');
    }
    final s = sodium!;
    final aead = s.crypto.aeadXChaCha20Poly1305IETF;

    final kekNonce = s.randombytes.buf(aead.nonceBytes);
    final vaultNonce = s.randombytes.buf(aead.nonceBytes);

    final dataKeyBytes = _dataKey!.extractBytes();
    final wrappedDataKey = aead.encrypt(
      message: Uint8List.fromList(dataKeyBytes),
      nonce: kekNonce,
      key: _kek!,
    );

    final json = Map<String, dynamic>.from(_cache!);
    if (_migrationDone) json['__migration_v1_done'] = '1';
    final plaintext = utf8.encode(jsonEncode(json));
    final vaultCt = aead.encrypt(
      message: Uint8List.fromList(plaintext),
      nonce: vaultNonce,
      key: _dataKey!,
    );

    final builder = BytesBuilder();
    builder.addByte(_formatVersion);
    _addUint32(builder, _argon2MemoryKiB);
    builder.addByte(_argon2OpsLimit);
    builder.addByte(1); // parallelism (sodium hardcodes 1)
    builder.add(_argon2Salt!);
    builder.add(kekNonce);
    builder.add(wrappedDataKey);
    builder.add(vaultNonce);
    builder.add(vaultCt);

    final blob = builder.takeBytes();
    final path = await _path();
    final tmp = File('$path.tmp');
    await tmp.writeAsBytes(blob, flush: true);
    await tmp.rename(path);
    try { await Process.run('/bin/chmod', ['600', path]); } catch (_) {}
  }

  Future<void> _createFreshVault(String pwd, {String? boundEmail}) async {
    final s = sodium!;
    LoggerService.log('MASTER_VAULT', 'Creating fresh vault file (v0x04 sodium)');
    _cache = {};
    _dataKey = s.secureRandom(_dataKeyBytes);

    // Generate a local random salt as the offline fallback. If we know which
    // account this vault is being bound to, ask the server whether another
    // device of the same user has already bound a salt — and use it if so.
    // This is the missing piece that lets the same master password derive
    // the same master key (and thus PgpSync blob KEK) on every device.
    Uint8List salt = _randomBytes(_argon2SaltBytes);
    if (boundEmail != null) {
      final remote = await MasterVaultMetaService.fetchOrBindSalt(
        email: boundEmail,
        localFallback: salt,
      );
      if (remote != null) {
        salt = remote;
        LoggerService.log('MASTER_VAULT',
            'Vault salt aligned with server-bound salt for $boundEmail');
      } else {
        LoggerService.logWarning('MASTER_VAULT',
            'Salt sync unavailable for $boundEmail — using local random '
            '(will retry on next unlock)');
      }
    }
    _argon2Salt = salt;

    final vaultMasterKey = await deriveMasterKey(pwd, _argon2Salt!);
    _kek = await _deriveKEKFromMasterKeyBytes(vaultMasterKey);
    for (var i = 0; i < vaultMasterKey.length; i++) vaultMasterKey[i] = 0;
  }

  /// Opportunistic salt-sync: try to bind the *current* local salt to the
  /// server for [boundEmail]. Server enforces first-write-wins, so if any
  /// other device of this user has already bound a different salt, this is
  /// a no-op (we keep our local salt — the existing local vault wouldn't
  /// be re-keyable without losing data anyway). Used for back-filling
  /// existing vaults that pre-date the salt-sync rollout.
  Future<void> _reconcileSaltWithServer(String boundEmail) async {
    if (_argon2Salt == null) return;
    try {
      final won = await MasterVaultMetaService.uploadSalt(
        boundEmail,
        _argon2Salt!,
      );
      if (won) {
        LoggerService.log('MASTER_VAULT',
            '✓ Local salt bound to server for $boundEmail (first device)');
      }
      // 409 → server already has a (different) salt for this user.
      // We keep our local salt; the user's other devices will fetch the
      // server's salt on their next fresh vault, so they'll align with
      // whoever bound first.
    } catch (ex) {
      LoggerService.logWarning('MASTER_VAULT',
          'Salt reconciliation skipped for $boundEmail (network): $ex');
    }
  }

  // ── v0x03 → v0x04 migration ─────────────────────────────────────

  Future<void> _migrateFromV3(Uint8List blob, String masterPassword) async {
    LoggerService.log('MASTER_VAULT',
        'Migrating vault from v0x03 (AES-GCM) to v0x04 (sodium)…');
    _initLegacyCrypto();

    var off = 1;
    final memKiB = blob[off] | (blob[off+1]<<8) | (blob[off+2]<<16) | (blob[off+3]<<24);
    off += 4;
    final iters = blob[off++];
    final paral = blob[off++];

    _legacyArgon2 = old_crypto.Argon2id(
      memory: memKiB, iterations: iters,
      parallelism: paral, hashLength: _hashLength,
    );

    final legacySalt = Uint8List.fromList(blob.sublist(off, off + _argon2SaltBytes));
    off += _argon2SaltBytes;
    final kekNonce = blob.sublist(off, off + _gcmNonceBytes); off += _gcmNonceBytes;
    final wrappedDataKey = blob.sublist(off, off + _dataKeyBytes + _gcmTagBytes);
    off += _dataKeyBytes + _gcmTagBytes;
    final vaultNonce = blob.sublist(off, off + _gcmNonceBytes); off += _gcmNonceBytes;
    final vaultCt = blob.sublist(off);

    // Derive legacy KEK
    final legacyMasterKey = await _legacyArgon2!.deriveKey(
      secretKey: old_crypto.SecretKey(utf8.encode(masterPassword)),
      nonce: legacySalt,
    );
    final legacyMkBytes = Uint8List.fromList(await legacyMasterKey.extractBytes());
    final machine = await _machineSecret();
    final ikmBytes = Uint8List.fromList(legacyMkBytes + utf8.encode(machine));
    final legacyKek = await _legacyHkdf!.deriveKey(
      secretKey: old_crypto.SecretKey(ikmBytes),
      nonce: utf8.encode(_legacyHkdfSalt),
      info: utf8.encode(_legacyHkdfInfoKek),
    );
    for (var i = 0; i < legacyMkBytes.length; i++) legacyMkBytes[i] = 0;
    for (var i = 0; i < ikmBytes.length; i++) ikmBytes[i] = 0;

    // Unwrap data_key with legacy AES-GCM
    final wrappedCt = wrappedDataKey.sublist(0, _dataKeyBytes);
    final wrappedTag = wrappedDataKey.sublist(_dataKeyBytes);
    final dataKeyBox = old_crypto.SecretBox(
      wrappedCt, nonce: kekNonce, mac: old_crypto.Mac(wrappedTag),
    );
    final dataKeyBytes = await _legacyAes!.decrypt(dataKeyBox, secretKey: legacyKek);

    // Decrypt vault with legacy AES-GCM
    final vaultBody = vaultCt.sublist(0, vaultCt.length - _gcmTagBytes);
    final vaultTag = vaultCt.sublist(vaultCt.length - _gcmTagBytes);
    final vaultBox = old_crypto.SecretBox(
      vaultBody, nonce: vaultNonce, mac: old_crypto.Mac(vaultTag),
    );
    final plaintext = await _legacyAes!.decrypt(
      vaultBox, secretKey: old_crypto.SecretKey(dataKeyBytes),
    );

    // Parse plaintext
    final json = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
    _cache = {};
    json.forEach((k, v) {
      if (k == '__migration_v1_done') {
        _migrationDone = (v == '1' || v == 1 || v == true);
      } else {
        _cache![k] = v.toString();
      }
    });

    // Re-encrypt under v0x04 (sodium)
    final s = sodium!;
    _argon2Salt = _randomBytes(_argon2SaltBytes);
    _dataKey = s.secureCopy(Uint8List.fromList(dataKeyBytes));
    final newMasterKey = await deriveMasterKey(masterPassword, _argon2Salt!);
    _kek = await _deriveKEKFromMasterKeyBytes(newMasterKey);
    for (var i = 0; i < newMasterKey.length; i++) newMasterKey[i] = 0;

    await _persist();
    LoggerService.log('MASTER_VAULT',
        '✓ Vault migrated to v0x04 (${_cache!.length} entries)');
  }

  // ── Legacy storage migration ────────────────────────────────────

  Future<void> _runMigrationFromLegacyStorage() async {
    if (_migrationDone) return;
    LoggerService.log('MASTER_VAULT',
        'Running migration of legacy secrets from PortableSecureStorage');
    final legacy = PortableSecureStorage.instance;
    const secretKeys = <String>[
      'icd360s_mtls_client_cert',
      'icd360s_mtls_client_key',
      'icd360s_mtls_ca_cert',
      'icd360s_mtls_username',
    ];
    var migrated = 0;
    for (final k in secretKeys) {
      try {
        final v = await legacy.read(key: k);
        if (v != null && v.isNotEmpty) {
          _cache![k] = v;
          await legacy.delete(key: k);
          migrated++;
        }
      } catch (ex) {
        LoggerService.logWarning('MASTER_VAULT',
            'migration: failed to migrate key $k: $ex');
      }
    }
    _migrationDone = true;
    LoggerService.log('MASTER_VAULT',
        '✓ Migration complete: $migrated legacy secrets moved to vault');
  }

  // ── Key wiping (sodium_memzero via SecureKey.dispose) ───────────

  void _wipeKeys({bool wipeMasterKeyCache = false}) {
    if (wipeMasterKeyCache) {
      _cachedMasterKey?.dispose();
      _cachedMasterKey = null;
    }
    _dataKey?.dispose();
    _dataKey = null;
    _kek?.dispose();
    _kek = null;
  }

  // ── Utilities ───────────────────────────────────────────────────

  Uint8List _randomBytes(int n) {
    if (sodium != null) return sodium!.randombytes.buf(n);
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }

  static int _readUint32(Uint8List data, int offset) =>
      data[offset] | (data[offset+1] << 8) | (data[offset+2] << 16) | (data[offset+3] << 24);

  static void _addUint32(BytesBuilder b, int v) {
    b.addByte(v & 0xFF);
    b.addByte((v >> 8) & 0xFF);
    b.addByte((v >> 16) & 0xFF);
    b.addByte((v >> 24) & 0xFF);
  }
}
