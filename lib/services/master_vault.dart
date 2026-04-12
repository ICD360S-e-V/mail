import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:path_provider/path_provider.dart';

import 'logger_service.dart';
import 'portable_secure_storage.dart';

/// Master-password-protected secrets vault. Stores the most sensitive
/// data (mTLS client cert + private key, account passwords, mail-admin
/// session tokens) in `secrets_vault.bin` under a key derived from
/// BOTH the user's master password AND the device's machine-bound
/// secret (IOPlatformUUID on macOS).
///
/// Architecture mirrors Bitwarden's two-secret KDF + envelope pattern
/// (see https://bitwarden.com/help/bitwarden-security-white-paper/):
///
///   master_pwd  →  Argon2id(64 MiB, 3 iters, 4 threads)  →  master_key
///   master_key + IOPlatformUUID  →  HKDF-SHA256  →  vault_KEK (cached)
///   data_key  =  random 32 bytes (one-shot per device, persisted)
///   protected_data_key  =  AES-256-GCM(data_key, vault_KEK, kek_nonce)
///   vault_blob  =  AES-256-GCM(json_secrets, data_key, vault_nonce)
///
/// Stored on disk:
///
///   [byte 0]      version_byte = 0x02
///   [byte 1-2]    argon2_memory_KiB (uint16 LE)
///   [byte 3]      argon2_iterations
///   [byte 4]      argon2_parallelism
///   [byte 5..20]  argon2_salt (16 bytes random — fixed for vault lifetime)
///   [byte 21..32] kek_nonce (12 bytes for AES-GCM, fresh per write)
///   [byte 33..80] protected_data_key (32 + 16 GCM tag = 48 bytes)
///   [byte 81..92] vault_nonce (12 bytes, fresh per write)
///   [byte 93..N]  vault_ciphertext + 16 bytes GCM tag
///
/// Why double-key envelope:
///   - Changing the master password = generate new argon2 salt, derive
///     new KEK, re-wrap the data_key (60 bytes). Vault data untouched.
///     Atomic, fast, hard to corrupt.
///   - Stolen file without master pwd = brute-force Argon2id at
///     ~600ms per attempt with 64 MiB working set. Practically
///     uncrackable for any non-trivial password.
///   - Cross-machine theft = different IOPlatformUUID = vault_KEK
///     can't be derived even with the right master pwd.
///
/// In-memory state lifecycle:
///   - Before unlock: empty (`_kek == null`, `_dataKey == null`,
///     `_cache == null`). Reads return null with a warning, writes
///     throw StateError.
///   - After unlock: KEK + data_key + cache held in memory. The
///     master password itself is NOT held — only the derived keys.
///   - On lock: all three are zeroed via `fillRange(0, len, 0)` and
///     nullified. This implements B5-Part-1 (the literal audit ask)
///     in addition to B5-Part-2 (master-pwd binding).
///
/// Migration from PortableSecureStorage:
///   On first successful [unlock], if the legacy
///   `PortableSecureStorage.instance` still contains keys whose names
///   match a known "secret" prefix (mTLS cert/key/CA), they are
///   read out and copied into the vault, then deleted from the
///   legacy store. Idempotent (a `__migration_v1_done` flag in the
///   vault prevents re-running).
///
/// macOS only — on iOS/Android/Windows/Linux this class is a thin
/// pass-through to `PortableSecureStorage` which itself delegates to
/// `flutter_secure_storage` (Keychain / Keystore / DPAPI / libsecret),
/// already password/biometric-protected at the OS level. The macOS
/// complexity exists because ad-hoc signed binaries cannot use the
/// macOS Keychain (errSecMissingEntitlement -34018) — see
/// PortableSecureStorage docs.
class MasterVault {
  MasterVault._();
  static final MasterVault instance = MasterVault._();

  // ── Format constants ─────────────────────────────────────────────
  // v0x02: 2-byte uint16 memory_KiB header — UNUSABLE because the
  //        Argon2 default of 65536 KiB overflows uint16 (max 65535)
  //        and is read back as 0, crashing Argon2id with
  //        "Invalid argument (memory): 0". Any vault file written
  //        with this format byte is corrupt and gets nuked on first
  //        load (see _loadAndDecrypt) — the user has to re-enter the
  //        master password to recreate it.
  // v0x03: 4-byte uint32 LE memory_KiB header. Fits any reasonable
  //        Argon2 memory cost up to 4 GiB.
  static const int _formatVersion = 0x03;
  static const int _legacyBuggyFormatVersion = 0x02;
  static const String _fileName = 'secrets_vault.bin';

  // ── Argon2id parameters (Bitwarden / OWASP 2026 defaults) ────────
  // 64 MiB memory, 3 iterations, 4-way parallelism, 32-byte output.
  // Targets ~600 ms on a modern Mac (M1+). Acceptable on unlock.
  static const int _argon2MemoryKiB = 65536; // 64 MiB
  static const int _argon2Iterations = 3;
  static const int _argon2Parallelism = 4;
  static const int _argon2SaltBytes = 16;
  static const int _hashLength = 32;
  static const int _gcmNonceBytes = 12;
  static const int _gcmTagBytes = 16;
  static const int _dataKeyBytes = 32;

  // ── HKDF info string (binds the derived KEK to a context) ───────
  static const _hkdfSalt = 'icd360s.macos.v2.master-vault.salt';

  // ── In-memory state (zeroized on lock) ───────────────────────────
  /// Cached masterKey bytes — kept in memory while unlocked so
  /// PinUnlockService can wrap it under a PIN during setup.
  /// Zeroed on lock().
  Uint8List? _cachedMasterKey;

  /// Cached KEK. Re-used for every persist while unlocked. Re-derived
  /// on next unlock from on-disk argon2 salt + entered password.
  SecretKey? _kek;

  /// Random data_key generated once per vault file. Persisted in
  /// encrypted form (wrapped under KEK). Stays the same forever
  /// unless the user explicitly does a factory reset or vault rotation.
  Uint8List? _dataKey;

  /// In-memory plaintext cache of all secrets. Keys are arbitrary
  /// strings (e.g. `icd360s_mtls_client_cert`), values are arbitrary
  /// strings (PEM blobs, passwords, etc.). Encrypted as a single
  /// JSON blob via the data_key on persist.
  Map<String, String>? _cache;

  /// Argon2id salt for THIS vault file. Read from disk on unlock or
  /// generated fresh on first creation. Fixed for the file's lifetime
  /// unless changeMasterPassword rotates it.
  Uint8List? _argon2Salt;

  String? _filePath;
  bool _migrationDone = false;

  // ── Cryptography handles (lazy) ──────────────────────────────────
  Argon2id? _argon2;
  AesGcm? _aes;
  Hkdf? _hkdf;

  // ── Public API ───────────────────────────────────────────────────

  bool get isUnlocked => _kek != null && _dataKey != null && _cache != null;

  /// Unlock the vault with the user's master password.
  ///
  /// Must be called from [MasterPasswordService.verifyMasterPassword]
  /// AFTER the master password has been verified against the stored
  /// hash. The verified password is the only piece of information
  /// needed here; the password itself is not retained after this call
  /// returns (only the derived KEK).
  ///
  /// On macOS:
  ///   - If the vault file does not exist → create a fresh vault
  ///     with a new random data_key + argon2 salt, encrypted under
  ///     the password. Then run the migration to import any legacy
  ///     secrets from PortableSecureStorage.
  ///   - If the vault file exists → derive the KEK from password +
  ///     on-disk argon2 salt, unwrap the data_key, decrypt the vault.
  ///     If decryption fails (cipher tag mismatch), the password is
  ///     wrong; throw and leave the vault locked.
  ///
  /// On non-macOS: no-op (the OS-level secure storage doesn't need
  /// a software vault layer).
  ///
  /// Idempotent: calling unlock when already unlocked returns
  /// immediately.
  Future<void> unlock(String masterPassword) async {
    if (!Platform.isMacOS) return;
    if (isUnlocked) return;
    LoggerService.log('MASTER_VAULT', 'Unlocking vault…');
    try {
      _initCryptoHandles();

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

      // Existing vault — parse header and decrypt.
      final blob = await file.readAsBytes();
      try {
        await _loadAndDecrypt(blob, masterPassword);
      } on _LegacyBuggyVaultException {
        // v2.30.6: any v0x02 vault file is corrupt due to the
        // uint16 memory_KiB overflow bug. Delete it and start fresh
        // — equivalent to a clean install for vault contents (cert
        // bundle has to be re-downloaded via Faza 3 anyway).
        LoggerService.logWarning('MASTER_VAULT',
            'Detected corrupt v0x02 vault file — deleting and recreating');
        await file.delete();
        // Reset state from any partial decrypt attempt.
        _wipeKeys();
        _cache = null;
        _argon2Salt = null;
        await _createFreshVault(masterPassword);
        await _runMigrationFromLegacyStorage();
        await _persist();
        LoggerService.log('MASTER_VAULT',
            '✓ Fresh vault recreated after v0x02 corruption recovery '
            '(${_cache!.length} entries after migration)');
        return;
      }
      // Migration may still be needed if user upgraded from a build
      // that wrote the vault but didn't yet purge legacy storage.
      if (!_migrationDone) {
        await _runMigrationFromLegacyStorage();
        if (_migrationDone) await _persist();
      }
      LoggerService.log('MASTER_VAULT',
          '✓ Vault unlocked (${_cache!.length} entries)');
    } catch (ex, st) {
      // Wrong password is the only common failure mode here. Make
      // sure we DON'T leak the cache or keys on partial failure.
      _wipeKeys();
      _cache = null;
      _argon2Salt = null;
      LoggerService.logError('MASTER_VAULT', ex, st);
      rethrow;
    }
  }

  /// Unlock with a pre-derived masterKey (from PinUnlockService).
  /// Bypasses Argon2id — the masterKey IS the Argon2id output cached
  /// by the PIN service. Only usable when the vault file already exists.
  Future<void> unlockWithKey(Uint8List masterKey) async {
    if (!Platform.isMacOS) return;
    if (isUnlocked) return;
    LoggerService.log('MASTER_VAULT', 'Unlocking vault with cached key…');
    try {
      _initCryptoHandles();
      final path = await _path();
      final file = File(path);
      if (!await file.exists()) {
        throw StateError('unlockWithKey: vault file not found');
      }
      final blob = await file.readAsBytes();
      // Parse header to get argon2Salt, then derive KEK from masterKey
      // (same as _loadAndDecrypt but skipping Argon2id)
      await _loadAndDecryptWithKey(blob, masterKey);
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
    }
  }

  /// Lock the vault: zero all in-memory keys, drop the cache. After
  /// this, [read] returns null and [write] throws until [unlock] is
  /// called again. Implements B5 Part 1.
  void lock() {
    if (!Platform.isMacOS) return;
    if (!isUnlocked) return;
    _wipeKeys();
    _cache = null;
    _argon2Salt = null;
    _migrationDone = false;
    LoggerService.log('MASTER_VAULT',
        'Vault locked, in-memory keys zeroed');
  }

  Future<String?> read({required String key}) async {
    if (!Platform.isMacOS) {
      return PortableSecureStorage.instance.read(key: key);
    }
    if (!isUnlocked) {
      LoggerService.logWarning('MASTER_VAULT',
          'read($key) before unlock — returning null');
      return null;
    }
    return _cache![key];
  }

  Future<void> write({required String key, required String? value}) async {
    if (!Platform.isMacOS) {
      return PortableSecureStorage.instance.write(key: key, value: value);
    }
    if (!isUnlocked) {
      throw StateError('MasterVault.write before unlock');
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

  /// Re-encrypt the vault under a new master password. Generates a
  /// fresh argon2 salt, derives a new KEK, re-wraps the existing
  /// data_key. Vault content is NOT re-encrypted (data_key unchanged),
  /// so this is fast and atomic.
  ///
  /// Caller must ensure the OLD password was verified and the vault
  /// is currently unlocked.
  Future<void> changeMasterPassword(String newMasterPassword) async {
    if (!Platform.isMacOS) return;
    if (!isUnlocked) {
      throw StateError('changeMasterPassword called on locked vault');
    }
    LoggerService.log('MASTER_VAULT', 'Re-keying vault under new password…');
    // Generate a fresh argon2 salt — defends against rainbow tables
    // and ensures the new KEK is unrelated to the old one.
    _argon2Salt = _randomBytes(_argon2SaltBytes);
    _kek = await _deriveKEK(newMasterPassword, _argon2Salt!);
    await _persist();
    LoggerService.log('MASTER_VAULT',
        '✓ Vault re-encrypted under new password');
  }

  // ── Internals ────────────────────────────────────────────────────

  void _initCryptoHandles() {
    _argon2 ??= Argon2id(
      memory: _argon2MemoryKiB,
      iterations: _argon2Iterations,
      parallelism: _argon2Parallelism,
      hashLength: _hashLength,
    );
    _aes ??= AesGcm.with256bits();
    _hkdf ??= Hkdf(hmac: Hmac.sha256(), outputLength: _hashLength);
  }

  Future<String> _path() async {
    if (_filePath != null) return _filePath!;
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) await dir.create(recursive: true);
    _filePath = '${dir.path}/$_fileName';
    return _filePath!;
  }

  Future<String> _machineSecret() async {
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
          // Combine both identifiers — attacker must reproduce both.
          return '$uuid:$serial';
        }
      }
    } catch (_) {}
    // Fallback (weaker but still per-machine)
    try {
      final hostResult = await Process.run('hostname', []);
      final host = (hostResult.stdout as String).trim();
      final user = Platform.environment['USER'] ?? 'unknown';
      return 'fallback:$host:$user';
    } catch (_) {
      return 'fallback:unknown';
    }
  }

  // ── HKDF info labels for single-derivation fan-out ──────────────
  static const _hkdfInfoKek = 'icd360s.macos.v2.master-vault.kek';
  static const _hkdfInfoAuth = 'icd360s.v1.auth-hash';

  /// Derive the Argon2id master key from password + salt.
  ///
  /// This is the SINGLE expensive KDF call per unlock. All sub-keys
  /// (vault KEK, auth hash, session key) are derived from this via
  /// cheap HKDF-Expand with distinct info labels (Bitwarden pattern).
  ///
  /// Returns a mutable copy of the raw 32-byte master key.
  /// Also caches it in [_cachedMasterKey] for PIN setup.
  Future<Uint8List> deriveMasterKey(
    String masterPassword,
    Uint8List argonSalt,
  ) async {
    _initCryptoHandles();
    final masterKey = await _argon2!.deriveKey(
      secretKey: SecretKey(utf8.encode(masterPassword)),
      nonce: argonSalt,
    );
    final masterKeyBytesView = await masterKey.extractBytes();
    final bytes = Uint8List.fromList(masterKeyBytesView);
    // Cache for PIN setup (zeroed on lock)
    _cachedMasterKey = Uint8List.fromList(bytes);
    return bytes;
  }

  /// Return cached masterKey for PIN wrapping. Returns null if locked.
  Future<Uint8List?> deriveMasterKeyFromCache() async {
    if (_cachedMasterKey == null) return null;
    return Uint8List.fromList(_cachedMasterKey!);
  }

  /// Derive auth hash from master key via HKDF-Expand.
  ///
  /// This is a cheap operation (one HMAC round). The auth hash is
  /// stored on disk for local password verification. Because it uses
  /// a distinct HKDF info label, it cannot be reversed to obtain the
  /// vault KEK or the master key.
  Future<Uint8List> deriveAuthHash(Uint8List masterKeyBytes) async {
    _initCryptoHandles();
    final authKey = await _hkdf!.deriveKey(
      secretKey: SecretKey(masterKeyBytes),
      nonce: utf8.encode(_hkdfSalt),
      info: utf8.encode(_hkdfInfoAuth),
    );
    final authBytes = await authKey.extractBytes();
    return Uint8List.fromList(authBytes);
  }

  /// Derive vault_KEK = HKDF-SHA256(masterKey || IOPlatformUUID).
  /// Both inputs must be present — pwd alone won't work cross-machine,
  /// machine alone won't work without the user's password.
  Future<SecretKey> _deriveKEK(
    String masterPassword,
    Uint8List argonSalt,
  ) async {
    final masterKeyBytes = await deriveMasterKey(masterPassword, argonSalt);
    final machine = await _machineSecret();
    final ikmBytes =
        Uint8List.fromList(masterKeyBytes + utf8.encode(machine));
    final hkdfKey = SecretKey(ikmBytes);
    final kek = await _hkdf!.deriveKey(
      secretKey: hkdfKey,
      nonce: utf8.encode(_hkdfSalt),
      info: utf8.encode(_hkdfInfoKek),
    );
    // Best-effort zero of intermediate bytes (Dart doesn't expose
    // mlock; this just removes the values from our heap reference).
    try {
      for (var i = 0; i < masterKeyBytes.length; i++) {
        masterKeyBytes[i] = 0;
      }
      for (var i = 0; i < ikmBytes.length; i++) {
        ikmBytes[i] = 0;
      }
    } catch (ex) {
      LoggerService.logWarning('MASTER_VAULT',
          'Could not zero intermediate KEK bytes (best-effort): $ex');
    }
    return kek;
  }

  /// Derive KEK from a pre-computed masterKey (bypasses Argon2id).
  Future<SecretKey> _deriveKEKFromMasterKey(Uint8List masterKey) async {
    final machine = await _machineSecret();
    final ikmBytes = Uint8List.fromList(masterKey + utf8.encode(machine));
    final hkdfKey = SecretKey(ikmBytes);
    final kek = await _hkdf!.deriveKey(
      secretKey: hkdfKey,
      nonce: utf8.encode(_hkdfSalt),
      info: utf8.encode(_hkdfInfoKek),
    );
    try {
      for (var i = 0; i < ikmBytes.length; i++) ikmBytes[i] = 0;
    } catch (_) {}
    return kek;
  }

  /// Parse vault header and decrypt using a pre-derived masterKey.
  /// Same as [_loadAndDecrypt] but skips Argon2id.
  Future<void> _loadAndDecryptWithKey(
      Uint8List blob, Uint8List masterKey) async {
    final minLen = 1 + 4 + 1 + 1 + _argon2SaltBytes +
        _gcmNonceBytes + _dataKeyBytes + _gcmTagBytes +
        _gcmNonceBytes + _gcmTagBytes;
    if (blob.length < minLen) {
      throw StateError('secrets_vault.bin too short — corrupt');
    }
    if (blob[0] == _legacyBuggyFormatVersion) {
      throw const _LegacyBuggyVaultException();
    }
    if (blob[0] != _formatVersion) {
      throw StateError('Unknown vault format: 0x${blob[0].toRadixString(16)}');
    }
    var off = 1 + 4 + 1 + 1; // skip version + memKiB + iters + paral
    _argon2Salt = Uint8List.fromList(
        blob.sublist(off, off + _argon2SaltBytes));
    off += _argon2SaltBytes;
    final kekNonce = blob.sublist(off, off + _gcmNonceBytes);
    off += _gcmNonceBytes;
    final wrappedDataKey = blob.sublist(
        off, off + _dataKeyBytes + _gcmTagBytes);
    off += _dataKeyBytes + _gcmTagBytes;
    final vaultNonce = blob.sublist(off, off + _gcmNonceBytes);
    off += _gcmNonceBytes;
    final vaultCt = blob.sublist(off);

    _kek = await _deriveKEKFromMasterKey(masterKey);

    final wrappedCt = wrappedDataKey.sublist(0, _dataKeyBytes);
    final wrappedTag = wrappedDataKey.sublist(_dataKeyBytes);
    final dataKeyBox = SecretBox(
      wrappedCt,
      nonce: kekNonce,
      mac: Mac(wrappedTag),
    );
    final dataKeyBytes =
        await _aes!.decrypt(dataKeyBox, secretKey: _kek!);
    _dataKey = Uint8List.fromList(dataKeyBytes);

    final vaultTag = vaultCt.sublist(vaultCt.length - _gcmTagBytes);
    final vaultBody = vaultCt.sublist(0, vaultCt.length - _gcmTagBytes);
    final vaultBox = SecretBox(
      vaultBody,
      nonce: vaultNonce,
      mac: Mac(vaultTag),
    );
    final dataKey = SecretKey(_dataKey!);
    final plaintext = await _aes!.decrypt(vaultBox, secretKey: dataKey);
    final jsonStr = utf8.decode(plaintext);
    _cache = Map<String, String>.from(
        jsonDecode(jsonStr) as Map<String, dynamic>);
  }

  Future<void> _createFreshVault(String pwd) async {
    LoggerService.log('MASTER_VAULT', 'Creating fresh vault file');
    _cache = {};
    _dataKey = _randomBytes(_dataKeyBytes);
    _argon2Salt = _randomBytes(_argon2SaltBytes);
    _kek = await _deriveKEK(pwd, _argon2Salt!);
  }

  Future<void> _loadAndDecrypt(Uint8List blob, String masterPassword) async {
    // Header layout (v0x03):
    //   [0]       version (0x03)
    //   [1..4]    memory_KiB (uint32 LE)
    //   [5]       iters
    //   [6]       parallelism
    //   [7..22]   argon2_salt (16)
    //   [23..34]  kek_nonce (12)
    //   [35..82]  wrapped_data_key (32 + 16 tag)
    //   [83..94]  vault_nonce (12)
    //   [95..N]   vault_ct + 16 tag
    final minLen = 1 + 4 + 1 + 1 + _argon2SaltBytes +
        _gcmNonceBytes + _dataKeyBytes + _gcmTagBytes +
        _gcmNonceBytes + _gcmTagBytes;
    if (blob.length < minLen) {
      throw StateError(
          'secrets_vault.bin too short (${blob.length} bytes) — corrupt');
    }
    if (blob[0] == _legacyBuggyFormatVersion) {
      // v0x02 format had a fatal bug: memory_KiB stored in 2 bytes
      // overflowed for the standard 65536-KiB Argon2 cost and was
      // read back as 0, crashing on every unlock. Any v0x02 file is
      // corrupt by definition. Nuke it so the caller falls back to
      // _createFreshVault on the next unlock attempt.
      throw const _LegacyBuggyVaultException();
    }
    if (blob[0] != _formatVersion) {
      throw StateError(
          'Unknown vault format byte: 0x${blob[0].toRadixString(16)}');
    }
    var off = 1;
    final memKiB = blob[off] |
        (blob[off + 1] << 8) |
        (blob[off + 2] << 16) |
        (blob[off + 3] << 24);
    off += 4;
    final iters = blob[off++];
    final paral = blob[off++];

    // Re-init Argon2id with the parameters from the file (in case
    // we ever upgrade them and migrate transparently).
    _argon2 = Argon2id(
      memory: memKiB,
      iterations: iters,
      parallelism: paral,
      hashLength: _hashLength,
    );

    _argon2Salt = Uint8List.fromList(
        blob.sublist(off, off + _argon2SaltBytes));
    off += _argon2SaltBytes;
    final kekNonce = blob.sublist(off, off + _gcmNonceBytes);
    off += _gcmNonceBytes;
    final wrappedDataKey = blob.sublist(
        off, off + _dataKeyBytes + _gcmTagBytes);
    off += _dataKeyBytes + _gcmTagBytes;
    final vaultNonce = blob.sublist(off, off + _gcmNonceBytes);
    off += _gcmNonceBytes;
    final vaultCt = blob.sublist(off);

    // Derive KEK from password + on-disk salt
    _kek = await _deriveKEK(masterPassword, _argon2Salt!);

    // Unwrap data_key
    final wrappedCt = wrappedDataKey.sublist(0, _dataKeyBytes);
    final wrappedTag = wrappedDataKey.sublist(_dataKeyBytes);
    final dataKeyBox = SecretBox(
      wrappedCt,
      nonce: kekNonce,
      mac: Mac(wrappedTag),
    );
    final dataKeyBytes = await _aes!.decrypt(dataKeyBox, secretKey: _kek!);
    _dataKey = Uint8List.fromList(dataKeyBytes);

    // Decrypt vault
    final vaultCtBytes = vaultCt.sublist(0, vaultCt.length - _gcmTagBytes);
    final vaultTag = vaultCt.sublist(vaultCt.length - _gcmTagBytes);
    final vaultBox = SecretBox(
      vaultCtBytes,
      nonce: vaultNonce,
      mac: Mac(vaultTag),
    );
    final plaintext = await _aes!.decrypt(
      vaultBox,
      secretKey: SecretKey(_dataKey!),
    );
    final json = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
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
    _initCryptoHandles();

    final kekNonce = _randomBytes(_gcmNonceBytes);
    final vaultNonce = _randomBytes(_gcmNonceBytes);

    // Wrap data_key under KEK with fresh nonce
    final dataKeyBox = await _aes!.encrypt(
      _dataKey!,
      secretKey: _kek!,
      nonce: kekNonce,
    );
    final wrappedDataKey = Uint8List.fromList(
        dataKeyBox.cipherText + dataKeyBox.mac.bytes);

    // Encrypt vault payload
    final json = Map<String, dynamic>.from(_cache!);
    if (_migrationDone) json['__migration_v1_done'] = '1';
    final plaintext = utf8.encode(jsonEncode(json));
    final vaultBox = await _aes!.encrypt(
      plaintext,
      secretKey: SecretKey(_dataKey!),
      nonce: vaultNonce,
    );
    final vaultCt = Uint8List.fromList(
        vaultBox.cipherText + vaultBox.mac.bytes);

    final builder = BytesBuilder();
    builder.addByte(_formatVersion);
    // memory_KiB as uint32 LE (4 bytes). v0x02 stored 2 bytes which
    // overflowed for the standard 65536-KiB Argon2 memory parameter.
    builder.addByte(_argon2MemoryKiB & 0xFF);
    builder.addByte((_argon2MemoryKiB >> 8) & 0xFF);
    builder.addByte((_argon2MemoryKiB >> 16) & 0xFF);
    builder.addByte((_argon2MemoryKiB >> 24) & 0xFF);
    builder.addByte(_argon2Iterations);
    builder.addByte(_argon2Parallelism);
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
    try {
      await Process.run('chmod', ['600', path]);
    } catch (_) {}
  }

  /// Read legacy secrets from PortableSecureStorage (which used the
  /// IOPlatformUUID-only key) and copy them into this vault. Idempotent
  /// — sets `__migration_v1_done` flag in the vault so subsequent
  /// unlocks skip the migration. Best-effort — failures don't abort.
  Future<void> _runMigrationFromLegacyStorage() async {
    if (_migrationDone) return;
    LoggerService.log('MASTER_VAULT',
        'Running migration of legacy secrets from PortableSecureStorage');
    final legacy = PortableSecureStorage.instance;

    // Known "secret" keys that were previously stored in
    // PortableSecureStorage and which now belong in MasterVault.
    // Anything not in this list stays in PortableSecureStorage
    // (rate-limit state, device_id, etc.).
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

  void _wipeKeys() {
    if (_cachedMasterKey != null) {
      for (var i = 0; i < _cachedMasterKey!.length; i++) {
        _cachedMasterKey![i] = 0;
      }
      _cachedMasterKey = null;
    }
    if (_dataKey != null) {
      for (var i = 0; i < _dataKey!.length; i++) {
        _dataKey![i] = 0;
      }
      _dataKey = null;
    }
    // SecretKey from cryptography package doesn't expose its bytes
    // for in-place zero, so we just drop the reference.
    _kek = null;
  }

  Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }
}

/// Internal sentinel: thrown by [MasterVault._loadAndDecrypt] when it
/// encounters a v0x02 vault file. Caught by [MasterVault.unlock] which
/// then deletes the file and recreates fresh. Not exported.
class _LegacyBuggyVaultException implements Exception {
  const _LegacyBuggyVaultException();
  @override
  String toString() =>
      'Vault file uses the buggy v0x02 format (uint16 memory_KiB overflow)';
}
