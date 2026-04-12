import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';

import 'aes_gcm_helpers.dart';
import 'logger_service.dart';

/// Cross-platform secure key/value storage that works on ad-hoc signed
/// macOS builds (no Apple Developer Program required).
///
/// Backend selection:
/// - **macOS**: AES-256-GCM encrypted file under `~/Library/Application
///   Support/<bundle>/secure_store.bin`. The encryption key is derived
///   via PBKDF2-HMAC-SHA256 (100k iters) from the Mac's Hardware UUID
///   (IOPlatformUUID), which is stable across reboots and unique per
///   machine. **Zero Keychain API calls.**
/// - **iOS / Android / Windows / Linux**: native `flutter_secure_storage`
///   (Keychain / Keystore / DPAPI / libsecret).
///
/// Why bypass Keychain on macOS:
///
/// flutter_secure_storage_darwin always invokes SecItemAdd / SecItemCopyMatching
/// with `kSecAttrAccessible` and friends. On macOS 14+/15+/26 with an
/// ad-hoc signed binary (no `application-identifier` entitlement), these
/// calls return `errSecMissingEntitlement (-34018)` regardless of the
/// `usesDataProtectionKeychain` flag — verified empirically and confirmed
/// by reading the plugin's Swift source. There is no flutter_secure_storage
/// configuration that works on ad-hoc signed macOS builds.
///
/// Threat model on macOS:
/// - Same-user malware can read the file AND query the Hardware UUID,
///   so it can decrypt. This matches what `kSecAttrAccessibleWhenUnlocked`
///   would protect against — i.e., this is not a regression vs Keychain.
/// - Cross-machine theft (cloned disk) defeats the key derivation
///   automatically: the Hardware UUID differs, decryption fails, the
///   user is silently logged out. This is a feature, not a bug.
/// - Stolen-laptop offline attack: an attacker with physical access
///   and the disk image can re-derive the key. To defeat that, the user
///   would need to enter a master password, which they already do via
///   MasterPasswordService for the AES-GCM session key in account_service.
///
/// API-compatible with the subset of FlutterSecureStorage we use.
class PortableSecureStorage {
  PortableSecureStorage._();
  static final PortableSecureStorage instance = PortableSecureStorage._();

  static const _fileName = 'secure_store.bin';
  // PBKDF2 salt: change this constant to invalidate all stored blobs
  // (e.g. forced re-login on a future security upgrade).
  static const _pbkdf2Salt = 'icd360s.mail.v1.macos.portable-storage';
  static const _pbkdf2Iterations = 100000;
  static const _pbkdf2KeyBytes = 32;

  // Native backend for non-macOS platforms.
  final FlutterSecureStorage _native = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
    lOptions: LinuxOptions(),
    wOptions: WindowsOptions(),
  );

  // macOS-only state.
  Map<String, String>? _cache;
  Uint8List? _key;
  String? _filePath;

  bool get _useFile => Platform.isMacOS;

  // ── Public API (subset compatible with FlutterSecureStorage) ──

  Future<String?> read({required String key}) async {
    if (_useFile) {
      await _ensureLoaded();
      return _cache![key];
    }
    return _native.read(key: key);
  }

  Future<void> write({required String key, required String? value}) async {
    if (_useFile) {
      await _ensureLoaded();
      if (value == null) {
        _cache!.remove(key);
      } else {
        _cache![key] = value;
      }
      await _persist();
      return;
    }
    await _native.write(key: key, value: value);
  }

  Future<void> delete({required String key}) => write(key: key, value: null);

  Future<bool> containsKey({required String key}) async =>
      (await read(key: key)) != null;

  Future<Map<String, String>> readAll() async {
    if (_useFile) {
      await _ensureLoaded();
      return Map<String, String>.unmodifiable(_cache!);
    }
    return _native.readAll();
  }

  Future<void> deleteAll() async {
    if (_useFile) {
      _cache = {};
      await _persist();
      return;
    }
    await _native.deleteAll();
  }

  /// Best-effort zero the cached AES key from memory.
  /// Call on app lock / master password lock to narrow the window
  /// during which the key is resident in the heap.
  void wipeKeyFromMemory() {
    final k = _key;
    if (k != null) {
      for (var i = 0; i < k.length; i++) {
        k[i] = 0;
      }
    }
    _key = null;
    _cache = null;
  }

  // ── macOS file backend ─────────────────────────────────────

  Future<String> _path() async {
    if (_filePath != null) return _filePath!;
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    _filePath = '${dir.path}/$_fileName';
    return _filePath!;
  }

  /// Read the macOS Hardware UUID + Serial Number via `ioreg`. Combines
  /// both identifiers so an attacker must reproduce both (harder in VMs).
  /// Stable across reboots, unique per machine, requires no entitlements.
  Future<String> _machineSecret() async {
    try {
      final result = await Process.run(
        '/usr/sbin/ioreg',
        ['-rd1', '-c', 'IOPlatformExpertDevice'],
      );
      if (result.exitCode == 0) {
        final out = result.stdout as String;
        final uuidMatch = RegExp(
          r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]+)"',
        ).firstMatch(out);
        if (uuidMatch != null) {
          final uuid = uuidMatch.group(1)!;
          final serial = _extractSerial(out);
          // Combine both identifiers — an attacker must know both.
          return '$uuid:$serial';
        }
      }
    } catch (_) {/* fall through */}

    // Fallback: hostname + user — weaker but still per-machine.
    try {
      final hostResult = await Process.run('hostname', []);
      final host = (hostResult.stdout as String).trim();
      final user = Platform.environment['USER'] ?? 'unknown';
      return 'fallback:$host:$user';
    } catch (_) {
      return 'fallback:unknown';
    }
  }

  /// Extract IOPlatformSerialNumber from ioreg output, empty if absent.
  static String _extractSerial(String ioregOutput) {
    final match = RegExp(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"')
        .firstMatch(ioregOutput);
    return match?.group(1) ?? '';
  }

  Future<Uint8List> _deriveKey() async {
    if (_key != null) return _key!;
    final secret = await _machineSecret();
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(
        Uint8List.fromList(utf8.encode(_pbkdf2Salt)),
        _pbkdf2Iterations,
        _pbkdf2KeyBytes,
      ));
    _key = pbkdf2.process(Uint8List.fromList(utf8.encode(secret)));
    return _key!;
  }

  Future<void> _ensureLoaded() async {
    if (_cache != null) return;
    final path = await _path();
    final file = File(path);
    if (!await file.exists()) {
      _cache = {};
      return;
    }
    try {
      final blob = await file.readAsBytes();
      final key = await _deriveKey();
      final plaintext =
          AesGcmHelpers.decrypt(key, blob, expectedVersionByte: 0x01);
      if (plaintext == null) {
        LoggerService.logWarning('PORTABLE_STORAGE',
            'Decrypt failed (machine UUID changed or blob corrupted); '
            'starting empty');
        _cache = {};
        try {
          await file.delete();
        } catch (_) {}
        return;
      }
      final decoded = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
      _cache = decoded.map((k, v) => MapEntry(k, v.toString()));
    } catch (ex) {
      LoggerService.logWarning('PORTABLE_STORAGE',
          'Failed to load secure store ($ex); starting empty');
      _cache = {};
    }
  }

  Future<void> _persist() async {
    try {
      final key = await _deriveKey();
      final plaintext =
          Uint8List.fromList(utf8.encode(jsonEncode(_cache)));
      final blob = AesGcmHelpers.encrypt(key, plaintext, versionByte: 0x01);
      final path = await _path();
      // Atomic write via temp + rename
      final tmp = File('$path.tmp');
      await tmp.writeAsBytes(blob, flush: true);
      await tmp.rename(path);
      // Tighten perms (user-only read/write)
      try {
        await Process.run('chmod', ['600', path]);
      } catch (_) {}
    } catch (ex, st) {
      LoggerService.logError('PORTABLE_STORAGE',
          'Failed to persist secure store: $ex', st);
      rethrow;
    }
  }
}
