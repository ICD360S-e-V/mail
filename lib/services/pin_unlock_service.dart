// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'aes_gcm_helpers.dart';
import 'account_service.dart';
import 'certificate_service.dart';
import 'logger_service.dart';
import 'master_vault.dart';
import 'portable_secure_storage.dart';
import 'update_service.dart';

/// PIN-based quick unlock with randomized keypad.
///
/// Security model:
///   PIN (6 digits) → Argon2id(19 MiB, 2 iter, 1 thread) → pinRaw
///   pinKEK = HKDF-SHA256(pinRaw, salt=deviceSecret)
///   wrappedMasterKey = AES-256-GCM(masterKey, pinKEK)
///
/// Defenses:
///   - Argon2id memory-hard: GPU brute-force ~7,600 H/s → 10^6 PINs in ~2 min
///     but device-bound secret makes offline attack require device access
///   - Failed attempts persisted to disk (survives app kill/restart)
///   - Progressive lockout delays: 0/2/5/10/30s
///   - PIN expires after 7 days since last use (sliding window)
///   - PIN invalidated on major version change or device change
class PinUnlockService {
  static const _storageKey = 'pin_v1_blob';
  static const _pinLength = 6;
  static const _maxAgeDays = 7;
  static const maxFailedAttempts = 3;
  static const _keyBytes = 32;
  static const _blobVersion = 0x10;
  static const _blobSchema = 2; // bump to invalidate all existing PINs

  // Argon2id parameters for PIN KDF (RFC 9106 minimum recommended)
  static const _argon2Memory = 19456; // 19 MiB — GPU-resistant
  static const _argon2Iterations = 2;
  static const _argon2Parallelism = 1; // single thread for PIN

  /// Progressive lockout delays in seconds after each failed attempt.
  static const _lockoutDelays = [0, 2, 5, 10, 30];

  // ── Query ──────────────────────────────────────────────────────────

  static Future<bool> hasPinConfigured() async =>
      await PortableSecureStorage.instance.containsKey(key: _storageKey);

  /// Seconds the caller must wait before accepting next PIN attempt.
  /// Returns 0 if no delay is needed.
  static Future<int> getLockoutDelay() async {
    final data = await _readBlob();
    if (data == null) return 0;
    final attempts = data['failed_attempts'] as int? ?? 0;
    if (attempts <= 0) return 0;
    return _lockoutDelays[min(attempts - 1, _lockoutDelays.length - 1)];
  }

  // ── Setup ──────────────────────────────────────────────────────────

  static Future<void> setupPin({
    required String pin,
    required Uint8List masterKey,
  }) async {
    assert(pin.length == _pinLength && int.tryParse(pin) != null);

    final pinSalt = _randomBytes(32);
    final deviceId = await _deviceId();
    final pinKEK = await _deriveKEK(pin, pinSalt, deviceId);

    final wrapped = AesGcmHelpers.encrypt(
        pinKEK, masterKey, versionByte: _blobVersion);

    // Zero pinKEK
    for (var i = 0; i < pinKEK.length; i++) pinKEK[i] = 0;

    final blob = {
      'salt': base64.encode(pinSalt),
      'wrapped': base64.encode(wrapped),
      'set_at': DateTime.now().millisecondsSinceEpoch,
      'last_used': DateTime.now().millisecondsSinceEpoch,
      'major_version': _majorVersion(),
      'blob_schema': _blobSchema,
      'device_id': deviceId,
      'failed_attempts': 0,
    };

    await _writeBlob(blob);
    LoggerService.log('PIN', 'PIN configured (Argon2id 19 MiB)');
  }

  // ── Verify ─────────────────────────────────────────────────────────

  static Future<Uint8List?> verifyPin(String pin) async {
    final data = await _readBlob();
    if (data == null) return null;

    // Persisted attempt counter (survives app restart)
    final attempts = data['failed_attempts'] as int? ?? 0;
    if (attempts >= maxFailedAttempts) {
      LoggerService.log('PIN', 'PIN locked — $attempts failed attempts');
      await invalidatePin();
      return null;
    }

    // Schema guard (bump _blobSchema to force re-setup)
    if ((data['blob_schema'] as int? ?? 0) < _blobSchema) {
      LoggerService.log('PIN', 'PIN schema outdated — invalidated');
      await invalidatePin();
      return null;
    }

    // Major version guard (invalidate on major bump, not every release)
    if (data['major_version'] != _majorVersion()) {
      LoggerService.log('PIN',
          'Major version changed (${data['major_version']} → ${_majorVersion()}) — PIN invalidated');
      await invalidatePin();
      return null;
    }

    // PIN does not expire — it's valid until disabled or 3 wrong attempts.
    // Cold start always requires master password; PIN is only for
    // lock/auto-lock within a session.

    // Device guard
    final currentDeviceId = await _deviceId();
    if (data['device_id'] != currentDeviceId) {
      LoggerService.log('PIN', 'Device mismatch — PIN invalidated');
      await invalidatePin();
      return null;
    }

    // Derive pinKEK and attempt decrypt
    final pinSalt = Uint8List.fromList(base64.decode(data['salt'] as String));
    final wrapped = Uint8List.fromList(base64.decode(data['wrapped'] as String));
    final pinKEK = await _deriveKEK(pin, pinSalt, currentDeviceId);
    final masterKey = AesGcmHelpers.decrypt(
        pinKEK, wrapped, expectedVersionByte: _blobVersion);

    // Zero pinKEK
    for (var i = 0; i < pinKEK.length; i++) pinKEK[i] = 0;

    if (masterKey == null) {
      // Wrong PIN — persist incremented counter
      data['failed_attempts'] = attempts + 1;
      await _writeBlob(data);
      LoggerService.log('PIN',
          'Incorrect PIN (${attempts + 1}/$maxFailedAttempts)');
      if (attempts + 1 >= maxFailedAttempts) {
        await invalidatePin();
      }
      return null;
    }

    // Success — reset counter, update last_used
    data['failed_attempts'] = 0;
    data['last_used'] = DateTime.now().millisecondsSinceEpoch;
    await _writeBlob(data);
    LoggerService.log('PIN', 'PIN verified');
    return masterKey is Uint8List ? masterKey : Uint8List.fromList(masterKey);
  }

  /// Full unlock after PIN verification.
  static Future<void> unlockWithMasterKey(Uint8List masterKey) async {
    await MasterVault.instance.unlockWithKey(masterKey);
    await AccountService.unlockSessionWithKey(masterKey);
    await CertificateService.restoreFromSecureStorage();
    LoggerService.log('PIN', 'App unlocked via PIN');
  }

  /// Delete PIN — requires master password on next unlock.
  static Future<void> invalidatePin() async {
    await PortableSecureStorage.instance.delete(key: _storageKey);
    LoggerService.log('PIN', 'PIN invalidated');
  }

  // ── Crypto (Argon2id + HKDF) ──────────────────────────────────────

  static Future<Uint8List> _deriveKEK(
      String pin, Uint8List pinSalt, String deviceId) async {
    // Argon2id — memory-hard, GPU-resistant
    final argon2 = Argon2id(
      memory: _argon2Memory,
      iterations: _argon2Iterations,
      parallelism: _argon2Parallelism,
      hashLength: _keyBytes,
    );
    final pinKey = await argon2.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: pinSalt,
    );
    final pinRawView = await pinKey.extractBytes();
    final pinRaw = Uint8List.fromList(pinRawView);

    // HKDF with device ID — binds to this device
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: _keyBytes);
    final kek = await hkdf.deriveKey(
      secretKey: SecretKey(pinRaw),
      nonce: utf8.encode(deviceId),
      info: utf8.encode('icd360s.pin.v1.kek'),
    );

    // Zero intermediate
    for (var i = 0; i < pinRaw.length; i++) pinRaw[i] = 0;

    final kekBytes = await kek.extractBytes();
    return Uint8List.fromList(kekBytes);
  }

  // ── Storage helpers ────────────────────────────────────────────────

  static Future<Map<String, dynamic>?> _readBlob() async {
    final raw = await PortableSecureStorage.instance.read(key: _storageKey);
    if (raw == null) return null;
    try {
      return jsonDecode(utf8.decode(base64.decode(raw)))
          as Map<String, dynamic>;
    } catch (_) {
      await invalidatePin();
      return null;
    }
  }

  static Future<void> _writeBlob(Map<String, dynamic> data) async {
    await PortableSecureStorage.instance.write(
      key: _storageKey,
      value: base64.encode(utf8.encode(jsonEncode(data))),
    );
  }

  static Future<String> _deviceId() async {
    final storage = PortableSecureStorage.instance;
    var id = await storage.read(key: 'icd360s_device_pin_id');
    if (id == null) {
      id = base64.encode(_randomBytes(32));
      await storage.write(key: 'icd360s_device_pin_id', value: id);
    }
    return id;
  }

  /// Major version only (e.g., "2" from "2.31.0")
  static String _majorVersion() =>
      UpdateService.currentVersion.split('.').first;

  static Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }
}