// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';

/// Authenticated-encryption helpers shared across services that need to
/// store small blobs of state on disk with both confidentiality AND
/// integrity in a single primitive.
///
/// Format of an encrypted blob (returned by [aesGcmEncrypt]):
///
///   `<version byte> | <12-byte IV> | <ciphertext + 16-byte GCM tag>`
///
/// The version byte is the caller's responsibility — it lets two
/// independent stores (e.g. credential fallback file vs rate-limit
/// state file) use different first bytes so a stray file cannot be
/// confused with another one. AES-GCM itself guarantees that any
/// tampering with the IV, ciphertext or tag is detected at decrypt
/// time and surfaced as a `null` return.
class AesGcmHelpers {
  /// Encrypt [plaintext] under [key] (32 bytes / AES-256), prepend
  /// [versionByte] and a freshly-generated 12-byte random IV. Returns
  /// `versionByte || iv || ciphertext+tag`.
  static Uint8List encrypt(
    Uint8List key,
    Uint8List plaintext, {
    int versionByte = 0x01,
  }) {
    final iv = _randomBytes(12);
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
    final ct = cipher.process(plaintext);
    final out = Uint8List(1 + iv.length + ct.length);
    out[0] = versionByte;
    out.setRange(1, 1 + iv.length, iv);
    out.setRange(1 + iv.length, out.length, ct);
    return out;
  }

  /// Decrypt a blob produced by [encrypt]. Returns `null` on any
  /// failure (wrong key, truncated data, modified ciphertext, wrong
  /// version byte, etc.) — every failure mode is observationally
  /// indistinguishable so a tampered blob is never silently accepted.
  static Uint8List? decrypt(
    Uint8List key,
    Uint8List blob, {
    int expectedVersionByte = 0x01,
  }) {
    if (blob.isEmpty || blob[0] != expectedVersionByte) return null;
    if (blob.length < 1 + 12 + 16) return null;
    try {
      final iv = Uint8List.fromList(blob.sublist(1, 13));
      final ct = Uint8List.fromList(blob.sublist(13));
      final cipher = GCMBlockCipher(AESEngine())
        ..init(false, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
      return cipher.process(ct);
    } catch (_) {
      return null;
    }
  }

  /// Raw AES-256-GCM encrypt with explicit key + IV (no version prefix).
  /// Returns ciphertext + 16-byte GCM tag. Compatible with WebCrypto API
  /// SubtleCrypto.decrypt({name:'AES-GCM', iv}, key, ct).
  static Uint8List encryptRaw(Uint8List key, Uint8List iv, Uint8List plaintext) {
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
    return cipher.process(plaintext);
  }

  static Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }
}