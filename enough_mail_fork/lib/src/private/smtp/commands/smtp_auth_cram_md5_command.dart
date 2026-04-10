import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../../smtp/smtp_response.dart';
import '../smtp_command.dart';

/// CRAM-MD5 SASL Authentication mechanism.
///
/// **DEPRECATED** — CRAM-MD5 is obsolete (RFC 6331-era).
///
/// Reasons to avoid:
/// - Uses HMAC-MD5; MD5 is disallowed by NIST SP 800-131A for any new
///   cryptographic use, and HMAC-MD5 is deprecated by RFC 6151 (2011).
/// - Forces the SERVER to store password-equivalent material (either
///   plaintext or HMAC-MD5 intermediate) — passdb compromise = full
///   credential compromise of every user, instantly, no cracking needed.
/// - No salt, no key stretching → captured (nonce, hash) pairs are
///   trivially brute-forced offline (~10 billion HMAC-MD5/sec on a
///   modern GPU).
/// - No mutual authentication, no channel binding.
/// - RFC 6331 §1: "The Salted Challenge Response Authentication
///   Mechanism (SCRAM) family of SASL mechanisms [RFC5802] has been
///   developed to provide similar features as DIGEST-MD5 but with a
///   better design."
///
/// **Migration path**: SCRAM-SHA-256 (RFC 7677) for self-hosted servers,
/// or PLAIN/LOGIN over TLS-with-pinning for legacy compatibility.
/// XOAUTH2 for Gmail / Microsoft 365 (which have removed all
/// password-based mechanisms).
///
/// This implementation is retained for backwards compatibility with
/// servers that still advertise CRAM-MD5, but should NEVER be selected
/// as the preferred mechanism when alternatives exist. A runtime
/// warning is logged on first use.
///
/// References: RFC 2195 (CRAM-MD5, 1997), RFC 4954 (SMTP AUTH),
/// RFC 6151 (deprecate HMAC-MD5), RFC 6331 (deprecate DIGEST-MD5),
/// RFC 7677 (SCRAM-SHA-256 replacement).
@Deprecated(
    'CRAM-MD5 is obsolete (RFC 6331-era). Forces password-equivalent '
    'storage on the server and uses deprecated HMAC-MD5. Use '
    'SCRAM-SHA-256 (RFC 7677) for self-hosted servers, or PLAIN over '
    'TLS for legacy compatibility. Will be removed in a future major '
    'version.')
class SmtpAuthCramMd5Command extends SmtpCommand {
  /// Creates a new AUTH CRAM-MD5 command
  SmtpAuthCramMd5Command(this._userName, this._password)
      : super('AUTH CRAM-MD5') {
    // One-shot deprecation warning at first use of the mechanism.
    if (!_warnedOnce) {
      _warnedOnce = true;
      // ignore: avoid_print
      print('WARNING: AUTH CRAM-MD5 is deprecated (RFC 6331). '
          'Use SCRAM-SHA-256 or PLAIN over TLS instead. '
          'CRAM-MD5 forces password-equivalent storage on the server.');
    }
  }

  final String _userName;
  final String _password;
  bool _authSent = false;
  static bool _warnedOnce = false;

  @override
  String get command => 'AUTH CRAM-MD5';

  @override
  String? nextCommand(SmtpResponse response) {
    /* Example flow:
C: AUTH CRAM-MD5
S: 334 BASE64(NONCE)
C: BASE64(USERNAME, " ", MD5((SECRET XOR opad),MD5((SECRET XOR ipad), NONCE)))
S: 235 Authentication succeeded
    */
    if (response.code != 334 && response.code != 235) {
      print('Warning: Unexpected status code during AUTH CRAM-MD5: '
          '${response.code}. Expected: 334 or 235. \nauthSent=$_authSent');
    }
    if (!_authSent) {
      _authSent = true;
      final base64Nonce = response.message ?? '';

      return getBase64EncodedData(base64Nonce);
    } else {
      return null;
    }
  }

  /// Converts the password using the [base64Nonce] to base64
  String getBase64EncodedData(String base64Nonce) {
    // BASE64(USERNAME, " ",
    //        MD5((SECRET XOR opad),MD5((SECRET XOR ipad), NONCE)))
    var password = utf8.encode(_password);
    if (password.length > 64) {
      final passwordDigest = md5.convert(password);
      password = Uint8List.fromList(passwordDigest.bytes);
    }
    final nonce = base64.decode(base64Nonce);
    final hmac = Hmac(md5, password);
    final hmacNonce = hmac.convert(nonce);
    final input = '$_userName $hmacNonce';
    final complete = utf8.encode(input);
    final authBase64Text = base64.encode(complete);

    return authBase64Text;
  }

  @override
  bool isCommandDone(SmtpResponse response) => _authSent;

  @override
  String toString() => 'AUTH CRAM-MD5 <base64 scrambled>';
}
