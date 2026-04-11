import '../../../smtp/smtp_response.dart';
import '../smtp_command.dart';

/// Signs in the SMTP user via AUTH EXTERNAL (RFC 4422 §6 SASL EXTERNAL).
///
/// The user identity is taken from the client certificate that mTLS
/// already presented to the server during the TLS handshake — there is
/// no password on the wire and the username is not transmitted by the
/// client at all. This is the SMTP analogue of the IMAP
/// `AUTHENTICATE EXTERNAL` flow added in v2.26.0.
///
/// Wire conversation:
///
///   C: AUTH EXTERNAL
///   S: 334
///   C: <empty line>
///   S: 235 2.7.0 Authentication successful
///
/// The continuation response is an EMPTY LINE (just CRLF), which
/// represents the empty SASL response (no authzid → server uses the
/// cert subject CN as the identity). Sending the literal `=` here
/// would cause Dovecot submission to reply BAD because `=` is the
/// inline-IR marker, not a valid base64 continuation. We learned this
/// the hard way with the IMAP equivalent in v2.28.0 — see the
/// `authenticateWithExternal()` doc in imap_client.dart.
///
/// Requires:
///   - The TLS connection presented a client cert that the server
///     validated against its trusted CA.
///   - The server advertises `AUTH EXTERNAL` in its EHLO response
///     (Dovecot submission with `auth_mechanisms = external`
///     enabled — Faza A3.2.5).
class SmtpAuthExternalCommand extends SmtpCommand {
  /// Creates a new AUTH EXTERNAL command. No credentials needed —
  /// the cert is the credential.
  SmtpAuthExternalCommand() : super('AUTH EXTERNAL');

  bool _continuationSent = false;

  @override
  String get command => 'AUTH EXTERNAL';

  @override
  String? nextCommand(SmtpResponse response) {
    if (response.code != 334 && response.code != 235) {
      // Server rejected — let isCommandDone() finish the command so
      // the caller sees the error response.
      return null;
    }
    if (!_continuationSent) {
      _continuationSent = true;
      // Empty SASL response (cert provides identity, no payload).
      return '';
    }
    return null;
  }

  @override
  bool isCommandDone(SmtpResponse response) =>
      response.code == 235 || response.code >= 400;

  @override
  String toString() => 'AUTH EXTERNAL (cert-based, no password)';
}
