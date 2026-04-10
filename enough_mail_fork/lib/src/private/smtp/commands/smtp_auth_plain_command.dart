import 'dart:convert';

import '../smtp_command.dart';

/// Authenticates the SMTP user via AUTH PLAIN (RFC 4616).
///
/// Format: base64(\0authcid\0passwd) — with empty authzid.
///
/// RFC 4616 §2: "The character encoding of all strings is UTF-8."
/// Empty authzid means the server derives the authorization identity
/// from the authentication identity (authcid), which is the standard
/// behavior for virtually all SMTP servers.
///
/// The previous implementation had two issues:
/// 1. Used `.codeUnits` (Latin-1/UTF-16) instead of `utf8.encode()`
///    — broke auth for non-ASCII usernames/passwords.
/// 2. Sent `authcid\0authcid\0passwd` (authzid = authcid) instead
///    of `\0authcid\0passwd` (empty authzid) — non-standard.
class SmtpAuthPlainCommand extends SmtpCommand {
  /// Creates a new AUTH PLAIN command
  SmtpAuthPlainCommand(this.userName, this.password) : super('AUTH PLAIN');

  /// The user name (authcid)
  final String userName;

  /// The password
  final String password;

  @override
  String get command {
    // RFC 4616: message = [authzid] \0 authcid \0 passwd
    // Empty authzid (most compatible, recommended by RFC):
    final plainMessage = '\u{0000}$userName\u{0000}$password';
    return 'AUTH PLAIN ${base64.encode(utf8.encode(plainMessage))}';
  }

  @override
  String toString() => 'AUTH PLAIN <password scrambled>';
}
