import 'dart:convert';

import '../../../smtp/smtp_response.dart';
import '../smtp_command.dart';

/// Signs in the SMTP user via AUTH LOGIN (base64 username + password).
///
/// Credentials are UTF-8 encoded before base64 per RFC 4954 §4 (SMTP
/// AUTH) → SASL (RFC 4422) → UTF-8 requirement. The previous
/// implementation used `.codeUnits` which produces Latin-1 for
/// U+0080–U+00FF, silently breaking authentication for any user with
/// non-ASCII characters in their username or password.
class SmtpAuthLoginCommand extends SmtpCommand {
  /// Creates a new AUTH LOGIN command
  SmtpAuthLoginCommand(this._userName, this._password) : super('AUTH LOGIN');

  final String _userName;
  final String _password;
  bool _userNameSent = false;
  bool _userPasswordSent = false;

  @override
  String get command => 'AUTH LOGIN';

  @override
  String? nextCommand(SmtpResponse response) {
    if (response.code != 334 && response.code != 235) {
      print(
        'Warning: Unexpected status code during AUTH LOGIN: ${response.code}. '
        'Expected: 334 or 235. \nuserNameSent=$_userNameSent, '
        'userPasswordSent=$_userPasswordSent',
      );
    }
    if (!_userNameSent) {
      _userNameSent = true;
      return base64.encode(utf8.encode(_userName));
    } else if (!_userPasswordSent) {
      _userPasswordSent = true;
      return base64.encode(utf8.encode(_password));
    } else {
      return null;
    }
  }

  @override
  bool isCommandDone(SmtpResponse response) => _userPasswordSent;

  @override
  String toString() => 'AUTH LOGIN <password scrambled>';
}
