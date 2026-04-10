import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../pop_command.dart';

/// The `APOP` command signs in the user.
///
/// SECURITY: The password is hashed (MD5 of timestamp+password) so it
/// cannot directly inject commands via the digest. But [user] is
/// interpolated raw — same CRLF-injection risk as USER. We validate
/// both name and password (the latter for fail-fast against future
/// USER/PASS fallback paths and to surface garbage credentials early).
class PopApopCommand extends PopCommand<String> {
  /// Creates a new `APOP` command
  PopApopCommand(String user, String pass, String serverTimestamp)
      : user = _validateName(user),
        super('APOP ${_validateName(user)} '
            '${toMd5(serverTimestamp + _validatePassword(pass))}');

  /// The user ID
  final String user;

  /// Generates the MD5 hash from the [input]
  static String toMd5(String input) {
    final inputBytes = utf8.encode(input);
    final digest = md5.convert(inputBytes);

    return digest.toString();
  }

  static String _validateName(String name) {
    if (name.isEmpty) {
      throw ArgumentError('APOP name must not be empty');
    }
    if (name.length > 200) {
      throw ArgumentError('APOP name too long (${name.length} > 200)');
    }
    for (var i = 0; i < name.length; i++) {
      final c = name.codeUnitAt(i);
      if (c < 0x20 || c == 0x7F) {
        throw ArgumentError(
            'APOP name contains forbidden control byte 0x'
            '${c.toRadixString(16).padLeft(2, '0')} at offset $i');
      }
      if (c == 0x20) {
        throw ArgumentError(
            'APOP name contains forbidden SPACE at offset $i');
      }
    }
    return name;
  }

  static String _validatePassword(String password) {
    if (password.isEmpty) {
      throw ArgumentError('APOP password must not be empty');
    }
    for (var i = 0; i < password.length; i++) {
      final c = password.codeUnitAt(i);
      if (c < 0x20 || c == 0x7F) {
        throw ArgumentError(
            'APOP password contains forbidden control byte 0x'
            '${c.toRadixString(16).padLeft(2, '0')} at offset $i');
      }
    }
    return password;
  }

  @override
  String toString() => 'APOP $user <MD5 scrambled>';
}
