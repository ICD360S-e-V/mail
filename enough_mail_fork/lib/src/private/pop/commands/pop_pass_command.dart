import '../pop_command.dart';

/// Signs in the user using a PASS command.
///
/// SECURITY: POP3 has no quoting/escape mechanism (RFC 1939 §3). Any
/// CR/LF/NUL in the password would inject arbitrary POP3 commands
/// (CWE-93). We reject all C0 controls and DEL. SPACE is allowed
/// because RFC 1939 explicitly says: "Since the PASS command has
/// exactly one argument, a POP3 server may treat spaces in the
/// argument as part of the password".
class PopPassCommand extends PopCommand<String> {
  /// Creates a new `PASS` command
  PopPassCommand(String pass) : super('PASS ${_validatePassword(pass)}');

  static String _validatePassword(String password) {
    if (password.isEmpty) {
      throw ArgumentError('POP3 password must not be empty');
    }
    if (password.length > 240) {
      throw ArgumentError(
          'POP3 password too long (${password.length} > 240, RFC 2449)');
    }
    for (var i = 0; i < password.length; i++) {
      final c = password.codeUnitAt(i);
      if (c < 0x20 || c == 0x7F) {
        throw ArgumentError(
            'POP3 password contains forbidden control byte 0x'
            '${c.toRadixString(16).padLeft(2, '0')} at offset $i');
      }
    }
    return password;
  }

  @override
  String toString() => 'PASS <password scrambled>';
}
