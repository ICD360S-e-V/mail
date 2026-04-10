import '../pop_command.dart';

/// Authenticates the user.
///
/// SECURITY: POP3 has no quoting/escape mechanism (RFC 1939 §3) — every
/// byte until CRLF is part of the current command. Any CR/LF/NUL/control
/// in the username would inject arbitrary POP3 commands under the
/// authenticated session (CWE-93). We reject all C0 controls, DEL, and
/// SPACE (which RFC 1939 uses as argument separator).
class PopUserCommand extends PopCommand<String> {
  /// Creates a new `USER` command
  PopUserCommand(String user) : super('USER ${_validateUsername(user)}');

  static String _validateUsername(String name) {
    if (name.isEmpty) {
      throw ArgumentError('POP3 username must not be empty');
    }
    if (name.length > 240) {
      throw ArgumentError(
          'POP3 username too long (${name.length} > 240, RFC 2449)');
    }
    for (var i = 0; i < name.length; i++) {
      final c = name.codeUnitAt(i);
      if (c < 0x20 || c == 0x7F) {
        throw ArgumentError(
            'POP3 username contains forbidden control byte 0x'
            '${c.toRadixString(16).padLeft(2, '0')} at offset $i');
      }
      if (c == 0x20) {
        throw ArgumentError(
            'POP3 username contains forbidden SPACE at offset $i '
            '(POP3 uses SPACE as argument separator)');
      }
    }
    return name;
  }
}
