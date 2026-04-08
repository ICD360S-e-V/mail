import 'dart:typed_data';

import '../util/uint8_list_reader.dart';
import 'imap_response.dart';
import 'imap_response_line.dart';

/// Reads IMAP responses
class ImapResponseReader {
  /// Creates a new imap response reader
  ImapResponseReader(this.onImapResponse);

  /// Callback for finished IMAP responses
  final Function(ImapResponse) onImapResponse;
  final Uint8ListReader _rawReader = Uint8ListReader();
  ImapResponse? _currentResponse;
  ImapResponseLine? _currentLine;

  /// Maximum allowed size for a single IMAP literal (in bytes).
  ///
  /// Defends against malicious or buggy servers that advertise a huge
  /// `{N}` literal size, which would otherwise cause unbounded memory
  /// allocation (DoS / OOM). 50 MiB accommodates legitimate large
  /// attachments fetched via FETCH BODY while preventing abuse.
  static const int maxLiteralSize = 50 * 1024 * 1024;

  /// Processes the given [data]
  void onData(Uint8List data) {
    _rawReader.add(data);
    // var text = String.fromCharCodes(data).replaceAll('\r\n', '<CRLF>\n');
    // print('onData: $text');
    final currentResponse = _currentResponse;
    final currentLine = _currentLine;
    if (currentResponse != null && currentLine != null) {
      _checkResponse(currentResponse, currentLine);
    }
    if (_currentResponse == null) {
      // there is currently no response awaiting its finalization
      var text = _rawReader.readLine();
      while (text != null) {
        final response = ImapResponse();
        final line = ImapResponseLine(text);
        response.add(line);
        if (line.isWithLiteral) {
          _currentLine = line;
          _currentResponse = response;
          _checkResponse(response, line);
        } else {
          // this is a simple response:
          onImapResponse(response);
        }
        if (_currentLine?.isWithLiteral ?? false) {
          break;
        }
        text = _rawReader.readLine();
      }
    }
  }

  void _checkResponse(ImapResponse response, ImapResponseLine line) {
    final literal = line.literal;
    if (literal != null && literal > 0) {
      if (literal > maxLiteralSize) {
        // Reject oversized literal to prevent OOM/DoS via malicious server.
        _currentResponse = null;
        _currentLine = null;
        throw FormatException(
          'IMAP literal size $literal exceeds maximum allowed '
          '($maxLiteralSize bytes)',
        );
      }
      if (_rawReader.isAvailable(literal)) {
        final rawLine = ImapResponseLine.raw(_rawReader.readBytes(literal));
        response.add(rawLine);
        _currentLine = rawLine;
        _checkResponse(response, rawLine);
      }
    } else {
      // current line has no literal
      final text = _rawReader.readLine();
      if (text != null) {
        final textLine = ImapResponseLine(text);
        // handle special case:
        // the remainder of this line may consists of only a literal,
        // in this case the information should be added on the previous line
        if (textLine.isWithLiteral && (textLine.line?.isEmpty ?? true)) {
          line.literal = textLine.literal;
        } else {
          if (textLine.line?.isNotEmpty ?? false) {
            response.add(textLine);
          }
          if (!textLine.isWithLiteral) {
            // this is the last line of this server response:
            onImapResponse(response);
            _currentResponse = null;
            _currentLine = null;
          } else {
            _currentLine = textLine;
            _checkResponse(response, textLine);
          }
        }
      }
    }
  }
}
