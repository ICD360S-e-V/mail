import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart' show IterableExtension;

import 'codecs/mail_codec.dart';
import 'mime_message.dart';
import 'private/imap/parser_helper.dart';
import 'private/util/ascii_runes.dart';
import 'private/util/byte_utils.dart';

// SECURITY (M5): defensive limits for the multipart parser.
//
// Without explicit limits a malicious or buggy IMAP server can
// trigger denial of service through:
//   - extremely long boundary strings (CVE-2024-7999 pattern)
//   - thousands of forged boundaries inside one body (memory blow-up
//     from String.split allocating one string per fragment)
//   - deeply-nested multipart structures (unbounded recursion through
//     parts -> TextMimeData(...).parse(null))
//   - boundaries containing CR / LF / NUL bytes (parser confusion)
//
// The constants below mirror the limits used by the Go standard
// library's `mime/multipart` package, which is the industry reference
// for hardened multipart parsing.
class _MimeParseLimits {
  /// RFC 2046 §5.1.1: boundary parameter is 1-70 characters.
  static const int maxBoundaryLength = 70;

  /// Maximum number of child parts inside a single multipart container.
  static const int maxParts = 1000;

  /// Maximum recursion depth for nested multipart bodies.
  static const int maxNestingDepth = 10;

  /// Refuse to run String.split on bodies larger than this; the split
  /// would otherwise allocate ~3x the body size in temporary fragment
  /// strings. 50 MiB comfortably accommodates real-world emails with
  /// attachments while preventing pathological inputs.
  static const int maxBodyBytesForSplit = 50 * 1024 * 1024;

  /// Current recursion depth across both TextMimeData and
  /// BinaryMimeData. Single-threaded per isolate, so a static counter
  /// is safe; the parsers always wrap recursive calls in try/finally
  /// so a thrown exception cannot leak the counter upwards.
  static int currentDepth = 0;
}

/// RFC 2046 forbids CR / LF / NUL inside boundary parameter values
/// and limits the boundary to 1-70 characters. We additionally reject
/// empty boundaries (which would split nothing or split everything).
bool _isValidMimeBoundary(String? boundary) {
  if (boundary == null || boundary.isEmpty) return false;
  if (boundary.length > _MimeParseLimits.maxBoundaryLength) return false;
  for (var i = 0; i < boundary.length; i++) {
    final c = boundary.codeUnitAt(i);
    if (c == 0x0D || c == 0x0A || c == 0x00) return false;
  }
  return true;
}

/// Abstracts textual or binary mime data
abstract class MimeData {
  /// Creates a new mime data
  ///
  /// Specify if this data contains header information with [containsHeader].
  MimeData({required this.containsHeader});

  /// Defines if this mime data includes header data
  final bool containsHeader;

  /// All known headers of this mime data
  List<Header>? headersList;

  /// Returns `true` when there are children
  bool get hasParts => parts?.isNotEmpty ?? false;

  /// The children of this mime data
  List<MimeData>? parts;

  ContentTypeHeader? _contentType;

  /// The content type of this mime data
  ContentTypeHeader? get contentType {
    var value = _contentType;
    if (value == null) {
      final headerText = _getHeaderValue('content-type');
      if (headerText != null) {
        value = ContentTypeHeader(headerText);
      }
    }

    return value;
  }

  bool _isParsed = false;
  ContentTypeHeader? _parsingContentTypeHeader;

  int _size = 0;

  /// Size of the entire MimePart
  int get size => _size;

  int _bodySize = 0;

  /// Size of the MimePart body
  int get bodySize => _bodySize;

  /// Decodes the text represented by the mime data
  String decodeText(
    ContentTypeHeader? contentTypeHeader,
    String? contentTransferEncoding,
  );

  /// Decodes the data represented by the mime data
  Uint8List decodeBinary(String? contentTransferEncoding);

  /// Decodes message/rfc822 content
  MimeData? decodeMessageData();

  /// Parses this data
  void parse(ContentTypeHeader? contentTypeHeader) {
    if (_isParsed && (contentTypeHeader == _parsingContentTypeHeader)) {
      return;
    }
    _isParsed = true;
    _parsingContentTypeHeader = contentTypeHeader;
    _parseContent(contentTypeHeader);
  }

  void _parseContent(ContentTypeHeader? contentTypeHeader);

  /// Renders this mime data.
  ///
  /// Optionally set [renderHeader] to `false` in case the
  /// message header should be skipped.
  void render(StringBuffer buffer, {bool renderHeader = true});

  Header? _getHeader(String lowerCaseName) =>
      headersList?.firstWhereOrNull((h) => h.lowerCaseName == lowerCaseName);

  String? _getHeaderValue(String lowerCaseName) =>
      _getHeader(lowerCaseName)?.value;

  @override
  String toString() {
    final buffer = StringBuffer();
    render(buffer);

    return buffer.toString();
  }
}

/// Represents textual mime data
class TextMimeData extends MimeData {
  /// Creates a new text based mime data
  ///
  /// with the specified [text] and the [containsHeader] information.
  TextMimeData(String text, {required bool containsHeader})
      : text = _normalizeLineEndings(text),
        super(containsHeader: containsHeader) {
    _size = this.text.length;
  }

  /// Normalizes bare LF to CRLF for RFC 5322 compliance.
  static String _normalizeLineEndings(String text) =>
      text.replaceAll(RegExp(r'(?<!\r)\n'), '\r\n');

  /// The text representation of the full mime data
  final String text;

  /// The body of the data
  late String body;

  @override
  void _parseContent(ContentTypeHeader? contentTypeHeader) {
    var bodyText = text;
    if (containsHeader) {
      if (text.startsWith('\r\n')) {
        // this part has no header
        bodyText = text.substring(2);
      } else {
        final headerParseResult = ParserHelper.parseHeader(text);
        final bodyStartIndex = headerParseResult.bodyStartIndex;
        if (bodyStartIndex != null) {
          bodyText = bodyStartIndex >= text.length
              ? ''
              : text.substring(bodyStartIndex);
        }
        headersList = headerParseResult.headersList;
      }
      // ignore: parameter_assignments
      contentTypeHeader ??= contentType;
    } else {
      bodyText = text;
    }
    body = bodyText;
    _bodySize = body.length;
    String? partsBoundary;
    if (contentTypeHeader?.mediaType.isMessage ?? false) {
      final headStop = body.indexOf('\r\n\r\n');
      final boundaryMatcher = RegExp(r'boundary="(.+)"');
      partsBoundary =
          boundaryMatcher.firstMatch(body.substring(0, headStop))?.group(1);
    } else {
      partsBoundary = contentTypeHeader?.boundary;
    }
    if (partsBoundary != null) {
      // SECURITY (M5): validate boundary, body size and nesting depth
      // BEFORE the expensive split. Each guard fails closed: if the
      // input violates a safety limit we simply do not populate
      // [parts]. The body remains accessible as a single text blob,
      // so a legitimate-looking-but-pathological email is still
      // openable, just not pre-split.
      if (!_isValidMimeBoundary(partsBoundary)) {
        return;
      }
      if (body.length > _MimeParseLimits.maxBodyBytesForSplit) {
        return;
      }
      if (_MimeParseLimits.currentDepth >= _MimeParseLimits.maxNestingDepth) {
        return;
      }
      _MimeParseLimits.currentDepth++;
      try {
        parts = [];
        final splitBoundary = '--\$partsBoundary\r\n';
        final childParts = bodyText.split(splitBoundary);
        if (!bodyText.startsWith(splitBoundary)) {
          // mime-readers can ignore the preamble:
          childParts.removeAt(0);
        }
        // SECURITY (M5): cap the number of fragments. Truncating
        // (rather than throwing) keeps the first N legitimate parts
        // visible to the user even if a malicious server padded the
        // body with extra forged boundaries.
        if (childParts.length > _MimeParseLimits.maxParts) {
          childParts.removeRange(
              _MimeParseLimits.maxParts, childParts.length);
        }
        if (childParts.isNotEmpty) {
          var lastPart = childParts.last;
          final closingIndex = lastPart.lastIndexOf('--\$partsBoundary--');
          if (closingIndex != -1) {
            childParts.removeLast();
            lastPart = lastPart.substring(0, closingIndex);
            childParts.add(lastPart);
          }
          for (final childPart in childParts) {
            if (childPart.isNotEmpty) {
              final part = TextMimeData(childPart, containsHeader: true)
                ..parse(null);
              parts?.add(part);
            }
          }
        }
      } finally {
        _MimeParseLimits.currentDepth--;
      }
    }
  }

  @override
  void render(StringBuffer buffer, {bool renderHeader = true}) {
    if (!renderHeader && containsHeader) {
      buffer.write(body);
    } else {
      buffer.write(text);
    }
  }

  @override
  Uint8List decodeBinary(String? contentTransferEncoding) =>
      MailCodec.decodeBinary(body, contentTransferEncoding);

  @override
  String decodeText(
    ContentTypeHeader? contentTypeHeader,
    String? contentTransferEncoding,
  ) =>
      MailCodec.decodeAnyText(
        body,
        contentTransferEncoding,
        contentTypeHeader?.charset,
      );

  @override
  MimeData? decodeMessageData() => TextMimeData(body, containsHeader: true);
}

/// Represents binary mime data
class BinaryMimeData extends MimeData {
  /// Creates a new binary mime data
  ///
  /// with the specified [data] and the [containsHeader] info.
  BinaryMimeData(this.data, {required bool containsHeader})
      : super(containsHeader: containsHeader) {
    _size = data.length;
  }

  /// The binary data
  final Uint8List data;
  int? _bodyStartIndex;
  late Uint8List _bodyData;

  @override
  void _parseContent(ContentTypeHeader? contentTypeHeader) {
    if (containsHeader) {
      headersList = _parseHeader();
    } else {
      _bodyStartIndex = 0;
    }
    final bodyStartIndex = _bodyStartIndex;
    if (bodyStartIndex == null) {
      _bodyData = Uint8List(0);
    } else {
      _bodyData = bodyStartIndex == 0 ? data : data.sublist(bodyStartIndex);
      final usedContentType = contentTypeHeader ?? contentType;
      String? partsBoundary;
      if (usedContentType?.mediaType.isMessage ?? false) {
        final headStop = '\r\n\r\n'.codeUnits;
        final headStopIndex = ByteUtils.findSequence(_bodyData, headStop);
        if (headStopIndex > 0) {
          final matcher = 'boundary="'.codeUnits;
          final boundaryPos = ByteUtils.findSequence(
            Uint8List.sublistView(_bodyData, 0, headStopIndex),
            matcher,
          );
          if (boundaryPos > 0) {
            partsBoundary = String.fromCharCodes(
              _bodyData.sublist(
                boundaryPos + matcher.length,
                _bodyData.indexOf(
                  AsciiRunes.runeDoubleQuote,
                  boundaryPos + matcher.length + 1,
                ),
              ),
            );
          }
          // print('message/rfc822 boundary: $partsBoundary');
        }
      } else {
        // Generic multipart
        partsBoundary = usedContentType?.boundary;
      }
      if (partsBoundary != null) {
        // SECURITY (M5): same defensive validation as TextMimeData.
        if (_isValidMimeBoundary(partsBoundary) &&
            _bodyData.length <= _MimeParseLimits.maxBodyBytesForSplit &&
            _MimeParseLimits.currentDepth <
                _MimeParseLimits.maxNestingDepth) {
          _MimeParseLimits.currentDepth++;
          try {
            parts = _splitAndParse(partsBoundary, _bodyData);
          } finally {
            _MimeParseLimits.currentDepth--;
          }
        }
      }
    }
    _bodySize = _bodyData.length;
  }

  List<BinaryMimeData> _splitAndParse(
    final String boundaryText,
    final Uint8List bodyData,
  ) {
    final boundary = '--$boundaryText\r\n'.codeUnits;
    final result = <BinaryMimeData>[];
    // end is expected to be \r\n for all but the last one, where -- is expected, possibly followed by \r\n
    int? startIndex;
    final maxIndex = bodyData.length - (3 * boundary.length);
    for (var i = 0; i < maxIndex; i++) {
      var foundMatch = true;
      for (var j = 0; j < boundary.length; j++) {
        if (bodyData[i + j] != boundary[j]) {
          foundMatch = false;
          break;
        }
      }
      if (foundMatch) {
        if (startIndex == null) {
          i += boundary.length;
          startIndex = i;
        } else {
          final partData = bodyData.sublist(startIndex, i);
          final part = BinaryMimeData(partData, containsHeader: true)
            ..parse(null);
          result.add(part);
          if (result.length >= _MimeParseLimits.maxParts) {
            // SECURITY (M5): too many parts — stop scanning rather
            // than allocate further sublists.
            return result;
          }
          i += boundary.length;
          startIndex = i;
        }
      }
    }
    // check and add end:
    if (startIndex != null) {
      final endBoundary = '--$boundaryText--'.codeUnits;
      for (var i = bodyData.length - endBoundary.length; i > startIndex; i--) {
        var foundMatch = true;
        for (var j = 0; j < endBoundary.length; j++) {
          if (bodyData[i + j] != endBoundary[j]) {
            foundMatch = false;
            break;
          }
        }
        if (foundMatch) {
          final partData = bodyData.sublist(startIndex, i);
          final part = BinaryMimeData(partData, containsHeader: true)
            ..parse(null);
          result.add(part);
          break;
        }
      }
    }

    return result;
  }

  @override
  String decodeText(
    ContentTypeHeader? contentTypeHeader,
    String? contentTransferEncoding,
  ) =>
      _bodyStartIndex == null
          ? ''
          : MailCodec.decodeAsText(
              _bodyData,
              contentTransferEncoding,
              contentTypeHeader?.charset,
            );

  @override
  Uint8List decodeBinary(String? contentTransferEncoding) {
    final contentTransferEncodingLC = contentTransferEncoding?.toLowerCase();
    if (_bodyStartIndex == null ||
        // do not try to decode textual content:
        contentTransferEncodingLC == '7bit' ||
        contentTransferEncodingLC == '8bit' ||
        contentTransferEncodingLC == 'quoted-printable') {
      return _bodyData;
    }
    // even with a 'binary' content transfer encoding there are \r\n
    // characters that need to be handled,
    // so translate to text first
    final dataText = utf8.decode(_bodyData);

    return MailCodec.decodeBinary(dataText, contentTransferEncodingLC);
  }

  List<Header> _parseHeader() {
    final headerData = data;
    // shortcut for having an empty line at the start:
    if (headerData.length > 1 &&
        headerData[0] == AsciiRunes.runeCarriageReturn &&
        headerData[1] == AsciiRunes.runeLineFeed) {
      _bodyStartIndex = 2;

      return [];
    }
    // check for first CRLF-CRLF sequence:
    for (var i = 0; i < headerData.length - 4; i++) {
      if (headerData[i] == AsciiRunes.runeCarriageReturn &&
          headerData[i + 1] == AsciiRunes.runeLineFeed &&
          headerData[i + 2] == AsciiRunes.runeCarriageReturn &&
          headerData[i + 3] == AsciiRunes.runeLineFeed) {
        final headerLines =
            String.fromCharCodes(headerData, 0, i).split('\r\n');
        _bodyStartIndex = i + 4;

        return ParserHelper.parseHeaderLines(headerLines).headersList;
      }
    }
    // the whole data is just headers:
    final headerLines = String.fromCharCodes(headerData).split('\r\n');

    return ParserHelper.parseHeaderLines(headerLines).headersList;
  }

  @override
  void render(StringBuffer buffer, {bool renderHeader = true}) {
    if (!renderHeader && containsHeader) {
      final text = String.fromCharCodes(_bodyData);
      buffer.write(text);
    } else {
      final text = String.fromCharCodes(data);
      buffer.write(text);
    }
  }

  @override
  MimeData? decodeMessageData() =>
      BinaryMimeData(_bodyData, containsHeader: true);
}
