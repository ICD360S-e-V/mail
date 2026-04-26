import '../../../../enough_mail.dart';
import '../smtp_command.dart';

enum _SmtpSendCommandSequence { mailFrom, rcptTo, data, done }

void _validateSmtpAddress(String? email) {
  if (email == null || email.isEmpty) return;
  for (var i = 0; i < email.length; i++) {
    final c = email.codeUnitAt(i);
    if (c < 32 || c == 127) {
      throw ArgumentError('Email address contains control character at $i');
    }
  }
  if (email.contains('<') || email.contains('>')) {
    throw ArgumentError('Email address contains angle brackets');
  }
  if (email.length > 254) {
    throw ArgumentError('Email address exceeds 254 characters');
  }
}

final RegExp _bccPattern = RegExp(
  r'^Bcc:[^\r\n]*\r\n(?:[ \t][^\r\n]*\r\n)*',
  multiLine: true,
  caseSensitive: false,
);

String _dotStuff(String data) {
  final result = data.replaceAll('\r\n.', '\r\n..');
  if (result.endsWith('\r\n')) {
    return '$result.\r\n';
  }
  return '$result\r\n.\r\n';
}

class _SmtpSendCommand extends SmtpCommand {
  _SmtpSendCommand(
    this.getData,
    this.fromEmail,
    this.recipientEmails, {
    required this.use8BitEncoding,
    this.requestDsn = false,
  }) : super('MAIL FROM');

  final String Function() getData;
  final String? fromEmail;
  final List<String> recipientEmails;
  final bool use8BitEncoding;
  final bool requestDsn;
  _SmtpSendCommandSequence _currentStep = _SmtpSendCommandSequence.mailFrom;
  int _recipientIndex = 0;

  @override
  String get command {
    _validateSmtpAddress(fromEmail);
    final buffer = StringBuffer('MAIL FROM:<$fromEmail>');
    if (use8BitEncoding) {
      buffer.write(' BODY=8BITMIME');
    }
    if (requestDsn) {
      buffer.write(' RET=HDRS');
    }
    return buffer.toString();
  }

  @override
  String? nextCommand(SmtpResponse response) {
    final step = _currentStep;
    switch (step) {
      case _SmtpSendCommandSequence.mailFrom:
        _currentStep = _SmtpSendCommandSequence.rcptTo;
        _recipientIndex++;
        return _getRecipientToCommand(recipientEmails[0]);
      case _SmtpSendCommandSequence.rcptTo:
        final index = _recipientIndex;
        if (index < recipientEmails.length) {
          _recipientIndex++;

          return _getRecipientToCommand(recipientEmails[index]);
        } else if (response.type == SmtpResponseType.success) {
          _currentStep = _SmtpSendCommandSequence.data;

          return 'DATA';
        } else {
          return null;
        }
      case _SmtpSendCommandSequence.data:
        _currentStep = _SmtpSendCommandSequence.done;
        return _dotStuff(getData());
      default:
        return null;
    }
  }

  String _getRecipientToCommand(String email) {
    _validateSmtpAddress(email);
    if (requestDsn) {
      return 'RCPT TO:<$email> NOTIFY=SUCCESS,FAILURE,DELAY';
    }
    return 'RCPT TO:<$email>';
  }

  @override
  bool isCommandDone(SmtpResponse response) {
    if (_currentStep == _SmtpSendCommandSequence.data) {
      return response.code == 354;
    }

    return (response.type != SmtpResponseType.success) ||
        (_currentStep == _SmtpSendCommandSequence.done);
  }
}

/// Sends a MIME message
class SmtpSendMailCommand extends _SmtpSendCommand {
  /// Creates a new DATA command
  SmtpSendMailCommand(
    this.message,
    MailAddress? from,
    List<String> recipientEmails, {
    required bool use8BitEncoding,
    bool requestDsn = false,
  }) : super(
          () => message
              .renderMessage()
              .replaceAll(_bccPattern, ''),
          from?.email ?? message.fromEmail,
          recipientEmails,
          use8BitEncoding: use8BitEncoding,
          requestDsn: requestDsn,
        );

  /// The message to be sent
  final MimeMessage message;
}

/// Sends the message data
class SmtpSendMailDataCommand extends _SmtpSendCommand {
  /// Creates a new DATA command
  SmtpSendMailDataCommand(
    this.data,
    MailAddress from,
    List<String> recipientEmails, {
    required bool use8BitEncoding,
  }) : super(
          () => data
              .toString()
              .replaceAll(_bccPattern, ''),
          from.email,
          recipientEmails,
          use8BitEncoding: use8BitEncoding,
        );

  /// The message data to be sent
  final MimeData data;
}

/// Sends textual message data
class SmtpSendMailTextCommand extends _SmtpSendCommand {
  /// Creates a new DATA command
  SmtpSendMailTextCommand(
    this.data,
    MailAddress from,
    List<String> recipientEmails, {
    required bool use8BitEncoding,
  }) : super(
          () => data,
          from.email,
          recipientEmails,
          use8BitEncoding: use8BitEncoding,
        );

  /// The message text data to be sent
  final String data;
}
