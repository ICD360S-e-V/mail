import 'dart:typed_data';

/// Email message model
class Email {
  String messageId;
  String from;
  String to;
  String cc;  // Carbon Copy recipients (visible when receiving)
  String subject;
  DateTime date;
  String body;
  bool isRead;
  String threatLevel;
  int threatScore;
  String threatDetails;
  int? uid; // IMAP UID for reliable operations

  // Attachments
  List<EmailAttachment> attachments;

  // Headers (for threat analysis)
  Map<String, String> headers;

  Email({
    this.messageId = '',
    this.from = '',
    this.to = '',
    this.cc = '',
    this.subject = '',
    DateTime? date,
    this.body = '',
    this.isRead = false,
    this.threatLevel = 'Safe',
    this.threatScore = 0,
    this.threatDetails = '',
    this.uid,
    List<EmailAttachment>? attachments,
    Map<String, String>? headers,
  })  : date = date ?? DateTime.now(),
        attachments = attachments ?? [],
        headers = headers ?? {};

  /// Convert Email to JSON for serialization
  Map<String, dynamic> toJson() {
    return {
      'messageId': messageId,
      'from': from,
      'to': to,
      'cc': cc,
      'subject': subject,
      'date': date.toIso8601String(),
      'body': body,
      'isRead': isRead,
      'threatLevel': threatLevel,
      'threatScore': threatScore,
      'threatDetails': threatDetails,
      'attachments': attachments.map((a) => a.toJson()).toList(),
      'headers': headers,
    };
  }

  /// Create Email from JSON
  factory Email.fromJson(Map<String, dynamic> json) {
    return Email(
      messageId: json['messageId'] as String? ?? '',
      from: json['from'] as String? ?? '',
      to: json['to'] as String? ?? '',
      cc: json['cc'] as String? ?? '',
      subject: json['subject'] as String? ?? '',
      date: json['date'] != null
          ? DateTime.parse(json['date'] as String)
          : DateTime.now(),
      body: json['body'] as String? ?? '',
      isRead: json['isRead'] as bool? ?? false,
      threatLevel: json['threatLevel'] as String? ?? 'Safe',
      threatScore: json['threatScore'] as int? ?? 0,
      threatDetails: json['threatDetails'] as String? ?? '',
      attachments: json['attachments'] != null
          ? (json['attachments'] as List)
              .map((a) => EmailAttachment.fromJson(a as Map<String, dynamic>))
              .toList()
          : [],
      headers: json['headers'] != null
          ? Map<String, String>.from(json['headers'] as Map)
          : {},
    );
  }

  /// Create a copy of this email with optional field modifications
  Email copyWith({
    String? messageId,
    String? from,
    String? to,
    String? cc,
    String? subject,
    DateTime? date,
    String? body,
    bool? isRead,
    String? threatLevel,
    int? threatScore,
    String? threatDetails,
    List<EmailAttachment>? attachments,
    Map<String, String>? headers,
  }) {
    return Email(
      messageId: messageId ?? this.messageId,
      from: from ?? this.from,
      to: to ?? this.to,
      cc: cc ?? this.cc,
      subject: subject ?? this.subject,
      date: date ?? this.date,
      body: body ?? this.body,
      isRead: isRead ?? this.isRead,
      threatLevel: threatLevel ?? this.threatLevel,
      threatScore: threatScore ?? this.threatScore,
      threatDetails: threatDetails ?? this.threatDetails,
      attachments: attachments ?? List.from(this.attachments),
      headers: headers ?? Map.from(this.headers),
    );
  }
}

/// Email attachment model
class EmailAttachment {
  String fileName;
  int size;
  String contentType;
  Uint8List? data;

  EmailAttachment({
    this.fileName = '',
    this.size = 0,
    this.contentType = '',
    this.data,
  });

  /// Convert EmailAttachment to JSON for serialization
  Map<String, dynamic> toJson() {
    return {
      'fileName': fileName,
      'size': size,
      'contentType': contentType,
      // Note: data is not serialized (too large for JSON)
      // In practice, attachments would be saved separately
    };
  }

  /// Create EmailAttachment from JSON
  factory EmailAttachment.fromJson(Map<String, dynamic> json) {
    return EmailAttachment(
      fileName: json['fileName'] as String? ?? '',
      size: json['size'] as int? ?? 0,
      contentType: json['contentType'] as String? ?? '',
      // data is not loaded from JSON
    );
  }

  /// Create a copy of this attachment with optional field modifications
  EmailAttachment copyWith({
    String? fileName,
    int? size,
    String? contentType,
    Uint8List? data,
  }) {
    return EmailAttachment(
      fileName: fileName ?? this.fileName,
      size: size ?? this.size,
      contentType: contentType ?? this.contentType,
      data: data ?? this.data,
    );
  }
}
