// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Connection status for email accounts
enum AccountConnectionStatus {
  unknown,    // Not yet tested
  connected,  // Successfully connected and authenticated
  authError,  // Authentication failed (wrong username or password)
  networkError, // Network/connection error
}

/// Email account model for IMAP/SMTP configuration
/// SECURITY: This client only connects to mail.icd360s.de server
class EmailAccount {
  // SECURITY: Server whitelist - only mail.icd360s.de allowed
  static const String allowedServer = 'mail.icd360s.de';
  static const int allowedImapPort = 993;
  static const int allowedSmtpPort = 587;

  String username;
  String mailServer;
  int imapPort;
  int smtpPort;
  bool useSsl;
  String lastFolder;
  bool isActive;
  int inboxCount;

  /// Signature auto-appended to new outgoing emails (after RFC 3676 "-- " marker).
  /// Stored per-account so switching accounts in compose swaps the signature.
  /// Empty by default; populated either via account settings UI or
  /// [defaultSignatureFor] for known accounts.
  String signature;

  // Folders fetched from server (not serialized, loaded dynamically)
  List<String> folders;

  // Folder message counts (not serialized, loaded dynamically)
  Map<String, int> folderCounts;

  // Connection status (not serialized, updated dynamically)
  AccountConnectionStatus connectionStatus;
  String? connectionError; // Error message if connection failed

  // Quota information (not serialized, fetched from server dynamically)
  int? quotaUsedKB;   // KB used
  int? quotaLimitKB;  // KB limit (e.g., 102400 = 100 MB)
  double? quotaPercentage; // Percentage used (0.0 - 100.0)

  EmailAccount({
    this.username = '',
    this.mailServer = allowedServer, // SECURITY: Locked to allowed server
    this.imapPort = allowedImapPort, // SECURITY: Locked to standard IMAP port
    this.smtpPort = allowedSmtpPort, // SECURITY: Locked to standard SMTP port
    this.useSsl = true,
    this.lastFolder = 'INBOX',
    this.isActive = true,
    this.inboxCount = 0,
    this.signature = '',
    List<String>? folders,
    Map<String, int>? folderCounts,
    this.connectionStatus = AccountConnectionStatus.unknown,
    this.connectionError,
  })  : folders = folders ?? [],
        folderCounts = folderCounts ?? {};

  /// Convert EmailAccount to JSON for serialization
  Map<String, dynamic> toJson() {
    return {
      'username': username,
      'mailServer': mailServer,
      'imapPort': imapPort,
      'smtpPort': smtpPort,
      'useSsl': useSsl,
      'lastFolder': lastFolder,
      'isActive': isActive,
      'inboxCount': inboxCount,
      'signature': signature,
      // Note: folders, folderCounts, and password are not serialized
    };
  }

  /// Create EmailAccount from JSON
  factory EmailAccount.fromJson(Map<String, dynamic> json) {
    return EmailAccount(
      username: json['username'] as String? ?? '',
      mailServer: json['mailServer'] as String? ?? 'mail.icd360s.de',
      imapPort: json['imapPort'] as int? ?? 993,
      smtpPort: json['smtpPort'] as int? ?? 587,
      useSsl: json['useSsl'] as bool? ?? true,
      lastFolder: json['lastFolder'] as String? ?? 'INBOX',
      isActive: json['isActive'] as bool? ?? true,
      inboxCount: json['inboxCount'] as int? ?? 0,
      signature: (json['signature'] as String?) ??
          defaultSignatureFor(json['username'] as String? ?? ''),
    );
  }

  /// Built-in default signature for known ICD360S e.V. mailboxes. Used as
  /// fallback when no stored signature exists yet (one-time migration for
  /// installs upgrading to client versions that introduce signature support).
  /// Returns '' for unknown accounts.
  static String defaultSignatureFor(String username) {
    final addr = username.toLowerCase();
    if (addr == 'icd@icd360s.de') {
      // Mandatory disclosures per § 5 TMG / § 26 BGB for an eingetragener
      // Verein: full association name, business address, Vertretungsberechtigter
      // (Vorstand) and Vereinsregister (court + VR-Nr). Tagline is the
      // association's official acronym expansion (Integration · Chancen ·
      // Diversity · 360° Support) as shown on icd360s.de header.
      return '''Freundliche Grüße

Ionuț Claudiu Duinea
1. Vorsitzender
____________________________________________


ICD360S e.V.
Eingetragener gemeinnütziger Verein

c/o Ionuț-Claudiu Duinea
Elsa-Brändström-Str. 13
89231 Neu-Ulm

E-Mail:    icd@icd360s.de
Internet:  www.icd360s.de
Telefon:   +49 160 9448 2053

Amtsgericht Memmingen · VR 201335
Gemeinnützig anerkannt

Integration · Chancen · Diversity
360° Support
____________________________________________
Diese E-Mail ist ausschließlich für den Adressaten/die Adressatin bestimmt
und kann vertrauliche oder gesetzlich geschützte Informationen enthalten.
Wenn Sie nicht der/die bestimmungsgemäße Adressat/-in sind, unterrichten
Sie bitte den Absender/die Absenderin und vernichten Sie diese E-Mail.''';
    }
    return '';
  }

  /// Create a copy of this account with optional field modifications
  EmailAccount copyWith({
    String? username,
    String? mailServer,
    int? imapPort,
    int? smtpPort,
    bool? useSsl,
    String? lastFolder,
    bool? isActive,
    int? inboxCount,
    String? signature,
    List<String>? folders,
    Map<String, int>? folderCounts,
    AccountConnectionStatus? connectionStatus,
    String? connectionError,
  }) {
    return EmailAccount(
      username: username ?? this.username,
      mailServer: mailServer ?? this.mailServer,
      imapPort: imapPort ?? this.imapPort,
      smtpPort: smtpPort ?? this.smtpPort,
      useSsl: useSsl ?? this.useSsl,
      lastFolder: lastFolder ?? this.lastFolder,
      isActive: isActive ?? this.isActive,
      inboxCount: inboxCount ?? this.inboxCount,
      signature: signature ?? this.signature,
      folders: folders ?? List.from(this.folders),
      folderCounts: folderCounts ?? Map.from(this.folderCounts),
      connectionStatus: connectionStatus ?? this.connectionStatus,
      connectionError: connectionError ?? this.connectionError,
    );
  }
}
