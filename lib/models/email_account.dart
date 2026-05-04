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
    );
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
      folders: folders ?? List.from(this.folders),
      folderCounts: folderCounts ?? Map.from(this.folderCounts),
      connectionStatus: connectionStatus ?? this.connectionStatus,
      connectionError: connectionError ?? this.connectionError,
    );
  }
}
