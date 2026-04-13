import 'dart:io';
import 'package:enough_mail/enough_mail.dart';
import '../models/models.dart';
import 'certificate_service.dart';
import 'dns_checker.dart';
import 'logger_service.dart';
import 'mtls_service.dart';
import 'pgp_key_service.dart';
import 'threat_intelligence_service.dart';
import 'trash_tracker_service.dart';
import 'email_history_service.dart';
import 'localization_service.dart';

/// Exception for authentication failures (wrong username or password)
class AuthenticationException implements Exception {
  final String message;
  final bool isLikelyPasswordError;
  final bool isLikelyUsernameError;

  AuthenticationException({
    required this.message,
    this.isLikelyPasswordError = false,
    this.isLikelyUsernameError = false,
  });

  @override
  String toString() => message;
}

/// Mail service for IMAP/SMTP operations
class MailService {
  // SECURITY: Whitelist of allowed mail servers
  static const String allowedServer = 'mail.icd360s.de';
  static const int allowedImapPort = 10993; // Dedicated mTLS-only port (was 993)
  static const int allowedSmtpPort = 465; // Changed from 587 (STARTTLS) to 465 (direct SSL/TLS for mTLS)

  // DNS cache — avoids repeated lookups that exhaust file descriptors on macOS
  static List<InternetAddress>? _dnsCache;
  static DateTime? _dnsCacheExpiry;
  static bool _dohFailed = false; // Skip DoH for rest of session if it failed once

  /// Resolve server via DNS-over-HTTPS (5 min cache TTL).
  ///
  /// Uses [DnsChecker.lookupA] (encrypted DoH to mail.icd360s.de or
  /// Cloudflare fallback) instead of the system resolver (plaintext
  /// UDP/53). This prevents local DNS poisoning attacks on untrusted
  /// networks from redirecting IMAP/SMTP connections to a rogue server.
  static Future<String> resolveServer() async {
    if (_dnsCache != null && _dnsCacheExpiry != null && DateTime.now().isBefore(_dnsCacheExpiry!)) {
      return _dnsCache!.first.address;
    }
    try {
      // Skip DoH if it already failed this session — go straight to system resolver
      if (!_dohFailed) {
        final results = await DnsChecker.lookupServerA(allowedServer);
        if (results.isNotEmpty) {
          _dnsCache = results.map((ip) => InternetAddress(ip)).toList();
          _dnsCacheExpiry = DateTime.now().add(const Duration(minutes: 5));
          LoggerService.log('DNS', '✓ Resolved $allowedServer → ${results.first} (DoH)');
          return results.first;
        }
        _dohFailed = true; // Don't try DoH again this session
      }
      // System resolver fallback
      _dnsCache = await InternetAddress.lookup(allowedServer);
      _dnsCacheExpiry = DateTime.now().add(const Duration(minutes: 5));
      return _dnsCache!.first.address;
    } catch (e) {
      if (_dnsCache != null) {
        _dnsCacheExpiry = DateTime.now().add(const Duration(minutes: 2));
        LoggerService.log('DNS', '⚠️ Lookup failed, reusing cached IP ${_dnsCache!.first.address}');
        return _dnsCache!.first.address;
      }
      rethrow;
    }
  }

  /// Extract email body - prefer plain text, fallback to HTML if plain is empty
  static String _extractEmailBody(MimeMessage message) {
    final plainText = message.decodeTextPlainPart();
    if (plainText != null && plainText.trim().isNotEmpty) {
      return plainText;
    }
    final htmlText = message.decodeTextHtmlPart();
    if (htmlText != null && htmlText.trim().isNotEmpty) {
      return htmlText;
    }
    return '(Empty email body)';
  }

  /// Extract username from email for server authentication
  /// Server expects "claudeai" not "claudeai@icd360s.de"
  String _getAuthUsername(String email) {
    if (email.contains('@')) {
      return email.split('@').first;
    }
    return email;
  }

  /// Authenticate to an already-connected SMTP submission client,
  /// preferring SASL EXTERNAL (cert-based, no password on the wire)
  /// when the server advertises `AUTH EXTERNAL` in its EHLO response.
  ///
  /// Pairs with the v2.29.0 server-side migration to Dovecot
  /// submission service (Faza A3.2.5). Same pattern as the IMAP
  /// `_authenticate` helper above — pick mechanism by capability,
  /// fall back to legacy LOGIN/PLAIN for any server that doesn't
  /// advertise EXTERNAL (third-party SMTP, dev environments).
  ///
  /// Caller MUST have called `smtpClient.ehlo()` first so
  /// `serverInfo.authMechanisms` is populated.
  Future<void> _authenticateSmtp(
      SmtpClient smtpClient, EmailAccount account) async {
    if (smtpClient.serverInfo.supportsAuth(AuthMechanism.external)) {
      LoggerService.log(
          'SMTP', 'Auth: SASL EXTERNAL (cert-based, no password)');
      await smtpClient.authenticateWithExternal();
      return;
    }
    LoggerService.log(
        'SMTP', 'Auth: PLAIN (server does not advertise AUTH EXTERNAL)');
    await smtpClient.authenticate(
      _getAuthUsername(account.username),
      account.password ?? '',
      AuthMechanism.plain,
    );
  }

  /// Authenticate to an already-connected IMAP client, preferring SASL
  /// EXTERNAL (cert-based, no password on the wire) when the server
  /// advertises it.
  ///
  /// This is the canonical entry point for IMAP auth in this app — every
  /// `client.login(...)` call site has been replaced with this helper.
  /// As of v2.26.0 (A3 phase 2), our HAProxy + Dovecot stack advertises
  /// `AUTH=EXTERNAL` after a successful mTLS handshake; the user is
  /// extracted from the client cert subject (CN=`<user>@icd360s.de`)
  /// and matched against `/etc/dovecot/users-external` server-side.
  ///
  /// Behavior:
  /// - If `serverInfo.supports('AUTH=EXTERNAL')` → call
  ///   `client.authenticateWithExternal()` (no password sent)
  /// - Else → fall back to legacy `client.login(user, password)` so the
  ///   app keeps working against any IMAP server that doesn't yet
  ///   support cert auth (e.g. third-party IMAP, dev environments)
  ///
  /// In production with mail.icd360s.de the EXTERNAL path is taken
  /// every time once the user has a valid client cert in their store.
  Future<void> _authenticate(ImapClient client, EmailAccount account) async {
    final user = _getAuthUsername(account.username);
    if (client.serverInfo.supports('AUTH=EXTERNAL')) {
      LoggerService.log('IMAP', 'Auth: SASL EXTERNAL (cert-based, no password)');
      await client.authenticateWithExternal();
      return;
    }
    LoggerService.log('IMAP', 'Auth: LOGIN (server does not advertise AUTH=EXTERNAL)');
    await client.login(user, account.password ?? '');
  }

  /// Quote a string for use in an IMAP command (RFC 3501 quoted-string).
  ///
  /// SECURITY: Prevents IMAP injection when interpolating attacker-controlled
  /// values (e.g. Message-ID headers from received mail, subject lines from
  /// forwarded/replied emails) into SEARCH criteria.
  ///
  /// RFC 3501 quoted-string rules:
  /// - CR, LF, NUL are NOT allowed in quoted strings (throws ArgumentError)
  /// - " and \ must be backslash-escaped
  /// - Any other 7-bit character is allowed literally
  ///
  /// Returns the value surrounded by double quotes, safe to drop into an
  /// IMAP command string.
  String _imapQuote(String value) {
    if (value.contains('\r') || value.contains('\n') || value.contains('\x00')) {
      throw ArgumentError('IMAP quoted string cannot contain CR, LF, or NUL');
    }
    final escaped = value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
    return '"$escaped"';
  }

  /// Validate account server and ports (security check)
  void _validateAccount(EmailAccount account) {
    if (account.mailServer != allowedServer) {
      LoggerService.log('SECURITY',
          '⚠️ BLOCKED connection to unauthorized server: ${account.mailServer}');
      final l10nService = LocalizationService.instance;
      throw Exception(l10nService.getText(
        (l10n) => l10n.mailServiceSecurityViolationServer(account.mailServer, allowedServer),
        'SECURITY VIOLATION: Connection to ${account.mailServer} is blocked. '
        'This client only connects to $allowedServer.'
      ));
    }

    if (account.imapPort != allowedImapPort || account.smtpPort != allowedSmtpPort) {
      LoggerService.log('SECURITY',
          '⚠️ BLOCKED connection to non-standard ports: IMAP:${account.imapPort} SMTP:${account.smtpPort}');
      final l10nService = LocalizationService.instance;
      throw Exception(l10nService.getText(
        (l10n) => l10n.mailServiceSecurityViolationPorts(allowedImapPort, allowedSmtpPort),
        'SECURITY VIOLATION: Only standard ports are allowed (IMAP:$allowedImapPort, SMTP:$allowedSmtpPort).'
      ));
    }
  }

  /// Fetch emails from a folder via IMAP
  Future<List<Email>> fetchEmailsAsync(
    EmailAccount account,
    String folder,
  ) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    final emails = <Email>[];
    ImapClient? client;

    try {
      // Connect to IMAP server with mTLS
      client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      LoggerService.log('IMAP',
          'Connecting to ${account.mailServer}:${account.imapPort} as ${account.username} (mTLS)...');

      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      LoggerService.log('IMAP', '✓ Connected to IMAP server (SSL: ${account.useSsl})');

      // Authenticate
      LoggerService.log('IMAP', 'Authenticating...');
      try {
        await _authenticate(client, account);
        LoggerService.log('IMAP', '✓ Authenticated as ${account.username}');
      } catch (authEx) {
        // L3 fix: only treat as auth error if the message contains a specific
        // IMAP/SMTP authentication error phrase. The previous list of broad
        // keywords ('no', 'bad', 'user') matched almost any error message and
        // misclassified network/server errors as wrong credentials.
        //
        // The phrases below are RFC 3501 (IMAP) auth-specific error patterns
        // and common server response strings. Network errors (timeouts, DNS
        // failures, connection refused) will fall through to rethrow and be
        // surfaced as their actual cause.
        final errorMsg = authEx.toString().toLowerCase();
        const authErrorPhrases = [
          'authentication failed',
          'authentication failure',
          'authenticationfailed', // ImapException class name used by enough_mail
          'login failed',
          'invalid credentials',
          'invalid username',
          'invalid password',
          'incorrect password',
          'incorrect username',
          'bad credentials',
          'bad username or password',
          'wrong password',
          'permission denied',
          'auth=plain failed',
          'authenticate failed',
          'sasl authentication',
        ];
        final isAuthError = authErrorPhrases.any(errorMsg.contains);

        if (isAuthError) {
          LoggerService.log('AUTH_ERROR', '❌ AUTHENTICATION FAILED for ${account.username}');
          LoggerService.log('AUTH_ERROR', 'Server response: $authEx');

          final isPasswordError = errorMsg.contains('password') ||
                                   errorMsg.contains('invalid credentials') ||
                                   errorMsg.contains('authentication failed');
          final isUsernameError = errorMsg.contains('invalid username') ||
                                   errorMsg.contains('incorrect username') ||
                                   (errorMsg.contains('user') &&
                                    (errorMsg.contains('not found') || errorMsg.contains('unknown')));

          final l10nService = LocalizationService.instance;
          throw AuthenticationException(
            message: l10nService.getText(
              (l10n) => l10n.mailServiceAuthenticationFailed(account.username),
              'Authentication failed for ${account.username}: Wrong username or password'
            ),
            isLikelyPasswordError: isPasswordError,
            isLikelyUsernameError: isUsernameError,
          );
        }
        // Not an auth error — let the real exception (network, TLS, etc.) propagate
        rethrow;
      }

      // Select folder
      LoggerService.log('IMAP', 'Selecting folder: $folder');
      final mailbox = await client.selectMailboxByPath(folder);
      LoggerService.log('IMAP', '✓ Folder selected. Messages: ${mailbox.messagesExists}');

      // Check if folder has messages
      if (mailbox.messagesExists == 0) {
        LoggerService.log('IMAP', 'Folder is empty - no messages to fetch');
        await client.logout();
        return emails;
      }

      // Fetch last 50 emails
      LoggerService.log('IMAP', 'Fetching recent messages (max 50)...');
      final fetchResult = await client.fetchRecentMessages(
        messageCount: 50,
        criteria: 'BODY.PEEK[]',
      );
      LoggerService.log('IMAP', '✓ Fetched ${fetchResult.messages.length} messages');

      for (final message in fetchResult.messages) {
        try {
          final email = Email(
            messageId: message.getHeaderValue('message-id') ??
                'CORRUPT-${message.uid}-${DateTime.now().millisecondsSinceEpoch}',
            uid: message.uid,
            from: message.from?.firstOrNull?.email ?? '(Unknown Sender)',
            to: message.to?.map((a) => a.email).join(', ') ?? '(Unknown Recipient)',
            cc: message.cc?.map((a) => a.email).join(', ') ?? '',
            subject: message.decodeSubject() ?? '(No Subject)',
            date: message.decodeDate() ?? DateTime.now(),
            body: _extractEmailBody(message),
            isRead: message.isSeen,
          );

          // Extract headers for threat analysis
          for (final header in message.headers ?? []) {
            email.headers[header.name] = header.value;
          }

          // E2EE: Detect PGP/MIME at the MimeMessage level (RFC 3156).
          // Runs AFTER Email construction — overwrites the empty/fallback
          // body from _extractEmailBody with the decrypted content.
          final pgpCiphertext = PgpKeyService.extractPgpCiphertext(message);
          if (pgpCiphertext != null) {
            try {
              email.body = await PgpKeyService.decrypt(pgpCiphertext);
              email.isEncrypted = true;
              LoggerService.log('PGP',
                  '✓ Decrypted E2EE email from ${email.from}');
            } catch (ex) {
              LoggerService.logWarning('PGP',
                  'Decryption failed for ${email.messageId}: $ex');
              email.body = '[Encrypted email — decryption failed]';
              email.isEncrypted = true;
            }
          }

          // Analyze threat level
          final threatAnalysis = ThreatIntelligenceService.analyzeEmail(email);
          email.threatLevel = threatAnalysis.level;
          email.threatScore = threatAnalysis.score;
          email.threatDetails = threatAnalysis.details;

          // Extract attachments (both 'attachment' and 'inline' with filename)
          for (final part in message.allPartsFlat) {
            final disposition = part.getHeaderContentDisposition();
            final fileName = part.decodeFileName();
            final isAttachment = disposition?.disposition == ContentDisposition.attachment;
            final isInlineWithFile = disposition?.disposition == ContentDisposition.inline && fileName != null && fileName.isNotEmpty;
            // Also catch parts with a filename but no explicit disposition (some mail clients)
            final hasFileNoDisposition = disposition == null && fileName != null && fileName.isNotEmpty && part.mediaType.sub != MediaSubtype.textPlain && part.mediaType.sub != MediaSubtype.textHtml;

            if (isAttachment || isInlineWithFile || hasFileNoDisposition) {
              final data = part.decodeContentBinary();
              if (data != null) {
                email.attachments.add(EmailAttachment(
                  fileName: fileName ?? 'unknown',
                  size: data.length,
                  contentType: part.mediaType.toString(),
                  data: data,
                ));
              }
            }
          }

          emails.add(email);
        } catch (ex, stackTrace) {
          LoggerService.logError('FETCH-EMAIL', ex, stackTrace);
          continue;
        }
      }

      await client.disconnect();

      // Sort emails by date: newest first (descending)
      emails.sort((a, b) => b.date.compareTo(a.date));

      LoggerService.log('IMAP', '✓ Fetched ${emails.length} emails from $folder (sorted newest first)');
    } catch (ex, stackTrace) {
      // Ensure client is disconnected on error
      try { await client?.disconnect(); } catch (_) {}
      LoggerService.logError('IMAP', ex, stackTrace);
      rethrow;
    }

    return emails;
  }

  /// Parse comma-separated emails into list
  List<String> _parseRecipients(String to) {
    return to
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  /// Send email with attachments via SMTP
  Future<void> sendEmailWithAttachmentsAsync(
    EmailAccount account,
    String to,
    String cc,
    String bcc,
    String subject,
    String body,
    List<dynamic> attachments, {
    int? draftUid,
  }) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    // Parse multiple recipients
    final recipients = _parseRecipients(to);
    if (recipients.isEmpty) {
      final l10nService = LocalizationService.instance;
      throw Exception(l10nService.getText(
        (l10n) => l10n.mailServiceAtLeastOneRecipient,
        'At least one recipient is required'
      ));
    }

    // Parse CC recipients
    final ccRecipients = _parseRecipients(cc);

    // Parse BCC recipients (Blind Carbon Copy - hidden from other recipients)
    final bccRecipients = _parseRecipients(bcc);

    SmtpClient? smtpClient;
    try {
      // Build message with attachments
      final messageBuilder = MessageBuilder.prepareMultipartMixedMessage();
      messageBuilder.from = [MailAddress('', account.username)];
      messageBuilder.to = recipients.map((email) => MailAddress('', email)).toList();
      if (ccRecipients.isNotEmpty) {
        messageBuilder.cc = ccRecipients.map((email) => MailAddress('', email)).toList();
      }
      if (bccRecipients.isNotEmpty) {
        messageBuilder.bcc = bccRecipients.map((email) => MailAddress('', email)).toList();
      }
      messageBuilder.subject = subject;
      messageBuilder.addTextPlain(body, transferEncoding: TransferEncoding.eightBit);

      // Add attachments
      for (final attachment in attachments) {
        final fileName = attachment.name ?? 'attachment';
        var bytes = attachment.bytes;
        // On macOS, bytes can be null - read from file path instead
        if (bytes == null && attachment.path != null) {
          try {
            bytes = await File(attachment.path!).readAsBytes();
            LoggerService.log('SMTP', 'Read attachment from path: ${attachment.path} (${(bytes.length / 1024).round()} KB)');
          } catch (ex) {
            LoggerService.logWarning('SMTP', 'Failed to read attachment from path: $ex');
            continue;
          }
        }
        if (bytes != null) {
          final fileSize = (bytes.length / 1024).round();
          messageBuilder.addBinary(
            bytes,
            MediaType.guessFromFileName(fileName),
            filename: fileName,
          );
          LoggerService.log('SMTP', 'Added attachment: $fileName ($fileSize KB, ${bytes.length} bytes)');
        } else {
          LoggerService.logWarning('SMTP', 'Attachment $fileName has no bytes and no path!');
        }
      }

      // Request read receipt (MDN)
      messageBuilder.setHeader('Disposition-Notification-To', account.username);
      messageBuilder.setHeader('Return-Receipt-To', account.username);
      messageBuilder.setHeader('X-Confirm-Reading-To', account.username);

      // Request delivery status notification (DSN)
      messageBuilder.setHeader('Return-Path', account.username);
      messageBuilder.setHeader('Delivery-Status-Notification-To', account.username);
      messageBuilder.setHeader('X-Delivery-Status-Notification', 'SUCCESS,FAILURE,DELAY');

      var mimeMessage = messageBuilder.buildMimeMessage();

      // ── E2EE: Encrypt for internal @icd360s.de recipients ──────────
      final allRecipientEmails = [
        ...recipients, ...ccRecipients, ...bccRecipients,
      ];
      final allInternal = allRecipientEmails.every(
          (e) => e.endsWith('@icd360s.de'));

      // Track if we encrypted (for BCC recipient handling)
      var isEncrypted = false;

      if (allInternal && allRecipientEmails.isNotEmpty) {
        try {
          final keyMap =
              await PgpKeyService.lookupAllRecipients(allRecipientEmails);
          final allKeysFound = keyMap.values.every((k) => k != null);

          if (allKeysFound) {
            final recipientKeys = keyMap.values.toList();

            // Build inner MIME body — strip transport headers (From/To/Cc/
            // Bcc/Subject/Date/Message-ID). Only keep MIME content headers.
            // This prevents BCC leakage and follows RFC 3156 practice.
            var innerMime = mimeMessage.renderMessage();
            innerMime = innerMime.replaceAll(
                RegExp(r'^(From|To|Cc|Bcc|Subject|Date|Message-ID):.*\r?\n',
                    multiLine: true, caseSensitive: false), '');

            // Extract Date and Message-ID before replacing
            final date = mimeMessage.getHeaderValue('date') ??
                DateCodec.encodeDate(DateTime.now());
            final msgId = mimeMessage.getHeaderValue('message-id') ??
                '<${DateTime.now().millisecondsSinceEpoch}@icd360s.de>';

            final pgpMimeRaw = await PgpKeyService.buildPgpMimeMessage(
              from: account.username,
              to: to,
              cc: cc,
              subject: subject,
              date: date,
              messageId: msgId,
              innerMimeBody: innerMime,
              recipientKeys: recipientKeys,
            );

            mimeMessage = MimeMessage.parseFromText(pgpMimeRaw);
            isEncrypted = true;
            LoggerService.log('PGP',
                '✓ Encrypted for ${allRecipientEmails.length} recipients');
          } else {
            final missing = keyMap.entries
                .where((e) => e.value == null)
                .map((e) => e.key)
                .join(', ');
            LoggerService.logWarning('PGP',
                'Keys missing for: $missing — sending plaintext');
          }
        } catch (ex) {
          LoggerService.logWarning('PGP',
              'Encryption failed, sending plaintext: $ex');
        }
      }

      // Calculate total message size
      final messageSizeKB = (mimeMessage.toString().length / 1024).round();
      LoggerService.log('SMTP', 'Total message size: $messageSizeKB KB (${attachments.length} attachments)');

      // Send via SMTP with mTLS (direct SSL on port 465)
      LoggerService.log('SMTP', 'Connecting to ${account.mailServer}:${account.smtpPort} (mTLS direct SSL)...');
      smtpClient = SmtpClient(
        'mail.icd360s.de',
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await smtpClient.connectToServer(
        await resolveServer(),
        account.smtpPort,
        isSecure: true, // Direct SSL/TLS (not STARTTLS) for mTLS
      );
      LoggerService.log('SMTP', '✓ Connected to SMTP server with direct SSL/TLS (mTLS)');

      await smtpClient.ehlo();
      LoggerService.log('SMTP', '✓ EHLO completed. Server capabilities: ${smtpClient.serverInfo.capabilities.join(", ")}');

      // Check SIZE extension (max message size supported by server)
      // RFC 1870: SIZE value is in BYTES
      final sizeExtension = smtpClient.serverInfo.capabilities
          .firstWhere((cap) => cap.toUpperCase().startsWith('SIZE'), orElse: () => '');
      if (sizeExtension.isNotEmpty) {
        final maxSizeBytes = int.tryParse(sizeExtension.split(' ').last) ?? 0;
        final maxSizeKB = maxSizeBytes > 0 ? (maxSizeBytes / 1024).round() : 0;
        if (maxSizeKB > 0 && messageSizeKB > maxSizeKB) {
          final l10nService = LocalizationService.instance;
          throw Exception(l10nService.getText(
            (l10n) => l10n.mailServiceMessageTooLarge(messageSizeKB, maxSizeKB),
            'Message too large: $messageSizeKB KB (server max: $maxSizeKB KB)'
          ));
        }
        LoggerService.log('SMTP', 'Server SIZE limit: $maxSizeKB KB (message: $messageSizeKB KB) ✓');
      }

      // No need for STARTTLS - already using direct SSL/TLS

      LoggerService.log('SMTP', 'Authenticating as ${account.username}...');
      await _authenticateSmtp(smtpClient, account);
      LoggerService.log('SMTP', '✓ Authentication successful');

      // Request DSN (Delivery Status Notification) if server supports it
      final supportsDsn = smtpClient.serverInfo.supportsDsn;
      if (supportsDsn) {
        LoggerService.log('SMTP', '✓ Server supports DSN - requesting delivery notifications');
      } else {
        LoggerService.log('SMTP', '⚠ Server does not advertise DSN support');
      }

      LoggerService.log('SMTP', 'Sending message with ${attachments.length} attachments to ${recipients.length} TO, ${ccRecipients.length} CC, ${bccRecipients.length} BCC...');
      // When encrypted, PGP/MIME outer message has no BCC header —
      // pass all recipients explicitly so RCPT TO includes BCC.
      final SmtpResponse response;
      if (isEncrypted && bccRecipients.isNotEmpty) {
        final allAddresses = allRecipientEmails
            .map((e) => MailAddress('', e))
            .toList();
        response = await smtpClient.sendMessage(mimeMessage,
            recipients: allAddresses, requestDsn: supportsDsn);
      } else {
        response = await smtpClient.sendMessage(mimeMessage,
            requestDsn: supportsDsn);
      }

      LoggerService.log('SMTP', '✓ Email sent to ${recipients.length} recipient(s): ${recipients.join(", ")}');
      if (ccRecipients.isNotEmpty) {
        LoggerService.log('SMTP', '✓ CC sent to ${ccRecipients.length} recipient(s): ${ccRecipients.join(", ")}');
      }
      if (bccRecipients.isNotEmpty) {
        LoggerService.log('SMTP', '✓ BCC sent to ${bccRecipients.length} recipient(s): ${bccRecipients.join(", ")} (hidden from others)');
      }
      LoggerService.log('SMTP', 'Server accepted: ${response.responseLines}');

      await smtpClient.disconnect();

      // Save recipients to history (fast, non-blocking)
      EmailHistoryService.addRecipients(to, cc, bcc).then((_) {
        LoggerService.log('EMAIL-HISTORY', '✓ Recipients saved to history');
      });

      // Save to Sent folder (awaited to ensure it completes)
      try {
        await _saveToSentFolder(account, mimeMessage, subject, draftUid: draftUid);
      } catch (sentEx) {
        LoggerService.logWarning('SMTP', '⚠ Email sent but could not save to Sent folder: $sentEx');
      }
    } catch (ex, stackTrace) {
      // Ensure SMTP client is disconnected on error
      try { await smtpClient?.disconnect(); } catch (_) {}
      LoggerService.logError('SMTP', ex, stackTrace);
      rethrow;
    }
  }

  /// Send email via SMTP and save to Sent folder
  Future<void> sendEmailAsync(
    EmailAccount account,
    String to,
    String subject,
    String body, {
    int? draftUid,
  }) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    // Parse multiple recipients
    final recipients = _parseRecipients(to);
    if (recipients.isEmpty) {
      final l10nService = LocalizationService.instance;
      throw Exception(l10nService.getText(
        (l10n) => l10n.mailServiceAtLeastOneRecipient,
        'At least one recipient is required'
      ));
    }

    try {
      // Build message
      final messageBuilder = MessageBuilder.prepareMultipartAlternativeMessage();
      messageBuilder.from = [MailAddress('', account.username)];
      messageBuilder.to = recipients.map((email) => MailAddress('', email)).toList();
      messageBuilder.subject = subject;
      messageBuilder.addTextPlain(body, transferEncoding: TransferEncoding.eightBit);

      // Request read receipt (MDN - Lesebestätigung)
      messageBuilder.setHeader('Disposition-Notification-To', account.username);
      messageBuilder.setHeader('Return-Receipt-To', account.username);
      messageBuilder.setHeader('X-Confirm-Reading-To', account.username);

      // Request delivery status notification (DSN)
      messageBuilder.setHeader('Return-Path', account.username);
      messageBuilder.setHeader('Delivery-Status-Notification-To', account.username);
      messageBuilder.setHeader('X-Delivery-Status-Notification', 'SUCCESS,FAILURE,DELAY');

      final mimeMessage = messageBuilder.buildMimeMessage();

      // Send via SMTP with mTLS (direct SSL on port 465)
      LoggerService.log('SMTP', 'Connecting to ${account.mailServer}:${account.smtpPort} (mTLS direct SSL)...');
      final smtpClient = SmtpClient(
        'mail.icd360s.de',
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await smtpClient.connectToServer(
        await resolveServer(),
        account.smtpPort,
        isSecure: true, // Direct SSL/TLS (not STARTTLS) for mTLS
      );
      LoggerService.log('SMTP', '✓ Connected to SMTP server with direct SSL/TLS (mTLS)');

      await smtpClient.ehlo();
      LoggerService.log('SMTP', '✓ EHLO completed. Server capabilities: ${smtpClient.serverInfo.capabilities.join(", ")}');

      // No need for STARTTLS - already using direct SSL/TLS

      LoggerService.log('SMTP', 'Authenticating as ${account.username}...');
      await _authenticateSmtp(smtpClient, account);
      LoggerService.log('SMTP', '✓ Authentication successful');

      LoggerService.log('SMTP', 'Sending message to ${recipients.length} recipient(s)...');
      final response = await smtpClient.sendMessage(mimeMessage);

      LoggerService.log('SMTP', '✓ Email sent to ${recipients.length} recipient(s): ${recipients.join(", ")}');
      LoggerService.log('SMTP', 'Server accepted: ${response.responseLines}');
      LoggerService.log('SMTP', 'MDN (Lesebestätigung/Read receipt) requested');
      LoggerService.log('SMTP', 'DSN (Delivery Status Notification) requested: SUCCESS,FAILURE,DELAY');

      await smtpClient.disconnect();

      // Save recipients to history (fast)
      EmailHistoryService.addRecipients(to, '', '').then((_) {
        LoggerService.log('EMAIL-HISTORY', '✓ Recipients saved to history');
      });

      // Save to Sent folder (awaited to ensure it completes)
      try {
        await _saveToSentFolder(account, mimeMessage, subject, draftUid: draftUid);
      } catch (sentEx) {
        LoggerService.logWarning('SMTP', '⚠ Email sent but could not save to Sent folder: $sentEx');
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('SMTP', ex, stackTrace);
      rethrow;
    }
  }

  /// Save message to Sent folder and delete drafts
  Future<void> _saveToSentFolder(
    EmailAccount account,
    MimeMessage mimeMessage,
    String subject, {
    int? draftUid,
  }) async {
    LoggerService.log('IMAP-SENT', 'Saving email to Sent folder for ${account.username}...');

    final imapClient = ImapClient(
      isLogEnabled: false,
      securityContext: MtlsService.getSecurityContext(),
      onBadCertificate: MtlsService.onBadCertificate,
    );
    await imapClient.connectToServer(
      await resolveServer(),
      account.imapPort,
      isSecure: account.useSsl,
    );
    await _authenticate(imapClient, account);
    LoggerService.log('IMAP-SENT', '✓ Connected to IMAP for Sent folder save');

    // Get mailboxes
    final mailboxes = await imapClient.listMailboxes();
    LoggerService.log('IMAP-SENT', 'Found ${mailboxes.length} mailboxes: ${mailboxes.map((b) => "${b.name}(${b.path})").join(", ")}');

    Mailbox? sentMailbox;

    // Find Sent folder
    for (final box in mailboxes) {
      if (box.hasFlag(MailboxFlag.sent) ||
          box.name.toLowerCase() == 'sent' ||
          box.path.toLowerCase().contains('sent')) {
        sentMailbox = box;
        LoggerService.log('IMAP-SENT', 'Found Sent mailbox: name=${box.name}, path=${box.path}');
        break;
      }
    }

    if (sentMailbox != null) {
      final msgSize = (mimeMessage.toString().length / 1024).round();
      LoggerService.log('IMAP-SENT', 'Appending message ($msgSize KB) to Sent folder...');
      await imapClient.appendMessage(
        mimeMessage,
        targetMailbox: sentMailbox,
        flags: [MessageFlags.seen],
      );
      LoggerService.log('IMAP-SENT', '✓ Email saved to Sent folder ($msgSize KB)');
    } else {
      LoggerService.log('IMAP-SENT', '⚠ Sent mailbox NOT FOUND!');
      throw Exception('Sent mailbox not found on server');
    }

    // Delete the draft this email was composed from (by UID — no search needed).
    // SECURITY: Using the UID returned from saveDraftAsync eliminates the need
    // to search the Drafts folder by SUBJECT, which previously interpolated
    // attacker-influenceable content into the IMAP command.
    if (draftUid != null) {
      try {
        Mailbox? draftsMailbox;
        for (final box in mailboxes) {
          if (box.hasFlag(MailboxFlag.drafts) ||
              box.name.toLowerCase() == 'drafts' ||
              box.path.toLowerCase().contains('drafts')) {
            draftsMailbox = box;
            break;
          }
        }

        if (draftsMailbox != null) {
          await imapClient.selectMailbox(draftsMailbox);
          final sequence = MessageSequence();
          sequence.add(draftUid);
          await imapClient.uidStore(
            sequence,
            [MessageFlags.deleted],
            action: StoreAction.add,
          );
          await imapClient.expunge();
          LoggerService.log('IMAP', '✓ Deleted draft UID $draftUid after sending');
        }
      } catch (draftEx) {
        LoggerService.log('IMAP-DRAFT', 'Could not delete draft UID $draftUid: $draftEx');
      }
    }

    await imapClient.disconnect();
  }

  /// Send read receipt (MDN) for an email
  Future<void> sendReadReceiptAsync(
    EmailAccount account,
    Email originalEmail,
    String receiptTo,
  ) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    try {
      // Create MDN message
      final messageBuilder = MessageBuilder.prepareMultipartAlternativeMessage();
      messageBuilder.from = [MailAddress('', account.username)];
      messageBuilder.to = [MailAddress('', receiptTo)];
      messageBuilder.subject = 'Read: ${originalEmail.subject}';

      final mdnBody = '''Your message:

To: ${originalEmail.to}
Subject: ${originalEmail.subject}
Sent: ${originalEmail.date.toString()}

was displayed on ${DateTime.now().toString()} by ${account.username}.

This is a read receipt (Lesebestätigung/MDN) confirming your message was opened.''';

      messageBuilder.addTextPlain(mdnBody, transferEncoding: TransferEncoding.eightBit);

      // Add MDN headers
      messageBuilder.setHeader('Disposition-Notification-To', receiptTo);
      messageBuilder.setHeader('Original-Message-ID', originalEmail.messageId);
      messageBuilder.setHeader('X-MSMail-Priority', 'Normal');
      messageBuilder.setHeader('X-Mailer', 'ICD360S Mail Client');

      final mimeMessage = messageBuilder.buildMimeMessage();

      // Send MDN with mTLS (direct SSL on port 465)
      final smtpClient = SmtpClient(
        'mail.icd360s.de',
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await smtpClient.connectToServer(
        await resolveServer(),
        account.smtpPort,
        isSecure: true, // Direct SSL/TLS for mTLS
      );

      await smtpClient.ehlo();

      await _authenticateSmtp(smtpClient, account);
      await smtpClient.sendMessage(mimeMessage);

      LoggerService.log('MDN', '✓ Read receipt sent to $receiptTo');

      await smtpClient.disconnect();
    } catch (ex, stackTrace) {
      LoggerService.logError('MDN', ex, stackTrace);
      rethrow;
    }
  }

  /// Save draft email to Drafts folder (with optional attachments)
  /// Returns the UID of the saved draft (for deleting it on next save)
  Future<int?> saveDraftAsync(
    EmailAccount account,
    String to,
    String cc,
    String bcc,
    String subject,
    String body, {
    List<dynamic> attachments = const [],
    int? previousDraftUid,
  }) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    try {
      // Use multipart mixed when there are attachments, simple builder for text-only
      final messageBuilder = attachments.isNotEmpty
          ? MessageBuilder.prepareMultipartMixedMessage()
          : MessageBuilder();
      messageBuilder.from = [MailAddress('', account.username)];
      if (to.isNotEmpty) {
        final recipients = _parseRecipients(to);
        if (recipients.isNotEmpty) {
          messageBuilder.to = recipients.map((email) => MailAddress('', email)).toList();
        }
      }
      if (cc.isNotEmpty) {
        final ccRecipients = _parseRecipients(cc);
        if (ccRecipients.isNotEmpty) {
          messageBuilder.cc = ccRecipients.map((email) => MailAddress('', email)).toList();
        }
      }
      if (bcc.isNotEmpty) {
        final bccRecipients = _parseRecipients(bcc);
        if (bccRecipients.isNotEmpty) {
          messageBuilder.bcc = bccRecipients.map((email) => MailAddress('', email)).toList();
        }
      }
      messageBuilder.subject = subject.isEmpty ? '(No Subject)' : subject;
      messageBuilder.addTextPlain(body, transferEncoding: TransferEncoding.eightBit);

      // Add attachments if present
      for (final attachment in attachments) {
        final fileName = attachment.name ?? 'attachment';
        var bytes = attachment.bytes;
        if (bytes == null && attachment.path != null) {
          try {
            bytes = await File(attachment.path!).readAsBytes();
            LoggerService.log('DRAFT-SAVE', 'Read attachment from path: ${attachment.path} (${(bytes.length / 1024).round()} KB)');
          } catch (ex) {
            LoggerService.logWarning('DRAFT-SAVE', 'Failed to read attachment from path: $ex');
            continue;
          }
        }
        if (bytes != null) {
          messageBuilder.addBinary(
            bytes,
            MediaType.guessFromFileName(fileName),
            filename: fileName,
          );
          LoggerService.log('DRAFT-SAVE', 'Added attachment: $fileName (${(bytes.length / 1024).round()} KB)');
        } else {
          LoggerService.logWarning('DRAFT-SAVE', 'Attachment $fileName has no bytes and no path!');
        }
      }

      final mimeMessage = messageBuilder.buildMimeMessage();

      // Save to Drafts via IMAP with mTLS
      final imapClient = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await imapClient.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(imapClient, account);

      // Find Drafts folder
      final mailboxes = await imapClient.listMailboxes();
      Mailbox? draftsMailbox;

      for (final box in mailboxes) {
        if (box.hasFlag(MailboxFlag.drafts) ||
            box.name.toLowerCase() == 'drafts' ||
            box.path.toLowerCase().contains('drafts')) {
          draftsMailbox = box;
          break;
        }
      }

      int? newDraftUid;
      if (draftsMailbox != null) {
        await imapClient.selectMailbox(draftsMailbox);

        // Delete previous draft by UID if we have one
        if (previousDraftUid != null) {
          try {
            final sequence = MessageSequence.fromId(previousDraftUid, isUid: true);
            await imapClient.uidStore(
              sequence,
              [MessageFlags.deleted],
              action: StoreAction.add,
            );
            await imapClient.expunge();
            LoggerService.log('DRAFT-SAVE', 'Deleted previous draft UID $previousDraftUid');
          } catch (ex) {
            LoggerService.logWarning('DRAFT-SAVE', 'Could not delete previous draft UID $previousDraftUid: $ex');
          }
        }

        // Append new draft and get its UID
        final appendResponse = await imapClient.appendMessage(
          mimeMessage,
          targetMailbox: draftsMailbox,
          flags: [MessageFlags.draft],
        );

        // Try to get the UID of the appended message
        final uidList = appendResponse.responseCodeAppendUid?.targetSequence.toList();
        if (uidList != null && uidList.isNotEmpty) {
          newDraftUid = uidList.last;
        }
        LoggerService.log('DRAFT-SAVE', '✓ Draft saved${newDraftUid != null ? ' (UID $newDraftUid)' : ''}');
      }

      await imapClient.disconnect();
      return newDraftUid;
    } catch (ex, stackTrace) {
      LoggerService.logError('DRAFT-SAVE', ex, stackTrace);
      return null;
    }
  }

  /// Move email between folders
  Future<void> moveEmailAsync(
    EmailAccount account,
    String messageId,
    String fromFolder,
    String toFolder, {
    int? uid,
  }) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    try {
      final client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(client, account);

      // Open source folder
      await client.selectMailboxByPath(fromFolder);

      // Handle missing MessageId
      if (messageId.isEmpty || messageId == 'null') {
        LoggerService.log('IMAP-ERROR',
            'Cannot move email: MessageId is null or empty (corrupt email?)');
        final l10nService = LocalizationService.instance;
        throw Exception(l10nService.getText(
          (l10n) => l10n.mailServiceEmailCorrupt,
          'Email MessageId is missing. This email may be corrupt and cannot be moved.'
        ));
      }

      // Search for message - prefer UID (reliable) over Message-ID header search
      MessageSequence? sequence;
      bool useUid = false;

      if (uid != null) {
        // Use UID directly - most reliable method
        LoggerService.log('IMAP', 'Using UID $uid to find email');
        sequence = MessageSequence();
        sequence.add(uid);
        useUid = true;
      } else if (messageId.startsWith('CORRUPT-')) {
        // Extract UID from corrupt MessageId format: CORRUPT-{UID}-{timestamp}
        final parts = messageId.split('-');
        if (parts.length >= 2) {
          final uidValue = int.tryParse(parts[1]);
          if (uidValue != null) {
            LoggerService.log('IMAP', 'Handling corrupt email with UID: $uidValue');
            sequence = MessageSequence();
            sequence.add(uidValue);
            useUid = true;
          }
        }
      } else {
        // Fallback: Search by MessageId header (only when UID is unavailable —
        // e.g. for older emails saved before the uid field was added to Email).
        // SECURITY: messageId comes from received-mail headers (attacker-controlled).
        // _imapQuote() prevents IMAP injection via crafted Message-ID values.
        // The fallback should be rare; log it so we can monitor.
        LoggerService.log('IMAP-MOVE',
            '⚠ Using Message-ID search fallback (no UID available for $messageId)');
        final searchResult = await client.searchMessages(
          searchCriteria: 'HEADER Message-ID ${_imapQuote(messageId)}',
        );
        sequence = searchResult.matchingSequence;
      }

      if (sequence != null && sequence.isNotEmpty) {
        // Get target mailbox
        final mailboxes = await client.listMailboxes();
        Mailbox? targetMailbox;

        for (final box in mailboxes) {
          if (box.path == toFolder || box.name == toFolder) {
            targetMailbox = box;
            break;
          }
        }

        if (targetMailbox != null) {
          // Move message (copy + delete original)
          if (useUid) {
            await client.uidCopy(sequence, targetMailbox: targetMailbox);
            await client.uidStore(
              sequence,
              [MessageFlags.deleted],
              action: StoreAction.add,
            );
          } else {
            await client.copy(sequence, targetMailbox: targetMailbox);
            await client.store(
              sequence,
              [MessageFlags.deleted],
              action: StoreAction.add,
            );
          }
          await client.expunge();
          LoggerService.log('IMAP', 'Moved email $messageId from $fromFolder to $toFolder (uid: $uid)');
        }
      } else {
        LoggerService.log('IMAP', 'Email $messageId not found in $fromFolder');
        final l10nService = LocalizationService.instance;
        throw Exception(l10nService.getText(
          (l10n) => l10n.mailServiceEmailNotFound(fromFolder),
          'Email not found in $fromFolder. It may have been already moved or deleted.'
        ));
      }

      await client.disconnect();
    } catch (ex, stackTrace) {
      LoggerService.logError('IMAP', ex, stackTrace);
      rethrow;
    }
  }

  /// Delete email (move to Trash)
  Future<void> deleteEmailAsync(
    EmailAccount account,
    String messageId,
    String folder, {
    int? uid,
  }) async {
    await moveEmailAsync(account, messageId, folder, 'Trash', uid: uid);
  }

  /// Permanently delete email (expunge immediately)
  Future<void> permanentDeleteEmailAsync(
    EmailAccount account,
    String messageId,
    String folder, {
    int? uid,
  }) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    try {
      final client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(client, account);

      await client.selectMailboxByPath(folder);

      // Search for message - prefer UID
      MessageSequence? sequence;
      bool useUid = false;

      if (uid != null) {
        LoggerService.log('IMAP', 'Using UID $uid for permanent delete');
        sequence = MessageSequence();
        sequence.add(uid);
        useUid = true;
      } else if (messageId.startsWith('CORRUPT-')) {
        final parts = messageId.split('-');
        if (parts.length >= 2) {
          final uidValue = int.tryParse(parts[1]);
          if (uidValue != null) {
            sequence = MessageSequence();
            sequence.add(uidValue);
            useUid = true;
          }
        }
      } else {
        // Fallback path — should be rare (UID is always set for modern Email instances).
        // SECURITY: messageId is attacker-controlled (from received headers).
        // _imapQuote() prevents IMAP injection.
        LoggerService.log('IMAP-DELETE',
            '⚠ Using Message-ID search fallback for permanent delete (no UID for $messageId)');
        final searchResult = await client.searchMessages(
          searchCriteria: 'HEADER Message-ID ${_imapQuote(messageId)}',
        );
        sequence = searchResult.matchingSequence;
      }

      if (sequence != null && sequence.isNotEmpty) {
        // Mark as deleted and expunge immediately
        if (useUid) {
          await client.uidStore(
            sequence,
            [MessageFlags.deleted],
            action: StoreAction.add,
          );
        } else {
          await client.store(
            sequence,
            [MessageFlags.deleted],
            action: StoreAction.add,
          );
        }
        await client.expunge();
        LoggerService.log('IMAP', 'PERMANENTLY deleted email $messageId from $folder (uid: $uid)');
      }

      await client.disconnect();
    } catch (ex, stackTrace) {
      LoggerService.logError('IMAP', ex, stackTrace);
      rethrow;
    }
  }

  /// Mark email as spam (move to Junk/Spam)
  Future<void> markAsSpamAsync(
    EmailAccount account,
    String messageId,
    String folder, {
    int? uid,
  }) async {
    try {
      await moveEmailAsync(account, messageId, folder, 'Junk', uid: uid);
    } catch (_) {
      // If Junk doesn't exist, try Spam
      await moveEmailAsync(account, messageId, folder, 'Spam', uid: uid);
    }
  }

  /// Get list of folders from IMAP server
  Future<List<String>> getFoldersAsync(EmailAccount account) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    final folders = <String>[];

    try {
      final client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(client, account);

      // List all mailboxes.
      //
      // v2.30.7: filter out mailboxes flagged \NoSelect at the IMAP
      // LIST level. Dovecot (and Cyrus, others) advertise namespace
      // placeholders and legacy/virtual mailboxes in LIST that
      // cannot actually be SELECT-ed — we observed an i***@ account
      // where Dovecot returned "Spam" in LIST but SELECT failed
      // with "Mailbox doesn't exist". Trusting LIST attributes
      // (RFC 3501 §7.2.2) is the canonical fix; the per-folder
      // try/catch added in email_provider.dart is defense in depth
      // for any remaining edge cases (race conditions, mailboxes
      // deleted between LIST and SELECT, etc.).
      final mailboxes = await client.listMailboxes();

      for (final mailbox in mailboxes) {
        if (mailbox.isUnselectable) {
          LoggerService.log('IMAP',
              'Skipping \\NoSelect mailbox: "${mailbox.name}"');
          continue;
        }
        folders.add(mailbox.name);
      }

      await client.disconnect();
    } catch (ex, stackTrace) {
      LoggerService.logError('IMAP', ex, stackTrace);
      rethrow;
    }

    return folders;
  }

  /// Get message count for a folder
  Future<int> getFolderCountAsync(
    EmailAccount account,
    String folderName,
  ) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    int count = 0;

    try {
      final client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(client, account);

      final mailbox = await client.selectMailboxByPath(folderName);
      count = mailbox.messagesExists;

      await client.disconnect();
    } catch (ex, stackTrace) {
      LoggerService.logError('IMAP', ex, stackTrace);
      rethrow;
    }

    return count;
  }

  /// Get mailbox quota information (used space / limit)
  /// Returns map with 'usedKB', 'limitKB', 'percentage'
  Future<Map<String, dynamic>?> getQuotaAsync(EmailAccount account) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    try {
      final client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(client, account);

      // Get quota using enough_mail's getQuotaRoot method
      final quotaResult = await client.getQuotaRoot(mailboxName: 'INBOX');

      await client.disconnect();

      // Extract STORAGE quota from result
      if (quotaResult.quotaRoots.isNotEmpty) {
        // Get first quota root
        final quota = quotaResult.quotaRoots.values.first;

        // Find STORAGE resource limit
        final storageLimit = quota.resourceLimits.firstWhere(
          (limit) => limit.name == 'STORAGE',
          orElse: () => throw Exception('No STORAGE quota found'),
        );

        final usedKB = storageLimit.currentUsage?.toInt() ?? 0;
        final limitKB = storageLimit.usageLimit?.toInt() ?? 0;

        if (limitKB > 0) {
          final percentage = (usedKB / limitKB) * 100;
          final usedMB = (usedKB / 1024).toStringAsFixed(1);
          final limitMB = (limitKB / 1024).toStringAsFixed(0);

          LoggerService.log('QUOTA',
              '${account.username}: $usedMB MB / $limitMB MB (${percentage.toStringAsFixed(1)}%)');

          return {
            'usedKB': usedKB,
            'limitKB': limitKB,
            'percentage': percentage,
            'usedMB': usedMB,
            'limitMB': limitMB,
          };
        }
      }

      return null;
    } catch (ex, stackTrace) {
      LoggerService.logError('QUOTA', ex, stackTrace);
      return null;
    }
  }

  /// Check target server max message size (SIZE extension)
  /// Conservative SMTP attachment size limit used to pre-warn users before
  /// they spend time composing a large email that the recipient's server
  /// will reject. 25 MB is the de facto standard ceiling — Gmail, Outlook,
  /// Yahoo, ProtonMail, and most providers accept up to that, very few
  /// accept more.
  ///
  /// SECURITY (L7): The previous implementation contacted the recipient's
  /// MX server on cleartext port 25, sent EHLO, and parsed the SIZE
  /// extension. That:
  ///   - Leaked the user's IP and "I'm about to email <domain>" intent to
  ///     arbitrary attacker-controllable hosts.
  ///   - Used cleartext SMTP (no STARTTLS), so any on-path observer saw
  ///     the same metadata.
  ///   - Performed a network operation per recipient, slowing compose UI.
  ///
  /// We now return a hardcoded conservative limit and let the actual SMTP
  /// send produce a precise error if the receiving server is below that.
  static const int _conservativeMaxSizeMB = 25;

  /// Returns the conservative max attachment size for a recipient domain.
  /// The `domain` argument is unused but kept for API compatibility with
  /// existing callers.
  // ignore: avoid_unused_parameter, prefer_function_declarations_over_variables
  Future<int?> checkTargetServerMaxSize(String domain) async {
    return _conservativeMaxSizeMB;
  }

  /// Clean Trash folder - permanently delete emails older than specified days
  /// Uses TrashTrackerService to determine when emails were moved to Trash
  /// Returns the number of emails deleted
  Future<int> cleanTrashAsync(EmailAccount account, {int olderThanDays = 30}) async {
    // SECURITY: Validate server before connecting
    _validateAccount(account);

    // Skip silently if no certificate is available for this account.
    // Trash cleanup runs on every startup for every account; logging a stack
    // trace per account when certs aren't loaded yet (or auth failed) creates
    // a flood of identical errors that hide real problems.
    if (!CertificateService.hasCertificates ||
        CertificateService.currentUsername != account.username) {
      return 0;
    }
    // NOTE (v2.27.0): the legacy `account.password == null` guard was
    // removed here. With Faza 3 (passwordless add-account flow), some
    // accounts have a null password and authenticate purely via SASL
    // EXTERNAL with the mTLS cert. The cert is what makes the IMAP
    // session work, not the password — `_authenticate()` already
    // selects the right mechanism.

    int deletedCount = 0;

    try {
      final client = ImapClient(
        isLogEnabled: false,
        securityContext: MtlsService.getSecurityContext(),
        onBadCertificate: MtlsService.onBadCertificate,
      );
      await client.connectToServer(
        await resolveServer(),
        account.imapPort,
        isSecure: account.useSsl,
      );
      await _authenticate(client, account);

      // Find Trash folder
      final mailboxes = await client.listMailboxes();
      Mailbox? trashMailbox;

      for (final box in mailboxes) {
        if (box.hasFlag(MailboxFlag.trash) ||
            box.name.toLowerCase() == 'trash' ||
            box.path.toLowerCase().contains('trash')) {
          trashMailbox = box;
          break;
        }
      }

      if (trashMailbox == null) {
        LoggerService.log('TRASH_CLEANUP', 'No Trash folder found');
        await client.disconnect();
        return 0;
      }

      final mailbox = await client.selectMailbox(trashMailbox);
      LoggerService.log('TRASH_CLEANUP', 'Selected Trash folder: ${trashMailbox.path} (${mailbox.messagesExists} messages)');

      if (mailbox.messagesExists == 0) {
        LoggerService.log('TRASH_CLEANUP', 'Trash folder is empty');
        await client.disconnect();
        return 0;
      }

      // Fetch all messages with their Message-ID and date
      final fetchResult = await client.fetchMessages(
        MessageSequence.fromRangeToLast(1),
        '(ENVELOPE)',
      );

      final toDelete = <int>[];
      final now = DateTime.now();

      for (final msg in fetchResult.messages) {
        final messageId = msg.envelope?.messageId ?? 'UID-${msg.uid}';
        final emailDate = msg.envelope?.date ?? now;

        // Check if email should be deleted based on tracker or fallback to email date
        final daysRemaining = TrashTrackerService.getDaysUntilDeletion(messageId, emailDate, retentionDays: olderThanDays);

        if (daysRemaining <= 0) {
          toDelete.add(msg.sequenceId ?? 0);
          LoggerService.log('TRASH_CLEANUP', 'Will delete: $messageId (0 days remaining)');
          // Remove from tracker
          await TrashTrackerService.removeTracking(messageId);
        }
      }

      if (toDelete.isNotEmpty) {
        deletedCount = toDelete.length;
        LoggerService.log('TRASH_CLEANUP', 'Found $deletedCount emails to permanently delete');

        // Create sequence and delete
        final sequence = MessageSequence();
        for (final id in toDelete) {
          if (id > 0) sequence.add(id);
        }

        if (sequence.isNotEmpty) {
          await client.store(
            sequence,
            [MessageFlags.deleted],
            action: StoreAction.add,
          );
          await client.expunge();
          LoggerService.log('TRASH_CLEANUP', '✓ Permanently deleted $deletedCount emails from Trash');
        }
      } else {
        LoggerService.log('TRASH_CLEANUP', 'No emails ready for deletion (all within $olderThanDays-day retention)');
      }

      // Cleanup old tracker entries
      await TrashTrackerService.cleanupOldEntries(retentionDays: olderThanDays);

      await client.disconnect();
    } catch (ex, stackTrace) {
      LoggerService.logError('TRASH_CLEANUP', ex, stackTrace);
      // Don't rethrow - this is a background cleanup operation
    }

    return deletedCount;
  }
}



