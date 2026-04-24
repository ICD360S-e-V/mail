// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:path/path.dart' as p;
import 'package:url_launcher/url_launcher.dart';
import 'package:printing/printing.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import '../utils/l10n_helper.dart';
import '../utils/safe_filename.dart';
import '../models/models.dart';
import '../providers/email_provider.dart';
import '../services/attachment_scan_service.dart';
import '../services/notification_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import 'compose_window.dart';
import 'attachment_viewer_window.dart';
import '../utils/phishing_detector.dart';
import '../utils/html_to_plain_text.dart';
import '../utils/safe_html_renderer.dart';
import '../utils/text_safety.dart';

/// Email viewer window
class EmailViewer extends StatefulWidget {
  final Email email;

  const EmailViewer({super.key, required this.email});

  @override
  State<EmailViewer> createState() => _EmailViewerState();
}

class _EmailViewerState extends State<EmailViewer> {
  final List<TapGestureRecognizer> _recognizers = [];

  /// Whether the user has opted to load remote images for this email.
  bool _allowRemoteContent = false;

  @override
  void initState() {
    super.initState();
    // Trigger AV scan on all attachments when email is opened.
    if (widget.email.attachments.isNotEmpty) {
      AttachmentScanService.scanAll(
        widget.email,
        onProgress: () {
          if (mounted) setState(() {});
        },
      );
    }
  }

  @override
  void dispose() {
    for (final recognizer in _recognizers) {
      recognizer.dispose();
    }
    super.dispose();
  }

  /// Strip HTML tags from text for plain text display
  String _stripHtmlTags(String html) {
    // Remove script and style tags with their content
    var text = html.replaceAll(RegExp(r'<script[^>]*>[\s\S]*?</script>', caseSensitive: false), '');
    text = text.replaceAll(RegExp(r'<style[^>]*>[\s\S]*?</style>', caseSensitive: false), '');

    // Replace common block elements with newlines
    text = text.replaceAll(RegExp(r'<br\s*/?>', caseSensitive: false), '\n');
    text = text.replaceAll(RegExp(r'</p>', caseSensitive: false), '\n\n');
    text = text.replaceAll(RegExp(r'</div>', caseSensitive: false), '\n');
    text = text.replaceAll(RegExp(r'</tr>', caseSensitive: false), '\n');
    text = text.replaceAll(RegExp(r'</li>', caseSensitive: false), '\n');
    text = text.replaceAll(RegExp(r'<li[^>]*>', caseSensitive: false), '• ');

    // Remove all remaining HTML tags
    text = text.replaceAll(RegExp(r'<[^>]+>'), '');

    // Decode HTML entities
    text = _decodeHtmlEntities(text);

    // Clean up whitespace
    text = text.replaceAll(RegExp(r'\n\s*\n\s*\n+'), '\n\n'); // Max 2 newlines
    text = text.trim();

    return text;
  }

  /// Rejoin URLs that were broken by quoted-printable line wrapping
  String _rejoinBrokenUrls(String text) {
    // Fix URLs broken by soft line breaks (=\r\n or =\n from quoted-printable)
    text = text.replaceAll(RegExp(r'=\r?\n'), '');
    // Fix URLs broken by line wrap mid-URL (https://...long\npath continues)
    // Rejoin if next line starts with URL-like characters (letters, numbers, /, ?, &, =, %, -, _, .)
    text = text.replaceAllMapped(
      RegExp(r'(https?://[^\s<>"]+)\r?\n([a-zA-Z0-9_./?&=#%\-][^\s<>"]*)'),
      (match) => '${match.group(1)}${match.group(2)}',
    );
    return text;
  }

  /// Build rich text with clickable URLs
  TextSpan _buildClickableText(String text, TextStyle? baseStyle) {
    // Decode HTML entities first (e.g., &amp; -> &, &#39; -> ')
    final decodedText = _rejoinBrokenUrls(_decodeHtmlEntities(text));

    // URL regex pattern - allow brackets [] in URLs (common in reference-style links)
    final urlPattern = RegExp(
      r'https?://[^\s<>\"]+',
      caseSensitive: false,
    );

    final spans = <InlineSpan>[];
    int lastEnd = 0;

    for (final match in urlPattern.allMatches(decodedText)) {
      // Add text before the URL
      if (match.start > lastEnd) {
        spans.add(TextSpan(
          text: decodedText.substring(lastEnd, match.start),
          style: baseStyle,
        ));
      }

      // Add clickable URL
      final url = match.group(0)!;
      final recognizer = TapGestureRecognizer()
        ..onTap = () => _openUrlInExternalBrowser(url);
      _recognizers.add(recognizer);

      spans.add(TextSpan(
        text: url,
        style: baseStyle?.copyWith(
          color: Colors.blue,
          decoration: TextDecoration.underline,
        ),
        recognizer: recognizer,
      ));

      lastEnd = match.end;
    }

    // Add remaining text after last URL
    if (lastEnd < decodedText.length) {
      spans.add(TextSpan(
        text: decodedText.substring(lastEnd),
        style: baseStyle,
      ));
    }

    return TextSpan(children: spans);
  }

  /// Decode HTML entities in text
  String _decodeHtmlEntities(String text) {
    // Decode numeric HTML entities (&#NNN; and &#xHHH;)
    text = text.replaceAllMapped(RegExp(r'&#(\d+);'), (match) {
      final code = int.tryParse(match.group(1)!);
      if (code != null && code > 0 && code <= 0x10FFFF) {
        return String.fromCharCode(code);
      }
      return match.group(0)!;
    });
    text = text.replaceAllMapped(RegExp(r'&#x([0-9a-fA-F]+);'), (match) {
      final code = int.tryParse(match.group(1)!, radix: 16);
      if (code != null && code > 0 && code <= 0x10FFFF) {
        return String.fromCharCode(code);
      }
      return match.group(0)!;
    });
    // Decode named HTML entities
    return text
        .replaceAll('&amp;', '&')
        .replaceAll('&lt;', '<')
        .replaceAll('&gt;', '>')
        .replaceAll('&quot;', '"')
        .replaceAll('&apos;', "'")
        .replaceAll('&nbsp;', ' ')
        .replaceAll('&auml;', 'ä')
        .replaceAll('&ouml;', 'ö')
        .replaceAll('&uuml;', 'ü')
        .replaceAll('&Auml;', 'Ä')
        .replaceAll('&Ouml;', 'Ö')
        .replaceAll('&Uuml;', 'Ü')
        .replaceAll('&szlig;', 'ß')
        .replaceAll('&euro;', '€')
        .replaceAll('&copy;', '©')
        .replaceAll('&reg;', '®')
        .replaceAll('&trade;', '™')
        .replaceAll('&ndash;', '–')
        .replaceAll('&mdash;', '—')
        .replaceAll('&laquo;', '«')
        .replaceAll('&raquo;', '»')
        .replaceAll('&bull;', '•')
        .replaceAll('&hellip;', '…');
  }

  /// Open URL in external system browser (cross-platform)
  /// Extract the domain from a URL string, or null if not parseable.
  static String? _extractDomain(String url) {
    try {
      return Uri.parse(url).host.toLowerCase();
    } catch (_) {
      return null;
    }
  }

  /// Returns true if [text] looks like a URL (contains a domain pattern
  /// with a TLD, or starts with http/https).
  static bool _looksLikeUrl(String text) {
    final t = text.trim().toLowerCase();
    return t.startsWith('http://') ||
        t.startsWith('https://') ||
        RegExp(r'^[a-z0-9.-]+\.[a-z]{2,}(/|$)').hasMatch(t);
  }

  /// Show a confirmation dialog before opening any external link.
  ///
  /// SECURITY (1.3): Phishing defense. HTML emails can display
  /// "https://paypal.com" as link text but point to "https://evil.com".
  /// This dialog ALWAYS shows the REAL destination URL so the user
  /// can verify before opening. If the visible text looks like a
  /// different domain, a prominent warning is shown.
  Future<bool> _showLinkConfirmDialog(String actualUrl, {String? displayText, PhishingResult? phishingResult}) async {
    final actualDomain = _extractDomain(actualUrl);
    final textDomain = (displayText != null && _looksLikeUrl(displayText))
        ? _extractDomain(displayText.startsWith('http')
            ? displayText
            : 'https://$displayText')
        : null;
    final isDomainMismatch = textDomain != null &&
        actualDomain != null &&
        textDomain != actualDomain;
    final isDangerous = isDomainMismatch ||
        (phishingResult?.isDangerous ?? false);

    if (!mounted) return false;
    final theme = FluentTheme.of(context);

    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => ContentDialog(
        title: Row(
          children: [
            Semantics(
              excludeSemantics: true,
              child: Icon(
                isDangerous ? FluentIcons.warning : FluentIcons.open_in_new_window,
                size: 20,
                color: isDangerous ? Colors.red : theme.accentColor,
              ),
            ),
            const SizedBox(width: 8),
            Text(isDangerous
                ? 'Suspicious link detected!'
                : 'Open external link?'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (isDomainMismatch) ...[
              Container(
                padding: const EdgeInsets.all(10),
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(
                  color: Colors.red.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: Colors.red.withValues(alpha: 0.3)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'The link text shows a different domain than the actual URL. '
                      'This is a common phishing technique.',
                      style: TextStyle(
                        color: Colors.red,
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text('Link text domain: $textDomain',
                        style: const TextStyle(fontSize: 12)),
                    Text('Actual domain: $actualDomain',
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                  ],
                ),
              ),
            ],
            // Layer 2+3 phishing warnings
            if (phishingResult != null && phishingResult.warnings.isNotEmpty) ...[
              Container(
                padding: const EdgeInsets.all(10),
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(
                  color: phishingResult.isDangerous
                      ? Colors.red.withValues(alpha: 0.1)
                      : Colors.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(
                    color: phishingResult.isDangerous
                        ? Colors.red.withValues(alpha: 0.3)
                        : Colors.orange.withValues(alpha: 0.3),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: phishingResult.warnings.map((w) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Semantics(
                          excludeSemantics: true,
                          child: Icon(
                            w.severity == WarningSeverity.critical || w.severity == WarningSeverity.high
                                ? FluentIcons.warning
                                : FluentIcons.info,
                            size: 14,
                            color: w.severity == WarningSeverity.critical || w.severity == WarningSeverity.high
                                ? Colors.red
                                : Colors.orange,
                          ),
                        ),
                        const SizedBox(width: 6),
                        Expanded(child: Text(w.message,
                            style: const TextStyle(fontSize: 12))),
                      ],
                    ),
                  )).toList(),
                ),
              ),
            ],
            const Text('This link will open in your browser:',
                style: TextStyle(fontSize: 13)),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: theme.micaBackgroundColor,
                borderRadius: BorderRadius.circular(4),
              ),
              child: SelectableText(
                actualUrl,
                style: TextStyle(
                  fontSize: 12,
                  fontFamily: 'monospace',
                  color: isDangerous ? Colors.red : null,
                ),
              ),
            ),
          ],
        ),
        actions: [
          Button(
            child: const Text('Cancel'),
            onPressed: () => Navigator.of(ctx).pop(false),
          ),
          FilledButton(
            style: isDangerous
                ? ButtonStyle(backgroundColor: WidgetStateProperty.all(Colors.red))
                : null,
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(isDangerous
                ? 'Open anyway (dangerous)'
                : 'Open in browser'),
          ),
        ],
      ),
    );
    return result == true;
  }

  Future<void> _openUrlInExternalBrowser(String url, {String? displayText}) async {
    // Decode HTML entities in URL (e.g., &amp; -> &)
    final decodedUrl = _decodeHtmlEntities(url);

    // SECURITY (1.3): Run multi-layer phishing analysis then show
    // confirmation dialog with real URL + any warnings.
    final result = await PhishingDetector.analyze(decodedUrl);
    final confirmed = await _showLinkConfirmDialog(decodedUrl, displayText: displayText, phishingResult: result);
    if (!confirmed) {
      LoggerService.log('EMAIL_VIEWER', 'User cancelled opening URL: $decodedUrl');
      return;
    }

    LoggerService.log('EMAIL_VIEWER', 'Opening URL in external browser: $decodedUrl');
    try {
      final uri = Uri.parse(decodedUrl);
      if (await canLaunchUrl(uri)) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      } else {
        throw Exception('Could not launch $decodedUrl');
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('BROWSER', ex, stackTrace);
      if (!mounted) return;
      final l10n = l10nOf(context);
      NotificationService.showErrorToast(l10n.errorTitle, ex.toString());
    }
  }

  /// Check if email body is HTML.
  ///
  /// v2.30.2 fix: the previous heuristic required either `<!doctype`,
  /// `<html`, or BOTH `<body>` AND `<head>` — which missed all HTML
  /// FRAGMENTS sent by modern editors (CKEditor, Gmail compose,
  /// Outlook Web, Microsoft support tooling). Those start directly
  /// with `<div>`, `<span>`, `<p>`, etc. and were rendered as raw
  /// text in the message view.
  ///
  /// New logic:
  ///   1. Trim leading whitespace
  ///   2. Full document: `<!doctype` or `<html`
  ///   3. Document with body: `<body`
  ///   4. Fragment starting with any opening tag: `<` + letter
  ///   5. Body containing common block tags anywhere
  bool _isHtmlEmail(String body) {
    final trimmed = body.trimLeft();
    if (trimmed.isEmpty) return false;
    final lower = trimmed.toLowerCase();
    if (lower.startsWith('<!doctype') || lower.startsWith('<html')) {
      return true;
    }
    if (lower.contains('<body')) return true;
    // Fragment heuristic: starts with `<` followed by a letter (= tag name)
    if (trimmed.length >= 2 &&
        trimmed[0] == '<' &&
        RegExp(r'[a-zA-Z]').hasMatch(trimmed[1])) {
      return true;
    }
    // Body contains common HTML block markers anywhere (catches plain-text
    // emails with embedded HTML signatures)
    return lower.contains('<div') ||
        lower.contains('<span') ||
        lower.contains('<p>') ||
        lower.contains('<p ') ||
        lower.contains('<table') ||
        lower.contains('<br>') ||
        lower.contains('<br/') ||
        lower.contains('<a href');
  }

  /// Build email body widget.
  ///
  /// HTML emails are rendered with [SafeHtmlRenderer] which shows
  /// formatted content while blocking all remote resources by default.
  /// Plain-text emails use the existing clickable-text renderer.
  Widget _buildEmailBody(FluentThemeData theme, Email email) {
    final isHtml = _isHtmlEmail(email.body);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (isHtml && !_allowRemoteContent)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              children: [
                Semantics(
                  excludeSemantics: true,
                  child: Icon(FluentIcons.shield_alert,
                      size: 14, color: theme.accentColor),
                ),
                const SizedBox(width: 6),
                Flexible(
                  child: Text(
                    'Remote images blocked for your privacy',
                    style: theme.typography.caption?.copyWith(
                      color: theme.inactiveColor,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                HyperlinkButton(
                  onPressed: () {
                    setState(() => _allowRemoteContent = true);
                    LoggerService.log('EMAIL_VIEW',
                        'User allowed remote content for this email');
                  },
                  child: const Text('Load remote images'),
                ),
              ],
            ),
          ),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: theme.micaBackgroundColor,
            borderRadius: BorderRadius.circular(4),
          ),
          child: isHtml
              ? SafeHtmlRenderer(
                  html: email.body,
                  allowRemoteContent: _allowRemoteContent,
                  textStyle: theme.typography.body,
                  onLinkTap: (url, {String? displayText}) => _openUrlInExternalBrowser(url, displayText: displayText),
                )
              : SelectableText.rich(
                  _buildClickableText(email.body, theme.typography.body),
                ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = l10nOf(context);
    final theme = FluentTheme.of(context);
    final emailProvider = context.read<EmailProvider>();
    final dateFormat = DateFormat('yyyy-MM-dd HH:mm:ss');
    final email = widget.email;

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 1000
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          if (email.isEncrypted)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Tooltip(
                message: 'End-to-end encrypted',
                child: Icon(FluentIcons.lock_solid, size: 16,
                    color: const Color(0xFF107C10)),
              ),
            ),
          Expanded(child: Text(sanitizeBidi(email.subject))),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Email metadata
            _buildMetadataRow(l10n.labelFrom, sanitizeBidi(email.from), theme),
            const SizedBox(height: 8),
            _buildMetadataRow(l10n.labelTo, sanitizeBidi(email.to), theme),
            if (email.cc.isNotEmpty) ...[
              const SizedBox(height: 8),
              _buildMetadataRow('CC:', sanitizeBidi(email.cc), theme),
            ],
            const SizedBox(height: 8),
            _buildMetadataRow(l10n.labelDate, dateFormat.format(email.date), theme),
            const SizedBox(height: 8),
            _buildMetadataRow(l10n.labelThreat, email.threatLevel, theme,
                threatLevel: email.threatLevel),
            const SizedBox(height: 16),

            // Divider
            const Divider(),
            const SizedBox(height: 16),

            // Email body - plain text with clickable links
            _buildEmailBody(theme, email),

            // Attachments
            if (email.attachments.isNotEmpty) ...[
              const SizedBox(height: 16),
              const Divider(),
              const SizedBox(height: 16),
              Text(
                l10n.infoAttachmentsTitle(email.attachments.length),
                style: theme.typography.subtitle,
              ),
              const SizedBox(height: 8),
              ...email.attachments.map((attachment) {
                // Create a Builder to get the correct context
                return Builder(
                  builder: (ctx) => _buildAttachment(attachment, theme, ctx),
                );
              }),
            ],
          ],
        ),
      ),
      actions: [
        // Reply button (icon only)
        Tooltip(message: 'Reply', child: IconButton(
          icon: const Icon(FluentIcons.reply, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Reply button clicked');
            // Capture navigator before pop
            final nav = Navigator.of(context);
            final parentContext = nav.context;
            nav.pop();
            // Open compose with pre-filled reply data
            await showDialog(
              context: parentContext,
              builder: (context) => ComposeWindow(
                replyTo: email.from,
                replySubject: 'Re: ${email.subject}',
              ),
            );
          },
        )),

        // Forward button (icon only)
        Tooltip(message: 'Forward', child: IconButton(
          icon: const Icon(FluentIcons.forward, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Forward button clicked');
            // Capture l10n and navigator before pop
            final l10nForward = l10nOf(context);
            final nav = Navigator.of(context);
            final parentContext = nav.context;
            nav.pop();
            // Convert HTML body to plain text for forwarding.
            // This strips dangerous tags, neutralizes phishing links
            // (text <url> format exposes mismatches), drops tracking
            // pixels and base64 images, and prevents the recipient
            // from receiving raw HTML that could re-render phishing
            // content with full styling.
            final plainBody = _isHtmlEmail(email.body)
                ? HtmlToPlainText.convert(email.body)
                : email.body;
            final forwardBody = '''
${l10nForward.infoForwardedMessage}
${l10nForward.labelFrom} ${email.from}
${l10nForward.labelDate} ${DateFormat('yyyy-MM-dd HH:mm:ss').format(email.date)}
${l10nForward.labelSubject} ${email.subject}
${l10nForward.labelTo} ${email.to}${email.cc.isNotEmpty ? '\nCC: ${email.cc}' : ''}

$plainBody
''';
            await showDialog(
              context: parentContext,
              builder: (context) => ComposeWindow(
                replySubject: 'Fwd: ${email.subject}',
                initialBody: forwardBody,
              ),
            );
          },
        )),

        // Print button (icon only) - cross-platform via printing package
        Tooltip(message: 'Print', child: IconButton(
          icon: const Icon(FluentIcons.print, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Print button clicked');
            try {
              final printContent = '''
Subject: ${email.subject}
From: ${email.from}
To: ${email.to}${email.cc.isNotEmpty ? '\nCC: ${email.cc}' : ''}
Date: ${DateFormat('yyyy-MM-dd HH:mm:ss').format(email.date)}
Threat: ${email.threatLevel}

${email.body}

${email.attachments.isNotEmpty ? '\nAttachments (${email.attachments.length}): ${email.attachments.map((a) => a.fileName).join(", ")}' : ''}
''';

              final pdf = pw.Document();
              pdf.addPage(
                pw.MultiPage(
                  pageFormat: PdfPageFormat.a4,
                  build: (context) => [
                    pw.Text(printContent, style: const pw.TextStyle(fontSize: 11)),
                  ],
                ),
              );

              await Printing.layoutPdf(onLayout: (format) async => pdf.save());

              LoggerService.log('EMAIL_VIEWER', 'Print dialog opened');
              if (!context.mounted) return;
              final l10nPrint = l10nOf(context);
              NotificationService.showSuccessToast(l10nPrint.successPrint, l10nPrint.successPrintDialogOpened);
            } catch (ex, stackTrace) {
              LoggerService.logError('PRINT', ex, stackTrace);
              if (!context.mounted) return;
              final l10nPrint = l10nOf(context);
              NotificationService.showErrorToast(l10nPrint.errorPrint, ex.toString());
            }
          },
        )),

        // Copy entire email button (icon only)
        Tooltip(message: 'Copy', child: IconButton(
          icon: const Icon(FluentIcons.copy, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Copy email button clicked');
            try {
              // Format email for clipboard (strip HTML tags for clean text)
              final cleanBody = _stripHtmlTags(email.body);
              final emailContent = '''
Subject: ${email.subject}
From: ${email.from}
To: ${email.to}${email.cc.isNotEmpty ? '\nCC: ${email.cc}' : ''}
Date: ${DateFormat('yyyy-MM-dd HH:mm:ss').format(email.date)}
Threat Level: ${email.threatLevel}

$cleanBody

${email.attachments.isNotEmpty ? '\nAttachments (${email.attachments.length}): ${email.attachments.map((a) => a.fileName).join(", ")}' : ''}
''';

              await Clipboard.setData(ClipboardData(text: emailContent));
              LoggerService.log('EMAIL_VIEWER', 'Email copied to clipboard');
              if (!context.mounted) return;
              final l10nCopy = l10nOf(context);
              NotificationService.showSuccessToast(l10nCopy.successCopied, l10nCopy.successEmailCopiedToClipboard);
            } catch (ex, stackTrace) {
              LoggerService.logError('COPY', ex, stackTrace);
              if (!context.mounted) return;
              final l10nCopy = l10nOf(context);
              NotificationService.showErrorToast(l10nCopy.errorCopy, ex.toString());
            }
          },
        )),

        // Delete button (icon only)
        Tooltip(message: 'Delete', child: IconButton(
          icon: const Icon(FluentIcons.delete, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Delete button clicked');
            final l10nDelete = l10nOf(context);
            Navigator.of(context).pop();
            await emailProvider.deleteEmail(email);
            NotificationService.showSuccessToast(l10nDelete.successDeleted, l10nDelete.successEmailMovedToTrash);
          },
        )),

        // Mark as spam button (icon only)
        Tooltip(message: 'Mark as spam', child: IconButton(
          icon: const Icon(FluentIcons.blocked2, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Spam button clicked');
            final l10nSpam = l10nOf(context);
            Navigator.of(context).pop();
            await emailProvider.markAsSpam(email);
            NotificationService.showSuccessToast(l10nSpam.successSpam, l10nSpam.successEmailMarkedAsSpam);
          },
        )),

        // Close button (filled, icon only)
        FilledButton(
          child: const Icon(FluentIcons.chrome_close, size: 20),
          onPressed: () {
            LoggerService.log('EMAIL_VIEWER', 'Close button clicked');
            Navigator.of(context).pop();
          },
        ),
      ],
    );
  }

  Widget _buildMetadataRow(String label, String value, FluentThemeData theme,
      {String? threatLevel}) {
    Color? valueColor;

    if (threatLevel != null) {
      switch (threatLevel.toLowerCase()) {
        case 'critical':
          valueColor = Colors.red;
          break;
        case 'high':
          valueColor = Colors.orange;
          break;
        case 'medium':
          valueColor = Colors.yellow;
          break;
        case 'low':
          valueColor = Colors.blue;
          break;
        case 'safe':
          valueColor = Colors.green;
          break;
      }
    }

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 80,
          child: Text(
            label,
            style: theme.typography.body?.copyWith(
              fontWeight: FontWeight.bold,
              color: theme.inactiveColor,
            ),
          ),
        ),
        Expanded(
          child: GestureDetector(
            onDoubleTap: () async {
              await Clipboard.setData(ClipboardData(text: value));
              if (!mounted) return;
              final l10n = l10nOf(context);
              NotificationService.showSuccessToast(l10n.successCopied, value);
            },
            child: Tooltip(
              message: 'Double-click to copy',
              child: Text(
                value,
                style: theme.typography.body?.copyWith(
                  color: valueColor,
                  fontWeight: valueColor != null ? FontWeight.bold : null,
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildAttachment(EmailAttachment attachment, FluentThemeData theme, BuildContext ctx) {
    final sizeKB = (attachment.size / 1024).toStringAsFixed(1);

    // Scan status badge + label
    Widget statusBadge;
    String statusLabel;
    bool canView = false;
    bool canDownload = false;
    Color? rowBorderColor;

    switch (attachment.scanStatus) {
      case AttachmentScanStatus.pending:
        statusBadge = Icon(FluentIcons.clock, size: 12, color: theme.inactiveColor);
        statusLabel = 'Waiting...';
      case AttachmentScanStatus.scanning:
        statusBadge = const SizedBox(
          width: 12, height: 12,
          child: ProgressRing(strokeWidth: 2),
        );
        statusLabel = 'Scanning...';
      case AttachmentScanStatus.clean:
        statusBadge = const Icon(FluentIcons.completed_solid, size: 12, color: Color(0xFF107C10));
        statusLabel = attachment.scanTimeMs != null
            ? 'Clean (${attachment.scanTimeMs}ms)'
            : 'Clean';
        canView = true;
        canDownload = true;
      case AttachmentScanStatus.infected:
        statusBadge = const Icon(FluentIcons.warning, size: 12, color: Color(0xFFD13438));
        statusLabel = 'THREAT: ${attachment.threatName ?? "Unknown"}';
        rowBorderColor = const Color(0xFFD13438);
      case AttachmentScanStatus.unscannable:
        statusBadge = const Icon(FluentIcons.info, size: 12, color: Color(0xFFCA5010));
        statusLabel = attachment.scanError ?? 'Cannot scan';
        canView = true;
        canDownload = true;
      case AttachmentScanStatus.error:
        statusBadge = Icon(FluentIcons.warning, size: 12, color: theme.inactiveColor);
        statusLabel = 'Scanner unavailable';
        canDownload = true; // allow download with warning
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: attachment.isBlocked
            ? const Color(0x14D13438)
            : theme.micaBackgroundColor,
        borderRadius: BorderRadius.circular(4),
        border: Border.all(
          color: rowBorderColor ?? theme.inactiveBackgroundColor,
        ),
      ),
      child: Row(
        children: [
          Icon(FluentIcons.attach, size: 16, color: theme.accentColor),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  attachment.fileName,
                  style: theme.typography.body?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 2),
                Row(
                  children: [
                    statusBadge,
                    const SizedBox(width: 4),
                    Flexible(
                      child: Text(
                        '$sizeKB KB  ·  $statusLabel',
                        style: theme.typography.caption?.copyWith(
                          color: attachment.isBlocked
                              ? const Color(0xFFD13438)
                              : theme.inactiveColor,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          // View button — only when scan passed and viewable type
          if (canView && _canViewAttachment(attachment.fileName))
            Tooltip(message: 'View attachment', child: IconButton(
              icon: const Icon(FluentIcons.view, size: 16),
              onPressed: () async {
                try {
                  if (attachment.data != null) {
                    await showDialog(
                      context: ctx,
                      builder: (dialogContext) => AttachmentViewerWindow(
                        fileName: attachment.fileName,
                        fileData: attachment.data!,
                      ),
                    );
                    LoggerService.log('EMAIL_VIEWER',
                        '✓ Viewed ${attachment.fileName} IN APP (SECURE)');
                  }
                } catch (ex, stackTrace) {
                  LoggerService.logError('VIEW', ex, stackTrace);
                  if (!ctx.mounted) return;
                  final l10nView = l10nOf(ctx);
                  NotificationService.showErrorToast(
                      l10nView.errorView, ex.toString());
                }
              },
            )),
          // Download button — blocked for infected, warning for error
          if (canDownload)
            Tooltip(message: 'Download attachment', child: IconButton(
              icon: const Icon(FluentIcons.download, size: 16),
              onPressed: () async {
                try {
                  // Warn if scanner was unavailable
                  if (attachment.scanStatus == AttachmentScanStatus.error) {
                    if (!ctx.mounted) return;
                    final proceed = await _confirmScannerUnavailable(ctx);
                    if (!proceed) return;
                  }
                  // Warn for dangerous extensions
                  if (_isDangerousAttachment(attachment.fileName)) {
                    if (!ctx.mounted) return;
                    final confirmed = await _confirmDangerousDownload(
                        ctx, attachment.fileName);
                    if (!confirmed) return;
                  }

                  final platform = PlatformService.instance;
                  final downloadsPath = platform.downloadsPath;
                  final safeName =
                      safeAttachmentFileName(attachment.fileName);
                  final file = File(p.join(downloadsPath, safeName));
                  if (attachment.data != null) {
                    await file.writeAsBytes(attachment.data!);
                    if (!ctx.mounted) return;
                    final l10nDl = l10nOf(ctx);
                    NotificationService.showSuccessToast(
                      l10nDl.successDownloaded,
                      l10nDl.successSavedTo(file.path),
                    );
                    LoggerService.log('EMAIL_VIEWER',
                        'Downloaded: $safeName (original: ${attachment.fileName})');
                  }
                } catch (ex) {
                  if (!ctx.mounted) return;
                  final l10nDl = l10nOf(ctx);
                  NotificationService.showErrorToast(
                      l10nDl.errorDownload, ex.toString());
                }
              },
            )),
          // Blocked indicator for infected files
          if (attachment.isBlocked)
            Tooltip(
              message: 'Blocked: ${attachment.threatName ?? "malware detected"}',
              child: const Padding(
                padding: EdgeInsets.symmetric(horizontal: 8),
                child: Icon(FluentIcons.blocked2, size: 16,
                    color: Color(0xFFD13438)),
              ),
            ),
        ],
      ),
    );
  }

  /// Check if attachment can be viewed (PDF and images)
  bool _canViewAttachment(String fileName) {
    final ext = fileName.toLowerCase().split('.').last;
    return ['pdf', 'jpg', 'jpeg', 'png'].contains(ext);
  }

  /// Confirm download when scanner was unavailable.
  static Future<bool> _confirmScannerUnavailable(BuildContext context) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => ContentDialog(
        title: Row(
          children: [
            Semantics(
              excludeSemantics: true,
              child: Icon(FluentIcons.warning, color: Colors.orange, size: 24),
            ),
            const SizedBox(width: 8),
            const Text('Scanner unavailable'),
          ],
        ),
        content: const Text(
          'The antivirus scanner could not be reached. This file has '
          'NOT been scanned for malware.\n\n'
          'Do you want to download it anyway?',
        ),
        actions: [
          Button(
            child: const Text('Cancel'),
            onPressed: () => Navigator.pop(ctx, false),
          ),
          FilledButton(
            style: ButtonStyle(
              backgroundColor: WidgetStatePropertyAll(Colors.orange),
            ),
            child: const Text('Download anyway'),
            onPressed: () => Navigator.pop(ctx, true),
          ),
        ],
      ),
    );
    return result ?? false;
  }

  /// Extensions that can execute code when opened by the OS.
  static const _dangerousExtensions = <String>{
    // Windows executables / scripts
    'exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'pif', 'ps1', 'vbs',
    'vbe', 'wsf', 'wsh', 'reg', 'inf', 'hta', 'cpl', 'msp', 'mst',
    // Cross-platform scripts
    'js', 'jse', 'sh', 'bash', 'command', 'py', 'pl', 'rb',
    // Web content (can execute JS in browser)
    'html', 'htm', 'xhtml', 'svg', 'xml', 'xht', 'mht', 'mhtml',
    // macOS-specific
    'app', 'action', 'workflow', 'dmg', 'pkg',
    // Linux-specific
    'desktop', 'run', 'appimage',
    // Office macros
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm',
    // Archives (can contain executables)
    'jar', 'iso', 'img',
  };

  /// Check if a filename has a potentially dangerous extension.
  static bool _isDangerousAttachment(String fileName) {
    final ext = fileName.toLowerCase().split('.').last;
    return _dangerousExtensions.contains(ext);
  }

  /// Show a confirmation dialog before downloading a dangerous attachment.
  static Future<bool> _confirmDangerousDownload(
      BuildContext context, String fileName) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => ContentDialog(
        title: Row(
          children: [
            Semantics(
              excludeSemantics: true,
              child: Icon(FluentIcons.warning, color: Colors.orange, size: 24),
            ),
            const SizedBox(width: 8),
            const Text('Potentially dangerous file'),
          ],
        ),
        content: Text(
          'The file "$fileName" has an extension that could execute '
          'code when opened. Only download files from senders you trust.\n\n'
          'Do you want to download this file?',
        ),
        actions: [
          Button(
            child: const Text('Cancel'),
            onPressed: () => Navigator.pop(ctx, false),
          ),
          FilledButton(
            style: ButtonStyle(
              backgroundColor: WidgetStatePropertyAll(Colors.orange),
            ),
            child: const Text('Download anyway'),
            onPressed: () => Navigator.pop(ctx, true),
          ),
        ],
      ),
    );
    return result ?? false;
  }
}