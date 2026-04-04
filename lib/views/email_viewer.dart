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
import '../models/models.dart';
import '../providers/email_provider.dart';
import '../services/notification_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import 'compose_window.dart';
import 'attachment_viewer_window.dart';

/// Email viewer window
class EmailViewer extends StatefulWidget {
  final Email email;

  const EmailViewer({super.key, required this.email});

  @override
  State<EmailViewer> createState() => _EmailViewerState();
}

class _EmailViewerState extends State<EmailViewer> {
  final List<TapGestureRecognizer> _recognizers = [];

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
  Future<void> _openUrlInExternalBrowser(String url) async {
    // Decode HTML entities in URL (e.g., &amp; -> &)
    final decodedUrl = _decodeHtmlEntities(url);
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

  /// Check if email body is HTML
  bool _isHtmlEmail(String body) {
    final lowerBody = body.toLowerCase().trimLeft();
    return lowerBody.startsWith('<!doctype') ||
           lowerBody.startsWith('<html') ||
           (lowerBody.contains('<body') && lowerBody.contains('<head'));
  }

  /// Build email body widget - plain text with clickable links
  Widget _buildEmailBody(FluentThemeData theme, Email email) {
    // Convert HTML to plain text if needed
    String displayBody = email.body;
    if (_isHtmlEmail(email.body)) {
      displayBody = _stripHtmlTags(email.body);
    }

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.micaBackgroundColor,
        borderRadius: BorderRadius.circular(4),
      ),
      child: SelectableText.rich(
        _buildClickableText(displayBody, theme.typography.body),
      ),
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
      title: Text(email.subject),
      content: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Email metadata
            _buildMetadataRow(l10n.labelFrom, email.from, theme),
            const SizedBox(height: 8),
            _buildMetadataRow(l10n.labelTo, email.to, theme),
            if (email.cc.isNotEmpty) ...[
              const SizedBox(height: 8),
              _buildMetadataRow('CC:', email.cc, theme),
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
        IconButton(
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
        ),

        // Forward button (icon only)
        IconButton(
          icon: const Icon(FluentIcons.forward, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Forward button clicked');
            // Capture l10n and navigator before pop
            final l10nForward = l10nOf(context);
            final nav = Navigator.of(context);
            final parentContext = nav.context;
            nav.pop();
            // Open compose with forwarded email content
            final forwardBody = '''
${l10nForward.infoForwardedMessage}
${l10nForward.labelFrom} ${email.from}
${l10nForward.labelDate} ${DateFormat('yyyy-MM-dd HH:mm:ss').format(email.date)}
${l10nForward.labelSubject} ${email.subject}
${l10nForward.labelTo} ${email.to}${email.cc.isNotEmpty ? '\nCC: ${email.cc}' : ''}

${email.body}
''';
            await showDialog(
              context: parentContext,
              builder: (context) => ComposeWindow(
                replySubject: 'Fwd: ${email.subject}',
                initialBody: forwardBody,
              ),
            );
          },
        ),

        // Print button (icon only) - cross-platform via printing package
        IconButton(
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
        ),

        // Copy entire email button (icon only)
        IconButton(
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
        ),

        // Delete button (icon only)
        IconButton(
          icon: const Icon(FluentIcons.delete, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Delete button clicked');
            final l10nDelete = l10nOf(context);
            Navigator.of(context).pop();
            await emailProvider.deleteEmail(email);
            NotificationService.showSuccessToast(l10nDelete.successDeleted, l10nDelete.successEmailMovedToTrash);
          },
        ),

        // Mark as spam button (icon only)
        IconButton(
          icon: const Icon(FluentIcons.blocked2, size: 20),
          onPressed: () async {
            LoggerService.log('EMAIL_VIEWER', 'Spam button clicked');
            final l10nSpam = l10nOf(context);
            Navigator.of(context).pop();
            await emailProvider.markAsSpam(email);
            NotificationService.showSuccessToast(l10nSpam.successSpam, l10nSpam.successEmailMarkedAsSpam);
          },
        ),

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

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.micaBackgroundColor,
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: theme.inactiveBackgroundColor),
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
                Text(
                  '$sizeKB KB - ${attachment.contentType}',
                  style: theme.typography.caption?.copyWith(
                    color: theme.inactiveColor,
                  ),
                ),
              ],
            ),
          ),
          // View button (icon only) - INTEGRATED VIEWER (PDF and images IN APP - SECURE!)
          if (_canViewAttachment(attachment.fileName))
            IconButton(
              icon: const Icon(FluentIcons.view, size: 16),
              onPressed: () async {
                try {
                  if (attachment.data != null) {
                    // ALWAYS open in integrated viewer (SECURE - NO external apps)
                    await showDialog(
                      context: ctx,
                      builder: (dialogContext) => AttachmentViewerWindow(
                        fileName: attachment.fileName,
                        fileData: attachment.data!,
                      ),
                    );
                    LoggerService.log('EMAIL_VIEWER', '✓ Viewed ${attachment.fileName} IN APP (SECURE)');
                  }
                } catch (ex, stackTrace) {
                  LoggerService.logError('VIEW', ex, stackTrace);
                  if (!ctx.mounted) return;
                  final l10nView = l10nOf(ctx);
                  NotificationService.showErrorToast(l10nView.errorView, ex.toString());
                }
              },
            ),
          // Download button (icon only)
          IconButton(
            icon: const Icon(FluentIcons.download, size: 16),
            onPressed: () async {
              try {
                // Save to Downloads folder (cross-platform)
                final platform = PlatformService.instance;
                final downloadsPath = platform.downloadsPath;

                final file = File(p.join(downloadsPath, attachment.fileName));
                if (attachment.data != null) {
                  await file.writeAsBytes(attachment.data!);
                  if (!ctx.mounted) return;
                  final l10nDownload = l10nOf(ctx);
                  NotificationService.showSuccessToast(
                    l10nDownload.successDownloaded,
                    l10nDownload.successSavedTo(file.path),
                  );
                  LoggerService.log('EMAIL_VIEWER', 'Downloaded attachment: ${attachment.fileName}');
                }
              } catch (ex) {
                if (!ctx.mounted) return;
                final l10nDownload = l10nOf(ctx);
                NotificationService.showErrorToast(l10nDownload.errorDownload, ex.toString());
              }
            },
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
}
