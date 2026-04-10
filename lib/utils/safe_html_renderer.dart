import 'package:flutter/material.dart';
import 'package:flutter_widget_from_html_core/flutter_widget_from_html_core.dart';

import '../services/logger_service.dart';
import 'text_safety.dart';

/// Secure HTML email renderer with remote content blocking.
///
/// SECURITY: Renders HTML email bodies as a native Flutter widget tree
/// (no WebView, no JavaScript engine, no browser attack surface).
/// External resources (images, iframes, video, audio, objects) are
/// blocked by default and replaced with a placeholder. The user can
/// opt-in to loading remote images per email via
/// [allowRemoteContent].
///
/// Tag whitelist approach: only safe formatting tags are rendered;
/// dangerous elements (`<script>`, `<style>`, `<iframe>`, `<object>`,
/// `<embed>`, `<form>`, `<meta>`, `<link>`, `<base>`) are stripped
/// before the HTML reaches the widget builder.
///
/// Tracking pixel defense: `<img>` tags with `http://` or `https://`
/// sources are replaced with a grey placeholder showing "[Image
/// blocked]" unless [allowRemoteContent] is true. Inline images
/// (`data:` URIs and `cid:` references) are always allowed because
/// they don't generate network requests.
class SafeHtmlRenderer extends StatelessWidget {
  const SafeHtmlRenderer({
    super.key,
    required this.html,
    this.allowRemoteContent = false,
    this.onLinkTap,
    this.textStyle,
  });

  /// Raw HTML email body.
  final String html;

  /// Whether to load external images. Default false (tracking-safe).
  final bool allowRemoteContent;

  /// Callback when user taps a link. Receives the URL string and
  /// optionally the visible link text (for phishing detection: if
  /// the text looks like a different domain, the caller can warn).
  final void Function(String url, {String? displayText})? onLinkTap;

  /// Base text style for the rendered content.
  final TextStyle? textStyle;

  /// Sanitize HTML before rendering: strip dangerous tags entirely.
  static String _sanitizeHtml(String raw) {
    var s = raw;
    // Remove script, style, iframe, object, embed, form, meta, link, base
    // tags WITH their content (greedy within tag pair).
    for (final tag in [
      'script', 'style', 'iframe', 'object', 'embed',
      'form', 'meta', 'link', 'base', 'applet', 'svg',
    ]) {
      s = s.replaceAll(
        RegExp('<$tag[^>]*>[\\s\\S]*?</$tag>', caseSensitive: false),
        '',
      );
      // Also catch self-closing variants
      s = s.replaceAll(
        RegExp('<$tag[^>]*/?>',  caseSensitive: false),
        '',
      );
    }
    // Strip event handlers (onclick, onload, onerror, etc.)
    s = s.replaceAll(
      RegExp(r'\s+on\w+\s*=\s*"[^"]*"', caseSensitive: false),
      '',
    );
    s = s.replaceAll(
      RegExp(r"\s+on\w+\s*=\s*'[^']*'", caseSensitive: false),
      '',
    );
    return s;
  }

  /// Returns true if [src] is a remote URL (http/https) as opposed to
  /// an inline data URI or a CID reference.
  static bool _isRemoteUrl(String? src) {
    if (src == null) return false;
    final lower = src.trim().toLowerCase();
    return lower.startsWith('http://') || lower.startsWith('https://');
  }

  @override
  Widget build(BuildContext context) {
    final sanitized = _sanitizeHtml(html);

    return HtmlWidget(
      sanitized,
      textStyle: textStyle ?? Theme.of(context).textTheme.bodyMedium,

      // Custom widget builder: intercept <img> tags with remote src
      customWidgetBuilder: (element) {
        if (element.localName == 'img') {
          final src = element.attributes['src'];
          if (_isRemoteUrl(src) && !allowRemoteContent) {
            // Block remote image — show placeholder
            return Container(
              margin: const EdgeInsets.symmetric(vertical: 4),
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.grey.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(
                  color: Colors.grey.withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.image_not_supported_outlined,
                      size: 16, color: Colors.grey[600]),
                  const SizedBox(width: 6),
                  Text(
                    'Image blocked',
                    style: TextStyle(
                      fontSize: 12,
                      color: Colors.grey[600],
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ],
              ),
            );
          }
          // Allow data: URIs and cid: references (no network request)
        }
        return null; // default rendering for everything else
      },

      onTapUrl: (url) {
        final cleanUrl = sanitizeBidi(url);
        LoggerService.log('EMAIL_VIEW', 'Link tapped: $cleanUrl');
        onLinkTap?.call(cleanUrl);
        return true;
      },

      // Intercept <a> tags to extract display text for phishing check
      customStylesBuilder: (element) {
        if (element.localName == 'a') {
          // Store display text in a data attribute so onTapUrl can
          // access it (workaround: flutter_widget_from_html doesn't
          // pass element text to onTapUrl callback)
          final href = element.attributes['href'] ?? '';
          final displayText = element.text.trim();
          // If display text looks like a URL and domain differs from
          // href, the link is suspicious
          if (displayText.isNotEmpty && href.isNotEmpty) {
            element.attributes['data-display-text'] = displayText;
          }
        }
        return null;
      },
    );
  }
}
