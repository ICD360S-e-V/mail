import 'package:flutter/material.dart';
import 'package:flutter_widget_from_html_core/flutter_widget_from_html_core.dart';
import 'package:html/parser.dart' as html_parser;
import 'package:html/dom.dart' as dom;

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
/// Sanitization is DOM-based (via package:html), not regex-based.
/// Uses an ALLOWLIST of safe tags and attributes — anything not
/// explicitly permitted is stripped. This follows the same approach
/// as Gmail, Outlook, Thunderbird, and OWASP guidelines.
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
  /// the visible link text (for phishing detection: if the text looks
  /// like a different domain, the caller can warn).
  final void Function(String url, {String? displayText})? onLinkTap;

  /// Base text style for the rendered content.
  final TextStyle? textStyle;

  // ──────────────────────────────────────────────────────────────
  //  DOM-based HTML sanitizer (allowlist approach)
  // ──────────────────────────────────────────────────────────────

  /// Tags safe for email rendering — similar to Gmail's allowlist.
  static const _allowedTags = <String>{
    // Structure
    'div', 'span', 'p', 'br', 'hr', 'center', 'address', 'article',
    'section', 'header', 'footer', 'main', 'aside', 'nav',
    // Headings
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    // Text formatting
    'b', 'i', 'u', 'em', 'strong', 'small', 'big', 's', 'strike',
    'sub', 'sup', 'tt', 'code', 'pre', 'samp', 'kbd', 'var',
    'del', 'ins', 'mark', 'abbr', 'cite', 'dfn', 'q',
    // Links and images
    'a', 'img',
    // Lists
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    // Tables
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th',
    'caption', 'col', 'colgroup',
    // Block
    'blockquote',
    // Misc safe
    'font', 'bdo', 'wbr', 'details', 'summary',
    'figure', 'figcaption',
  };

  /// Safe non-URL attributes.
  static const _allowedAttributes = <String>{
    'align', 'alt', 'bgcolor', 'border', 'cellpadding', 'cellspacing',
    'class', 'color', 'colspan', 'dir', 'face', 'height', 'id', 'lang',
    'name', 'rel', 'role', 'rowspan', 'scope', 'size', 'start', 'style',
    'summary', 'tabindex', 'target', 'title', 'type', 'valign', 'value',
    'width',
  };

  /// Attributes that contain URLs — subject to scheme validation.
  static const _urlAttributes = <String>{'href', 'src', 'cite'};

  /// Allowed URL schemes.
  static const _allowedSchemes = <String>{
    'http', 'https', 'mailto', 'cid', 'data',
  };

  /// Tags removed WITH all their children (content is dangerous).
  static const _stripWithChildren = <String>{
    'script', 'style', 'iframe', 'object', 'embed', 'form', 'meta',
    'link', 'base', 'applet', 'svg', 'math', 'video', 'audio', 'canvas',
    'template', 'noscript', 'textarea', 'select', 'input', 'button',
  };

  /// Sanitize [rawHtml] using a DOM allowlist and return clean HTML.
  static String _sanitizeHtml(String raw) {
    final fragment = html_parser.parseFragment(raw);
    _walkAndClean(fragment.nodes);
    return fragment.outerHtml;
  }

  /// Recursively walk the DOM tree and clean it in-place.
  static void _walkAndClean(dom.NodeList nodes) {
    for (var i = nodes.length - 1; i >= 0; i--) {
      final node = nodes[i];

      if (node is dom.Element) {
        final tag = node.localName?.toLowerCase() ?? '';

        // Dangerous tags: remove entirely including children.
        if (_stripWithChildren.contains(tag)) {
          node.remove();
          continue;
        }

        // Unknown/disallowed tags: unwrap (keep children, remove tag).
        if (!_allowedTags.contains(tag)) {
          final parent = node.parentNode;
          if (parent != null) {
            final childNodes = node.nodes.toList();
            for (final child in childNodes) {
              parent.insertBefore(child, node);
            }
            node.remove();
          }
          continue;
        }

        // Clean attributes on allowed tags.
        _cleanAttributes(node);

        // Recurse into children.
        _walkAndClean(node.nodes);
      } else if (node is dom.Text) {
        // Text nodes are safe.
      } else {
        // Comments, processing instructions — remove.
        node.remove();
      }
    }
  }

  /// Remove dangerous attributes from an element.
  static void _cleanAttributes(dom.Element element) {
    final keysToRemove = <dynamic>[];

    element.attributes.forEach((key, value) {
      final attrName = key.toString().toLowerCase();

      // Remove ALL event handlers (on*) — regardless of quoting style.
      if (attrName.startsWith('on')) {
        keysToRemove.add(key);
        return;
      }

      // Validate URL attributes — block javascript: and other
      // dangerous schemes.
      if (_urlAttributes.contains(attrName)) {
        if (_hasDisallowedScheme(value)) {
          keysToRemove.add(key);
        }
        return;
      }

      // Remove attributes not in the allowlist.
      if (!_allowedAttributes.contains(attrName)) {
        keysToRemove.add(key);
      }
    });

    for (final key in keysToRemove) {
      element.attributes.remove(key);
    }
  }

  /// Check if a URL attribute value uses a disallowed scheme.
  static bool _hasDisallowedScheme(String value) {
    final trimmed = value.trim();

    // Relative URLs, fragments, query-only are safe.
    if (trimmed.isEmpty ||
        trimmed.startsWith('/') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('?')) {
      return false;
    }

    // Find the scheme portion (before first ':').
    final colonIndex = trimmed.indexOf(':');
    if (colonIndex < 0) return false; // No scheme — relative URL.

    // A slash before the colon means it's a path, not a scheme.
    final slashIndex = trimmed.indexOf('/');
    if (slashIndex >= 0 && slashIndex < colonIndex) return false;

    final scheme = trimmed.substring(0, colonIndex).trim().toLowerCase();
    return !_allowedSchemes.contains(scheme);
  }

  // ──────────────────────────────────────────────────────────────
  //  Link extraction for phishing detection (Layer 1)
  // ──────────────────────────────────────────────────────────────

  /// Extract a map of href → display text from all <a> tags in [rawHtml].
  /// Called BEFORE sanitization so we see the original HTML.
  static Map<String, String> _extractLinkDisplayTexts(String rawHtml) {
    final fragment = html_parser.parseFragment(rawHtml);
    final map = <String, String>{};
    for (final anchor in fragment.querySelectorAll('a')) {
      final href = anchor.attributes['href'];
      final displayText = anchor.text.trim();
      if (href != null && href.isNotEmpty && displayText.isNotEmpty) {
        map[href] = displayText;
      }
    }
    return map;
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
    // Step 1: Extract link display texts BEFORE sanitization (for
    // phishing detection — Layer 1 needs the original <a> text).
    final linkTexts = _extractLinkDisplayTexts(html);

    // Step 2: DOM-based sanitization (allowlist approach).
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
        // Pass display text from pre-extracted map for phishing check.
        final displayText = linkTexts[url] ?? linkTexts[cleanUrl];
        onLinkTap?.call(cleanUrl, displayText: displayText);
        return true;
      },

      customStylesBuilder: (element) {
        return null;
      },
    );
  }
}
