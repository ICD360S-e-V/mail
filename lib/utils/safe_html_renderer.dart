// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:math';
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


  /// Safe MIME types for data: URIs (raster images only).
  /// SVG blocked: parser differentials, CSS exfiltration (ProtonMail 2023 vuln).
  static const _safeDataMimes = <String>{
    'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp',
  };

  /// Check if a data: URI has a safe MIME type AND valid magic bytes.
  static bool _isSafeDataUri(String uri) {
    if (!uri.startsWith('data:')) return false;
    final mimeEnd = uri.indexOf(';');
    final commaEnd = uri.indexOf(',');
    final end = (mimeEnd > 0 && mimeEnd < commaEnd) ? mimeEnd : commaEnd;
    if (end < 0) return false;
    final mime = uri.substring(5, end).trim().toLowerCase();
    if (!_safeDataMimes.contains(mime)) return false;
    if (!uri.contains(';base64,')) return false;
    final b64Start = uri.indexOf(';base64,') + 8;
    if (b64Start >= uri.length) return false;
    try {
      final bytes = base64.decode(uri.substring(b64Start, min(b64Start + 16, uri.length)));
      if (bytes.length < 4) return false;
      if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) return true; // PNG
      if (bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF) return true; // JPEG
      if (bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x38) return true; // GIF
      if (bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46) return true; // WebP
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Allowed URL schemes for `src` attributes (images, embedded content).
  static const _allowedSrcSchemes = <String>{
    'http', 'https', 'mailto', 'cid',
  };

  /// Allowed URL schemes for `href`/`cite` attributes — `data:` is
  /// excluded to prevent data-URI phishing (see issue #3).
  static const _allowedHrefSchemes = <String>{
    'http', 'https', 'mailto', 'cid',
  };

  // ──────────────────────────────────────────────────────────────
  //  CSS inline style sanitizer (Proton Mail + Tuta Mail approach)
  // ──────────────────────────────────────────────────────────────

  /// Regex matching dangerous CSS value patterns (case-insensitive).
  /// Applied AFTER recursive unescaping and comment stripping.
  static final _dangerousCssValue = RegExp(
    r'expression\s*\('    // IE JS execution
    r'|image-set\s*\('    // alternate url() syntax
    r'|image\s*\('        // CSS image() type with plain URL
    r'|element\s*\('      // references arbitrary DOM element
    r'|var\s*\('          // custom properties can defer url() resolution
    r'|src\s*\('          // obscure resource reference
    r'|-moz-binding'      // old Firefox XBL execution
    r'|behavior\s*:'      // IE HTC execution
    r'|-o-link'           // old Opera link behavior
    r'|javascript\s*:'    // script execution
    r'|vbscript\s*:',     // IE script execution
    caseSensitive: false,
  );

  /// Matches `url(...)` calls, capturing the URL inside.
  static final _cssUrlCall = RegExp(
    r'''url\s*\(\s*(['"]?)(.*?)\1\s*\)''',
    caseSensitive: false,
  );

  /// CSS hex escape: `\41` or `\000041`.
  static final _cssHexEscape = RegExp(r'\\([0-9a-fA-F]{1,6})\s?');

  /// HTML numeric entities: `&#65;` or `&#x41;`.
  static final _htmlNumericEntity = RegExp(r'&#x?([0-9a-fA-F]+);');

  /// Sanitize an inline `style` attribute value.
  ///
  /// Strips dangerous CSS functions (`url()` to external hosts,
  /// `expression()`, `var()`, `image-set()`, etc.) while preserving
  /// safe visual properties (colors, fonts, margins, borders).
  ///
  /// Follows the combined Proton Mail + Tuta Mail approach:
  /// 1. Recursive CSS/HTML unescape (anti-bypass, up to 5 rounds)
  /// 2. Strip CSS comments
  /// 3. Block dangerous value patterns in any property
  /// 4. Allow `url(data:…)` and `url(cid:…)` for inline images
  /// 5. Block `position: absolute/fixed/sticky`
  static String _sanitizeStyleValue(String style) {
    if (style.length > 4096) return '';
    var decoded = style;
    for (var i = 0; i < 5; i++) {
      final prev = decoded;
      decoded = _cssUnescape(decoded);
      if (decoded == prev) break; // stable
    }

    // Step 2: Strip CSS comments.
    decoded = decoded.replaceAll(RegExp(r'/\*.*?\*/', dotAll: true), '');

    // Step 3: Parse into declarations and filter each one.
    final declarations = decoded.split(';');
    final safe = <String>[];

    for (final decl in declarations) {
      final colonIdx = decl.indexOf(':');
      if (colonIdx < 0) continue;

      final property = decl.substring(0, colonIdx).trim().toLowerCase();
      var value = decl.substring(colonIdx + 1).trim();

      // Reject declarations that don't look like valid CSS.
      if (!RegExp(r'^-?-?[a-z][\w-]*$').hasMatch(property)) continue;

      // Block explicitly dangerous properties.
      if (property == '-moz-binding' ||
          property == 'behavior' ||
          property == '-o-link' ||
          property == '-o-link-source' ||
          property == 'color-scheme') continue;

      // Block position: absolute/fixed/sticky (UI overlay attacks).
      if (property == 'position' &&
          RegExp(r'\b(absolute|fixed|sticky)\b', caseSensitive: false)
              .hasMatch(value)) continue;

      // Block any value containing dangerous patterns.
      if (_dangerousCssValue.hasMatch(value)) continue;

      // Handle url() calls: allow only data: and cid: schemes.
      if (_cssUrlCall.hasMatch(value)) {
        value = value.replaceAllMapped(_cssUrlCall, (m) {
          final url = (m.group(2) ?? '').trim().toLowerCase();
          if (url.startsWith('data:') || url.startsWith('cid:')) {
            return m.group(0)!; // safe — inline image
          }
          return 'none'; // external URL → neutralize
        });
      }

      safe.add('$property: $value');
    }

    return safe.join('; ');
  }

  /// Unescape one level of CSS hex escapes and HTML numeric entities.
  static String _cssUnescape(String input) {
    var result = input.replaceAllMapped(_cssHexEscape, (m) {
      final code = int.tryParse(m.group(1)!, radix: 16);
      return (code != null && code > 0) ? String.fromCharCode(code) : '';
    });
    result = result.replaceAllMapped(_htmlNumericEntity, (m) {
      final raw = m.group(1)!;
      final radix = m.group(0)!.startsWith('&#x') ? 16 : 10;
      final code = int.tryParse(raw, radix: radix);
      return (code != null && code > 0) ? String.fromCharCode(code) : '';
    });
    return result;
  }

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

      // Sanitize inline style attributes — strip dangerous CSS.
      if (attrName == 'style') {
        final sanitized = _sanitizeStyleValue(value);
        if (sanitized.isEmpty) {
          keysToRemove.add(key);
        } else {
          element.attributes[key] = sanitized;
        }
        return;
      }

      // Validate URL attributes — block javascript: and other
      // dangerous schemes.  Use stricter scheme set for href/cite
      // (no data: — prevents data-URI phishing).
      if (_urlAttributes.contains(attrName)) {
        final schemes = (attrName == 'src')
            ? _allowedSrcSchemes
            : _allowedHrefSchemes;
        // Allow data: URIs only in src with safe raster MIME type
        if (value.trim().toLowerCase().startsWith('data:')) {
          if (attrName != 'src' || !_isSafeDataUri(value.trim().toLowerCase())) {
            keysToRemove.add(key);
          }
          return;
        }
        if (_hasDisallowedScheme(value, schemes)) {
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
  static bool _hasDisallowedScheme(String value, [Set<String>? allowed]) {
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
    return !(allowed ?? _allowedSrcSchemes).contains(scheme);
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
                  Semantics(
                    label: 'Image blocked',
                    child: Icon(Icons.image_not_supported_outlined,
                        size: 16, color: Colors.grey[600]),
                  ),
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