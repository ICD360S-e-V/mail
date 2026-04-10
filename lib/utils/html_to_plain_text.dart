import 'package:html/dom.dart' as dom;
import 'package:html/parser.dart' as html_parser;

/// Convert HTML email body to plain text suitable for the forward
/// compose box.
///
/// Goals:
///   - No raw HTML reaches the recipient (phishing / re-injection risk).
///   - Visible text stays readable, block structure preserved.
///   - URLs shown as `text <url>` so phishing is exposed:
///     `<a href="evil.com">google.com</a>` → `google.com <evil.com>`
///   - <style>/<script> are dropped, not rendered as text.
///   - Inline images, base64 data URIs, and tracking pixels neutralized.
///
/// Reference: Thunderbird nsPlainTextSerializer, html2text (Aaron Swartz),
/// K-9 Mail / FairEmail JSoup-based converters.
class HtmlToPlainText {
  /// Convert [html] to plain text.
  static String convert(String html) {
    if (html.trim().isEmpty) return '';
    final doc = html_parser.parse(html);
    final body = doc.body ?? doc.documentElement;
    if (body == null) return '';
    final ctx = _WalkCtx();
    _walk(body, ctx);
    return _postProcess(ctx.out.toString());
  }

  // ── DOM walk ─────────────────────────────────────────────────────────

  static const _blockTags = <String>{
    'address', 'article', 'aside', 'blockquote', 'center', 'details',
    'dialog', 'div', 'dl', 'dd', 'dt', 'fieldset', 'figcaption', 'figure',
    'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header',
    'hgroup', 'hr', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'summary',
    'table', 'tbody', 'tfoot', 'thead', 'tr', 'ul', 'li',
  };

  static const _dropTags = <String>{
    'style', 'script', 'head', 'noscript', 'meta', 'link', 'title',
    'object', 'embed', 'iframe', 'svg', 'canvas', 'video', 'audio',
  };

  static void _walk(dom.Node node, _WalkCtx ctx) {
    if (node is dom.Text) {
      _emitText(node.text, ctx);
      return;
    }
    if (node is! dom.Element) {
      for (final c in node.nodes) {
        _walk(c, ctx);
      }
      return;
    }

    final tag = node.localName?.toLowerCase() ?? '';
    if (_dropTags.contains(tag)) return;

    switch (tag) {
      case 'br':
        ctx.newline();
        return;

      case 'hr':
        ctx.blockBreak();
        ctx.out.write('--------------------------------------------------');
        ctx.blockBreak();
        return;

      case 'a':
        _emitAnchor(node, ctx);
        return;

      case 'img':
        _emitImage(node, ctx);
        return;

      case 'blockquote':
        ctx.blockBreak();
        ctx.blockquoteDepth++;
        for (final c in node.nodes) {
          _walk(c, ctx);
        }
        ctx.blockquoteDepth--;
        ctx.blockBreak();
        return;

      case 'pre':
        ctx.blockBreak();
        ctx.preDepth++;
        for (final c in node.nodes) {
          _walk(c, ctx);
        }
        ctx.preDepth--;
        ctx.blockBreak();
        return;

      case 'ul':
      case 'ol':
        ctx.blockBreak();
        ctx.listStack.add(
            tag == 'ol' ? _ListCtx.ordered() : _ListCtx.unordered());
        for (final c in node.nodes) {
          _walk(c, ctx);
        }
        ctx.listStack.removeLast();
        ctx.blockBreak();
        return;

      case 'li':
        ctx.newline();
        final list = ctx.listStack.isNotEmpty ? ctx.listStack.last : null;
        final indent = '  ' * (ctx.listStack.length - 1).clamp(0, 999);
        final bullet = list == null
            ? '* '
            : (list.ordered ? '${list.counter++}. ' : '* ');
        ctx.out.write('$indent$bullet');
        for (final c in node.nodes) {
          _walk(c, ctx);
        }
        ctx.newline();
        return;

      case 'h1':
      case 'h2':
      case 'h3':
      case 'h4':
      case 'h5':
      case 'h6':
        ctx.blockBreak();
        for (final c in node.nodes) {
          _walk(c, ctx);
        }
        ctx.blockBreak();
        return;

      case 'table':
        ctx.blockBreak();
        _emitTable(node, ctx);
        ctx.blockBreak();
        return;

      default:
        final isBlock = _blockTags.contains(tag);
        if (isBlock) ctx.blockBreak();
        for (final c in node.nodes) {
          _walk(c, ctx);
        }
        if (isBlock) ctx.blockBreak();
        return;
    }
  }

  // ── Text / whitespace ────────────────────────────────────────────────

  static void _emitText(String text, _WalkCtx ctx) {
    if (ctx.preDepth > 0) {
      // Preserve whitespace verbatim inside <pre>
      ctx.flushPending();
      ctx.out.write(text);
      ctx.atLineStart = text.endsWith('\n');
      return;
    }
    // Collapse runs of whitespace (including NBSP) to single space
    final collapsed = text.replaceAll(RegExp(r'[\s\u00A0]+'), ' ');
    if (collapsed.isEmpty) return;
    ctx.flushPending();
    ctx.out.write(collapsed);
    ctx.atLineStart = false;
  }

  // ── Links ────────────────────────────────────────────────────────────

  static void _emitAnchor(dom.Element a, _WalkCtx ctx) {
    final href = (a.attributes['href'] ?? '').trim();
    // Render visible text into a sub-buffer
    final textBuf = _WalkCtx();
    for (final c in a.nodes) {
      _walk(c, textBuf);
    }
    final visible = _postProcess(textBuf.out.toString()).trim();

    final safeHref = _sanitizeHref(href);

    if (safeHref == null) {
      // Dangerous or useless URL — emit visible text only
      if (visible.isNotEmpty) {
        ctx.flushPending();
        ctx.out.write(visible);
        ctx.atLineStart = false;
      }
      return;
    }

    ctx.flushPending();
    if (visible.isEmpty) {
      ctx.out.write(safeHref);
    } else if (_sameUrl(visible, safeHref)) {
      ctx.out.write(safeHref);
    } else {
      // Thunderbird-style: "text <url>"
      // Recipient mail readers auto-linkify the angle-bracketed URL,
      // and visible text + real destination are both unambiguous.
      ctx.out.write('$visible <$safeHref>');
    }
    ctx.atLineStart = false;
  }

  static String? _sanitizeHref(String href) {
    if (href.isEmpty) return null;
    final lower = href.toLowerCase();
    if (lower.startsWith('javascript:')) return null;
    if (lower.startsWith('data:')) return null;
    if (lower.startsWith('vbscript:')) return null;
    if (lower.startsWith('#')) return null;
    if (lower.startsWith('mailto:')) return href.substring(7);
    if (lower.startsWith('tel:')) return href.substring(4);
    return href;
  }

  static bool _sameUrl(String visible, String url) {
    String norm(String s) => s
        .toLowerCase()
        .replaceAll(RegExp(r'^https?://'), '')
        .replaceAll(RegExp(r'/$'), '');
    return norm(visible) == norm(url);
  }

  // ── Images ───────────────────────────────────────────────────────────

  static void _emitImage(dom.Element img, _WalkCtx ctx) {
    final src = (img.attributes['src'] ?? '').trim();
    final alt = (img.attributes['alt'] ?? '').trim();
    final width = img.attributes['width'];
    final height = img.attributes['height'];

    // Drop tracking pixels
    if (width == '1' && height == '1') return;
    final style = (img.attributes['style'] ?? '').toLowerCase();
    if (style.contains('width:1px') || style.contains('width: 1px')) {
      return;
    }

    // Drop base64 data URIs entirely — don't re-serve the payload
    if (src.toLowerCase().startsWith('data:')) {
      if (alt.isNotEmpty) {
        ctx.flushPending();
        ctx.out.write('[Image: $alt]');
        ctx.atLineStart = false;
      }
      return;
    }

    // cid: inline attachment — meaningless once detached from MIME
    if (src.toLowerCase().startsWith('cid:')) {
      ctx.flushPending();
      ctx.out.write(alt.isNotEmpty ? '[Image: $alt]' : '[Inline image]');
      ctx.atLineStart = false;
      return;
    }

    if (src.isEmpty && alt.isEmpty) return;

    ctx.flushPending();
    if (alt.isNotEmpty) {
      ctx.out.write('[Image: $alt]');
    } else {
      ctx.out.write('[Image]');
    }
    ctx.atLineStart = false;
  }

  // ── Tables ───────────────────────────────────────────────────────────

  static void _emitTable(dom.Element table, _WalkCtx ctx) {
    final rows = table.querySelectorAll('tr');
    if (rows.isEmpty) {
      for (final c in table.nodes) {
        _walk(c, ctx);
      }
      return;
    }

    final List<List<String>> grid = [];
    for (final tr in rows) {
      final cells = <String>[];
      for (final cell in tr.children) {
        final name = cell.localName?.toLowerCase();
        if (name != 'td' && name != 'th') continue;
        final cellCtx = _WalkCtx();
        for (final c in cell.nodes) {
          _walk(c, cellCtx);
        }
        cells.add(_postProcess(cellCtx.out.toString())
            .replaceAll('\n', ' ')
            .trim());
      }
      if (cells.isNotEmpty) grid.add(cells);
    }

    // Transparent single-cell table (common in marketing layouts)
    if (grid.length == 1 && grid.first.length == 1) {
      ctx.flushPending();
      ctx.out.write(grid.first.first);
      ctx.atLineStart = false;
      return;
    }

    ctx.flushPending();
    for (final row in grid) {
      ctx.out.write(row.join(' | '));
      ctx.out.write('\n');
    }
    ctx.atLineStart = true;
  }

  // ── Post-processing ──────────────────────────────────────────────────

  static String _postProcess(String s) {
    var out = s;
    // Collapse 3+ newlines into 2
    out = out.replaceAll(RegExp(r'\n{3,}'), '\n\n');
    // Trim trailing spaces per line
    out = out
        .split('\n')
        .map((l) => l.replaceAll(RegExp(r'[ \t]+$'), ''))
        .join('\n');
    return out.trim();
  }
}

// ── Walker state ──────────────────────────────────────────────────────

class _WalkCtx {
  final StringBuffer out = StringBuffer();

  /// Number of pending block breaks to emit before next content.
  int pendingBreaks = 0;

  /// True if we're at the start of a logical line (for blockquote prefix).
  bool atLineStart = true;

  int blockquoteDepth = 0;
  int preDepth = 0;
  final List<_ListCtx> listStack = [];

  void newline() {
    if (pendingBreaks < 1) pendingBreaks = 1;
  }

  void blockBreak() {
    pendingBreaks = 2;
    atLineStart = true;
  }

  void flushPending() {
    if (pendingBreaks == 0) return;
    final prefix = '> ' * blockquoteDepth;
    for (var i = 0; i < pendingBreaks; i++) {
      out.write('\n');
    }
    if (blockquoteDepth > 0) out.write(prefix);
    pendingBreaks = 0;
    atLineStart = false;
  }
}

class _ListCtx {
  final bool ordered;
  int counter;
  _ListCtx.ordered()
      : ordered = true,
        counter = 1;
  _ListCtx.unordered()
      : ordered = false,
        counter = 0;
}
