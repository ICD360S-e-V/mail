// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

/// PII (Personally Identifiable Information) redaction for diagnostic logs.
///
/// GDPR Art. 25 (Privacy by Design): redaction is built into the logging
/// architecture, not bolted on at each call site.
///
/// Two layers of protection:
/// 1. **Typed [Pii] wrappers** — call sites use [piiEmail], [piiUrl], etc.
///    whose `toString()` returns the redacted form automatically via Dart
///    string interpolation.
/// 2. **Regex safety net** — [PiiRedactor.sanitize] runs on every log
///    message before it enters the buffer, catching any PII that leaked
///    through unstructured string interpolation.
library;

/// PII field types with type-specific redaction policies.
enum PiiType {
  email,
  url,
  ipAddress,
  emailSubject,
  username,
  recipientList,
}

/// Wrapper that marks a value as PII. Its [toString] returns the
/// redacted form, so `'Error for ${piiEmail(addr)}'` is safe by
/// construction.
class Pii {
  final String value;
  final PiiType type;
  const Pii(this.value, this.type);

  @override
  String toString() => PiiRedactor.redact(value, type);
}

// ── Convenience constructors ───────────────────────────────────

/// `john.doe@example.com` → `j***@example.com`
Pii piiEmail(String email) => Pii(email, PiiType.email);

/// `https://example.com/path?q=v` → `https://example.com/[path]`
Pii piiUrl(String url) => Pii(url, PiiType.url);

/// `192.168.1.42` → `192.168.x.x`
Pii piiIp(String ip) => Pii(ip, PiiType.ipAddress);

/// `Meeting tomorrow 3pm` → `[subject:21chars]`
Pii piiSubject(String subject) => Pii(subject, PiiType.emailSubject);

/// `johndoe` → `j***`
Pii piiUsername(String username) => Pii(username, PiiType.username);

/// `['a@b.com','c@d.com']` → `recipients:2`
Pii piiRecipients(List<String> recipients) =>
    Pii('recipients:${recipients.length}', PiiType.recipientList);

// ── Central redaction engine ───────────────────────────────────

/// All PII flows through this class — both typed fields and the
/// regex safety net.
class PiiRedactor {
  PiiRedactor._();

  // ── Type-specific redaction ────────────────────────────────

  /// Redact [value] according to its [PiiType] policy.
  static String redact(String value, PiiType type) {
    switch (type) {
      case PiiType.email:
        return _redactEmail(value);
      case PiiType.url:
        return _redactUrl(value);
      case PiiType.ipAddress:
        return _redactIp(value);
      case PiiType.emailSubject:
        return _redactSubject(value);
      case PiiType.username:
        return _redactUsername(value);
      case PiiType.recipientList:
        return value; // Already just "recipients:N"
    }
  }

  /// `john.doe@example.com` → `j***@example.com`
  static String _redactEmail(String email) {
    final atIndex = email.indexOf('@');
    if (atIndex <= 0) return '[redacted-email]';
    final firstChar = email[0];
    final domain = email.substring(atIndex + 1);
    return '$firstChar***@$domain';
  }

  /// `https://example.com/inbox/123?token=abc` → `https://example.com/[path]`
  static String _redactUrl(String url) {
    try {
      final uri = Uri.parse(url);
      if (uri.host.isEmpty) return '[redacted-url]';
      return '${uri.scheme}://${uri.host}/[path]';
    } catch (_) {
      return '[redacted-url]';
    }
  }

  /// `192.168.1.42` → `192.168.x.x`
  static String _redactIp(String ip) {
    final v4Parts = ip.split('.');
    if (v4Parts.length == 4) {
      return '${v4Parts[0]}.${v4Parts[1]}.x.x';
    }
    // IPv6 — keep first 2 groups
    final v6Parts = ip.split(':');
    if (v6Parts.length >= 4) {
      return '${v6Parts.take(2).join(':')}:x:x:...';
    }
    return '[redacted-ip]';
  }

  /// `Meeting tomorrow at 3pm` → `[subject:24chars]`
  static String _redactSubject(String subject) {
    return '[subject:${subject.length}chars]';
  }

  /// `johndoe` → `j***`
  static String _redactUsername(String username) {
    if (username.isEmpty) return '[empty]';
    return '${username[0]}***';
  }

  // ── Regex safety net ───────────────────────────────────────

  static final _emailPattern =
      RegExp(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}');

  static final _urlPattern = RegExp(r'https?://[^\s\]>)"]+');

  static final _ipv4Pattern =
      RegExp(r'\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b');

  static final _phonePattern =
      RegExp(r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}');

  /// Run the regex safety net on a fully-formed log string.
  /// Catches PII that leaked through unstructured interpolation.
  static String sanitize(String text) {
    var result = text;

    // Redact email addresses
    result = result.replaceAllMapped(_emailPattern, (match) {
      return _redactEmail(match.group(0)!);
    });

    // Redact URLs with paths (keep scheme + host)
    result = result.replaceAllMapped(_urlPattern, (match) {
      return _redactUrl(match.group(0)!);
    });

    // Redact IPv4 addresses (keep first two octets for diagnostics)
    result = result.replaceAllMapped(_ipv4Pattern, (match) {
      final o1 = int.tryParse(match.group(1) ?? '') ?? 0;
      final o2 = int.tryParse(match.group(2) ?? '') ?? 0;
      if (o1 > 255 || o2 > 255) return match.group(0)!;
      // Skip localhost and common non-PII ranges
      if (match.group(0) == '127.0.0.1') return match.group(0)!;
      return '${match.group(1)}.${match.group(2)}.x.x';
    });

    // Redact phone numbers
    result = result.replaceAllMapped(_phonePattern, (match) {
      final raw = match.group(0)!;
      final digits = raw.replaceAll(RegExp(r'[^\d]'), '');
      if (digits.length < 7) return raw;
      return '****${digits.substring(digits.length - 4)}';
    });

    return result;
  }

  /// Sanitize an exception's toString() output.
  static String sanitizeException(Object error) {
    return sanitize(error.toString());
  }
}