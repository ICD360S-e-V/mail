import 'package:path/path.dart' as p;

/// Sanitize an attachment filename for safe local storage.
///
/// SECURITY: Email attachment filenames come from the MIME Content-Disposition
/// header, which is fully attacker-controlled. Without sanitization, an
/// attacker can send an email with a crafted filename to:
/// - Use absolute paths (`/etc/cron.d/x`, `C:\Windows\System32\...`)
/// - Use `..` traversal to escape the intended directory
/// - Overwrite arbitrary files (~/.bashrc, authorized_keys, Startup folder, etc.)
///
/// `package:path` `p.join(dir, abs)` returns `abs` unchanged when `abs` is
/// absolute, which is exactly the trap that makes the naive code vulnerable.
///
/// This function:
/// - Strips any directory components (defeats absolute paths and `..`)
/// - Also strips Windows-style separators on POSIX systems
/// - Removes control characters and null bytes
/// - Replaces Windows-illegal characters (`< > : " | ? *`) with `_`
/// - Rejects Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
/// - Truncates to 200 chars (preserves extension)
/// - Falls back to `"attachment"` if nothing safe remains
///
/// Use this on EVERY attachment filename before passing it to `File(...)`,
/// `p.join`, or any filesystem API.
String safeAttachmentFileName(String raw) {
  // Step 1: strip any directory components — defeats path traversal
  var name = p.basename(raw);

  // Step 2: also handle Windows-style separators that p.basename misses on POSIX
  final lastSep = name.lastIndexOf(RegExp(r'[\\/]'));
  if (lastSep >= 0) {
    name = name.substring(lastSep + 1);
  }

  // Step 3: remove control characters (0x00-0x1F, 0x7F) and null bytes,
  // plus Unicode bidirectional controls (Trojan Source / CVE-2021-42574)
  name = name.replaceAll(
    RegExp(r'[\x00-\x1F\x7F\u200E\u200F\u202A-\u202E\u2066-\u2069]'),
    '',
  );

  // Step 4: replace Windows-illegal filename chars
  name = name.replaceAll(RegExp(r'[<>:"|?*]'), '_');

  // Step 5: trim whitespace
  name = name.trim();

  // Step 6: reject dangerous bare names
  if (name.isEmpty || name == '.' || name == '..') {
    return 'attachment';
  }

  // Step 7: reject Windows reserved device names (case-insensitive)
  final stem = name.split('.').first.toUpperCase();
  const reserved = {
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
  };
  if (reserved.contains(stem)) {
    name = '_$name';
  }

  // Step 8: truncate to 200 chars while preserving extension
  if (name.length > 200) {
    final ext = p.extension(name);
    final stemPart = p.basenameWithoutExtension(name);
    final maxStem = 200 - ext.length;
    name = stemPart.substring(0, maxStem > 0 ? maxStem : 0) + ext;
  }

  return name;
}
