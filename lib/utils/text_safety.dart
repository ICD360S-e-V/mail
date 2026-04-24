// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Strips Unicode bidirectional control characters from a string.
///
/// SECURITY: Defends against "Trojan Source" / CVE-2021-42574 visual
/// spoofing attacks. Email headers (`From`, `To`, `Subject`) and
/// attachment filenames come from attacker-controlled input. Without
/// sanitization, characters such as `U+202E` (RIGHT-TO-LEFT OVERRIDE)
/// can be embedded so the displayed text differs from the underlying
/// bytes — for example making `support@evil.com` look like
/// `support@bank.com` to the user.
///
/// Stripped codepoints (Unicode bidi controls):
/// - `U+200E` LRM, `U+200F` RLM (left/right marks)
/// - `U+202A` LRE, `U+202B` RLE, `U+202C` PDF
/// - `U+202D` LRO, `U+202E` RLO (overrides — the dangerous ones)
/// - `U+2066` LRI, `U+2067` RLI, `U+2068` FSI, `U+2069` PDI (isolates)
///
/// Apply this to any header or filename before passing it to a UI
/// widget. Do NOT apply to message bodies (legitimate RTL languages
/// rely on these characters to render correctly) or to outgoing
/// reply/forward content (would corrupt the user's own message).
String sanitizeBidi(String input) {
  return input.replaceAll(
    RegExp(r'[\u200E\u200F\u202A-\u202E\u2066-\u2069]'),
    '',
  );
}