/// Validation helper for Let's Encrypt issuer DNs.
///
/// SECURITY: Dart's `X509Certificate.issuer` returns the DN in OpenSSL
/// slash-separated format (e.g. `/C=US/O=Let's Encrypt/CN=E7`). The
/// previous validation code in v2.20.0 - v2.20.1 compared against
/// RFC 4514 comma-separated strings which never matched.
///
/// HISTORY: Earlier revisions of this helper maintained a hardcoded
/// allowlist of intermediate Common Names (R3, R10-R12, E5-E8). That
/// approach is brittle: Let's Encrypt rotates intermediates roughly
/// yearly, and in November 2025 introduced an entirely new "Generation
/// Y" hierarchy with intermediates named YE1-YE3 / YR1-YR3 and new
/// roots ISRG Root YE / YR — none of which match the previous CN
/// patterns. A hardcoded list would silently DoS the app on the next
/// LE rotation.
///
/// CURRENT APPROACH: Validate by Organization (O) field only. Any
/// certificate issued by `Let's Encrypt` (intermediate) or by
/// `Internet Security Research Group` (root) is accepted, regardless
/// of CN. This is safe because:
///
///   1. Dart's `dart:io` already performs full PKIX chain validation
///      against the system trust store BEFORE invoking onBadCertificate
///      callbacks. By the time this function runs, the chain is known
///      to terminate at a system-trusted root.
///   2. DNS CAA records on icd360s.de restrict certificate issuance to
///      `letsencrypt.org` only — no other CA can mint a cert for our
///      hostnames.
///   3. Mobile platforms (Android/iOS) additionally pin the SPKI of
///      the ISRG roots in network_security_config.xml / NSPinnedDomains.
///   4. Certificate Transparency logs all LE issuances publicly.
///
/// Used by:
///   - mtls_service.dart       (server cert during mTLS handshake)
///   - certificate_service.dart (downloading per-user cert)
///   - update_service.dart     (downloading version.json + binaries)
///   - log_upload_service.dart (uploading diagnostic logs)
///   - changelog_service.dart  (downloading changelog)

const _trustedOrganizations = {
  "Let's Encrypt", // intermediates: E5-E8, R10-R13, YE1-YE3, YR1-YR3, ...
  'Internet Security Research Group', // legacy roots: ISRG Root X1, X2
  'ISRG', // Generation Y roots (Nov 2025+): Root YE, Root YR, ...
};

/// Returns true if the given X509 issuer DN string was signed by
/// Let's Encrypt or its parent organization (ISRG).
///
/// Accepts the OpenSSL slash format that Dart's X509Certificate.issuer
/// uses, e.g. `/C=US/O=Let's Encrypt/CN=E7`.
///
/// This intentionally does NOT match against CN — see file header for
/// rationale. Future LE intermediate rotations (E9, R14, YE4, ZE1, ...)
/// are accepted automatically as long as the O field is unchanged.
bool isTrustedLetsEncryptIssuer(String issuer) {
  final oMatch = RegExp(r'/O=([^/]+)').firstMatch(issuer);
  if (oMatch == null) return false;
  return _trustedOrganizations.contains(oMatch.group(1));
}
