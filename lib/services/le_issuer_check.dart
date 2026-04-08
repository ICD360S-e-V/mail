/// Validation helper for Let's Encrypt issuer DNs.
///
/// SECURITY: Dart's `X509Certificate.issuer` returns the DN in OpenSSL
/// slash-separated format (e.g. `/C=US/O=Let's Encrypt/CN=E7`). The
/// previous validation code in v2.20.0 - v2.20.1 compared against
/// RFC 4514 comma-separated strings (e.g. `CN=E7,O=Let's Encrypt,C=US`)
/// which never matched. Result: every legitimate Let's Encrypt cert was
/// rejected by `badCertificateCallback`, breaking IMAP/SMTP/HTTPS in
/// every TLS-validating service.
///
/// This helper parses the CN and O fields out of Dart's slash format and
/// compares against an allowlist. Used by:
///   - mtls_service.dart      (server cert during mTLS handshake)
///   - certificate_service.dart (downloading per-user cert)
///   - update_service.dart    (downloading version.json + binaries)
///   - log_upload_service.dart (uploading diagnostic logs)
///   - changelog_service.dart (downloading changelog)

const _trustedRootCns = ['ISRG Root X1', 'ISRG Root X2'];
const _trustedRootO = 'Internet Security Research Group';
const _trustedIntermediateCns = [
  'R3', 'R10', 'R11', 'R12',
  'E5', 'E6', 'E7', 'E8',
];
const _trustedIntermediateO = "Let's Encrypt";

/// Returns true if the given X509 issuer DN string matches a known
/// Let's Encrypt root or intermediate CA.
///
/// Accepts the OpenSSL slash format that Dart's X509Certificate.issuer
/// uses, e.g. `/C=US/O=Let's Encrypt/CN=E7`.
bool isTrustedLetsEncryptIssuer(String issuer) {
  final cnMatch = RegExp(r'/CN=([^/]+)').firstMatch(issuer);
  final oMatch = RegExp(r'/O=([^/]+)').firstMatch(issuer);
  if (cnMatch == null || oMatch == null) return false;
  final cn = cnMatch.group(1)!;
  final o = oMatch.group(1)!;
  if (_trustedRootCns.contains(cn) && o == _trustedRootO) return true;
  if (_trustedIntermediateCns.contains(cn) && o == _trustedIntermediateO) return true;
  return false;
}
