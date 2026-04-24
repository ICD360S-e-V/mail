// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'dart:convert';
import 'le_issuer_check.dart';
import 'logger_service.dart';
import 'certificate_service.dart';
import 'pinned_security_context.dart';

/// mTLS (Mutual TLS) Service - Client certificate authentication
/// Uses per-user certificates (downloaded at login, NOT hardcoded)
///
/// SECURITY: No certificates hardcoded in code - eliminates extraction vulnerability
/// Each user gets a UNIQUE certificate from server (not shared between users)
class MtlsService {
  // No hardcoded certificates - all downloaded dynamically per-user
  // This prevents certificate extraction from compiled .exe file

  /// The expected hostname for server certificate validation.
  static const _expectedHost = 'mail.icd360s.de';

  /// Extract CN from an OpenSSL oneline subject/issuer string.
  ///
  /// Input format: `/C=US/O=Let's Encrypt/CN=E7`
  /// Returns: `E7` (or null if no CN found)
  static String? _extractCN(String dn) {
    final match = RegExp(r'/CN=([^/]+)').firstMatch(dn);
    return match?.group(1);
  }

  /// Get SecurityContext for mTLS connections
  /// Uses per-user certificates downloaded from server (NOT hardcoded)
  /// Must call CertificateService.downloadCertificateForUser() first
  static SecurityContext getSecurityContext() {
    // Check if certificates are available
    if (!CertificateService.hasCertificates) {
      LoggerService.log('MTLS',
          '❌ ERROR: No certificates downloaded! Call CertificateService.downloadCertificateForUser() first.');
      throw Exception(
          'mTLS Error: Per-user certificate not downloaded. Please login to download your unique certificate.');
    }

    try {
      LoggerService.log('MTLS',
          'Creating SecurityContext with per-user certificate...');

      // Restrict trust store to the four ISRG roots only — defense in
      // depth against compromised system CAs on desktop platforms.
      final context = PinnedSecurityContext.create();

      // STEP 1: Add private key (unique per user)
      context.usePrivateKeyBytes(utf8.encode(CertificateService.clientKey!));
      LoggerService.log('MTLS', '✓ Per-user private key loaded');

      // STEP 2: Add certificate chain (unique per user)
      final fullChain =
          '${CertificateService.clientCert!}\n${CertificateService.caCert!}';
      context.useCertificateChainBytes(utf8.encode(fullChain));
      LoggerService.log('MTLS', '✓ Per-user certificate chain loaded');

      LoggerService.log('MTLS', '✓ SecurityContext ready for mTLS (per-user mode)');

      return context;
    } catch (ex, stackTrace) {
      LoggerService.logError('MTLS', ex, stackTrace);
      rethrow;
    }
  }

  /// Returns an [HttpClient] configured for mTLS — both server cert
  /// pinning (via the SecurityContext from [getSecurityContext]) AND
  /// client cert presentation. Used by /api/client/* endpoints in
  /// v2.28.0+ (B1 from audit) so that nginx can validate the client
  /// against the ICD360S Mail CA chain and extract the username from
  /// the cert CN, eliminating the need for `device_id` as a bearer.
  ///
  /// Returns null if certificates are not yet available (call
  /// [CertificateService.downloadCertificateForUser] first).
  static HttpClient? createMtlsHttpClient() {
    if (!CertificateService.hasCertificates) {
      return null;
    }
    try {
      final context = getSecurityContext();
      final client = HttpClient(context: context)
        ..connectionTimeout = const Duration(seconds: 10)
        ..idleTimeout = const Duration(seconds: 5);
      // For server cert validation: defer to onBadCertificate which
      // already implements the LE issuer + hostname check.
      client.badCertificateCallback =
          (cert, host, port) => onBadCertificate(cert);
      return client;
    } catch (ex, st) {
      LoggerService.logError('MTLS', ex, st);
      return null;
    }
  }

  /// Callback for server certificate validation.
  ///
  /// SECURITY: This callback fires when Dart's built-in PKIX chain
  /// validation fails against our pinned SecurityContext (ISRG roots).
  ///
  /// NOTE: mail_service.dart connects using the resolved IP address
  /// (from DNS lookup), not the hostname "mail.icd360s.de". This causes
  /// hostname verification to fail even for valid LE certs, which is why
  /// this callback is invoked on every connection. We must therefore
  /// perform our own validation here:
  ///
  ///   1. For the LEAF cert: extract CN with exact match against
  ///      "mail.icd360s.de" (not substring contains()), AND verify
  ///      its ISSUER is a trusted LE organization.
  ///   2. For INTERMEDIATE certs (LE CAs): verify their ISSUER is
  ///      a trusted ISRG organization — NOT their subject (previous
  ///      versions incorrectly checked subject).
  ///   3. For ROOT certs (ISRG): verify by exact organization match
  ///      in subject (roots are self-signed, so subject == issuer).
  ///   4. Everything else: reject.
  static bool onBadCertificate(X509Certificate cert) {
    try {
      final subject = cert.subject;
      final issuer = cert.issuer;
      final subjectCN = _extractCN(subject);
      final issuerCN = _extractCN(issuer);

      // Case 1: LEAF cert for our domain.
      // Extract CN exactly — no substring matching.
      if (subjectCN == _expectedHost) {
        // Verify the leaf was signed by a trusted LE intermediate.
        if (isTrustedLetsEncryptIssuer(issuer)) {
          LoggerService.log('MTLS',
              '✓ Accepted leaf: CN=$subjectCN (issuer CN=$issuerCN)');
          return true;
        }
        LoggerService.logWarning('MTLS',
            '❌ REJECTED leaf CN=$subjectCN: issuer not trusted LE '
            '(issuer: $issuer)');
        return false;
      }

      // Case 2: INTERMEDIATE cert (LE CA like E7, R10, YE1 etc.).
      //
      // An intermediate has BOTH:
      //   - Subject O = "Let's Encrypt" (or ISRG)
      //   - Issuer O  = "Internet Security Research Group" (or ISRG)
      //
      // Checking ONLY the issuer (as previous code did) is dangerous:
      // a leaf cert issued by LE for any domain (e.g. evil.com) also
      // has a trusted LE issuer, so it would pass Case 2 and be
      // accepted without hostname verification.
      //
      // By requiring the SUBJECT to also be a trusted LE/ISRG org,
      // we ensure only actual CA intermediates pass — leaf certs for
      // arbitrary domains have subject CN=<domain>, not O=Let's Encrypt.
      if (isTrustedLetsEncryptIssuer(subject) &&
          isTrustedLetsEncryptIssuer(issuer)) {
        LoggerService.log('MTLS',
            '✓ Accepted intermediate: CN=$subjectCN (issuer CN=$issuerCN)');
        return true;
      }

      // Case 3: ROOT cert (ISRG Root X1, X2, YE, YR).
      // Roots are self-signed: subject == issuer. We check subject
      // here because for a root there is no separate issuer to verify.
      if (isTrustedLetsEncryptIssuer(subject)) {
        // Double-check it's actually self-signed (subject ≈ issuer).
        if (subject == issuer ||
            _extractCN(subject) == _extractCN(issuer)) {
          LoggerService.log('MTLS',
              '✓ Accepted root: CN=$subjectCN');
          return true;
        }
      }

      // Case 4: Unknown cert — reject.
      LoggerService.logWarning('MTLS',
          '❌ REJECTED: CN=$subjectCN is neither our domain leaf, '
          'a LE intermediate, nor an ISRG root '
          '(subject: $subject, issuer: $issuer)');
      return false;
    } catch (ex) {
      LoggerService.logWarning('MTLS',
          '❌ Certificate validation error: $ex — rejecting');
      return false;
    }
  }
}
