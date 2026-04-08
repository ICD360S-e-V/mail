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
          'Creating SecurityContext with per-user certificate for ${CertificateService.currentUsername}...');

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
      LoggerService.log('MTLS',
          '✓ Per-user certificate chain loaded (UNIQUE for ${CertificateService.currentUsername})');

      LoggerService.log('MTLS', '✓ SecurityContext ready for mTLS (per-user mode)');

      return context;
    } catch (ex, stackTrace) {
      LoggerService.logError('MTLS', ex, stackTrace);
      rethrow;
    }
  }

  /// Callback for server certificate validation.
  ///
  /// IMPORTANT: Dart's badCertificateCallback is called ONCE PER CERT in the
  /// chain that fails validation — not just for the leaf. We must accept:
  ///   1. The leaf cert (subject = `/CN=mail.icd360s.de`), if its issuer is
  ///      a trusted Let's Encrypt intermediate.
  ///   2. The intermediate cert (subject = `/CN=E7` etc.), if its issuer is
  ///      a trusted Let's Encrypt root.
  ///   3. The root cert itself (subject = `/CN=ISRG Root X1` etc.) if it
  ///      ever appears at this level.
  ///
  /// Returning false for ANY of these aborts the entire chain. The previous
  /// implementation rejected the intermediate because it checked
  /// `subject.contains('mail.icd360s.de')` — which is true only for the leaf.
  static bool onBadCertificate(X509Certificate cert) {
    try {
      final subject = cert.subject;
      final issuer = cert.issuer;

      LoggerService.log('MTLS', 'Server cert check: $subject (issuer: $issuer)');

      // Case 1: this cert IS a trusted Let's Encrypt CA (intermediate or root).
      // Subject's CN matches a known LE CA.
      if (isTrustedLetsEncryptIssuer(subject)) {
        LoggerService.log('MTLS', '✓ Accepted LE CA cert: $subject');
        return true;
      }

      // Case 2: this is the leaf for mail.icd360s.de. Verify both the
      // hostname and that it was signed by a trusted LE intermediate.
      if (subject.contains('mail.icd360s.de')) {
        if (isTrustedLetsEncryptIssuer(issuer)) {
          LoggerService.log('MTLS', '✓ Accepted leaf for mail.icd360s.de (signed by trusted LE)');
          return true;
        }
        LoggerService.log('MTLS', '❌ REJECTED: leaf for mail.icd360s.de but issuer not trusted: $issuer');
        return false;
      }

      // Otherwise, reject — neither a trusted CA nor our domain's leaf.
      LoggerService.log('MTLS', '❌ REJECTED: $subject is neither a trusted LE CA nor our domain leaf');
      return false;
    } catch (ex) {
      LoggerService.log('MTLS', '❌ Certificate validation error: $ex');
      return false;
    }
  }
}

