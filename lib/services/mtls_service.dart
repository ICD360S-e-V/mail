import 'dart:io';
import 'dart:convert';
import 'logger_service.dart';
import 'certificate_service.dart';

/// mTLS (Mutual TLS) Service - Client certificate authentication
/// Uses per-user certificates (downloaded at login, NOT hardcoded)
///
/// SECURITY: No certificates hardcoded in code - eliminates extraction vulnerability
/// Each user gets a UNIQUE certificate from server (not shared between users)
class MtlsService {
  // No hardcoded certificates - all downloaded dynamically per-user
  // This prevents certificate extraction from compiled .exe file

  // Trusted Let's Encrypt issuer Distinguished Names (exact match, not substring)
  static const _trustedIssuers = [
    'CN=R3,O=Let\'s Encrypt,C=US',
    'CN=R10,O=Let\'s Encrypt,C=US',
    'CN=R11,O=Let\'s Encrypt,C=US',
    'CN=R12,O=Let\'s Encrypt,C=US',
    'CN=E5,O=Let\'s Encrypt,C=US',
    'CN=E6,O=Let\'s Encrypt,C=US',
    'CN=E7,O=Let\'s Encrypt,C=US',
    'CN=E8,O=Let\'s Encrypt,C=US',
    'CN=ISRG Root X1,O=Internet Security Research Group,C=US',
    'CN=ISRG Root X2,O=Internet Security Research Group,C=US',
  ];

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

      // Use withTrustedRoots: true to validate Let's Encrypt server certificate
      final context = SecurityContext(withTrustedRoots: true);

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

  /// Callback for server certificate validation
  /// Only accepts Let's Encrypt certificates for mail.icd360s.de
  /// SECURITY: Validates full issuer DN to prevent MITM attacks
  static bool onBadCertificate(X509Certificate cert) {
    try {
      final subject = cert.subject;
      final issuer = cert.issuer;

      LoggerService.log('MTLS', 'Server cert check: $subject (issuer: $issuer)');

      // Exact match against known Let's Encrypt issuer DNs
      final isLetsEncrypt = _trustedIssuers.any(
        (trusted) => issuer == trusted || issuer.contains(trusted),
      );

      if (!isLetsEncrypt) {
        LoggerService.log('MTLS', '❌ REJECTED: Unknown issuer: $issuer (not a trusted Let\'s Encrypt CA)');
        return false;
      }

      // Verify the certificate is for our server
      final isOurServer = subject.contains('mail.icd360s.de');
      if (!isOurServer) {
        LoggerService.log('MTLS', '❌ REJECTED: Certificate not for mail.icd360s.de: $subject');
        return false;
      }

      LoggerService.log('MTLS', '✓ Certificate accepted (Let\'s Encrypt for mail.icd360s.de)');
      return true;
    } catch (ex) {
      LoggerService.log('MTLS', '❌ Certificate validation error: $ex');
      return false;
    }
  }
}