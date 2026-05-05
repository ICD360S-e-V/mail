// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'le_issuer_check.dart';
import 'package:basic_utils/basic_utils.dart';
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

  /// SPKI pins (SHA-256 of Subject Public Key Info, base64).
  /// Matches ANY cert in the chain — survives LE renewals as long as
  /// the server key stays the same. Backup pins for ISRG roots ensure
  /// continuity if the leaf key is rotated.
  static const _spkiPins = <String>{
    'xOwN8+H2i85WBB5cWFKJ3JwWEtPyvOEYz6P5SGm7/uE=', // leaf mail.icd360s.de
    'iFvwVyJSxnQdyaUvUERIf+8qk7gRze3612JMwoO3zdU=', // intermediate LE E8
    'C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=', // ISRG Root X1
    'diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=', // ISRG Root X2
  };

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
      context.usePrivateKeyBytes(CertificateService.clientKey!);
      LoggerService.log('MTLS', '✓ Per-user private key loaded');

      // STEP 2: Add certificate chain (unique per user)
      final certBytes = CertificateService.clientCert!;
      final caBytes = CertificateService.caCert!;
      final fullChain = Uint8List(certBytes.length + 1 + caBytes.length)
        ..setAll(0, certBytes)
        ..[certBytes.length] = 0x0A // newline
        ..setAll(certBytes.length + 1, caBytes);
      context.useCertificateChainBytes(fullChain);
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
      client.badCertificateCallback =
          (cert, host, port) => onBadCertificate(cert, host);
      return client;
    } catch (ex, st) {
      LoggerService.logError('MTLS', ex, st);
      return null;
    }
  }


  /// Check if cert's SAN contains the expected hostname.
  /// Falls back to CN check if SAN parsing fails.
  static bool _matchesExpectedHost(X509Certificate cert) {
    // Primary: SAN check via basic_utils (future-proof, RFC 6125)
    try {
      final certData = X509Utils.x509CertificateFromPem(cert.pem);
      final sans = certData.subjectAlternativNames ?? [];
      if (sans.any((san) => san.toLowerCase() == _expectedHost)) {
        return true;
      }
    } catch (_) {
      // SAN parsing failed — fall through to CN check
    }
    // Fallback: CN check (deprecated per RFC 6125, but still works)
    final subjectCN = _extractCN(cert.subject);
    return subjectCN == _expectedHost;
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
  static bool onBadCertificate(X509Certificate cert, [String? host]) {
    try {
      final subject = cert.subject;
      final issuer = cert.issuer;
      final subjectCN = _extractCN(subject);
      final issuerCN = _extractCN(issuer);

      // SPKI pinning: SHA-256 of the cert's public key DER.
      // Survives cert renewals as long as the key pair stays the same.
      // Even a compromised CA cannot forge a cert with our pinned key.
      final spkiMatch = _checkSpkiPin(cert);

      // Case 1: LEAF cert for our domain.
      if (_matchesExpectedHost(cert)) {
        if (!isTrustedLetsEncryptIssuer(issuer)) {
          LoggerService.logWarning('MTLS',
              '❌ REJECTED leaf CN=$subjectCN: issuer not trusted LE');
          return false;
        }
        if (!spkiMatch) {
          LoggerService.logWarning('MTLS',
              '❌ REJECTED leaf CN=$subjectCN: SPKI pin mismatch');
          return false;
        }
        LoggerService.log('MTLS',
            '✓ Accepted leaf: CN=$subjectCN (SPKI pinned, issuer CN=$issuerCN)');
        return true;
      }

      // Case 2: INTERMEDIATE cert (LE CA).
      if (isTrustedLetsEncryptIssuer(subject) &&
          isTrustedLetsEncryptIssuer(issuer)) {
        if (spkiMatch) {
          LoggerService.log('MTLS',
              '✓ Accepted intermediate: CN=$subjectCN (SPKI pinned)');
        } else {
          LoggerService.log('MTLS',
              '✓ Accepted intermediate: CN=$subjectCN (issuer trusted)');
        }
        return true;
      }

      // Case 3: ROOT cert (ISRG Root X1, X2).
      if (isTrustedLetsEncryptIssuer(subject)) {
        if (subject == issuer ||
            _extractCN(subject) == _extractCN(issuer)) {
          LoggerService.log('MTLS', '✓ Accepted root: CN=$subjectCN');
          return true;
        }
      }

      LoggerService.logWarning('MTLS',
          '❌ REJECTED: CN=$subjectCN (host=$host, subject=$subject)');
      return false;
    } catch (ex) {
      LoggerService.logWarning('MTLS',
          '❌ Certificate validation error: $ex — rejecting');
      return false;
    }
  }

  static bool _checkSpkiPin(X509Certificate cert) {
    try {
      final pem = cert.pem;
      final derCert = base64.decode(
          pem.replaceAll('-----BEGIN CERTIFICATE-----', '')
             .replaceAll('-----END CERTIFICATE-----', '')
             .replaceAll(RegExp(r'\s'), ''));
      final spkiDer = _extractSpkiFromDer(derCert);
      if (spkiDer == null) return false;
      final hash = sha256.convert(spkiDer);
      final pin = base64.encode(hash.bytes);
      return _spkiPins.contains(pin);
    } catch (_) {
      return false;
    }
  }

  static Uint8List? _extractSpkiFromDer(Uint8List certDer) {
    try {
      var offset = 0;
      int readTag() => certDer[offset++];
      int readLength() {
        var len = certDer[offset++];
        if (len & 0x80 != 0) {
          final numBytes = len & 0x7F;
          len = 0;
          for (var i = 0; i < numBytes; i++) {
            len = (len << 8) | certDer[offset++];
          }
        }
        return len;
      }
      void skipTlv() { readTag(); final l = readLength(); offset += l; }

      readTag(); readLength(); // outer SEQUENCE
      readTag(); readLength(); // tbsCertificate SEQUENCE
      // version [0] (if present)
      if (certDer[offset] == 0xA0) { readTag(); final l = readLength(); offset += l; }
      skipTlv(); // serialNumber
      skipTlv(); // signature
      skipTlv(); // issuer
      skipTlv(); // validity
      skipTlv(); // subject
      // subjectPublicKeyInfo SEQUENCE — this is SPKI
      final spkiStart = offset;
      readTag();
      final spkiBodyLen = readLength();
      return Uint8List.sublistView(certDer, spkiStart, offset + spkiBodyLen);
    } catch (_) {
      return null;
    }
  }
}
