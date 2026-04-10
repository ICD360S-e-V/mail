import 'package:basic_utils/basic_utils.dart';
import 'certificate_service.dart';
import 'logger_service.dart';
import 'portable_secure_storage.dart';

/// Monitor certificate expiration using the real NotAfter date parsed
/// from the PEM certificate (via basic_utils X509 parser).
///
/// Previous implementation estimated expiry as 90 days from first
/// check — this was inaccurate (drifted on restart, broke if server
/// changed validity period).
class CertificateExpiryMonitor {
  // PortableSecureStorage uses native storage on iOS/Android/Windows/
  // Linux and AES-GCM file backend on macOS (Keychain unavailable on
  // ad-hoc signed builds).
  static final _storage = PortableSecureStorage.instance;
  static const _kNotAfter = 'client_cert_not_after_utc';
  static const _kNotBefore = 'client_cert_not_before_utc';

  static DateTime? _certNotAfter;
  static DateTime? _certNotBefore;

  /// Parse the real expiry from a PEM certificate string and persist it.
  ///
  /// Call this from CertificateService after a successful download.
  /// Returns the NotAfter DateTime, or null if parsing failed.
  ///
  /// PEM parsing and persistence are wrapped in SEPARATE try/catch
  /// blocks so the log message accurately reflects which step failed.
  /// (Previously a Keychain failure during persist was misreported as
  /// "Failed to parse certificate expiry from PEM".)
  static Future<DateTime?> parseCertAndPersistExpiry(String pemCert) async {
    // ── Step 1: Parse PEM ──
    DateTime notAfter;
    DateTime notBefore;
    try {
      final certData = X509Utils.x509CertificateFromPem(pemCert);
      final validity = certData.tbsCertificate?.validity;
      if (validity == null) {
        LoggerService.logWarning('CERT-EXPIRY',
            'PEM parse: tbsCertificate or validity field is null');
        return null;
      }
      notAfter = validity.notAfter;
      notBefore = validity.notBefore;
    } catch (ex, stackTrace) {
      LoggerService.logError('CERT-EXPIRY',
          'PEM parse failed: $ex', stackTrace);
      return null;
    }

    // ── Step 2: Update in-memory cache (always succeeds) ──
    _certNotAfter = notAfter;
    _certNotBefore = notBefore;
    LoggerService.log('CERT-EXPIRY',
        'Parsed certificate validity: '
        '${notBefore.toIso8601String()} to ${notAfter.toIso8601String()} '
        '(${notAfter.difference(notBefore).inDays} days)');

    // ── Step 3: Persist to secure storage (best-effort) ──
    // On macOS ad-hoc signed builds, flutter_secure_storage may fail
    // with errSecMissingEntitlement (-34018). The in-memory cache
    // above still works for the current session, so log a warning
    // but do not treat persistence failure as a hard error.
    try {
      await _storage.write(
        key: _kNotAfter,
        value: notAfter.toUtc().toIso8601String(),
      );
      await _storage.write(
        key: _kNotBefore,
        value: notBefore.toUtc().toIso8601String(),
      );
    } catch (ex) {
      LoggerService.logWarning('CERT-EXPIRY',
          'Could not persist expiry to secure storage '
          '(in-memory cache still works): $ex');
    }

    return notAfter;
  }

  /// Load persisted expiry from secure storage (call on app startup).
  static Future<void> loadPersistedExpiry() async {
    try {
      final notAfterStr = await _storage.read(key: _kNotAfter);
      final notBeforeStr = await _storage.read(key: _kNotBefore);

      if (notAfterStr != null) {
        _certNotAfter = DateTime.parse(notAfterStr);
      }
      if (notBeforeStr != null) {
        _certNotBefore = DateTime.parse(notBeforeStr);
      }
    } catch (ex) {
      LoggerService.logWarning('CERT-EXPIRY',
          'Could not load persisted expiry: $ex');
    }
  }

  /// Get days until certificate expiry.
  /// Returns negative if expired, null if unknown.
  static int? getDaysUntilExpiry() {
    if (!CertificateService.hasCertificates) {
      return null;
    }

    // Try in-memory cache first
    if (_certNotAfter != null) {
      final daysLeft = _certNotAfter!.difference(DateTime.now().toUtc()).inDays;
      LoggerService.log('CERT-EXPIRY',
          'Certificate expires in $daysLeft days '
          '(${_certNotAfter!.toIso8601String()})');
      return daysLeft;
    }

    // If no parsed expiry available, try parsing the current cert
    final cert = CertificateService.clientCert;
    if (cert != null) {
      try {
        final certData = X509Utils.x509CertificateFromPem(cert);
        final validity = certData.tbsCertificate?.validity;
        if (validity == null) {
          LoggerService.logWarning('CERT-EXPIRY',
              'On-demand parse: validity is null');
          return null;
        }
        _certNotAfter = validity.notAfter;
        _certNotBefore = validity.notBefore;

        final daysLeft =
            _certNotAfter!.difference(DateTime.now().toUtc()).inDays;
        LoggerService.log('CERT-EXPIRY',
            'Parsed on-demand: expires in $daysLeft days');
        return daysLeft;
      } catch (ex) {
        LoggerService.logWarning('CERT-EXPIRY',
            'Could not parse certificate: $ex');
      }
    }

    return null;
  }

  /// Check if certificate is expiring soon (< 30 days)
  static bool isExpiringSoon() {
    final days = getDaysUntilExpiry();
    if (days == null) return false;
    return days < 30 && days >= 0;
  }

  /// Check if certificate is expired
  static bool isExpired() {
    final days = getDaysUntilExpiry();
    if (days == null) return false;
    return days < 0;
  }

  /// Get user-friendly expiry message
  static String getExpiryMessage() {
    final days = getDaysUntilExpiry();

    if (days == null) {
      return 'Certificate status unknown';
    } else if (days < 0) {
      return 'Certificate EXPIRED - Please re-login to renew';
    } else if (days < 7) {
      return 'Certificate expires in $days days - Re-login urgently';
    } else if (days < 30) {
      return 'Certificate expires in $days days - Re-login recommended';
    } else {
      return 'Certificate valid for $days days';
    }
  }

  /// Clear persisted expiry (call on logout/cert wipe).
  static Future<void> clearExpiry() async {
    _certNotAfter = null;
    _certNotBefore = null;
    await _storage.delete(key: _kNotAfter);
    await _storage.delete(key: _kNotBefore);
  }
}
