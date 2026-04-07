import 'dart:convert';
import 'dart:io';
import 'logger_service.dart';

/// Model for a changelog section (one version)
class ChangelogSection {
  final String title;
  final List<String> entries;

  ChangelogSection({required this.title, required this.entries});
}

/// Service for fetching changelog from server
class ChangelogService {
  static const String changelogUrl =
      'https://mail.icd360s.de/updates/changelog.json';

  // Trusted Let's Encrypt issuer DNs (same exact DN list as MtlsService,
  // CertificateService, UpdateService, LogUploadService — keep in sync).
  // SECURITY (L8): Replaces the previous loose `cert.issuer.contains("Let's
  // Encrypt")` check that would accept any cert whose issuer string happened
  // to mention Let's Encrypt anywhere.
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

  /// Strict TLS validation: only accept certs for mail.icd360s.de signed by
  /// a known Let's Encrypt issuer DN (exact match, not substring).
  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    final issuer = cert.issuer;
    return _trustedIssuers.any(
      (trusted) => issuer == trusted || issuer.contains(trusted),
    );
  }

  /// Fetch structured changelog from server
  /// Returns null if server is unreachable (fallback to local)
  static Future<List<ChangelogSection>?> fetchChangelog() async {
    try {
      LoggerService.log('CHANGELOG', 'Fetching changelog from $changelogUrl');

      final client = HttpClient()
        ..badCertificateCallback = _validateCertificate;
      try {
        final request = await client.getUrl(Uri.parse(changelogUrl));
        final response = await request.close();

        if (response.statusCode == 200) {
          final jsonString = await response.transform(utf8.decoder).join();
          final json = jsonDecode(jsonString) as Map<String, dynamic>;
          final versions = json['versions'] as List<dynamic>;

          final sections = versions.map((v) {
            final map = v as Map<String, dynamic>;
            return ChangelogSection(
              title: map['title'] as String,
              entries: (map['entries'] as List<dynamic>).cast<String>(),
            );
          }).toList();

          LoggerService.log(
              'CHANGELOG', 'Fetched ${sections.length} versions from server');
          return sections;
        }
      } finally {
        client.close();
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('CHANGELOG', ex, stackTrace);
    }
    return null;
  }
}
