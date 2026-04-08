import 'dart:convert';
import 'dart:io';
import 'le_issuer_check.dart';
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

  /// Strict TLS validation using shared LE issuer helper.
  /// Only accept certs for mail.icd360s.de signed by a known LE CA.
  static bool _validateCertificate(X509Certificate cert, String host, int port) {
    if (host != 'mail.icd360s.de') return false;
    return isTrustedLetsEncryptIssuer(cert.issuer);
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

