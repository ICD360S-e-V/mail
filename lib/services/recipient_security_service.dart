// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'dns_checker.dart';
import 'logger_service.dart';

enum RecipientSecurityLevel {
  e2ee,
  daneTls,
  tls,
  plaintext,
  checking,
  error,
}

class RecipientSecurityResult {
  final RecipientSecurityLevel level;
  final String label;
  final String detail;

  const RecipientSecurityResult({
    required this.level,
    required this.label,
    required this.detail,
  });

  static const checking = RecipientSecurityResult(
    level: RecipientSecurityLevel.checking,
    label: 'Checking...',
    detail: 'Verifying recipient security',
  );
}

class RecipientSecurityService {
  static final Map<String, RecipientSecurityResult> _cache = {};
  static final Map<String, DateTime> _cacheExpiry = {};
  static const _cacheDuration = Duration(minutes: 10);

  static Future<RecipientSecurityResult> check(String email) async {
    final domain = email.split('@').last.toLowerCase();

    final cached = _cache[domain];
    final expiry = _cacheExpiry[domain];
    if (cached != null && expiry != null && DateTime.now().isBefore(expiry)) {
      return cached;
    }

    try {
      final result = await _checkDomain(domain);
      _cache[domain] = result;
      _cacheExpiry[domain] = DateTime.now().add(_cacheDuration);
      return result;
    } catch (ex) {
      LoggerService.logWarning('RCPT_SEC', 'Check failed for $domain: $ex');
      return const RecipientSecurityResult(
        level: RecipientSecurityLevel.error,
        label: 'Unknown',
        detail: 'Could not verify recipient security',
      );
    }
  }

  static Future<RecipientSecurityResult> _checkDomain(String domain) async {
    // Internal domain — always E2EE
    if (domain == 'icd360s.de') {
      return const RecipientSecurityResult(
        level: RecipientSecurityLevel.e2ee,
        label: 'E2EE',
        detail: 'End-to-end encrypted (PGP, internal)',
      );
    }

    // Check WKD for PGP key
    // WKD requires HTTPS request which is complex here,
    // so we skip for now and focus on transport security

    // Check DANE TLSA
    final mx = await DnsChecker.lookupMx(domain);
    if (mx.isEmpty) {
      return const RecipientSecurityResult(
        level: RecipientSecurityLevel.plaintext,
        label: 'No MX',
        detail: 'No mail server found for this domain',
      );
    }

    // Extract MX hostname from response (format: "10 mail.example.com.")
    String mxHost = mx.first;
    if (mxHost.contains(' ')) {
      mxHost = mxHost.split(' ').last;
    }
    mxHost = mxHost.replaceAll(RegExp(r'\.$'), '');

    // Check DANE TLSA for MX
    final tlsa = await DnsChecker.lookupTlsa(mxHost);
    if (tlsa.isNotEmpty) {
      final dnssec = await DnsChecker.checkDnssec(domain);
      if (dnssec) {
        return RecipientSecurityResult(
          level: RecipientSecurityLevel.daneTls,
          label: 'DANE+TLS',
          detail: 'Transport verified via DANE/DNSSEC ($mxHost)',
        );
      }
    }

    // Check if MX supports STARTTLS by attempting connection
    try {
      final socket = await Socket.connect(mxHost, 25,
          timeout: const Duration(seconds: 5));
      final banner = await socket.transform(
        const SystemEncoding().decoder).first.timeout(
        const Duration(seconds: 5));
      socket.write('EHLO icd360s.de\r\n');
      await Future.delayed(const Duration(seconds: 1));
      final response = await socket.transform(
        const SystemEncoding().decoder).first.timeout(
        const Duration(seconds: 5));
      socket.destroy();

      if (response.contains('STARTTLS')) {
        return RecipientSecurityResult(
          level: RecipientSecurityLevel.tls,
          label: 'TLS',
          detail: 'Transport encrypted (STARTTLS on $mxHost)',
        );
      }
    } catch (_) {
      // Connection failed or timeout — can't verify TLS
    }

    // Check MTA-STS as fallback indicator
    final mtaSts = await DnsChecker.lookupMtaSts(domain);
    if (mtaSts != null) {
      return RecipientSecurityResult(
        level: RecipientSecurityLevel.tls,
        label: 'MTA-STS',
        detail: 'Transport policy enforced via MTA-STS ($domain)',
      );
    }

    return RecipientSecurityResult(
      level: RecipientSecurityLevel.plaintext,
      label: 'Plaintext',
      detail: 'No TLS verification available for $domain',
    );
  }
}
