import 'dart:io';
import '../models/models.dart';
import 'logger_service.dart';

/// Threat intelligence service for spam/phishing detection
class ThreatIntelligenceService {
  static final List<String> _dnsBlacklists = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
  ];

  /// Analyze email for threats and return (level, score, details)
  static ThreatAnalysis analyzeEmail(Email email) {
    int score = 0;
    final indicators = <String>[];

    // Whitelist internal emails (from your own server/domain)
    if (email.from.contains('@icd360s.de') ||
        email.from.contains('@mail.icd360s.de') ||
        email.from.contains('localhost') ||
        email.from.contains('127.0.0.1') ||
        email.subject.startsWith('Read:') || // MDN read receipts
        email.subject.startsWith('Gelesen:')) {
      LoggerService.log('THREAT',
          'Internal/trusted email detected: ${email.from} - score=0');
      return ThreatAnalysis(
        level: 'Safe',
        score: 0,
        details: '✅ Internal/trusted email (whitelisted)',
      );
    }

    // 1. Check DKIM signature
    if (email.headers.containsKey('DKIM-Signature') ||
        email.headers.containsKey('dkim-signature')) {
      indicators.add('DKIM: present');
    } else {
      score += 20;
      indicators.add('DKIM: missing');
    }

    // 2. Check SPF
    final spf = email.headers['Received-SPF'] ??
        email.headers['received-spf'] ??
        email.headers['Authentication-Results'];

    if (spf != null) {
      if (spf.toLowerCase().contains('pass')) {
        indicators.add('SPF: pass');
      } else if (spf.toLowerCase().contains('fail')) {
        score += 30;
        indicators.add('SPF: fail');
      }
    }

    // 3. Extract sender IP from Received headers
    final senderIp = _extractSenderIp(email);
    if (senderIp != null) {
      indicators.add('IP $senderIp: detected');
      // Note: Blacklist check requires async DNS lookup
      // Use analyzeEmailAsync() for full blacklist checking
    }

    // 4. Check for suspicious keywords in subject
    final suspiciousKeywords = [
      'urgent',
      'verify',
      'suspended',
      'click here',
      'confirm',
      'password'
    ];

    for (final keyword in suspiciousKeywords) {
      if (email.subject.toLowerCase().contains(keyword)) {
        score += 10;
        indicators.add('Keyword: $keyword');
      }
    }

    // 5. Check for mismatched sender domain
    if (email.from.contains('@')) {
      final parts = email.from.split('@');
      if (parts.length == 2) {
        final fromDomain = parts[1].replaceAll('>', '').trim().toLowerCase();
        final returnPath = email.headers['Return-Path'] ?? email.headers['return-path'];

        if (returnPath != null) {
          if (!returnPath.toLowerCase().contains(fromDomain)) {
            score += 25;
            indicators.add('Domain mismatch');
          }
        }
      }
    }

    // Determine threat level
    final level = switch (score) {
      >= 70 => 'Critical',
      >= 50 => 'High',
      >= 30 => 'Medium',
      >= 10 => 'Low',
      _ => 'Safe',
    };

    // Build details string
    final details = indicators.join(' | ');

    return ThreatAnalysis(level: level, score: score, details: details);
  }

  /// Extract sender IP from Received headers
  static String? _extractSenderIp(Email email) {
    final received = email.headers['Received'] ?? email.headers['received'];

    if (received != null) {
      // Extract IP from "Received: from ... [1.2.3.4]"
      final regex = RegExp(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]');
      final match = regex.firstMatch(received);

      if (match != null && match.groupCount >= 1) {
        return match.group(1);
      }
    }

    return null;
  }

  /// Analyze email with full async blacklist checking
  static Future<ThreatAnalysis> analyzeEmailAsync(Email email) async {
    // Start with synchronous analysis
    final basicAnalysis = analyzeEmail(email);

    // If internal/trusted, return immediately
    if (basicAnalysis.level == 'Safe' && basicAnalysis.score == 0) {
      return basicAnalysis;
    }

    // Add async blacklist check
    int score = basicAnalysis.score;
    final indicators = basicAnalysis.details.split(' | ').toList();

    final senderIp = _extractSenderIp(email);
    if (senderIp != null) {
      final isBlacklisted = await _checkBlacklistsAsync(senderIp);
      if (isBlacklisted) {
        score += 50;
        // Replace "IP detected" with blacklist result
        indicators.removeWhere((i) => i.startsWith('IP $senderIp'));
        indicators.add('IP $senderIp: BLACKLISTED');
      } else {
        indicators.removeWhere((i) => i.startsWith('IP $senderIp'));
        indicators.add('IP $senderIp: clean');
      }
    }

    // Recalculate threat level with blacklist data
    final level = switch (score) {
      >= 70 => 'Critical',
      >= 50 => 'High',
      >= 30 => 'Medium',
      >= 10 => 'Low',
      _ => 'Safe',
    };

    return ThreatAnalysis(
      level: level,
      score: score,
      details: indicators.join(' | '),
    );
  }

  /// Check if IP is in DNS blacklists
  static Future<bool> _checkBlacklistsAsync(String ip) async {
    try {
      final octets = ip.split('.');
      if (octets.length != 4) return false;

      // Reverse IP for DNS query
      final reversedIp = '${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}';

      for (final blacklist in _dnsBlacklists) {
        try {
          final query = '$reversedIp.$blacklist';
          final addresses = await InternetAddress.lookup(query);

          // If we get a response, the IP is blacklisted
          if (addresses.isNotEmpty) {
            LoggerService.log('THREAT', '⚠️ IP $ip blacklisted on $blacklist');
            return true;
          }
        } on SocketException {
          // NXDOMAIN = not listed (good)
          continue;
        } catch (_) {
          continue;
        }
      }

      return false;
    } catch (_) {
      return false;
    }
  }
}

/// Threat analysis result
class ThreatAnalysis {
  final String level;
  final int score;
  final String details;

  ThreatAnalysis({
    required this.level,
    required this.score,
    required this.details,
  });
}
