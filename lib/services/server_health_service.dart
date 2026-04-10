import 'dart:io';
import 'dns_checker.dart';
import 'logger_service.dart';

/// Server health service for checking SPF/DKIM/DMARC DNS records
class ServerHealthService {
  final String domain;

  ServerHealthService({this.domain = 'icd360s.de'});

  /// Check all server health indicators
  Future<ServerHealthStatus> checkHealthAsync() async {
    final status = ServerHealthStatus();

    try {
      // Check SPF
      status.spfStatus = await _checkSpfAsync();

      // Check DKIM
      status.dkimStatus = await _checkDkimAsync();

      // Check IPv4 blacklist
      status.ipv4Status = await _checkIpBlacklistAsync(true);

      // Check IPv6 blacklist
      status.ipv6Status = await _checkIpBlacklistAsync(false);
    } catch (ex, stackTrace) {
      LoggerService.logError('HEALTH', ex, stackTrace);
    }

    return status;
  }

  /// Check SPF record via DoH (works on all platforms including mobile)
  Future<HealthCheckResult> _checkSpfAsync() async {
    try {
      final spf = await DnsChecker.lookupSpf(domain);
      if (spf != null) {
        LoggerService.log('HEALTH', 'SPF record found for $domain');
        return HealthCheckResult(
          status: 'OK',
          color: 'Green',
          message: 'SPF record exists for $domain: $spf',
        );
      }
      return HealthCheckResult(
        status: 'MISSING',
        color: 'Orange',
        message: 'No SPF record found for $domain',
      );
    } catch (ex) {
      return HealthCheckResult(
        status: 'ERROR',
        color: 'Orange',
        message: ex.toString(),
      );
    }
  }

  /// Check DKIM record via DoH (works on all platforms including mobile)
  Future<HealthCheckResult> _checkDkimAsync() async {
    try {
      final dkim = await DnsChecker.lookupDkim(domain);
      if (dkim != null) {
        LoggerService.log('HEALTH', 'DKIM record found for $domain');
        return HealthCheckResult(
          status: 'OK',
          color: 'Green',
          message: 'DKIM record exists for default._domainkey.$domain',
        );
      }
      return HealthCheckResult(
        status: 'MISSING',
        color: 'Orange',
        message: 'No DKIM record found for default._domainkey.$domain',
      );
    } catch (ex) {
      return HealthCheckResult(
        status: 'ERROR',
        color: 'Orange',
        message: ex.toString(),
      );
    }
  }

  /// Check IP blacklist
  Future<HealthCheckResult> _checkIpBlacklistAsync(bool isIpv4) async {
    try {
      // Resolve server IP dynamically via DNS
      final addresses = await InternetAddress.lookup('mail.$domain');
      final ip = addresses
          .where((a) => isIpv4
              ? a.type == InternetAddressType.IPv4
              : a.type == InternetAddressType.IPv6)
          .map((a) => a.address)
          .firstOrNull;
      if (ip == null) {
        return HealthCheckResult(
          status: 'ERROR',
          color: 'Orange',
          message: 'No ${isIpv4 ? "IPv4" : "IPv6"} address found for mail.$domain',
        );
      }

      final blacklists = isIpv4
          ? [
              // Major IPv4 blacklists (comprehensive check)
              'zen.spamhaus.org',           // Spamhaus ZEN (most important)
              'bl.spamcop.net',             // SpamCop
              'dnsbl.sorbs.net',            // SORBS
              'b.barracudacentral.org',     // Barracuda
              'cbl.abuseat.org',            // CBL
              'psbl.surriel.com',           // PSBL
              'dnsbl.dronebl.org',          // DroneBL
              'dnsbl-1.uceprotect.net',     // UCEPROTECT Level 1
              'dnsbl-2.uceprotect.net',     // UCEPROTECT Level 2
              'dnsbl-3.uceprotect.net',     // UCEPROTECT Level 3
              'ix.dnsbl.manitu.net',        // Manitu
              's5h.net',                    // S5H
              'all.s5h.net',                // S5H All
              'dnsbl.abuse.ch',             // Abuse.ch
              'spam.dnsbl.anonmails.de',    // Anonmails
              'bl.blocklist.de',            // Blocklist.de
              'dnsbl.inps.de',              // INPS
              'dnsbl.kempt.net',            // Kempt
              'backscatterer.spamrats.com', // SpamRATS Backscatterer
              'noptr.spamrats.com',         // SpamRATS NoPtr
              'spam.spamrats.com',          // SpamRATS Spam
              'dyna.spamrats.com',          // SpamRATS Dyna
              'bl.mailspike.net',           // MailSpike
              'z.mailspike.net',            // MailSpike Z
              'truncate.gbudb.net',         // Truncate
              'hostkarma.junkemailfilter.com', // Hostkarma Black
              'wormrbl.imp.ch',             // IMP Worm
              'web.dnsbl.sorbs.net',        // SORBS Web
              'socks.dnsbl.sorbs.net',      // SORBS Socks
            ]
          : [
              // IPv6-capable blacklists (fewer than IPv4, but comprehensive)
              'zen.spamhaus.org',        // Spamhaus ZEN - full IPv6 support
              'bl.spamcop.net',          // SpamCop - IPv6 support
              'dnsbl.sorbs.net',         // SORBS - IPv6 support
              'ix.dnsbl.manitu.net',     // Manitu - IPv6-specific
              'ipv6.blacklist.woody.ch', // Woody - IPv6-specific
              'dnsbl-2.uceprotect.net',  // UCEPROTECT Level 2 - IPv6
              'dnsbl-3.uceprotect.net',  // UCEPROTECT Level 3 - IPv6
              'bl.mailspike.net',        // MailSpike - IPv6 support
              'backscatterer.spamrats.com', // SpamRATS Backscatterer - IPv6
              'noptr.spamrats.com',      // SpamRATS NoPtr - IPv6
              'spam.spamrats.com',       // SpamRATS Spam - IPv6
              'dyna.spamrats.com',       // SpamRATS Dyna - IPv6
              'web.dnsbl.sorbs.net',     // SORBS Web - IPv6
              'socks.dnsbl.sorbs.net',   // SORBS Socks - IPv6
            ];

      int totalChecked = 0;
      int listedCount = 0;
      final listedOn = <String>[];

      // Reverse IP for DNS lookup
      final reversedIp = isIpv4 ? _reverseIpv4(ip) : _reverseIpv6(ip);

      for (final blacklist in blacklists) {
        try {
          totalChecked++;
          final query = '$reversedIp.$blacklist';
          final addresses = await InternetAddress.lookup(query);

          // DNSBL standard: Only 127.0.0.x responses indicate listing
          if (addresses.isNotEmpty) {
            for (final addr in addresses) {
              // Check if response is in 127.0.0.0/8 range (standard DNSBL response)
              if (addr.address.startsWith('127.')) {
                listedCount++;
                listedOn.add(blacklist);
                break; // One positive response is enough
              }
            }
          }
        } on SocketException {
          // NXDOMAIN = not listed (good)
          continue;
        } catch (_) {
          continue;
        }
      }

      // Color logic: Green = 0, Orange = 1, Red = 2+
      final color = listedCount == 0
          ? 'Green'
          : (listedCount == 1 ? 'Orange' : 'Red');
      final status = listedCount == 0 ? 'CLEAN' : 'LISTED($listedCount)';
      final message = '$ip - $totalChecked checks: '
          '${totalChecked - listedCount} clean, $listedCount listed'
          '${listedCount > 0 ? '\nListed on: ${listedOn.join(", ")}' : ''}';

      LoggerService.log('HEALTH',
          '${isIpv4 ? "IPv4" : "IPv6"} blacklist: $status ($totalChecked providers checked)');

      return HealthCheckResult(
        status: status,
        color: color,
        message: message,
      );
    } catch (ex) {
      return HealthCheckResult(
        status: 'ERROR',
        color: 'Orange',
        message: ex.toString(),
      );
    }
  }

  /// Reverse IPv4 for DNS query (1.2.3.4 -> 4.3.2.1)
  String _reverseIpv4(String ip) {
    final octets = ip.split('.');
    return '${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}';
  }

  /// Reverse IPv6 for DNS query (simplified version)
  String _reverseIpv6(String ip) {
    // Parse and expand IPv6
    final addr = InternetAddress(ip);
    final bytes = addr.rawAddress;

    // Convert each byte to hex nibbles and reverse
    final nibbles = <String>[];
    for (int i = bytes.length - 1; i >= 0; i--) {
      final hex = bytes[i].toRadixString(16).padLeft(2, '0');
      nibbles.add(hex[1]);
      nibbles.add(hex[0]);
    }

    return nibbles.join('.');
  }
}

/// Server health status
class ServerHealthStatus {
  HealthCheckResult spfStatus;
  HealthCheckResult dkimStatus;
  HealthCheckResult ipv4Status;
  HealthCheckResult ipv6Status;

  ServerHealthStatus({
    HealthCheckResult? spfStatus,
    HealthCheckResult? dkimStatus,
    HealthCheckResult? ipv4Status,
    HealthCheckResult? ipv6Status,
  })  : spfStatus = spfStatus ?? HealthCheckResult(),
        dkimStatus = dkimStatus ?? HealthCheckResult(),
        ipv4Status = ipv4Status ?? HealthCheckResult(),
        ipv6Status = ipv6Status ?? HealthCheckResult();
}

/// Health check result
class HealthCheckResult {
  String status;
  String color;
  String message;

  HealthCheckResult({
    this.status = '',
    this.color = 'Gray',
    this.message = '',
  });
}