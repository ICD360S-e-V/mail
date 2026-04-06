import 'dart:async';
import 'dart:io';
import 'logger_service.dart';

/// Connection monitor for checking mail server ports
class ConnectionMonitor {
  /// Check if a port is open/closed
  Future<PortStatus> checkPortAsync(String server, int port, String protocol) async {
    try {
      final socket = await Socket.connect(server, port, timeout: const Duration(seconds: 3));
      await socket.close();

      return PortStatus(
        port: port,
        protocol: protocol,
        isConnected: true,
        color: 'Green',
        status: 'OPEN',
      );
    } on TimeoutException {
      return PortStatus(
        port: port,
        protocol: protocol,
        isConnected: false,
        color: 'Orange',
        status: 'TIMEOUT',
      );
    } catch (_) {
      return PortStatus(
        port: port,
        protocol: protocol,
        isConnected: false,
        color: 'Red',
        status: 'CLOSED',
      );
    }
  }

  /// Check all mail server ports (IMAP, SMTP, HTTPS)
  /// Uses the actual ports the application connects to
  Future<ConnectionStatus> checkAllPortsAsync(String server) async {
    final status = ConnectionStatus();

    try {
      // Check HTTPS (443) — web/API
      status.httpsStatus = await checkPortAsync(server, 443, 'HTTPS');

      // Check SMTP (465) — submission over TLS
      status.smtpStatus = await checkPortAsync(server, 465, 'SMTP');

      // Check IMAP (993) — IMAP over TLS
      status.imapStatus = await checkPortAsync(server, 993, 'IMAP');

      LoggerService.log('PORTS',
          'HTTPS:443=${status.httpsStatus.status}, '
          'SMTP:465=${status.smtpStatus.status}, '
          'IMAP:993=${status.imapStatus.status}');
    } catch (ex, stackTrace) {
      LoggerService.logError('PORTS', ex, stackTrace);
    }

    return status;
  }
}

/// Connection status for all ports
class ConnectionStatus {
  PortStatus imapStatus;
  PortStatus smtpStatus;
  PortStatus httpsStatus;

  ConnectionStatus({
    PortStatus? imapStatus,
    PortStatus? smtpStatus,
    PortStatus? httpsStatus,
  })  : imapStatus = imapStatus ?? PortStatus(),
        smtpStatus = smtpStatus ?? PortStatus(),
        httpsStatus = httpsStatus ?? PortStatus();
}

/// Port status result
class PortStatus {
  int port;
  String protocol;
  bool isConnected;
  String color;
  String status;

  PortStatus({
    this.port = 0,
    this.protocol = '',
    this.isConnected = false,
    this.color = 'Gray',
    this.status = 'UNKNOWN',
  });
}