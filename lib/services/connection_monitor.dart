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

  /// Check all mail server ports (IMAP, SMTP, SSH, HTTP, HTTPS)
  Future<ConnectionStatus> checkAllPortsAsync(String server) async {
    final status = ConnectionStatus();

    try {
      // Check SSH (22)
      status.sshStatus = await checkPortAsync(server, 22, 'SSH');

      // Check HTTP (80)
      status.httpStatus = await checkPortAsync(server, 80, 'HTTP');

      // Check HTTPS (443)
      status.httpsStatus = await checkPortAsync(server, 443, 'HTTPS');

      // Check SMTP (587)
      status.smtpStatus = await checkPortAsync(server, 587, 'SMTP');

      // Check IMAP (993)
      status.imapStatus = await checkPortAsync(server, 993, 'IMAP');

      LoggerService.log('PORTS',
          'SSH:22=${status.sshStatus.status}, HTTP:80=${status.httpStatus.status}, '
          'HTTPS:443=${status.httpsStatus.status}, SMTP:587=${status.smtpStatus.status}, '
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
  PortStatus sshStatus;
  PortStatus httpStatus;
  PortStatus httpsStatus;

  ConnectionStatus({
    PortStatus? imapStatus,
    PortStatus? smtpStatus,
    PortStatus? sshStatus,
    PortStatus? httpStatus,
    PortStatus? httpsStatus,
  })  : imapStatus = imapStatus ?? PortStatus(),
        smtpStatus = smtpStatus ?? PortStatus(),
        sshStatus = sshStatus ?? PortStatus(),
        httpStatus = httpStatus ?? PortStatus(),
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
