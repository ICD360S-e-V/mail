// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../models/models.dart';
import 'logger_service.dart';
import 'mtls_service.dart';
import 'le_issuer_check.dart';
import 'pinned_security_context.dart';

/// Server-side ClamAV attachment scanning via mTLS-authenticated API.
///
/// Architecture:
///   Flutter app  ──POST bytes──►  /api/scan-attachment.php (mTLS)
///                                    │
///                                    ├─ Valkey cache hit (SHA-256) → instant
///                                    └─ clamd INSTREAM scan (5-300ms)
///
/// Scan is triggered lazily when the user opens an email (not at IMAP
/// fetch time). Results are cached both server-side (Valkey, 7-30 days)
/// and client-side (in-memory, per session).
class AttachmentScanService {
  static const _scanEndpoint =
      'https://mail.icd360s.de/api/scan-attachment.php';
  static const _timeout = Duration(seconds: 60);

  /// In-memory session cache: sha256 → result.
  static final Map<String, _ScanResult> _cache = {};

  /// Scan a single attachment. Updates [attachment] fields in place.
  static Future<void> scan(EmailAttachment attachment) async {
    final data = attachment.data;
    if (data == null || data.isEmpty) {
      attachment.scanStatus = AttachmentScanStatus.error;
      attachment.scanError = 'No data';
      return;
    }

    // SHA-256 for cache lookup
    final hash = crypto.sha256.convert(data).toString();
    attachment.sha256 = hash;

    // Local cache hit
    final cached = _cache[hash];
    if (cached != null) {
      _applyResult(attachment, cached);
      LoggerService.log('AVSCAN',
          '${attachment.fileName}: ${cached.status.name} (local cache)');
      return;
    }

    attachment.scanStatus = AttachmentScanStatus.scanning;

    try {
      final client = MtlsService.createMtlsHttpClient() ??
          PinnedSecurityContext.createHttpClient()
        ..badCertificateCallback = (cert, host, port) {
          if (host == 'mail.icd360s.de') {
            return isTrustedLetsEncryptIssuer(cert.issuer);
          }
          return false;
        };

      final request = await client
          .postUrl(Uri.parse(_scanEndpoint))
          .timeout(_timeout);
      request.headers
        ..set('Content-Type', 'application/octet-stream')
        ..set('X-File-SHA256', hash)
        ..set('X-File-Name', Uri.encodeComponent(attachment.fileName));
      request.contentLength = data.length;
      request.add(data);

      final response = await request.close().timeout(_timeout);
      final body = await response.transform(utf8.decoder).join();
      client.close();

      if (response.statusCode != 200) {
        throw HttpException('HTTP ${response.statusCode}: $body');
      }

      final json = jsonDecode(body) as Map<String, dynamic>;
      final result = _ScanResult.fromJson(json);

      _applyResult(attachment, result);
      _cache[hash] = result;

      LoggerService.log('AVSCAN',
          '${attachment.fileName}: ${result.status.name}'
          '${result.threat != null ? " (${result.threat})" : ""}'
          ' [${result.scanTimeMs ?? "?"}ms'
          '${result.cached ? ", server-cached" : ""}]');
    } on TimeoutException {
      attachment.scanStatus = AttachmentScanStatus.error;
      attachment.scanError = 'Scan timed out';
      LoggerService.logWarning('AVSCAN',
          '${attachment.fileName}: timeout after 60s');
    } catch (ex, st) {
      attachment.scanStatus = AttachmentScanStatus.error;
      attachment.scanError = ex.toString();
      LoggerService.logError('AVSCAN', ex, st);
    }
  }

  /// Scan all pending attachments on an email (batches of 3).
  /// Calls [onProgress] after each batch completes so the UI can rebuild.
  static Future<void> scanAll(
    Email email, {
    void Function()? onProgress,
  }) async {
    final pending = email.attachments
        .where((a) =>
            a.data != null &&
            a.data!.isNotEmpty &&
            a.scanStatus == AttachmentScanStatus.pending)
        .toList();

    for (var i = 0; i < pending.length; i += 3) {
      final batch = pending.skip(i).take(3).toList();
      await Future.wait(batch.map(scan));
      onProgress?.call();
    }
  }

  static void _applyResult(EmailAttachment a, _ScanResult r) {
    a.scanStatus = r.status;
    a.threatName = r.threat;
    a.scanTimeMs = r.scanTimeMs;
    if (r.reason != null) a.scanError = r.reason;
  }
}

class _ScanResult {
  final AttachmentScanStatus status;
  final String? threat;
  final int? scanTimeMs;
  final bool cached;
  final String? reason;

  const _ScanResult({
    required this.status,
    this.threat,
    this.scanTimeMs,
    this.cached = false,
    this.reason,
  });

  factory _ScanResult.fromJson(Map<String, dynamic> json) {
    final s = json['status'] as String? ?? 'error';
    final status = switch (s) {
      'clean' => AttachmentScanStatus.clean,
      'infected' => AttachmentScanStatus.infected,
      'unscannable' => AttachmentScanStatus.unscannable,
      _ => AttachmentScanStatus.error,
    };
    return _ScanResult(
      status: status,
      threat: json['threat'] as String?,
      scanTimeMs: json['scan_time_ms'] as int?,
      cached: json['cached'] as bool? ?? false,
      reason: json['reason'] as String?,
    );
  }
}