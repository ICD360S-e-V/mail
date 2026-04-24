// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:developer' as developer;
import 'package:intl/intl.dart';
import '../utils/pii_redactor.dart';

/// Simple logging service for debugging and diagnostics.
///
/// All log messages pass through [PiiRedactor.sanitize] before being
/// stored in the buffer — this is the safety net that catches any PII
/// leaked through unstructured string interpolation.
///
/// Preferred usage: wrap PII values with typed helpers so redaction
/// happens at interpolation time (before the safety net):
/// ```dart
/// LoggerService.log('IMAP', 'Auth for ${piiEmail(user)}');
/// LoggerService.log('SEND', 'To ${piiRecipients(toList)}');
/// ```
class LoggerService {
  static final DateFormat _timeFormat = DateFormat('HH:mm:ss');
  static final List<String> _logBuffer = [];
  static const int _maxLogEntries = 1000; // Keep last 1000 entries

  /// Get all logs (already redacted).
  static List<String> getLogs() => List.unmodifiable(_logBuffer);

  /// Clear all logs
  static void clearLogs() {
    _logBuffer.clear();
    developer.log('Logs cleared', name: 'LOGGER');
  }

  /// Add log to buffer after PII redaction safety net.
  static void _addToBuffer(String logMessage) {
    final sanitized = PiiRedactor.sanitize(logMessage);
    _logBuffer.add(sanitized);
    // Keep only last N entries
    if (_logBuffer.length > _maxLogEntries) {
      _logBuffer.removeAt(0);
    }
  }

  /// Log general information message
  static void log(String category, String message) {
    final timestamp = _timeFormat.format(DateTime.now());
    final logMessage = '[$timestamp] [$category] $message';
    developer.log(logMessage, name: category);
    _addToBuffer(logMessage);
  }

  /// Log error with optional exception details.
  /// Exception toString() is sanitized before entering the buffer
  /// to prevent PII leaks from library exceptions (e.g. IMAP errors
  /// that embed email addresses or SQL errors that embed user data).
  static void logError(String category, dynamic error, [StackTrace? stackTrace]) {
    final timestamp = _timeFormat.format(DateTime.now());
    final safeError = PiiRedactor.sanitizeException(error);
    final errorMessage = '[$timestamp] [ERROR] [$category] $safeError';
    developer.log(
      errorMessage,
      name: category,
      error: error,
      stackTrace: stackTrace,
    );
    _addToBuffer(errorMessage);
    if (stackTrace != null) {
      _addToBuffer('  StackTrace: ${stackTrace.toString().split('\n').take(3).join('\n  ')}');
    }
  }

  /// Log warning message
  static void logWarning(String category, String message) {
    final timestamp = _timeFormat.format(DateTime.now());
    final logMessage = '[$timestamp] [WARNING] [$category] $message';
    developer.log(logMessage, name: category);
    _addToBuffer(logMessage);
  }

  /// Log debug message (only in debug mode).
  /// Still passes through PII sanitization and buffer so debug logs
  /// uploaded to server don't leak PII.
  static void logDebug(String category, String message) {
    assert(() {
      final timestamp = _timeFormat.format(DateTime.now());
      final logMessage = '[$timestamp] [DEBUG] [$category] $message';
      developer.log(logMessage, name: category);
      _addToBuffer(logMessage);
      return true;
    }());
  }
}
