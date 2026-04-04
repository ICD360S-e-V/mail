import 'dart:developer' as developer;
import 'package:intl/intl.dart';

/// Simple logging service for debugging and diagnostics
class LoggerService {
  static final DateFormat _timeFormat = DateFormat('HH:mm:ss');
  static final List<String> _logBuffer = [];
  static const int _maxLogEntries = 1000; // Keep last 1000 entries

  /// Get all logs
  static List<String> getLogs() => List.unmodifiable(_logBuffer);

  /// Clear all logs
  static void clearLogs() {
    _logBuffer.clear();
    developer.log('Logs cleared', name: 'LOGGER');
  }

  /// Add log to buffer
  static void _addToBuffer(String logMessage) {
    _logBuffer.add(logMessage);
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

  /// Log error with optional exception details
  static void logError(String category, dynamic error, [StackTrace? stackTrace]) {
    final timestamp = _timeFormat.format(DateTime.now());
    final errorMessage = '[$timestamp] [ERROR] [$category] $error';
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

  /// Log debug message (only in debug mode)
  static void logDebug(String category, String message) {
    assert(() {
      final timestamp = _timeFormat.format(DateTime.now());
      final logMessage = '[$timestamp] [DEBUG] [$category] $message';
      developer.log(logMessage, name: category);
      return true;
    }());
  }
}
