import 'dart:io';
import 'dart:convert';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// Service for email recipient history and auto-complete suggestions (cross-platform)
class EmailHistoryService {
  static String? _historyFilePath;
  static Map<String, int> _recipientHistory = {}; // email -> count

  /// Initialize service
  static Future<void> initialize() async {
    if (_historyFilePath != null) return;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    _historyFilePath = p.join(appDataPath, 'email_history.json');

    // Create directory if needed
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    // Load existing history
    await _loadHistory();
  }

  /// Load recipient history from disk
  static Future<void> _loadHistory() async {
    try {
      final file = File(_historyFilePath!);

      if (await file.exists()) {
        final json = await file.readAsString();
        final Map<String, dynamic> data = jsonDecode(json);

        _recipientHistory = data.map((key, value) => MapEntry(key, value as int));

        LoggerService.log('EMAIL-HISTORY',
            'Loaded ${_recipientHistory.length} recipients from history');
      } else {
        _recipientHistory = {};
        LoggerService.log('EMAIL-HISTORY', 'No history file found, starting fresh');
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('EMAIL-HISTORY', ex, stackTrace);
      _recipientHistory = {};
    }
  }

  /// Save recipient history to disk
  static Future<void> _saveHistory() async {
    try {
      await initialize();

      final file = File(_historyFilePath!);
      final json = jsonEncode(_recipientHistory);

      await file.writeAsString(json);

      LoggerService.log('EMAIL-HISTORY',
          'Saved ${_recipientHistory.length} recipients to history');
    } catch (ex, stackTrace) {
      LoggerService.logError('EMAIL-HISTORY', ex, stackTrace);
    }
  }

  /// Add email to history (increment usage count)
  static Future<void> addRecipient(String email) async {
    await initialize();

    final cleanEmail = email.trim().toLowerCase();

    if (cleanEmail.isEmpty || !cleanEmail.contains('@')) {
      return; // Invalid email
    }

    // Increment count
    _recipientHistory[cleanEmail] = (_recipientHistory[cleanEmail] ?? 0) + 1;

    LoggerService.log('EMAIL-HISTORY',
        'Added $cleanEmail to history (used ${_recipientHistory[cleanEmail]} times)');

    // Save to disk
    await _saveHistory();
  }

  /// Add multiple recipients (TO, CC, BCC fields)
  static Future<void> addRecipients(String to, String cc, String bcc) async {
    final allRecipients = <String>[];

    // Parse TO
    if (to.isNotEmpty) {
      allRecipients.addAll(to.split(',').map((e) => e.trim()));
    }

    // Parse CC
    if (cc.isNotEmpty) {
      allRecipients.addAll(cc.split(',').map((e) => e.trim()));
    }

    // Parse BCC
    if (bcc.isNotEmpty) {
      allRecipients.addAll(bcc.split(',').map((e) => e.trim()));
    }

    // Add each recipient
    for (final email in allRecipients) {
      if (email.isNotEmpty) {
        await addRecipient(email);
      }
    }
  }

  /// Get suggestions based on input (first 3+ characters)
  /// Returns list of emails sorted by usage frequency (most used first)
  static List<String> getSuggestions(String input) {
    if (input.length < 3) {
      return []; // Require minimum 3 characters
    }

    final searchTerm = input.trim().toLowerCase();

    // Find matching emails
    final matches = _recipientHistory.keys.where((email) {
      return email.toLowerCase().startsWith(searchTerm) ||
          email.toLowerCase().contains(searchTerm);
    }).toList();

    // Sort by usage frequency (descending)
    matches.sort((a, b) {
      final countA = _recipientHistory[a] ?? 0;
      final countB = _recipientHistory[b] ?? 0;
      return countB.compareTo(countA); // Most used first
    });

    // Return top 10 suggestions
    return matches.take(10).toList();
  }

  /// Get most frequently used recipients (top 20)
  static List<MapEntry<String, int>> getMostUsed({int limit = 20}) {
    final sorted = _recipientHistory.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value)); // Most used first

    return sorted.take(limit).toList();
  }

  /// Get total number of recipients in history
  static int get recipientCount => _recipientHistory.length;

  /// Clear all history
  static Future<void> clearHistory() async {
    _recipientHistory.clear();
    await _saveHistory();
    LoggerService.log('EMAIL-HISTORY', 'History cleared');
  }
}
