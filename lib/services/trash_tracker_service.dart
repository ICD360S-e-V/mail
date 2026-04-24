// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:convert';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'logger_service.dart';
import 'platform_service.dart';

/// Service to track when emails were moved to Trash (cross-platform)
/// Stores messageId -> movedToTrashDate mapping
class TrashTrackerService {
  static String? _trashFilePath;
  static Map<String, DateTime> _trashDates = {};

  /// Initialize service and load existing data
  static Future<void> initialize() async {
    if (_trashFilePath != null) return;

    // Use cross-platform app data path
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    _trashFilePath = p.join(appDataPath, 'trash_dates.json');

    // Create directory if needed
    final dir = Directory(appDataPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    await _load();
  }

  /// Load trash dates from file
  static Future<void> _load() async {
    try {
      final file = File(_trashFilePath!);
      if (await file.exists()) {
        final jsonStr = await file.readAsString();
        final Map<String, dynamic> data = json.decode(jsonStr);

        _trashDates = data.map((key, value) =>
          MapEntry(key, DateTime.parse(value as String))
        );

        LoggerService.log('TRASH_TRACKER', 'Loaded ${_trashDates.length} trash date records');
      }
    } catch (ex) {
      LoggerService.logWarning('TRASH_TRACKER', 'Could not load trash dates: $ex');
      _trashDates = {};
    }
  }

  /// Save trash dates to file
  static Future<void> _save() async {
    try {
      final file = File(_trashFilePath!);
      final data = _trashDates.map((key, value) =>
        MapEntry(key, value.toIso8601String())
      );
      await file.writeAsString(json.encode(data));
    } catch (ex) {
      LoggerService.logError('TRASH_TRACKER', ex, StackTrace.current);
    }
  }

  /// Record when an email was moved to Trash
  static Future<void> recordMovedToTrash(String messageId) async {
    await initialize();
    _trashDates[messageId] = DateTime.now();
    await _save();
    LoggerService.log('TRASH_TRACKER', 'Recorded: $messageId moved to Trash');
  }

  /// Get the date when email was moved to Trash
  /// Returns null if not tracked (use email date as fallback)
  static DateTime? getMovedToTrashDate(String messageId) {
    return _trashDates[messageId];
  }

  /// Calculate days until auto-deletion (30 days from moved date)
  /// If not tracked, uses email sent date as fallback
  static int getDaysUntilDeletion(String messageId, DateTime emailDate, {int retentionDays = 30}) {
    final movedDate = _trashDates[messageId] ?? emailDate;
    final daysSinceMoved = DateTime.now().difference(movedDate).inDays;
    final daysRemaining = retentionDays - daysSinceMoved;
    return daysRemaining < 0 ? 0 : daysRemaining;
  }

  /// Remove tracking for an email (when permanently deleted or restored)
  static Future<void> removeTracking(String messageId) async {
    await initialize();
    if (_trashDates.containsKey(messageId)) {
      _trashDates.remove(messageId);
      await _save();
    }
  }

  /// Clean up old entries (emails that should have been deleted)
  static Future<void> cleanupOldEntries({int retentionDays = 30}) async {
    await initialize();
    final now = DateTime.now();
    final toRemove = <String>[];

    for (final entry in _trashDates.entries) {
      final daysSinceMoved = now.difference(entry.value).inDays;
      if (daysSinceMoved > retentionDays + 7) { // Keep 7 extra days buffer
        toRemove.add(entry.key);
      }
    }

    if (toRemove.isNotEmpty) {
      for (final id in toRemove) {
        _trashDates.remove(id);
      }
      await _save();
      LoggerService.log('TRASH_TRACKER', 'Cleaned up ${toRemove.length} old entries');
    }
  }

  /// Get all tracked emails and their trash dates (for debugging)
  static Map<String, DateTime> getAllTrackedEmails() {
    return Map.unmodifiable(_trashDates);
  }
}