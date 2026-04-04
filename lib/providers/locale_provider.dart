import 'dart:io';
import 'package:flutter/material.dart';
import '../services/logger_service.dart';
import '../services/settings_service.dart';

/// Locale provider for managing application language
/// Detects system locale on first run, supports manual override
class LocaleProvider extends ChangeNotifier {
  Locale? _currentLocale;

  // Supported languages
  static const supportedLocales = [
    Locale('en'), // English (fallback)
    Locale('ro'), // Romanian
    Locale('de'), // German
    Locale('ru'), // Russian
    Locale('uk'), // Ukrainian
  ];

  Locale get currentLocale => _currentLocale ?? _detectSystemLocale();

  LocaleProvider() {
    _loadSavedLocale();
  }

  /// Detect system locale from OS
  Locale _detectSystemLocale() {
    try {
      final systemLocale = Platform.localeName; // e.g., 'en_US', 'ro_RO'
      final languageCode = systemLocale.split('_')[0];

      // Check if system language is supported
      final supported = supportedLocales.firstWhere(
        (locale) => locale.languageCode == languageCode,
        orElse: () => const Locale('en'), // Fallback to English
      );

      LoggerService.log('LOCALE', 'Detected system locale: $systemLocale → ${supported.languageCode}');
      return supported;
    } catch (ex, stackTrace) {
      LoggerService.logError('LOCALE', ex, stackTrace);
      return const Locale('en'); // Fallback on error
    }
  }

  /// Set locale manually (from language selector)
  Future<void> setLocale(Locale locale) async {
    if (_currentLocale == locale) return;

    _currentLocale = locale;
    await _saveLocale();
    notifyListeners();

    LoggerService.log('LOCALE', 'Locale changed to: ${locale.languageCode}');
  }

  /// Load saved locale from settings.json
  Future<void> _loadSavedLocale() async {
    try {
      final languageCode = await SettingsService.getLanguage();

      if (languageCode != null) {
        // Use saved language
        _currentLocale = Locale(languageCode);
        LoggerService.log('LOCALE', 'Loaded saved locale: $languageCode');
      } else {
        // First run - detect system locale and save it
        _currentLocale = _detectSystemLocale();
        await _saveLocale();
      }

      notifyListeners();
    } catch (ex, stackTrace) {
      LoggerService.logError('LOCALE', ex, stackTrace);
      _currentLocale = const Locale('en'); // Fallback
      notifyListeners();
    }
  }

  /// Save locale to settings.json
  Future<void> _saveLocale() async {
    try {
      final settings = await SettingsService.loadSettings();
      await SettingsService.saveSettings(
        autoUpdateEnabled: settings['autoUpdateEnabled'] as bool? ?? true,
        loggingEnabled: settings['loggingEnabled'] as bool? ?? true,
        notificationsEnabled: settings['notificationsEnabled'] as bool? ?? true,
        theme: settings['theme'] as String? ?? 'light',
        language: _currentLocale?.languageCode,
      );
      LoggerService.log('LOCALE', '✓ Locale preference saved to settings.json');
    } catch (ex, stackTrace) {
      LoggerService.logError('LOCALE', ex, stackTrace);
    }
  }
}
