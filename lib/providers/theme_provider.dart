import 'package:fluent_ui/fluent_ui.dart';
import '../services/logger_service.dart';
import '../services/settings_service.dart';

/// Theme provider for managing dark/light mode
/// Now uses SettingsService for persistence (consolidated settings.json)
class ThemeProvider with ChangeNotifier {
  ThemeMode _themeMode = ThemeMode.light;

  ThemeMode get themeMode => _themeMode;

  bool get isDarkMode => _themeMode == ThemeMode.dark;

  ThemeProvider() {
    _loadThemeMode();
  }

  /// Load saved theme mode from SettingsService
  Future<void> _loadThemeMode() async {
    try {
      final theme = await SettingsService.getTheme();
      _themeMode = theme == 'dark' ? ThemeMode.dark : ThemeMode.light;
      notifyListeners();
      LoggerService.log('THEME', 'Theme loaded from settings: $theme');
    } catch (ex, stackTrace) {
      LoggerService.logError('THEME', ex, stackTrace);
      // Use default light mode on error
    }
  }

  /// Toggle between light and dark mode
  Future<void> toggleTheme() async {
    final oldMode = _themeMode == ThemeMode.light ? 'Light' : 'Dark';
    _themeMode = _themeMode == ThemeMode.light ? ThemeMode.dark : ThemeMode.light;
    final newMode = isDarkMode ? 'Dark' : 'Light';

    LoggerService.log('THEME', 'Theme toggled: $oldMode → $newMode');

    // Save to SettingsService (consolidated settings.json)
    await _saveTheme();

    notifyListeners();
  }

  /// Set specific theme mode
  Future<void> setThemeMode(ThemeMode mode) async {
    if (_themeMode == mode) return;

    _themeMode = mode;

    // Save to SettingsService
    await _saveTheme();

    notifyListeners();
  }

  /// Save theme preference to SettingsService
  Future<void> _saveTheme() async {
    try {
      final settings = await SettingsService.loadSettings();
      await SettingsService.saveSettings(
        autoUpdateEnabled: settings['autoUpdateEnabled'] as bool? ?? true,
        loggingEnabled: settings['loggingEnabled'] as bool? ?? true,
        notificationsEnabled: settings['notificationsEnabled'] as bool? ?? true,
        theme: isDarkMode ? 'dark' : 'light',
        language: settings['language'] as String?,
      );
      LoggerService.log('THEME', '✓ Theme preference saved to settings.json');
    } catch (ex, stackTrace) {
      LoggerService.logError('THEME', ex, stackTrace);
    }
  }
}
