import '../generated/app_localizations.dart';
import 'logger_service.dart';

/// Localization service singleton for accessing translations from services
/// Services don't have BuildContext, so this provides global access to AppLocalizations
class LocalizationService {
  static LocalizationService? _instance;
  AppLocalizations? _localizations;

  /// Whether we have already logged a "not initialized" warning. We log it
  /// once per session to flag the issue, then stay silent. Without this
  /// guard, code paths like update download progress (which fires hundreds
  /// of times per second) flood the log with identical warnings.
  bool _loggedNotInitializedOnce = false;

  static LocalizationService get instance {
    _instance ??= LocalizationService._();
    return _instance!;
  }

  LocalizationService._();

  /// Set localizations (called from main.dart after first build)
  void setLocalizations(AppLocalizations localizations) {
    _localizations = localizations;
    LoggerService.log('LOCALIZATION', 'AppLocalizations initialized for services');
  }

  /// Get localized text with fallback
  /// Usage: getText((l10n) => l10n.buttonCancel, 'Cancel')
  String getText(String Function(AppLocalizations) selector, String fallback) {
    if (_localizations == null) {
      if (!_loggedNotInitializedOnce) {
        _loggedNotInitializedOnce = true;
        LoggerService.log('LOCALIZATION',
            'AppLocalizations not initialized yet — using fallback strings (will not log this again until reset)');
      }
      return fallback;
    }
    return selector(_localizations!);
  }

  /// Check if localizations are initialized
  bool get isInitialized => _localizations != null;
}
