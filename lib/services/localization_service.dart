import '../generated/app_localizations.dart';
import 'logger_service.dart';

/// Localization service singleton for accessing translations from services
/// Services don't have BuildContext, so this provides global access to AppLocalizations
class LocalizationService {
  static LocalizationService? _instance;
  AppLocalizations? _localizations;

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
      LoggerService.log('LOCALIZATION', 'WARNING: AppLocalizations not initialized yet, using fallback: "$fallback"');
      return fallback;
    }
    return selector(_localizations!);
  }

  /// Check if localizations are initialized
  bool get isInitialized => _localizations != null;
}
