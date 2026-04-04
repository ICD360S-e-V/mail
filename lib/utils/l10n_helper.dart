import 'package:fluent_ui/fluent_ui.dart';
import '../generated/app_localizations.dart';

/// Safe localization helper — returns English fallback if locale is unsupported
/// Fixes crash on GrapheneOS and other custom ROMs with non-standard locales
AppLocalizations l10nOf(BuildContext context) {
  return AppLocalizations.of(context) ?? lookupAppLocalizations(const Locale('en'));
}
