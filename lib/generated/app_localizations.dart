import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_ro.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'generated/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
      : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations? of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations);
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
    delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
  ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('ro')
  ];

  /// No description provided for @dialogTitleAddAccount.
  ///
  /// In en, this message translates to:
  /// **'Add Email Account'**
  String get dialogTitleAddAccount;

  /// No description provided for @dialogTitleCompose.
  ///
  /// In en, this message translates to:
  /// **'Compose Email'**
  String get dialogTitleCompose;

  /// No description provided for @labelEmailAddress.
  ///
  /// In en, this message translates to:
  /// **'Email Address:'**
  String get labelEmailAddress;

  /// No description provided for @placeholderUsername.
  ///
  /// In en, this message translates to:
  /// **'username'**
  String get placeholderUsername;

  /// No description provided for @labelPassword.
  ///
  /// In en, this message translates to:
  /// **'Password:'**
  String get labelPassword;

  /// No description provided for @placeholderPassword.
  ///
  /// In en, this message translates to:
  /// **'Enter password...'**
  String get placeholderPassword;

  /// No description provided for @labelMailServer.
  ///
  /// In en, this message translates to:
  /// **'Mail Server (locked):'**
  String get labelMailServer;

  /// No description provided for @labelImapPort.
  ///
  /// In en, this message translates to:
  /// **'IMAP Port (locked):'**
  String get labelImapPort;

  /// No description provided for @labelSmtpPort.
  ///
  /// In en, this message translates to:
  /// **'SMTP Port (locked):'**
  String get labelSmtpPort;

  /// No description provided for @labelFromAccount.
  ///
  /// In en, this message translates to:
  /// **'From Account:'**
  String get labelFromAccount;

  /// No description provided for @labelTo.
  ///
  /// In en, this message translates to:
  /// **'To (Primary Recipients):'**
  String get labelTo;

  /// No description provided for @labelCc.
  ///
  /// In en, this message translates to:
  /// **'CC (Carbon Copy):'**
  String get labelCc;

  /// No description provided for @labelBcc.
  ///
  /// In en, this message translates to:
  /// **'BCC (Blind Carbon Copy - Hidden):'**
  String get labelBcc;

  /// No description provided for @labelSubject.
  ///
  /// In en, this message translates to:
  /// **'Subject:'**
  String get labelSubject;

  /// No description provided for @labelMessage.
  ///
  /// In en, this message translates to:
  /// **'Message:'**
  String get labelMessage;

  /// No description provided for @placeholderSelectAccount.
  ///
  /// In en, this message translates to:
  /// **'Select account...'**
  String get placeholderSelectAccount;

  /// No description provided for @placeholderRecipients.
  ///
  /// In en, this message translates to:
  /// **'email1@example.com, email2@example.com'**
  String get placeholderRecipients;

  /// No description provided for @placeholderRecipientsOptional.
  ///
  /// In en, this message translates to:
  /// **'Optional: email1@example.com, email2@example.com'**
  String get placeholderRecipientsOptional;

  /// No description provided for @placeholderSubject.
  ///
  /// In en, this message translates to:
  /// **'Enter subject...'**
  String get placeholderSubject;

  /// No description provided for @placeholderMessage.
  ///
  /// In en, this message translates to:
  /// **'Type your message here...'**
  String get placeholderMessage;

  /// No description provided for @infoSslEnabled.
  ///
  /// In en, this message translates to:
  /// **'SSL/TLS Encryption: ENABLED (locked for security)'**
  String get infoSslEnabled;

  /// No description provided for @infoTooltip.
  ///
  /// In en, this message translates to:
  /// **'Primary recipients of the email - everyone will see this address'**
  String get infoTooltip;

  /// No description provided for @infoCcTooltip.
  ///
  /// In en, this message translates to:
  /// **'Receive a copy and ALL recipients see who is in CC'**
  String get infoCcTooltip;

  /// No description provided for @infoBccTooltip.
  ///
  /// In en, this message translates to:
  /// **'Receive a copy but NOBODY sees they received it (hidden)'**
  String get infoBccTooltip;

  /// No description provided for @infoRecipientCount.
  ///
  /// In en, this message translates to:
  /// **'{count} recipient(s)'**
  String infoRecipientCount(int count);

  /// No description provided for @infoCcCount.
  ///
  /// In en, this message translates to:
  /// **'{count} CC recipient(s)'**
  String infoCcCount(int count);

  /// No description provided for @infoBccCount.
  ///
  /// In en, this message translates to:
  /// **'{count} BCC recipient(s) (hidden)'**
  String infoBccCount(int count);

  /// No description provided for @infoTotalRecipients.
  ///
  /// In en, this message translates to:
  /// **'Total: {total}/{max} recipients (TO + CC + BCC)'**
  String infoTotalRecipients(int total, int max);

  /// No description provided for @infoCheckingServer.
  ///
  /// In en, this message translates to:
  /// **'Checking server...'**
  String get infoCheckingServer;

  /// No description provided for @infoServerMax.
  ///
  /// In en, this message translates to:
  /// **'Server max: {size} MB'**
  String infoServerMax(int size);

  /// No description provided for @infoLastAutoSaved.
  ///
  /// In en, this message translates to:
  /// **'Last auto-saved: {seconds} seconds ago'**
  String infoLastAutoSaved(int seconds);

  /// No description provided for @infoAttachmentsCount.
  ///
  /// In en, this message translates to:
  /// **'{count}/{max} files ({used}/{total} MB)'**
  String infoAttachmentsCount(int count, int max, int used, int total);

  /// No description provided for @buttonAddAccount.
  ///
  /// In en, this message translates to:
  /// **'Add Account'**
  String get buttonAddAccount;

  /// No description provided for @buttonAddAttachments.
  ///
  /// In en, this message translates to:
  /// **'Add Attachments'**
  String get buttonAddAttachments;

  /// No description provided for @buttonScanDocument.
  ///
  /// In en, this message translates to:
  /// **'Scan Document'**
  String get buttonScanDocument;

  /// No description provided for @buttonSaveDraft.
  ///
  /// In en, this message translates to:
  /// **'Save Draft'**
  String get buttonSaveDraft;

  /// No description provided for @buttonCancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get buttonCancel;

  /// No description provided for @buttonSend.
  ///
  /// In en, this message translates to:
  /// **'Send'**
  String get buttonSend;

  /// No description provided for @buttonSending.
  ///
  /// In en, this message translates to:
  /// **'Sending...'**
  String get buttonSending;

  /// No description provided for @buttonClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get buttonClose;

  /// No description provided for @errorTitle.
  ///
  /// In en, this message translates to:
  /// **'Error'**
  String get errorTitle;

  /// No description provided for @errorTooManyFiles.
  ///
  /// In en, this message translates to:
  /// **'Too Many Files'**
  String get errorTooManyFiles;

  /// No description provided for @errorTooManyFilesMessage.
  ///
  /// In en, this message translates to:
  /// **'Maximum {max} attachments allowed'**
  String errorTooManyFilesMessage(int max);

  /// No description provided for @errorFilesTooLarge.
  ///
  /// In en, this message translates to:
  /// **'Files Too Large'**
  String get errorFilesTooLarge;

  /// No description provided for @errorFilesTooLargeMessage.
  ///
  /// In en, this message translates to:
  /// **'Total attachment size must be under {max} MB (currently {current}MB)'**
  String errorFilesTooLargeMessage(int max, int current);

  /// No description provided for @errorFailedToPickFiles.
  ///
  /// In en, this message translates to:
  /// **'Failed to pick files'**
  String get errorFailedToPickFiles;

  /// No description provided for @errorScanFailed.
  ///
  /// In en, this message translates to:
  /// **'Failed to scan document'**
  String get errorScanFailed;

  /// No description provided for @errorPleaseSelectAccount.
  ///
  /// In en, this message translates to:
  /// **'Please select an account'**
  String get errorPleaseSelectAccount;

  /// No description provided for @errorAtLeastOneRecipient.
  ///
  /// In en, this message translates to:
  /// **'At least one recipient email is required'**
  String get errorAtLeastOneRecipient;

  /// No description provided for @errorMaxRecipientsExceeded.
  ///
  /// In en, this message translates to:
  /// **'Maximum {max} recipients allowed'**
  String errorMaxRecipientsExceeded(int max);

  /// No description provided for @errorInvalidEmail.
  ///
  /// In en, this message translates to:
  /// **'Invalid Email'**
  String get errorInvalidEmail;

  /// No description provided for @errorInvalidEmailFormat.
  ///
  /// In en, this message translates to:
  /// **'Invalid email format: {email}'**
  String errorInvalidEmailFormat(String email);

  /// No description provided for @errorInvalidCcEmail.
  ///
  /// In en, this message translates to:
  /// **'Invalid CC Email'**
  String get errorInvalidCcEmail;

  /// No description provided for @errorInvalidCcEmailFormat.
  ///
  /// In en, this message translates to:
  /// **'Invalid CC email format: {email}'**
  String errorInvalidCcEmailFormat(String email);

  /// No description provided for @errorInvalidBccEmail.
  ///
  /// In en, this message translates to:
  /// **'Invalid BCC Email'**
  String get errorInvalidBccEmail;

  /// No description provided for @errorInvalidBccEmailFormat.
  ///
  /// In en, this message translates to:
  /// **'Invalid BCC email format: {email}'**
  String errorInvalidBccEmailFormat(String email);

  /// No description provided for @errorTotalRecipientsExceeded.
  ///
  /// In en, this message translates to:
  /// **'Total recipients (TO + CC + BCC) cannot exceed {max}'**
  String errorTotalRecipientsExceeded(int max);

  /// No description provided for @errorSendFailed.
  ///
  /// In en, this message translates to:
  /// **'Send Failed'**
  String get errorSendFailed;

  /// No description provided for @errorDraft.
  ///
  /// In en, this message translates to:
  /// **'Draft Error'**
  String get errorDraft;

  /// No description provided for @successTitle.
  ///
  /// In en, this message translates to:
  /// **'Success'**
  String get successTitle;

  /// No description provided for @successEmailSentMultiple.
  ///
  /// In en, this message translates to:
  /// **'Email sent to {count} recipients!'**
  String successEmailSentMultiple(int count);

  /// No description provided for @successEmailSent.
  ///
  /// In en, this message translates to:
  /// **'Email sent successfully!'**
  String get successEmailSent;

  /// No description provided for @successDraftTitle.
  ///
  /// In en, this message translates to:
  /// **'Draft'**
  String get successDraftTitle;

  /// No description provided for @successDraftSaved.
  ///
  /// In en, this message translates to:
  /// **'Draft saved successfully'**
  String get successDraftSaved;

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'ICD360S Mail Client'**
  String get appTitle;

  /// No description provided for @appVersion.
  ///
  /// In en, this message translates to:
  /// **'v{version}'**
  String appVersion(String version);

  /// No description provided for @labelToRecipients.
  ///
  /// In en, this message translates to:
  /// **'To (Primary Recipients):'**
  String get labelToRecipients;

  /// No description provided for @labelCcFull.
  ///
  /// In en, this message translates to:
  /// **'CC (Carbon Copy):'**
  String get labelCcFull;

  /// No description provided for @labelBccFull.
  ///
  /// In en, this message translates to:
  /// **'BCC (Blind Carbon Copy - Hidden):'**
  String get labelBccFull;

  /// No description provided for @infoTooltipRecipients.
  ///
  /// In en, this message translates to:
  /// **'Primary recipients of the email - everyone will see this address'**
  String get infoTooltipRecipients;

  /// No description provided for @infoCcTooltipFull.
  ///
  /// In en, this message translates to:
  /// **'Receive a copy and ALL recipients see who is in CC'**
  String get infoCcTooltipFull;

  /// No description provided for @infoBccTooltipFull.
  ///
  /// In en, this message translates to:
  /// **'Receive a copy but NOBODY sees they received it (hidden)'**
  String get infoBccTooltipFull;

  /// No description provided for @infoRecipientsSimple.
  ///
  /// In en, this message translates to:
  /// **'{count} recipient(s)'**
  String infoRecipientsSimple(int count);

  /// No description provided for @infoCcSimple.
  ///
  /// In en, this message translates to:
  /// **'{count} CC recipient(s)'**
  String infoCcSimple(int count);

  /// No description provided for @infoBccSimple.
  ///
  /// In en, this message translates to:
  /// **'{count} BCC recipient(s) (hidden)'**
  String infoBccSimple(int count);

  /// No description provided for @infoTotalDestinatari.
  ///
  /// In en, this message translates to:
  /// **'Total: {total}/{max} recipients (TO + CC + BCC)'**
  String infoTotalDestinatari(int total, int max);

  /// No description provided for @infoLoadingHtml.
  ///
  /// In en, this message translates to:
  /// **'Loading HTML email...'**
  String get infoLoadingHtml;

  /// No description provided for @labelFrom.
  ///
  /// In en, this message translates to:
  /// **'From:'**
  String get labelFrom;

  /// No description provided for @labelDate.
  ///
  /// In en, this message translates to:
  /// **'Date:'**
  String get labelDate;

  /// No description provided for @labelThreat.
  ///
  /// In en, this message translates to:
  /// **'Threat:'**
  String get labelThreat;

  /// No description provided for @infoAttachmentsTitle.
  ///
  /// In en, this message translates to:
  /// **'Attachments ({count})'**
  String infoAttachmentsTitle(int count);

  /// No description provided for @infoForwardedMessage.
  ///
  /// In en, this message translates to:
  /// **'---------- Forwarded message ---------'**
  String get infoForwardedMessage;

  /// No description provided for @buttonReply.
  ///
  /// In en, this message translates to:
  /// **'Reply'**
  String get buttonReply;

  /// No description provided for @buttonForward.
  ///
  /// In en, this message translates to:
  /// **'Forward'**
  String get buttonForward;

  /// No description provided for @buttonDelete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get buttonDelete;

  /// No description provided for @buttonPrint.
  ///
  /// In en, this message translates to:
  /// **'Print'**
  String get buttonPrint;

  /// No description provided for @buttonCopy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get buttonCopy;

  /// No description provided for @buttonSpam.
  ///
  /// In en, this message translates to:
  /// **'Mark as Spam'**
  String get buttonSpam;

  /// No description provided for @successDeleted.
  ///
  /// In en, this message translates to:
  /// **'Deleted'**
  String get successDeleted;

  /// No description provided for @successEmailMovedToTrash.
  ///
  /// In en, this message translates to:
  /// **'Email moved to Trash'**
  String get successEmailMovedToTrash;

  /// No description provided for @successSpam.
  ///
  /// In en, this message translates to:
  /// **'Spam'**
  String get successSpam;

  /// No description provided for @successEmailMarkedAsSpam.
  ///
  /// In en, this message translates to:
  /// **'Email marked as spam'**
  String get successEmailMarkedAsSpam;

  /// No description provided for @successPrint.
  ///
  /// In en, this message translates to:
  /// **'Print'**
  String get successPrint;

  /// No description provided for @successPrintDialogOpened.
  ///
  /// In en, this message translates to:
  /// **'Print dialog opened'**
  String get successPrintDialogOpened;

  /// No description provided for @successCopied.
  ///
  /// In en, this message translates to:
  /// **'Copied'**
  String get successCopied;

  /// No description provided for @successEmailCopiedToClipboard.
  ///
  /// In en, this message translates to:
  /// **'Email content copied to clipboard'**
  String get successEmailCopiedToClipboard;

  /// No description provided for @successDownloaded.
  ///
  /// In en, this message translates to:
  /// **'Downloaded'**
  String get successDownloaded;

  /// No description provided for @successSavedTo.
  ///
  /// In en, this message translates to:
  /// **'Saved to: {path}'**
  String successSavedTo(String path);

  /// No description provided for @errorPrint.
  ///
  /// In en, this message translates to:
  /// **'Print Error'**
  String get errorPrint;

  /// No description provided for @errorCopy.
  ///
  /// In en, this message translates to:
  /// **'Copy Error'**
  String get errorCopy;

  /// No description provided for @errorView.
  ///
  /// In en, this message translates to:
  /// **'View Error'**
  String get errorView;

  /// No description provided for @errorDownload.
  ///
  /// In en, this message translates to:
  /// **'Download Error'**
  String get errorDownload;

  /// No description provided for @mainWindowTitle.
  ///
  /// In en, this message translates to:
  /// **'ICD360S Mail Client'**
  String get mainWindowTitle;

  /// No description provided for @mainWindowComposeButton.
  ///
  /// In en, this message translates to:
  /// **'Compose Email'**
  String get mainWindowComposeButton;

  /// No description provided for @mainWindowAccountsHeader.
  ///
  /// In en, this message translates to:
  /// **'📬 Accounts'**
  String get mainWindowAccountsHeader;

  /// No description provided for @mainWindowAddAccount.
  ///
  /// In en, this message translates to:
  /// **'Add Account'**
  String get mainWindowAddAccount;

  /// No description provided for @mainWindowFolderInbox.
  ///
  /// In en, this message translates to:
  /// **'Inbox'**
  String get mainWindowFolderInbox;

  /// No description provided for @mainWindowFolderSent.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get mainWindowFolderSent;

  /// No description provided for @mainWindowFolderDrafts.
  ///
  /// In en, this message translates to:
  /// **'Drafts'**
  String get mainWindowFolderDrafts;

  /// No description provided for @mainWindowFolderTrash.
  ///
  /// In en, this message translates to:
  /// **'Trash'**
  String get mainWindowFolderTrash;

  /// No description provided for @mainWindowFolderJunk.
  ///
  /// In en, this message translates to:
  /// **'Junk'**
  String get mainWindowFolderJunk;

  /// No description provided for @mainWindowSwitchAccount.
  ///
  /// In en, this message translates to:
  /// **'Switch Account'**
  String get mainWindowSwitchAccount;

  /// No description provided for @mainWindowInboxMessages.
  ///
  /// In en, this message translates to:
  /// **'messages in Inbox'**
  String get mainWindowInboxMessages;

  /// No description provided for @mainWindowStatusConnected.
  ///
  /// In en, this message translates to:
  /// **'Connected'**
  String get mainWindowStatusConnected;

  /// No description provided for @mainWindowStatusAuthError.
  ///
  /// In en, this message translates to:
  /// **'Authentication failed: {error}'**
  String mainWindowStatusAuthError(String error);

  /// No description provided for @mainWindowStatusNetworkError.
  ///
  /// In en, this message translates to:
  /// **'Connection error: {error}'**
  String mainWindowStatusNetworkError(String error);

  /// No description provided for @mainWindowStatusChecking.
  ///
  /// In en, this message translates to:
  /// **'Checking connection...'**
  String get mainWindowStatusChecking;

  /// No description provided for @mainWindowTooltipQuota.
  ///
  /// In en, this message translates to:
  /// **'Storage: {used} MB / {limit} MB ({percentage}%)'**
  String mainWindowTooltipQuota(String used, String limit, String percentage);

  /// No description provided for @mainWindowDialogDeleteAccountTitle.
  ///
  /// In en, this message translates to:
  /// **'Delete Account'**
  String get mainWindowDialogDeleteAccountTitle;

  /// No description provided for @mainWindowDialogDeleteAccountMessage.
  ///
  /// In en, this message translates to:
  /// **'Remove {username} from the app?\n\nThis will ONLY remove it from the app, NOT from the server.'**
  String mainWindowDialogDeleteAccountMessage(String username);

  /// No description provided for @mainWindowButtonDeleteFromApp.
  ///
  /// In en, this message translates to:
  /// **'Delete from App'**
  String get mainWindowButtonDeleteFromApp;

  /// No description provided for @mainWindowEmailsCount.
  ///
  /// In en, this message translates to:
  /// **'{count} emails'**
  String mainWindowEmailsCount(int count);

  /// No description provided for @mainWindowNoEmails.
  ///
  /// In en, this message translates to:
  /// **'No emails in {folder}'**
  String mainWindowNoEmails(String folder);

  /// No description provided for @mainWindowTooltipAutoDelete.
  ///
  /// In en, this message translates to:
  /// **'Se va șterge automat în {days} zile'**
  String mainWindowTooltipAutoDelete(int days);

  /// No description provided for @mainWindowTooltipAutoDeleteToday.
  ///
  /// In en, this message translates to:
  /// **'Se va șterge la următoarea pornire'**
  String get mainWindowTooltipAutoDeleteToday;

  /// No description provided for @mainWindowBadgeDaysShort.
  ///
  /// In en, this message translates to:
  /// **'🗑️ {days}z'**
  String mainWindowBadgeDaysShort(int days);

  /// No description provided for @mainWindowBadgeToday.
  ///
  /// In en, this message translates to:
  /// **'⚠️ Azi'**
  String get mainWindowBadgeToday;

  /// No description provided for @mainWindowStatusReady.
  ///
  /// In en, this message translates to:
  /// **'Ready - All systems operational'**
  String get mainWindowStatusReady;

  /// No description provided for @mainWindowStatusCheckingEmails.
  ///
  /// In en, this message translates to:
  /// **'Checking for new emails from server ({account})...'**
  String mainWindowStatusCheckingEmails(String account);

  /// No description provided for @mainWindowStatusError.
  ///
  /// In en, this message translates to:
  /// **'Error: {error}'**
  String mainWindowStatusError(String error);

  /// No description provided for @mainWindowFooterCopyright.
  ///
  /// In en, this message translates to:
  /// **'© 2025-{year} ICD360S e.V. | All Rights Reserved'**
  String mainWindowFooterCopyright(int year);

  /// No description provided for @mainWindowVersion.
  ///
  /// In en, this message translates to:
  /// **'v{version}'**
  String mainWindowVersion(String version);

  /// No description provided for @mainWindowLegalImpressum.
  ///
  /// In en, this message translates to:
  /// **'Impressum'**
  String get mainWindowLegalImpressum;

  /// No description provided for @mainWindowLegalPrivacy.
  ///
  /// In en, this message translates to:
  /// **'Datenschutz'**
  String get mainWindowLegalPrivacy;

  /// No description provided for @mainWindowLegalWithdrawal.
  ///
  /// In en, this message translates to:
  /// **'Widerrufsrecht'**
  String get mainWindowLegalWithdrawal;

  /// No description provided for @mainWindowLegalCancellation.
  ///
  /// In en, this message translates to:
  /// **'Kündigung'**
  String get mainWindowLegalCancellation;

  /// No description provided for @mainWindowLegalConstitution.
  ///
  /// In en, this message translates to:
  /// **'Satzung'**
  String get mainWindowLegalConstitution;

  /// No description provided for @mainWindowDialogLockedTitle.
  ///
  /// In en, this message translates to:
  /// **'Application Locked'**
  String get mainWindowDialogLockedTitle;

  /// No description provided for @mainWindowDialogLockedEnterPassword.
  ///
  /// In en, this message translates to:
  /// **'Enter your master password to unlock:'**
  String get mainWindowDialogLockedEnterPassword;

  /// No description provided for @mainWindowPlaceholderMasterPassword.
  ///
  /// In en, this message translates to:
  /// **'Master Password'**
  String get mainWindowPlaceholderMasterPassword;

  /// No description provided for @mainWindowButtonUnlock.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get mainWindowButtonUnlock;

  /// No description provided for @mainWindowLockedTitle.
  ///
  /// In en, this message translates to:
  /// **'Application Locked'**
  String get mainWindowLockedTitle;

  /// No description provided for @mainWindowLockedSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Auto-locked after 15 minutes of inactivity'**
  String get mainWindowLockedSubtitle;

  /// No description provided for @mainWindowLockedNotification.
  ///
  /// In en, this message translates to:
  /// **'Windows notifications continue to work in background'**
  String get mainWindowLockedNotification;

  /// No description provided for @mainWindowNotificationUpdateAvailable.
  ///
  /// In en, this message translates to:
  /// **'Actualizare disponibilă'**
  String get mainWindowNotificationUpdateAvailable;

  /// No description provided for @mainWindowNotificationDownloading.
  ///
  /// In en, this message translates to:
  /// **'Se descarcă v{version}...'**
  String mainWindowNotificationDownloading(String version);

  /// No description provided for @mainWindowNotificationUpdateInProgress.
  ///
  /// In en, this message translates to:
  /// **'Actualizare în curs'**
  String get mainWindowNotificationUpdateInProgress;

  /// No description provided for @mainWindowUnreadCount.
  ///
  /// In en, this message translates to:
  /// **'{count} unread'**
  String mainWindowUnreadCount(int count);

  /// No description provided for @masterPasswordDialogTitle.
  ///
  /// In en, this message translates to:
  /// **'Master Password'**
  String get masterPasswordDialogTitle;

  /// No description provided for @masterPasswordDialogAppTitle.
  ///
  /// In en, this message translates to:
  /// **'Client Mail'**
  String get masterPasswordDialogAppTitle;

  /// No description provided for @masterPasswordDialogFirstTimeMessage.
  ///
  /// In en, this message translates to:
  /// **'This is your first time using ICD360S Mail Client.\nPlease set a master password to protect your email accounts.'**
  String get masterPasswordDialogFirstTimeMessage;

  /// No description provided for @masterPasswordDialogLoginMessage.
  ///
  /// In en, this message translates to:
  /// **'Enter your master password to access email accounts.'**
  String get masterPasswordDialogLoginMessage;

  /// No description provided for @masterPasswordLabelPassword.
  ///
  /// In en, this message translates to:
  /// **'Password:'**
  String get masterPasswordLabelPassword;

  /// No description provided for @masterPasswordPlaceholderPassword.
  ///
  /// In en, this message translates to:
  /// **'Enter master password...'**
  String get masterPasswordPlaceholderPassword;

  /// No description provided for @masterPasswordLabelConfirm.
  ///
  /// In en, this message translates to:
  /// **'Confirm Password:'**
  String get masterPasswordLabelConfirm;

  /// No description provided for @masterPasswordPlaceholderConfirm.
  ///
  /// In en, this message translates to:
  /// **'Confirm password...'**
  String get masterPasswordPlaceholderConfirm;

  /// No description provided for @masterPasswordErrorEmpty.
  ///
  /// In en, this message translates to:
  /// **'Password cannot be empty'**
  String get masterPasswordErrorEmpty;

  /// No description provided for @masterPasswordErrorMismatch.
  ///
  /// In en, this message translates to:
  /// **'Passwords do not match'**
  String get masterPasswordErrorMismatch;

  /// No description provided for @masterPasswordErrorIncorrect.
  ///
  /// In en, this message translates to:
  /// **'Incorrect password'**
  String get masterPasswordErrorIncorrect;

  /// No description provided for @masterPasswordErrorGeneric.
  ///
  /// In en, this message translates to:
  /// **'Error: {error}'**
  String masterPasswordErrorGeneric(String error);

  /// No description provided for @masterPasswordErrorFailedToSet.
  ///
  /// In en, this message translates to:
  /// **'Failed to set password: {error}'**
  String masterPasswordErrorFailedToSet(String error);

  /// No description provided for @masterPasswordButtonResetApp.
  ///
  /// In en, this message translates to:
  /// **'Reset App'**
  String get masterPasswordButtonResetApp;

  /// No description provided for @masterPasswordButtonExitApp.
  ///
  /// In en, this message translates to:
  /// **'Exit App'**
  String get masterPasswordButtonExitApp;

  /// No description provided for @masterPasswordButtonSetPassword.
  ///
  /// In en, this message translates to:
  /// **'Set Password'**
  String get masterPasswordButtonSetPassword;

  /// No description provided for @masterPasswordButtonUnlock.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get masterPasswordButtonUnlock;

  /// No description provided for @masterPasswordButtonVerifying.
  ///
  /// In en, this message translates to:
  /// **'Verifying...'**
  String get masterPasswordButtonVerifying;

  /// No description provided for @masterPasswordDialogResetTitle.
  ///
  /// In en, this message translates to:
  /// **'Reset Application'**
  String get masterPasswordDialogResetTitle;

  /// No description provided for @masterPasswordDialogResetMessage.
  ///
  /// In en, this message translates to:
  /// **'This will DELETE ALL data:\n\n• Master password\n• All email accounts\n• All saved passwords\n• All settings\n\nThe app will restart as NEW.\n\nAre you sure?'**
  String get masterPasswordDialogResetMessage;

  /// No description provided for @masterPasswordLegalImpressum.
  ///
  /// In en, this message translates to:
  /// **'Impressum'**
  String get masterPasswordLegalImpressum;

  /// No description provided for @masterPasswordLegalPrivacy.
  ///
  /// In en, this message translates to:
  /// **'Datenschutz'**
  String get masterPasswordLegalPrivacy;

  /// No description provided for @masterPasswordLegalWithdrawal.
  ///
  /// In en, this message translates to:
  /// **'Widerrufsrecht'**
  String get masterPasswordLegalWithdrawal;

  /// No description provided for @masterPasswordLegalCancellation.
  ///
  /// In en, this message translates to:
  /// **'Kündigung'**
  String get masterPasswordLegalCancellation;

  /// No description provided for @masterPasswordLegalConstitution.
  ///
  /// In en, this message translates to:
  /// **'Satzung'**
  String get masterPasswordLegalConstitution;

  /// No description provided for @masterPasswordFooterCopyright.
  ///
  /// In en, this message translates to:
  /// **'© 2025-{year} ICD360S e.V. | Alle Rechte vorbehalten'**
  String masterPasswordFooterCopyright(int year);

  /// No description provided for @firstRunAppTitle.
  ///
  /// In en, this message translates to:
  /// **'Mail Client'**
  String get firstRunAppTitle;

  /// No description provided for @firstRunAppVersion.
  ///
  /// In en, this message translates to:
  /// **'v2.6.0'**
  String get firstRunAppVersion;

  /// No description provided for @firstRunWelcomeTitle.
  ///
  /// In en, this message translates to:
  /// **'Welcome to ICD360S Mail Client!'**
  String get firstRunWelcomeTitle;

  /// No description provided for @firstRunWelcomeMessage.
  ///
  /// In en, this message translates to:
  /// **'Before you start, please configure your preferences:'**
  String get firstRunWelcomeMessage;

  /// No description provided for @firstRunSectionAutoUpdate.
  ///
  /// In en, this message translates to:
  /// **'Automatic Updates'**
  String get firstRunSectionAutoUpdate;

  /// No description provided for @firstRunAutoUpdateDescription.
  ///
  /// In en, this message translates to:
  /// **'The app will automatically check for new updates on mail.icd360s.de and notify you when a new version is available.'**
  String get firstRunAutoUpdateDescription;

  /// No description provided for @firstRunCheckboxAutoUpdate.
  ///
  /// In en, this message translates to:
  /// **'Enable automatic updates (recommended)'**
  String get firstRunCheckboxAutoUpdate;

  /// No description provided for @firstRunSectionLogging.
  ///
  /// In en, this message translates to:
  /// **'Diagnostic & Logging'**
  String get firstRunSectionLogging;

  /// No description provided for @firstRunLoggingDescription.
  ///
  /// In en, this message translates to:
  /// **'Send diagnostic logs to the server to help us identify and resolve issues. Logs contain information about errors and usage, but DO NOT contain passwords or email content.'**
  String get firstRunLoggingDescription;

  /// No description provided for @firstRunCheckboxLogging.
  ///
  /// In en, this message translates to:
  /// **'Enable diagnostic logging (helps improve the app)'**
  String get firstRunCheckboxLogging;

  /// No description provided for @firstRunSectionNotifications.
  ///
  /// In en, this message translates to:
  /// **'Windows Notifications'**
  String get firstRunSectionNotifications;

  /// No description provided for @firstRunNotificationsDescription.
  ///
  /// In en, this message translates to:
  /// **'Receive Windows Toast notifications when new emails arrive in INBOX. Notifications appear in Action Center and include the sender and subject of the email.'**
  String get firstRunNotificationsDescription;

  /// No description provided for @firstRunCheckboxNotifications.
  ///
  /// In en, this message translates to:
  /// **'Enable notifications for new emails (recommended)'**
  String get firstRunCheckboxNotifications;

  /// No description provided for @firstRunPrivacyTitle.
  ///
  /// In en, this message translates to:
  /// **'Privacy'**
  String get firstRunPrivacyTitle;

  /// No description provided for @firstRunPrivacyMessage.
  ///
  /// In en, this message translates to:
  /// **'Your data is protected. Logs are sent securely via HTTPS and never contain passwords or personal content.'**
  String get firstRunPrivacyMessage;

  /// No description provided for @firstRunFooterCopyright.
  ///
  /// In en, this message translates to:
  /// **'© 2025-{year} ICD360S e.V. | All Rights Reserved'**
  String firstRunFooterCopyright(int year);

  /// No description provided for @firstRunButtonContinue.
  ///
  /// In en, this message translates to:
  /// **'Continue'**
  String get firstRunButtonContinue;

  /// No description provided for @changelogDialogTitle.
  ///
  /// In en, this message translates to:
  /// **'Changelog - ICD360S Mail Client'**
  String get changelogDialogTitle;

  /// No description provided for @changelogButtonClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get changelogButtonClose;

  /// No description provided for @logViewerDialogTitle.
  ///
  /// In en, this message translates to:
  /// **'Log Viewer'**
  String get logViewerDialogTitle;

  /// No description provided for @logViewerButtonClearLogs.
  ///
  /// In en, this message translates to:
  /// **'Clear Logs'**
  String get logViewerButtonClearLogs;

  /// No description provided for @logViewerButtonCopyAll.
  ///
  /// In en, this message translates to:
  /// **'Copy All'**
  String get logViewerButtonCopyAll;

  /// No description provided for @logViewerButtonClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get logViewerButtonClose;

  /// No description provided for @logViewerLogsCopied.
  ///
  /// In en, this message translates to:
  /// **'Logs copied to clipboard ({count} entries)'**
  String logViewerLogsCopied(int count);

  /// No description provided for @logViewerMetadataHeader.
  ///
  /// In en, this message translates to:
  /// **'=== ICD360S Mail Client Logs ==='**
  String get logViewerMetadataHeader;

  /// No description provided for @logViewerMetadataVersion.
  ///
  /// In en, this message translates to:
  /// **'Version: {version}'**
  String logViewerMetadataVersion(String version);

  /// No description provided for @logViewerMetadataPlatform.
  ///
  /// In en, this message translates to:
  /// **'Platform: {platform} {version}'**
  String logViewerMetadataPlatform(String platform, String version);

  /// No description provided for @logViewerMetadataTimestamp.
  ///
  /// In en, this message translates to:
  /// **'Timestamp: {timestamp}'**
  String logViewerMetadataTimestamp(String timestamp);

  /// No description provided for @logViewerMetadataTotalEntries.
  ///
  /// In en, this message translates to:
  /// **'Total Entries: {count}'**
  String logViewerMetadataTotalEntries(int count);

  /// No description provided for @logViewerMetadataSeparator.
  ///
  /// In en, this message translates to:
  /// **'==================================='**
  String get logViewerMetadataSeparator;

  /// No description provided for @authWrapperLoading.
  ///
  /// In en, this message translates to:
  /// **'Loading...'**
  String get authWrapperLoading;

  /// No description provided for @authWrapperAuthRequired.
  ///
  /// In en, this message translates to:
  /// **'Authentication Required'**
  String get authWrapperAuthRequired;

  /// No description provided for @authWrapperButtonExit.
  ///
  /// In en, this message translates to:
  /// **'Exit Application'**
  String get authWrapperButtonExit;

  /// No description provided for @attachmentViewerButtonDownload.
  ///
  /// In en, this message translates to:
  /// **'Download'**
  String get attachmentViewerButtonDownload;

  /// No description provided for @attachmentViewerButtonPrint.
  ///
  /// In en, this message translates to:
  /// **'Print'**
  String get attachmentViewerButtonPrint;

  /// No description provided for @attachmentViewerButtonClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get attachmentViewerButtonClose;

  /// No description provided for @attachmentViewerLoadingPdf.
  ///
  /// In en, this message translates to:
  /// **'Loading PDF...'**
  String get attachmentViewerLoadingPdf;

  /// No description provided for @attachmentViewerUnsupportedType.
  ///
  /// In en, this message translates to:
  /// **'Unsupported file type'**
  String get attachmentViewerUnsupportedType;

  /// No description provided for @attachmentViewerSuccessDownloaded.
  ///
  /// In en, this message translates to:
  /// **'Downloaded'**
  String get attachmentViewerSuccessDownloaded;

  /// No description provided for @attachmentViewerSuccessSavedTo.
  ///
  /// In en, this message translates to:
  /// **'Saved to: {path}'**
  String attachmentViewerSuccessSavedTo(String path);

  /// No description provided for @attachmentViewerErrorDownload.
  ///
  /// In en, this message translates to:
  /// **'Download Error'**
  String get attachmentViewerErrorDownload;

  /// No description provided for @attachmentViewerSuccessPrint.
  ///
  /// In en, this message translates to:
  /// **'Print'**
  String get attachmentViewerSuccessPrint;

  /// No description provided for @attachmentViewerSuccessPrintDialogOpened.
  ///
  /// In en, this message translates to:
  /// **'Print dialog opened'**
  String get attachmentViewerSuccessPrintDialogOpened;

  /// No description provided for @attachmentViewerErrorPrint.
  ///
  /// In en, this message translates to:
  /// **'Print Error'**
  String get attachmentViewerErrorPrint;

  /// No description provided for @blacklistDetailsTitle.
  ///
  /// In en, this message translates to:
  /// **'{ipType} Blacklist Check Results'**
  String blacklistDetailsTitle(String ipType);

  /// No description provided for @blacklistDetailsLabelStatus.
  ///
  /// In en, this message translates to:
  /// **'Status:'**
  String get blacklistDetailsLabelStatus;

  /// No description provided for @blacklistDetailsLabelIpAddress.
  ///
  /// In en, this message translates to:
  /// **'IP Address:'**
  String get blacklistDetailsLabelIpAddress;

  /// No description provided for @blacklistDetailsResultsTitle.
  ///
  /// In en, this message translates to:
  /// **'Blacklist Check Results:'**
  String get blacklistDetailsResultsTitle;

  /// No description provided for @blacklistDetailsNoCheck.
  ///
  /// In en, this message translates to:
  /// **'No blacklist check performed yet.'**
  String get blacklistDetailsNoCheck;

  /// No description provided for @blacklistDetailsProvidersTitle.
  ///
  /// In en, this message translates to:
  /// **'Checked Providers ({count}):'**
  String blacklistDetailsProvidersTitle(int count);

  /// No description provided for @blacklistDetailsExplanation.
  ///
  /// In en, this message translates to:
  /// **'DNS blacklist (DNSBL) checks verify if your mail server IP is listed as a spam source. Clean status ensures email deliverability.'**
  String get blacklistDetailsExplanation;

  /// No description provided for @blacklistDetailsButtonRefresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh Check'**
  String get blacklistDetailsButtonRefresh;

  /// No description provided for @blacklistDetailsNotificationRefresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get blacklistDetailsNotificationRefresh;

  /// No description provided for @blacklistDetailsNotificationRefreshMessage.
  ///
  /// In en, this message translates to:
  /// **'Re-checking blacklists...'**
  String get blacklistDetailsNotificationRefreshMessage;

  /// No description provided for @dnsDetailsTitle.
  ///
  /// In en, this message translates to:
  /// **'{recordType} Record Details'**
  String dnsDetailsTitle(String recordType);

  /// No description provided for @dnsDetailsLabelStatus.
  ///
  /// In en, this message translates to:
  /// **'Status:'**
  String get dnsDetailsLabelStatus;

  /// No description provided for @dnsDetailsLabelRecordType.
  ///
  /// In en, this message translates to:
  /// **'Record Type:'**
  String get dnsDetailsLabelRecordType;

  /// No description provided for @dnsDetailsLabelDomain.
  ///
  /// In en, this message translates to:
  /// **'Domain:'**
  String get dnsDetailsLabelDomain;

  /// No description provided for @dnsDetailsNoRecord.
  ///
  /// In en, this message translates to:
  /// **'No DNS record found or check not implemented yet.'**
  String get dnsDetailsNoRecord;

  /// No description provided for @dnsDetailsExplanationSpf.
  ///
  /// In en, this message translates to:
  /// **'SPF (Sender Policy Framework) validates that emails from your domain are sent from authorized servers. This prevents email spoofing.'**
  String get dnsDetailsExplanationSpf;

  /// No description provided for @dnsDetailsExplanationDkim.
  ///
  /// In en, this message translates to:
  /// **'DKIM (DomainKeys Identified Mail) adds a digital signature to your emails to verify they haven\'t been tampered with in transit.'**
  String get dnsDetailsExplanationDkim;

  /// No description provided for @webBrowserDefaultTitle.
  ///
  /// In en, this message translates to:
  /// **'Browser'**
  String get webBrowserDefaultTitle;

  /// No description provided for @webBrowserButtonClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get webBrowserButtonClose;

  /// No description provided for @updateDownloadingUpdate.
  ///
  /// In en, this message translates to:
  /// **'Downloading update v'**
  String get updateDownloadingUpdate;

  /// No description provided for @updateDownloadingProgress.
  ///
  /// In en, this message translates to:
  /// **'Downloading: '**
  String get updateDownloadingProgress;

  /// No description provided for @updateInstalling.
  ///
  /// In en, this message translates to:
  /// **'Installing update... App will restart automatically.'**
  String get updateInstalling;

  /// No description provided for @updateError.
  ///
  /// In en, this message translates to:
  /// **'Update error: {error}'**
  String updateError(String error);

  /// No description provided for @mailServiceSecurityViolationServer.
  ///
  /// In en, this message translates to:
  /// **'SECURITY VIOLATION: Connection to {server} is blocked. This client only connects to {allowedServer}.'**
  String mailServiceSecurityViolationServer(
      String server, String allowedServer);

  /// No description provided for @mailServiceSecurityViolationPorts.
  ///
  /// In en, this message translates to:
  /// **'SECURITY VIOLATION: Only standard ports are allowed (IMAP:{imapPort}, SMTP:{smtpPort}).'**
  String mailServiceSecurityViolationPorts(int imapPort, int smtpPort);

  /// No description provided for @mailServiceAuthenticationFailed.
  ///
  /// In en, this message translates to:
  /// **'Authentication failed for {username}: Wrong username or password'**
  String mailServiceAuthenticationFailed(String username);

  /// No description provided for @mailServiceAtLeastOneRecipient.
  ///
  /// In en, this message translates to:
  /// **'At least one recipient is required'**
  String get mailServiceAtLeastOneRecipient;

  /// No description provided for @mailServiceMessageTooLarge.
  ///
  /// In en, this message translates to:
  /// **'Message too large: {messageSizeKB} KB (server max: {maxSizeKB} KB)'**
  String mailServiceMessageTooLarge(int messageSizeKB, int maxSizeKB);

  /// No description provided for @mailServiceEmailCorrupt.
  ///
  /// In en, this message translates to:
  /// **'Email MessageId is missing. This email may be corrupt and cannot be moved.'**
  String get mailServiceEmailCorrupt;

  /// No description provided for @mailServiceEmailNotFound.
  ///
  /// In en, this message translates to:
  /// **'Email not found in {folder}. It may have been already moved or deleted.'**
  String mailServiceEmailNotFound(String folder);

  /// No description provided for @accountServiceSecurityErrorServer.
  ///
  /// In en, this message translates to:
  /// **'Security Error: Only {allowedServer} server is allowed. This client is locked to ICD360S mail server.'**
  String accountServiceSecurityErrorServer(String allowedServer);

  /// No description provided for @accountServiceSecurityErrorPorts.
  ///
  /// In en, this message translates to:
  /// **'Security Error: Only secure ports (IMAP:10993, SMTP:465) are allowed for mTLS.'**
  String get accountServiceSecurityErrorPorts;

  /// No description provided for @notificationNewEmailFrom.
  ///
  /// In en, this message translates to:
  /// **'New Email from {from}'**
  String notificationNewEmailFrom(String from);

  /// No description provided for @notificationEmailSubjectThreat.
  ///
  /// In en, this message translates to:
  /// **'{subject}\nThreat: {threat}'**
  String notificationEmailSubjectThreat(String subject, String threat);

  /// No description provided for @certExpiryStatusUnknown.
  ///
  /// In en, this message translates to:
  /// **'Certificate status unknown'**
  String get certExpiryStatusUnknown;

  /// No description provided for @certExpiryExpired.
  ///
  /// In en, this message translates to:
  /// **'Certificate EXPIRED - Please re-login to renew'**
  String get certExpiryExpired;

  /// No description provided for @certExpiryExpiresSoon.
  ///
  /// In en, this message translates to:
  /// **'Certificate expires in {days} days - Re-login recommended'**
  String certExpiryExpiresSoon(int days);

  /// No description provided for @certExpiryValid.
  ///
  /// In en, this message translates to:
  /// **'Certificate valid for {days}+ days'**
  String certExpiryValid(int days);
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'ro'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'ro':
      return AppLocalizationsRo();
  }

  throw FlutterError(
      'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
      'an issue with the localizations generation tool. Please file an issue '
      'on GitHub with a reproducible sample app and the gen-l10n configuration '
      'that was used.');
}
