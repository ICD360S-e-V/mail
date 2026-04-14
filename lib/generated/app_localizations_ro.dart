// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Romanian Moldavian Moldovan (`ro`).
class AppLocalizationsRo extends AppLocalizations {
  AppLocalizationsRo([String locale = 'ro']) : super(locale);

  @override
  String get dialogTitleAddAccount => 'Adaugă Cont Email';

  @override
  String get dialogTitleCompose => 'Compune Email';

  @override
  String get labelEmailAddress => 'Adresă Email:';

  @override
  String get placeholderUsername => 'utilizator';

  @override
  String get labelPassword => 'Parolă:';

  @override
  String get placeholderPassword => 'Introdu parola...';

  @override
  String get labelMailServer => 'Server Mail (blocat):';

  @override
  String get labelImapPort => 'Port IMAP (blocat):';

  @override
  String get labelSmtpPort => 'Port SMTP (blocat):';

  @override
  String get labelFromAccount => 'De la Cont:';

  @override
  String get labelTo => 'Către (Destinatari principali):';

  @override
  String get labelCc => 'CC (Copie Vizibilă):';

  @override
  String get labelBcc => 'BCC (Copie Ascunsă):';

  @override
  String get labelSubject => 'Subiect:';

  @override
  String get labelMessage => 'Mesaj:';

  @override
  String get placeholderSelectAccount => 'Selectează cont...';

  @override
  String get placeholderRecipients => 'email1@example.com, email2@example.com';

  @override
  String get placeholderRecipientsOptional =>
      'Opțional: email1@example.com, email2@example.com';

  @override
  String get placeholderSubject => 'Introdu subiectul...';

  @override
  String get placeholderMessage => 'Scrie mesajul tău aici...';

  @override
  String get infoSslEnabled =>
      'Criptare SSL/TLS: ACTIVATĂ (blocat pentru securitate)';

  @override
  String get infoTooltip =>
      'Destinatarii principali ai emailului - toți vor vedea această adresă';

  @override
  String get infoCcTooltip =>
      'Primesc o copie și TOȚI destinatarii văd cine e în CC';

  @override
  String get infoBccTooltip =>
      'Primesc o copie dar NIMENI nu vede că au primit (ascunși)';

  @override
  String infoRecipientCount(int count) {
    return '$count destinatar(i)';
  }

  @override
  String infoCcCount(int count) {
    return '$count CC destinatar(i)';
  }

  @override
  String infoBccCount(int count) {
    return '$count BCC destinatar(i) (ascunși)';
  }

  @override
  String infoTotalRecipients(int total, int max) {
    return 'Total: $total/$max destinatari (TO + CC + BCC)';
  }

  @override
  String get infoCheckingServer => 'Verificare server...';

  @override
  String infoServerMax(int size) {
    return 'Server max: $size MB';
  }

  @override
  String infoLastAutoSaved(int seconds) {
    return 'Ultima salvare automată: acum $seconds secunde';
  }

  @override
  String infoAttachmentsCount(int count, int max, int used, int total) {
    return '$count/$max fișiere ($used/$total MB)';
  }

  @override
  String get buttonAddAccount => 'Adaugă Cont';

  @override
  String get buttonAddAttachments => 'Adaugă Atașamente';

  @override
  String get buttonScanDocument => 'Scanează Document';

  @override
  String get buttonSaveDraft => 'Salvează Ciornă';

  @override
  String get buttonCancel => 'Anulează';

  @override
  String get buttonSend => 'Trimite';

  @override
  String get buttonSending => 'Se trimite...';

  @override
  String get buttonClose => 'Închide';

  @override
  String get errorTitle => 'Eroare';

  @override
  String get errorTooManyFiles => 'Prea Multe Fișiere';

  @override
  String errorTooManyFilesMessage(int max) {
    return 'Maxim $max atașamente permise';
  }

  @override
  String get errorFilesTooLarge => 'Fișiere Prea Mari';

  @override
  String errorFilesTooLargeMessage(int max, int current) {
    return 'Dimensiunea totală a atașamentelor trebuie să fie sub $max MB (actualmente ${current}MB)';
  }

  @override
  String get errorFailedToPickFiles => 'Eșec la selectarea fișierelor';

  @override
  String get errorScanFailed => 'Scanarea documentului a eșuat';

  @override
  String get errorPleaseSelectAccount => 'Te rog selectează un cont';

  @override
  String get errorAtLeastOneRecipient => 'Este necesar cel puțin un destinatar';

  @override
  String errorMaxRecipientsExceeded(int max) {
    return 'Maxim $max destinatari permis';
  }

  @override
  String get errorInvalidEmail => 'Email Invalid';

  @override
  String errorInvalidEmailFormat(String email) {
    return 'Format email invalid: $email';
  }

  @override
  String get errorInvalidCcEmail => 'Email CC Invalid';

  @override
  String errorInvalidCcEmailFormat(String email) {
    return 'Format email CC invalid: $email';
  }

  @override
  String get errorInvalidBccEmail => 'Email BCC Invalid';

  @override
  String errorInvalidBccEmailFormat(String email) {
    return 'Format email BCC invalid: $email';
  }

  @override
  String errorTotalRecipientsExceeded(int max) {
    return 'Total destinatari (TO + CC + BCC) nu poate depăși $max';
  }

  @override
  String get errorSendFailed => 'Eșec la Trimitere';

  @override
  String get errorDraft => 'Eroare Ciornă';

  @override
  String get successTitle => 'Succes';

  @override
  String successEmailSentMultiple(int count) {
    return 'Email trimis la $count destinatari!';
  }

  @override
  String get successEmailSent => 'Email trimis cu succes!';

  @override
  String get successDraftTitle => 'Ciornă';

  @override
  String get successDraftSaved => 'Ciornă salvată cu succes';

  @override
  String get appTitle => 'ICD360S Client Mail';

  @override
  String appVersion(String version) {
    return 'v$version';
  }

  @override
  String get labelToRecipients => 'Către (Destinatari principali):';

  @override
  String get labelCcFull => 'CC (Copie Vizibilă):';

  @override
  String get labelBccFull => 'BCC (Copie Ascunsă):';

  @override
  String get infoTooltipRecipients =>
      'Destinatarii principali ai emailului - toți vor vedea această adresă';

  @override
  String get infoCcTooltipFull =>
      'Primesc o copie și TOȚI destinatarii văd cine e în CC';

  @override
  String get infoBccTooltipFull =>
      'Primesc o copie dar NIMENI nu vede că au primit (ascunși)';

  @override
  String infoRecipientsSimple(int count) {
    return '$count destinatar(i)';
  }

  @override
  String infoCcSimple(int count) {
    return '$count CC destinatar(i)';
  }

  @override
  String infoBccSimple(int count) {
    return '$count BCC destinatar(i) (ascunși)';
  }

  @override
  String infoTotalDestinatari(int total, int max) {
    return 'Total: $total/$max destinatari (TO + CC + BCC)';
  }

  @override
  String get infoLoadingHtml => 'Încărcare email HTML...';

  @override
  String get labelFrom => 'De la:';

  @override
  String get labelDate => 'Data:';

  @override
  String get labelThreat => 'Amenințare:';

  @override
  String infoAttachmentsTitle(int count) {
    return 'Atașamente ($count)';
  }

  @override
  String get infoForwardedMessage => '---------- Mesaj redirectat ---------';

  @override
  String get buttonReply => 'Răspunde';

  @override
  String get buttonForward => 'Redirecționează';

  @override
  String get buttonDelete => 'Șterge';

  @override
  String get buttonPrint => 'Printează';

  @override
  String get buttonCopy => 'Copiază';

  @override
  String get buttonSpam => 'Marchează ca Spam';

  @override
  String get successDeleted => 'Șters';

  @override
  String get successEmailMovedToTrash => 'Email mutat în Coș';

  @override
  String get successSpam => 'Spam';

  @override
  String get successEmailMarkedAsSpam => 'Email marcat ca spam';

  @override
  String get successPrint => 'Printare';

  @override
  String get successPrintDialogOpened => 'Fereastra de printare deschisă';

  @override
  String get successCopied => 'Copiat';

  @override
  String get successEmailCopiedToClipboard =>
      'Conținutul emailului copiat în clipboard';

  @override
  String get successDownloaded => 'Descărcat';

  @override
  String successSavedTo(String path) {
    return 'Salvat în: $path';
  }

  @override
  String get errorPrint => 'Eroare Printare';

  @override
  String get errorCopy => 'Eroare Copiere';

  @override
  String get errorView => 'Eroare Vizualizare';

  @override
  String get errorDownload => 'Eroare Descărcare';

  @override
  String get mainWindowTitle => 'ICD360S Client Mail';

  @override
  String get mainWindowComposeButton => 'Compune Email';

  @override
  String get mainWindowAccountsHeader => '📬 Conturi';

  @override
  String get mainWindowAddAccount => 'Adaugă Cont';

  @override
  String get mainWindowFolderInbox => 'Inbox';

  @override
  String get mainWindowFolderSent => 'Trimise';

  @override
  String get mainWindowFolderDrafts => 'Ciorne';

  @override
  String get mainWindowFolderTrash => 'Coș';

  @override
  String get mainWindowFolderJunk => 'Spam';

  @override
  String get attachSourceFile => 'Alege fișier';

  @override
  String get attachSourceCamera => 'Scanează cu camera';

  @override
  String get mainWindowSwitchAccount => 'Schimbă cont';

  @override
  String get mainWindowInboxMessages => 'mesaje în Inbox';

  @override
  String get mainWindowStatusConnected => 'Conectat';

  @override
  String mainWindowStatusAuthError(String error) {
    return 'Autentificare eșuată: $error';
  }

  @override
  String mainWindowStatusNetworkError(String error) {
    return 'Eroare de conexiune: $error';
  }

  @override
  String get mainWindowStatusChecking => 'Verificare conexiune...';

  @override
  String mainWindowTooltipQuota(String used, String limit, String percentage) {
    return 'Spațiu: $used MB / $limit MB ($percentage%)';
  }

  @override
  String get mainWindowDialogDeleteAccountTitle => 'Șterge Cont';

  @override
  String mainWindowDialogDeleteAccountMessage(String username) {
    return 'Elimini $username din aplicație?\n\nAcest lucru va elimina contul DOAR din aplicație, NU de pe server.';
  }

  @override
  String get mainWindowButtonDeleteFromApp => 'Șterge din Aplicație';

  @override
  String mainWindowEmailsCount(int count) {
    return '$count emailuri';
  }

  @override
  String mainWindowNoEmails(String folder) {
    return 'Niciun email în $folder';
  }

  @override
  String mainWindowTooltipAutoDelete(int days) {
    return 'Se va șterge automat în $days zile';
  }

  @override
  String get mainWindowTooltipAutoDeleteToday =>
      'Se va șterge la următoarea pornire';

  @override
  String mainWindowBadgeDaysShort(int days) {
    return '🗑️ ${days}z';
  }

  @override
  String get mainWindowBadgeToday => '⚠️ Azi';

  @override
  String get mainWindowStatusReady => 'Gata - Toate sistemele funcționează';

  @override
  String mainWindowStatusCheckingEmails(String account) {
    return 'Verificare emailuri noi de pe server ($account)...';
  }

  @override
  String mainWindowStatusError(String error) {
    return 'Eroare: $error';
  }

  @override
  String mainWindowFooterCopyright(int year) {
    return '© 2025-$year ICD360S e.V. | Toate Drepturile Rezervate';
  }

  @override
  String mainWindowVersion(String version) {
    return 'v$version';
  }

  @override
  String get mainWindowLegalImpressum => 'Impressum';

  @override
  String get mainWindowLegalPrivacy => 'Datenschutz';

  @override
  String get mainWindowLegalWithdrawal => 'Widerrufsrecht';

  @override
  String get mainWindowLegalCancellation => 'Kündigung';

  @override
  String get mainWindowLegalConstitution => 'Satzung';

  @override
  String get mainWindowDialogLockedTitle => 'Aplicație Blocată';

  @override
  String get mainWindowDialogLockedEnterPassword =>
      'Introdu parola master pentru deblocare:';

  @override
  String get mainWindowPlaceholderMasterPassword => 'Parolă Master';

  @override
  String get mainWindowButtonUnlock => 'Deblochează';

  @override
  String get mainWindowLockedTitle => 'Aplicație Blocată';

  @override
  String get mainWindowLockedSubtitle =>
      'Blocat automat după 15 minute de inactivitate';

  @override
  String get mainWindowLockedNotification =>
      'Notificările Windows continuă să funcționeze în fundal';

  @override
  String get mainWindowNotificationUpdateAvailable => 'Actualizare disponibilă';

  @override
  String mainWindowNotificationDownloading(String version) {
    return 'Se descarcă v$version...';
  }

  @override
  String get mainWindowNotificationUpdateInProgress => 'Actualizare în curs';

  @override
  String mainWindowUnreadCount(int count) {
    return '$count necitite';
  }

  @override
  String get masterPasswordDialogTitle => 'Parolă Master';

  @override
  String get masterPasswordDialogAppTitle => 'Client Mail';

  @override
  String get masterPasswordDialogFirstTimeMessage =>
      'Aceasta este prima utilizare a ICD360S Mail Client.\nTe rog setează o parolă master pentru a-ți proteja conturile email.';

  @override
  String get masterPasswordDialogLoginMessage =>
      'Introdu parola master pentru acces la conturile email.';

  @override
  String get masterPasswordLabelPassword => 'Parolă:';

  @override
  String get masterPasswordPlaceholderPassword => 'Introdu parola master...';

  @override
  String get masterPasswordLabelConfirm => 'Confirmă Parola:';

  @override
  String get masterPasswordPlaceholderConfirm => 'Confirmă parola...';

  @override
  String get masterPasswordErrorEmpty => 'Parola nu poate fi goală';

  @override
  String get masterPasswordErrorMismatch => 'Parolele nu se potrivesc';

  @override
  String get masterPasswordErrorIncorrect => 'Parolă incorectă';

  @override
  String masterPasswordErrorGeneric(String error) {
    return 'Eroare: $error';
  }

  @override
  String masterPasswordErrorFailedToSet(String error) {
    return 'Eșec la setarea parolei: $error';
  }

  @override
  String get masterPasswordButtonResetApp => 'Resetare Aplicație';

  @override
  String get masterPasswordButtonExitApp => 'Ieșire Aplicație';

  @override
  String get masterPasswordButtonSetPassword => 'Setează Parola';

  @override
  String get masterPasswordButtonUnlock => 'Deblochează';

  @override
  String get masterPasswordButtonVerifying => 'Verificare...';

  @override
  String get masterPasswordDialogResetTitle => 'Resetare Aplicație';

  @override
  String get masterPasswordDialogResetMessage =>
      'Aceasta va ȘTERGE TOATE datele:\n\n• Parola master\n• Toate conturile email\n• Toate parolele salvate\n• Toate setările\n\nAplicația va reporni ca NOUĂ.\n\nEști sigur?';

  @override
  String get masterPasswordLegalImpressum => 'Impressum';

  @override
  String get masterPasswordLegalPrivacy => 'Datenschutz';

  @override
  String get masterPasswordLegalWithdrawal => 'Widerrufsrecht';

  @override
  String get masterPasswordLegalCancellation => 'Kündigung';

  @override
  String get masterPasswordLegalConstitution => 'Satzung';

  @override
  String masterPasswordFooterCopyright(int year) {
    return '© 2025-$year ICD360S e.V. | Alle Rechte vorbehalten';
  }

  @override
  String get firstRunAppTitle => 'Client Mail';

  @override
  String get firstRunAppVersion => 'v2.6.0';

  @override
  String get firstRunWelcomeTitle => 'Bun venit la ICD360S Mail Client!';

  @override
  String get firstRunWelcomeMessage =>
      'Înainte de a începe, te rugăm să configurezi preferințele tale:';

  @override
  String get firstRunSectionAutoUpdate => 'Actualizări Automate';

  @override
  String get firstRunAutoUpdateDescription =>
      'Aplicația va verifica automat pentru actualizări noi pe mail.icd360s.de și te va notifica când este disponibilă o versiune nouă.';

  @override
  String get firstRunCheckboxAutoUpdate =>
      'Activează actualizări automate (recomandat)';

  @override
  String get firstRunSectionLogging => 'Diagnostic & Logging';

  @override
  String get firstRunLoggingDescription =>
      'Trimite log-uri diagnostic pe server pentru a ne ajuta să identificăm și să rezolvăm problemele. Log-urile conțin informații despre erori și utilizare, dar NU conțin parole sau conținut email.';

  @override
  String get firstRunCheckboxLogging =>
      'Activează diagnostic logging (ajută la îmbunătățirea aplicației)';

  @override
  String get firstRunSectionNotifications => 'Notificări Windows';

  @override
  String get firstRunNotificationsDescription =>
      'Primește notificări Windows Toast când sosesc emailuri noi în INBOX. Notificările apar în Action Center și includ expeditorul și subiectul emailului.';

  @override
  String get firstRunCheckboxNotifications =>
      'Activează notificări pentru emailuri noi (recomandat)';

  @override
  String get firstRunPrivacyTitle => 'Confidențialitate';

  @override
  String get firstRunPrivacyMessage =>
      'Datele tale sunt protejate. Log-urile sunt trimise securizat prin HTTPS și nu conțin niciodată parole sau conținut personal.';

  @override
  String firstRunFooterCopyright(int year) {
    return '© 2025-$year ICD360S e.V. | Alle Rechte vorbehalten';
  }

  @override
  String get firstRunButtonContinue => 'Continuă';

  @override
  String get changelogDialogTitle => 'Changelog - ICD360S Mail Client';

  @override
  String get changelogButtonClose => 'Închide';

  @override
  String get logViewerDialogTitle => 'Vizualizator Log';

  @override
  String get logViewerButtonClearLogs => 'Șterge Log-uri';

  @override
  String get logViewerButtonCopyAll => 'Copiază Tot';

  @override
  String get logViewerButtonClose => 'Închide';

  @override
  String logViewerLogsCopied(int count) {
    return 'Log-uri copiate în clipboard ($count intrări)';
  }

  @override
  String get logViewerMetadataHeader => '=== ICD360S Mail Client Log-uri ===';

  @override
  String logViewerMetadataVersion(String version) {
    return 'Versiune: $version';
  }

  @override
  String logViewerMetadataPlatform(String platform, String version) {
    return 'Platformă: $platform $version';
  }

  @override
  String logViewerMetadataTimestamp(String timestamp) {
    return 'Timestamp: $timestamp';
  }

  @override
  String logViewerMetadataTotalEntries(int count) {
    return 'Total Intrări: $count';
  }

  @override
  String get logViewerMetadataSeparator =>
      '===================================';

  @override
  String get authWrapperLoading => 'Încărcare...';

  @override
  String get authWrapperAuthRequired => 'Autentificare Necesară';

  @override
  String get authWrapperButtonExit => 'Ieșire Aplicație';

  @override
  String get attachmentViewerButtonDownload => 'Descarcă';

  @override
  String get attachmentViewerButtonPrint => 'Printează';

  @override
  String get attachmentViewerButtonClose => 'Închide';

  @override
  String get attachmentViewerLoadingPdf => 'Încărcare PDF...';

  @override
  String get attachmentViewerUnsupportedType => 'Tip fișier nesuportat';

  @override
  String get attachmentViewerSuccessDownloaded => 'Descărcat';

  @override
  String attachmentViewerSuccessSavedTo(String path) {
    return 'Salvat în: $path';
  }

  @override
  String get attachmentViewerErrorDownload => 'Eroare Descărcare';

  @override
  String get attachmentViewerSuccessPrint => 'Printare';

  @override
  String get attachmentViewerSuccessPrintDialogOpened =>
      'Fereastra de printare deschisă';

  @override
  String get attachmentViewerErrorPrint => 'Eroare Printare';

  @override
  String blacklistDetailsTitle(String ipType) {
    return 'Rezultate Verificare Blacklist $ipType';
  }

  @override
  String get blacklistDetailsLabelStatus => 'Status:';

  @override
  String get blacklistDetailsLabelIpAddress => 'Adresă IP:';

  @override
  String get blacklistDetailsResultsTitle => 'Rezultate Verificare Blacklist:';

  @override
  String get blacklistDetailsNoCheck =>
      'Nu s-a efectuat încă nicio verificare blacklist.';

  @override
  String blacklistDetailsProvidersTitle(int count) {
    return 'Provideri Verificați ($count):';
  }

  @override
  String get blacklistDetailsExplanation =>
      'Verificările DNS blacklist (DNSBL) confirmă dacă IP-ul serverului tău de mail este listat ca sursă de spam. Statusul clean asigură livrabilitatea emailurilor.';

  @override
  String get blacklistDetailsButtonRefresh => 'Reîmprospătează Verificare';

  @override
  String get blacklistDetailsNotificationRefresh => 'Reîmprospătare';

  @override
  String get blacklistDetailsNotificationRefreshMessage =>
      'Re-verificare blacklist-uri...';

  @override
  String dnsDetailsTitle(String recordType) {
    return 'Detalii Record $recordType';
  }

  @override
  String get dnsDetailsLabelStatus => 'Status:';

  @override
  String get dnsDetailsLabelRecordType => 'Tip Record:';

  @override
  String get dnsDetailsLabelDomain => 'Domeniu:';

  @override
  String get dnsDetailsNoRecord =>
      'Nu s-a găsit record DNS sau verificarea nu este încă implementată.';

  @override
  String get dnsDetailsExplanationSpf =>
      'SPF (Sender Policy Framework) validează că emailurile de la domeniul tău sunt trimise de pe servere autorizate. Aceasta previne email spoofing.';

  @override
  String get dnsDetailsExplanationDkim =>
      'DKIM (DomainKeys Identified Mail) adaugă o semnătură digitală la emailurile tale pentru a verifica că nu au fost modificate în tranzit.';

  @override
  String get webBrowserDefaultTitle => 'Browser';

  @override
  String get webBrowserButtonClose => 'Închide';

  @override
  String get updateDownloadingUpdate => 'Se descarcă actualizarea v';

  @override
  String get updateDownloadingProgress => 'Se descarcă: ';

  @override
  String get updateInstalling =>
      'Se instalează actualizarea... Aplicația va reporni automat.';

  @override
  String updateError(String error) {
    return 'Eroare actualizare: $error';
  }

  @override
  String mailServiceSecurityViolationServer(
      String server, String allowedServer) {
    return 'VIOLARE DE SECURITATE: Conexiunea la $server este blocată. Acest client se conectează doar la $allowedServer.';
  }

  @override
  String mailServiceSecurityViolationPorts(int imapPort, int smtpPort) {
    return 'VIOLARE DE SECURITATE: Doar porturile standard sunt permise (IMAP:$imapPort, SMTP:$smtpPort).';
  }

  @override
  String mailServiceAuthenticationFailed(String username) {
    return 'Autentificare eșuată pentru $username: Nume utilizator sau parolă greșită';
  }

  @override
  String get mailServiceAtLeastOneRecipient =>
      'Este necesar cel puțin un destinatar';

  @override
  String mailServiceMessageTooLarge(int messageSizeKB, int maxSizeKB) {
    return 'Mesaj prea mare: $messageSizeKB KB (max server: $maxSizeKB KB)';
  }

  @override
  String get mailServiceEmailCorrupt =>
      'MessageId-ul emailului lipsește. Acest email ar putea fi corupt și nu poate fi mutat.';

  @override
  String mailServiceEmailNotFound(String folder) {
    return 'Email negăsit în $folder. Ar putea fi deja mutat sau șters.';
  }

  @override
  String accountServiceSecurityErrorServer(String allowedServer) {
    return 'Eroare de Securitate: Doar serverul $allowedServer este permis. Acest client este blocat la serverul de mail ICD360S.';
  }

  @override
  String get accountServiceSecurityErrorPorts =>
      'Eroare de Securitate: Doar porturile securizate (IMAP:10993, SMTP:465) sunt permise pentru mTLS.';

  @override
  String notificationNewEmailFrom(String from) {
    return 'Email nou de la $from';
  }

  @override
  String notificationEmailSubjectThreat(String subject, String threat) {
    return '$subject\nAmenințare: $threat';
  }

  @override
  String get certExpiryStatusUnknown => 'Status certificat necunoscut';

  @override
  String get certExpiryExpired =>
      'Certificat EXPIRAT - Te rog autentifică-te din nou pentru reînnoire';

  @override
  String certExpiryExpiresSoon(int days) {
    return 'Certificatul expiră în $days zile - Reautentificare recomandată';
  }

  @override
  String certExpiryValid(int days) {
    return 'Certificat valabil pentru $days+ zile';
  }
}
