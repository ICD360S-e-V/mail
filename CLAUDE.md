# ICD360S Mail Client - Documentatie

**Actualizat:** 7 Aprilie 2026
**Versiune Curenta:** 2.20.0 (Cross-Platform)

---

## 1. SERVER

### Conexiune
```bash
# Cheia SSH se afla in directorul proiectului (fisierul vps_mail.icd360s.de)
# Portul SSH si IP-ul serverului sunt documentate intern — nu in repo public
ssh -i <SSH_KEY_PATH> -p <SSH_PORT> root@mail.icd360s.de
```

> **SECURITY NOTE:** IP-uri, porturi, credentiale si configurari server sunt documentate
> intr-un loc privat (nu in repo). Consultati documentatia interna.

### Stack Server
- **OS:** AlmaLinux 10.1
- **Mail:** Postfix + Dovecot + HAProxy (mTLS enforcement)
- **Anti-Spam:** Rspamd (Bayesian, fuzzy, phishing detection, domain blacklists)
- **Web:** Nginx (certificate API, updates)
- **Security:** fail2ban (multiple jails), firewalld (rate limiting)
- **DNS:** Unbound (local resolver)
- **Cache:** Valkey (Redis fork, Rspamd backend)
- **SSL:** Let's Encrypt (dual ECDSA + RSA, DANE/TLSA)

### Certificate API
- Descarca certificat mTLS per-user (90 zile validitate, auto-renewal la < 30 zile)
- Endpoint: `https://mail.icd360s.de/api/get-certificate.php`

---

## 2. APLICATIA FLUTTER

### Platforme Suportate
| Platforma | Status | Notificari | Storage Securizat |
|-----------|--------|------------|-------------------|
| **macOS** | Complet | System + In-App | Keychain |
| **Windows** | Complet | In-App Only | Credential Manager |
| **Linux** | Complet | System + In-App | Encrypted Storage |
| **Android** | Experimental | System + In-App | EncryptedSharedPreferences |
| **iOS** | Experimental | System + In-App | Keychain |

### Stack Tehnologic
| Pachet | Versiune | Scop |
|--------|----------|------|
| Flutter | 3.41.4 | Framework |
| Dart | 3.11.1 | SDK |
| fluent_ui | ^4.15.0 | UI Framework (Windows 11 style, cross-platform) |
| enough_mail | Local fork | IMAP/SMTP cu suport mTLS |
| provider | ^6.1.0 | State management |
| flutter_secure_storage | ^10.0.0 | Secure storage (Keychain/Credential Manager/EncryptedSharedPreferences) |
| flutter_local_notifications | ^18.0.1 | Notificari cross-platform |
| window_manager | ^0.5.1 | Window control desktop |
| url_launcher | ^6.3.1 | Deschide URL-uri in browser extern |
| file_picker | ^10.3.8 | Selectie fisiere pentru atasamente |
| printing | ^5.13.4 | Dialog nativ de printare |
| pdf | ^3.11.1 | Generare PDF pentru print imagini |
| pdfrx | ^1.0.100 | Viewer PDF nativ (PDFium) |
| http | ^1.2.0 | HTTP client pentru Certificate API |
| path_provider | ^2.1.5 | Directoare cross-platform app data |
| crypto | ^3.0.0 | SHA-256 hashing master password |
| intl | 0.20.2 | Formatare data/ora |
| cunning_document_scanner | ^1.4.0 | Document scanner (Android/iOS) |

### Localizare (i18n)
| Limba | Fisier | Status |
|-------|--------|--------|
| English | `lib/l10n/app_en.arb` | Complet |
| Romanian | `lib/l10n/app_ro.arb` | Complet |
| German | - | Suportat in LocaleProvider |
| Russian | - | Suportat in LocaleProvider |
| Ukrainian | - | Suportat in LocaleProvider |

### Arhitectura
```
lib/
├── main.dart            Entry point, single instance check, provider setup
├── models/              3 fisiere - Email, EmailAccount, EmailAttachment, models.dart (barrel)
├── services/            21 servicii (mail, account, mtls, certificate, platform, etc.)
├── providers/           3 providers - email_provider, theme_provider, locale_provider
├── views/               12 views (main, compose, viewer, dialogs, etc.)
├── l10n/                Fisiere localizare (.arb)
├── generated/           Cod generat automat (localizari)
└── utils/               (gol - rezervat)
```

### Servicii (lib/services/) - 21 fisiere
| Serviciu | Fisier | Scop |
|----------|--------|------|
| MailService | `mail_service.dart` | Operatii IMAP/SMTP (fetch, send, delete, move, quota) |
| AccountService | `account_service.dart` | Management conturi cu password storage securizat |
| MtlsService | `mtls_service.dart` | Mutual TLS - SecurityContext cu certificat per-user |
| CertificateService | `certificate_service.dart` | Download certificat unic per-user de pe server |
| CertificateExpiryMonitor | `certificate_expiry_monitor.dart` | Monitorizare expirare certificat |
| NotificationService | `notification_service.dart` | Notificari cross-platform (system + in-app) |
| ThreatIntelligenceService | `threat_intelligence_service.dart` | Analiza amenintari email (DKIM, SPF, blacklists) |
| ServerHealthService | `server_health_service.dart` | Verificari DNS, SPF, DKIM, IP blacklists |
| MasterPasswordService | `master_password_service.dart` | Autentificare master password (SHA-256, salted, 100K iterations) |
| PlatformService | `platform_service.dart` | Abstractie cross-platform (cai, OS info) |
| UpdateService | `update_service.dart` | Auto-update (Windows: silent install, Mobile: browser) |
| LoggerService | `logger_service.dart` | Logging in-memory (max 1000 entries) |
| LogUploadService | `log_upload_service.dart` | Upload diagnostic logs pe server (15 min interval) |
| SettingsService | `settings_service.dart` | Persistare preferinte (settings.json) |
| EmailHistoryService | `email_history_service.dart` | Auto-complete destinatari (email_history.json) |
| TrashTrackerService | `trash_tracker_service.dart` | Countdown 30 zile auto-delete Trash |
| ChangelogService | `changelog_service.dart` | Fetch changelog de pe server |
| ConnectionMonitor | `connection_monitor.dart` | Verificare conectivitate porturi mail server |
| PerformanceMonitor | `performance_monitor.dart` | CPU/RAM usage monitoring |
| LocalizationService | `localization_service.dart` | Acces localizari din servicii (fara BuildContext) |
| Services barrel | `services.dart` | Re-export toate serviciile |

### Views (lib/views/) - 12 fisiere
| View | Fisier | Scop |
|------|--------|------|
| MainWindow | `main_window.dart` | UI principal - sidebar conturi, lista email, navigatie |
| ComposeWindow | `compose_window.dart` | Compunere email cu atasamente, CC/BCC, auto-save draft |
| EmailViewer | `email_viewer.dart` | Vizualizare email cu reply, forward, print, threat level |
| AuthWrapper | `auth_wrapper.dart` | Gate autentificare (first-run consent + master password) |
| AddAccountDialog | `add_account_dialog.dart` | Adaugare cont email (server/porturi locked) |
| AttachmentViewerWindow | `attachment_viewer_window.dart` | Viewer PDF/imagini nativ cu zoom, print, download |
| MasterPasswordDialog | `master_password_dialog.dart` | Setup/login master password + factory reset |
| LogViewerWindow | `log_viewer_window.dart` | Vizualizare loguri color-coded |
| ChangelogWindow | `changelog_window.dart` | Release notes (fetch server, fallback local) |
| DnsDetailsWindow | `dns_details_window.dart` | Detalii DNS records (SPF/DKIM) |
| BlacklistDetailsWindow | `blacklist_details_window.dart` | Status IP blacklists |
| FirstRunConsentDialog | `first_run_consent_dialog.dart` | Consent dialog (auto-update, logging, notifications) |

### Models (lib/models/) - 3 fisiere
| Model | Fisier | Proprietati cheie |
|-------|--------|-------------------|
| Email | `email.dart` | messageId, from, to, cc, subject, date, body, threatLevel, threatScore, threatDetails, attachments, headers, isRead, uid |
| EmailAttachment | `email.dart` | fileName, size, contentType, data (Uint8List) |
| EmailAccount | `email_account.dart` | username, mailServer, imapPort, smtpPort, useSsl, folders, folderCounts, password, connectionStatus, connectionError, quotaUsedKB, quotaLimitKB, quotaPercentage, lastFolder, isActive, inboxCount |
| AccountConnectionStatus | `email_account.dart` | enum: unknown, connected, authError, networkError |

### Providers (lib/providers/)
| Provider | Fisier | Scop |
|----------|--------|------|
| EmailProvider | `email_provider.dart` | State central: conturi, emailuri, folder curent, server health, refresh timers |
| ThemeProvider | `theme_provider.dart` | Dark/light mode cu persistare in settings.json |
| LocaleProvider | `locale_provider.dart` | Selectie limba cu detectie automata sistem |

### PlatformService (Cross-Platform Abstraction)
Serviciu central pentru operatii specifice platformei:
- `appDataPath` - Director date aplicatie
- `downloadsPath` - Director Downloads utilizator
- `computerName` - Nume calculator
- `username` - Nume utilizator OS
- `isDesktop` / `isMobile` - Detectare tip platforma
- `platformName` - Nume platforma pentru logging

**Cai Platform-Specifice:**
| Platforma | App Data Path |
|-----------|---------------|
| macOS | `~/Library/Application Support/ICD360S Mail Client` |
| Windows | `%APPDATA%\ICD360S Mail Client` |
| Linux | `~/.local/share/ICD360S Mail Client` |
| Android | App-specific internal storage (via path_provider) |
| iOS | App-specific Documents directory (via path_provider) |

### enough_mail_fork (Local Fork)
- **Locatie:** `./enough_mail_fork/` (163 fisiere Dart)
- **Baza:** enough_mail library (IMAP/SMTP/POP3/MIME)
- **Modificari:** Suport mTLS, porturi custom
- **Dependinte proprii:** trebuie rulat `flutter pub get` separat

### Securitate
- **EXCLUSIVE ACCESS:** Doar aplicatia ICD360S se poate conecta
- **mTLS Enforced:** Client certificate authentication obligatorie
- **Server Whitelist:** DOAR mail.icd360s.de (validare in MailService + EmailAccount)
- **Per-User Certificates:** Certificat UNIC per user, downloadat la login, stocat doar in memorie
- **Certificate Validity:** 90 zile (auto-renewal la < 30 zile via API)
- **Master Password:** SHA-256 salted hash (100K iterations), rate limited
- **Passwords:** Criptate cu Keychain (macOS/iOS) / Credential Manager (Windows) / EncryptedSharedPreferences (Android)
- **Auto-Lock:** Dupa 15 minute inactivitate
- **Single Instance:** Lock file cu TTL 5 secunde (doar desktop)
- **Update Integrity:** SHA-256 hash obligatoriu pentru auto-update

### Keyboard Shortcuts
| Shortcut (macOS) | Shortcut (Windows) | Actiune |
|------------------|-------------------|---------|
| Delete / Backspace | Delete | Sterge email |
| Cmd+N | Ctrl+N | Compose |
| Cmd+R | F5 / Ctrl+R | Refresh |

### Auto-Update
- **Check interval:** La pornire + la fiecare 5 minute
- **URL:** `https://mail.icd360s.de/updates/version.json`
- **Windows:** Download + silent install Inno Setup + auto-restart
- **Android/iOS:** Deschide URL download in browser
- **macOS:** Download + DMG install
- **Integrity:** SHA-256 hash verification obligatoriu

### Timers (MainWindow)
| Timer | Interval | Scop |
|-------|----------|------|
| Server health check | 1 ora | SPF/DKIM/IP blacklists |
| Performance monitor | 10 secunde | CPU/RAM usage |
| Email check | 60 secunde | Verificare emailuri noi in INBOX |
| Update check | 5 minute | Verificare versiune noua |
| Auto-lock | 15 minute | Blocare dupa inactivitate |
| Ping (latency) | 10 secunde | Latenta catre mail.icd360s.de |

---

## 3. COMENZI DEVELOPMENT

### Rulare Development
```bash
cd <PROJECT_DIR>
flutter run -d macos
```

### Build Release
```bash
# macOS
flutter build macos --release

# Linux
flutter build linux --release

# Windows
flutter build windows --release

# Android
flutter build apk --release

# iOS
flutter build ios --release
```

---

## 4. RELEASE WORKFLOW

**Urmeaza pasii in ordine!**

### PASUL 0: Verifica versiunea curenta
```bash
grep "version:" pubspec.yaml | head -1
grep "currentVersion" lib/services/update_service.dart
grep "mainWindowVersion" lib/views/main_window.dart
grep "MyAppVersion" windows/installer.iss | head -1
```
Toate 4 trebuie sa aiba ACEEASI versiune.

### PASUL 1: Actualizeaza Changelog in Aplicatie
```dart
// lib/views/changelog_window.dart
// Adauga noua versiune LA INCEPUT
_buildSection(theme, 'Version X.Y.Z - DD Luna YYYY', [
  'Feature noua',
  'Bug fix',
]),
```

**Prefix-uri changelog:** Feature | Bug | Refactor | Security | UI | Performance | Compatibility

### PASUL 2: Actualizeaza Versiunea (4 fisiere!)

**IMPORTANT:** Versiunea TREBUIE sa fie NOUA (mai mare decat cea curenta)!

```yaml
# 1. pubspec.yaml - incrementeaza si BUILD number!
version: X.Y.Z+BUILD
```

```dart
// 2. lib/services/update_service.dart
static const String currentVersion = 'X.Y.Z';
```

```dart
// 3. lib/views/main_window.dart - cauta "mainWindowVersion"
l10n.mainWindowVersion('X.Y.Z'),
```

```pascal
// 4. windows/installer.iss
#define MyAppVersion "X.Y.Z"
```

### PASUL 3: Build Flutter Release
```bash
flutter build apk --release
flutter build macos --release
```

### PASUL 4: Create Installer (optional)
```bash
# macOS DMG
hdiutil create -volname "ICD360S Mail Client" -srcfolder build/macos/Build/Products/Release/icd360s_mail_client.app -ov -format UDZO build/installer/ICD360S_MailClient_vX.Y.Z.dmg
```

### PASUL 5: Upload pe Server
```bash
# Upload binaries pe server (via SCP)
# Update version.json cu SHA-256 hash OBLIGATORIU:
{
  "version": "X.Y.Z",
  "download_url": "https://mail.icd360s.de/updates/ICD360S_MailClient_Setup_vX.Y.Z.exe",
  "download_url_macos": "https://mail.icd360s.de/updates/ICD360S_MailClient_vX.Y.Z.dmg",
  "download_url_android": "https://mail.icd360s.de/updates/ICD360S_MailClient_vX.Y.Z.apk",
  "changelog": "Descriere scurta",
  "sha256": "<SHA256_HASH_OF_BINARY>"
}
```

### PASUL 6: Update changelog.json pe Server
Adauga noua versiune in `/var/www/html/updates/changelog.json` pe server.

### PASUL 7: Actualizeaza CLAUDE.md
- Actualizeaza `Versiune Curenta` la inceputul fisierului
- Adauga noua versiune in tabelul `ISTORIC VERSIUNI`

### Checklist Release
```
[] 0. Verifica versiunea curenta in toate 4 fisierele
[] 1. changelog_window.dart - adauga noua versiune LA INCEPUT
[] 2. pubspec.yaml - version: X.Y.Z+BUILD
[] 3. update_service.dart - currentVersion = 'X.Y.Z'
[] 4. main_window.dart - l10n.mainWindowVersion('X.Y.Z')
[] 5. installer.iss - #define MyAppVersion "X.Y.Z"
[] 6. flutter build (apk/macos/windows)
[] 7. Creeaza DMG/Installer daca e cazul
[] 8. Upload binaries pe server
[] 9. Update version.json (cu SHA-256 hash!)
[] 10. Update changelog.json pe server
[] 11. CLAUDE.md - actualizeaza versiunea si istoricul
```

---

## 5. CONFIGURARI SERVER (Rezumat)

> **NOTA:** Configurarile detaliate ale serverului (porturi interne, cai fisiere config,
> reguli firewall, fail2ban jails, etc.) sunt documentate intern pe server.
> Acest CLAUDE.md contine doar informatii necesare pentru development.

### Componente principale
- **HAProxy** — mTLS enforcement layer (verify required)
- **Dovecot** — IMAP backend (localhost only)
- **Postfix** — SMTP cu dual cert ECDSA+RSA, RBL, HELO required
- **Rspamd** — Anti-spam (Bayesian, fuzzy, phishing, domain blacklists)
- **Nginx** — Serves updates + certificate API (PHP whitelist)
- **fail2ban** — Multiple jails cu incremental banning
- **firewalld** — Rate limiting per service
- **Let's Encrypt** — Auto-renewal cu DANE/TLSA

### Troubleshooting (pe server)
```bash
# Verificare servicii
systemctl status postfix dovecot nginx fail2ban haproxy rspamd

# Mail logs
tail -f /var/log/maillog

# fail2ban — verificare/unban
fail2ban-client status
fail2ban-client set <jail> unbanip <IP>

# Testare IMAP mTLS
openssl s_client -connect mail.icd360s.de:<IMAP_PORT> -cert client-cert.pem -key client-key.pem

# Verificare certificat user
openssl x509 -in /etc/ssl/icd360s-user-certs/<USERNAME>/cert.pem -noout -dates -subject
```

---

## 6. ANDROID CONFIGURATION

### Namespace & Bundle ID
- **Package:** `de.icd360s.mailclient`
- **Java:** VERSION_17
- **Signing:** Via `android/key.properties` + `android/upload-keystore.jks` (gitignored)
- **R8/ProGuard:** Enabled (minify + shrink resources)
- **Security:** `allowBackup=false`, `networkSecurityConfig` cu certificate pinning

### Product Flavors
- `universal` — APK universal
- `fdroid` — F-Droid (.fdroid suffix)
- `googleplay` — Google Play (.gplay suffix)
- `samsung` — Samsung Galaxy Store (.samsung suffix)
- `huawei` — Huawei AppGallery (.huawei suffix)

---

## 7. iOS CONFIGURATION

### Bundle
- **Bundle ID:** `de.icd360s.mailclient`
- **Display Name:** `ICD360S Mail`
- **Platform:** iOS 13.0+

---

## 8. macOS CONFIGURATION

### Build
- **Sandbox:** Currently disabled (ENABLE_APP_SANDBOX = NO) — TODO: enable with proper entitlements

---

## 9. ISTORIC VERSIUNI (Changelog Sumar)

| Versiune | Data | Highlights |
|----------|------|------------|
| 2.20.0 | 7 Apr 2026 | Mass Security Hardening (24 fixes): IMAP injection escape, path traversal sanitize, persisted rate limit + exponential lockout, APK signature verification, RFC 7469 backup pin, iOS NSPinnedDomains, AES-GCM credential storage, factory reset typed confirmation, GPG-signed AppImage, libsecret runtime dep, SHA-pinned actions, VC redist download verified, gitignore expansion, Janus mitigation |
| 2.19.0 | 7 Apr 2026 | CI/CD Security: non-root deploy user, restricted rrsync, pinned SSH host key, production environment with required reviewer, workflow least-privilege permissions |
| 2.18.0 | 6 Apr 2026 | Security Audit Release: certificate API authentication, TLS exact DN validation, mandatory SHA-256 updates, CSPRNG salt, rate limiting, ProGuard/R8, certificate pinning, info disclosure cleanup, CLAUDE.md redacted |
| 2.17.11 | 6 Apr 2026 | Security audit fixes: TLS validation, salt CSPRNG, rate limiting, ProGuard, certificate pinning, info disclosure cleanup |
| 2.17.2 | 4 Apr 2026 | GrapheneOS Fix: locale fallback, l10nOf() helper, CupertinoLocalizations |
| 2.17.1 | 4 Apr 2026 | GrapheneOS Compatibility: Impeller dezactivat (Skia), edge-to-edge display |
| 2.17.0 | 3 Apr 2026 | Security Hardening (25 fix-uri): certificate validation, auto-update SHA-256, master password salted |
| 2.16.1 | 22 Feb 2026 | URL Fix, DSN Delivery Status Notifications |
| 2.16.0 | 18 Feb 2026 | Document Scanner, Cross-Platform support complet |
| 2.15.6 | 1 Feb 2026 | Clean Footer, Server Diagnostics |
| 2.15.5 | 1 Feb 2026 | Server Changelog, VC++ Redistributable |
| 2.15.4 | 1 Feb 2026 | SSL Certificate Fix Windows |
| 2.15.3 | 28 Ian 2026 | RDP Compatibility |
| 2.15.0 | 28 Ian 2026 | PDF Viewer Nativ, Certificate Auto-Download, Multi-Account Fix |
| 2.13.0 | 22 Ian 2026 | Email Auto-Complete, Storage Quota |
| 2.11.0 | 22 Ian 2026 | Certificate Expiry Monitor, Code Cleanup |
| 2.10.0 | 22 Ian 2026 | CRITICAL FIX - Per-User Certificates (eliminata vulnerabilitate CVSS 9.8) |
| 2.9.0 | 22 Ian 2026 | mTLS EXCLUSIVE MODE |
| 2.0.0 | 16 Ian 2026 | Migrare completa C# WPF -> Flutter |

**Changelog complet:** Vezi `lib/views/changelog_window.dart` sau `https://mail.icd360s.de/updates/changelog.json`

---

## 10. TODO / PLANIFICAT

- [ ] Backup automat pe server
- [ ] Email search functionality
- [ ] Calendar integration
- [ ] SELinux Enforcing mode
- [ ] Android/iOS testing si polish
- [ ] Localizare completa German/Russian/Ukrainian (.arb files)
- [ ] Enable macOS App Sandbox cu entitlements corecte
- [x] Adauga autentificare la Certificate API (Dovecot backend, 6 Apr 2026)

---

## SETUP DEVELOPMENT (Prima rulare pe masina noua)

### Cerinte preliminare (macOS)
```bash
brew install cocoapods
```

### 1. Instaleaza dependintele fork-ului enough_mail
```bash
cd enough_mail_fork
flutter pub get
```

### 2. Instaleaza dependintele proiectului principal
```bash
cd <PROJECT_ROOT>
flutter pub get
```

### 3. Verifica ca nu sunt erori
```bash
flutter analyze
```

### 4. Ruleaza aplicatia
```bash
flutter run -d macos       # macOS
flutter run -d <device-id> # Android/iOS
```

**Nota:** Fork-ul `enough_mail_fork` e in `./enough_mail_fork/` (in proiect).

---

## FISIERE IMPORTANTE (Quick Reference)

| Fisier | Scop |
|--------|------|
| `pubspec.yaml` | Dependinte, versiune aplicatie |
| `lib/services/update_service.dart` | `currentVersion` constant |
| `lib/views/main_window.dart` | Versiune afisata in footer |
| `windows/installer.iss` | Versiune installer Windows |
| `android/app/build.gradle.kts` | Configurare build Android |
| `ios/Podfile` | Configurare iOS dependencies |
| `ios/Runner/Info.plist` | Configurare iOS app |
| `enough_mail_fork/` | Fork local enough_mail cu mTLS |
| `assets/logo.png` | Logo aplicatie |

---

## NOTE

- **Aplicatia conecteaza DOAR la mail.icd360s.de** — server whitelist hardcodat
- **Passwords stocate securizat** — Keychain / Credential Manager / EncryptedSharedPreferences
- **Auto-update cu SHA-256 verification** — https://mail.icd360s.de/updates/version.json
- **Certificat per-user:** Downloadat la login, stocat DOAR in memorie, unic per user
- **Certificat validitate:** 90 zile (server auto-renews la < 30 zile remaining)

