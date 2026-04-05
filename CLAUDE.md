# ICD360S Mail Client - Documentatie

**Actualizat:** 5 Aprilie 2026
**Versiune Curenta:** 2.17.9 (Cross-Platform)

---

## 1. SERVER - mail.icd360s.de

### Conexiune
```bash
# Cheia SSH se afla in directorul proiectului
ssh -i /Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter/vps_mail.icd360s.de -p 36000 root@mail.icd360s.de

# Prima conectare pe masina noua - adauga server la known_hosts:
ssh-keyscan -p 36000 mail.icd360s.de >> ~/.ssh/known_hosts
```

### Sistem
- **IP:** 49.13.174.172 (Hetzner Cloud VPS)
- **OS:** AlmaLinux 10.1 (Heliotrope Lion, suport pana 2035)
- **Kernel:** 6.12.0-124.45.1.el10_1.x86_64
- **CPU:** 2 cores
- **RAM:** 3.5 GB | **Swap:** 2 GB (`/swapfile`) | **Disk:** 38 GB

### Versiuni Software
| Software | Versiune |
|----------|----------|
| Postfix | 3.8.5 |
| Dovecot | 2.3.21 |
| HAProxy | 3.0.5 (LTS pana Q2 2029) |
| Nginx | 1.26.3 |
| Rspamd | 3.14.3 |
| fail2ban | 1.1.0 |
| PHP | 8.4.19 (CLI) |
| Valkey | 8.0.7 (Redis fork) |

### Servicii Active
| Serviciu | Port | Status |
|----------|------|--------|
| HAProxy (mTLS Frontend) | 10993 (IMAP), 465 (SMTP) | mTLS STRICT enforcement |
| Dovecot (Backend) | 10994 (localhost only) | Plain IMAP + LMTP |
| Postfix (SMTP) | 25 (primire), 10465 (backend) | Dual cert ECDSA+RSA, RBL (Spamhaus, SpamCop), 50 MB limit |
| Nginx (Updates + Certificate API) | 80, 443 | Activ |
| Rspamd | 11332 (milter), 11333 (fuzzy), 11334 (controller) | Localhost only, inlocuieste SpamAssassin |
| OpenDKIM | 8891 (localhost only) | DKIM signing |
| Unbound (DNS Resolver) | 53 (localhost only) | Local DNS cache/resolver |
| Valkey (Redis fork) | 6379 (localhost only) | Cache pentru Rspamd Bayesian |
| fail2ban | - | Activ (11 jails: sshd, dovecot, postfix-sasl, postfix-ssl, postfix-rbl, postfix-ddos, postfix-nonsmtp, haproxy-mtls, nginx-scanner, nginx-proxy, recidive) |
| firewalld (nftables) | - | Activ, rate limiting SSH + SMTP, ~128 rich rules |
| SSH | 36000 | Port non-standard (portul 22 INCHIS) |

**EXCLUSIVE MODE:** Porturile 993, 587 DISABLED - Thunderbird/Outlook BLOCATI
**HAProxy mTLS:** `verify required` - SSL alert 116 (certificate_required) pentru conexiuni fara certificat client

### SSL Certificate
- **Provider:** Let's Encrypt (auto-renew)
- **ECDSA cert:** `/etc/letsencrypt/live/mail.icd360s.de/` (primary, Key Type: ECDSA)
- **RSA cert:** `/etc/letsencrypt/live/mail.icd360s.de-rsa/` (fallback, Key Type: RSA)
- **Dual cert Postfix:** ECDSA + RSA servite simultan (negociere automata per client)
- **Combined PEMs:** `/etc/postfix/ssl/ecdsa-combined.pem`, `/etc/postfix/ssl/rsa-combined.pem`
- **Renewal hook:** `/etc/letsencrypt/renewal-hooks/deploy/postfix-dual-cert.sh` (regenereaza PEMs + reload Postfix/HAProxy)
- **DANE/TLSA:** `_25._tcp.mail.icd360s.de` TLSA `2 1 1` (pin pe CA, nu pe cert — supravietuieste renewal)
- **DNS provider TLSA:** INWX (ns.inwx.de)

### Certificate API
- **PHP API:** `https://mail.icd360s.de/api/get-certificate.php` - descarca certificat per-user
- **Script generare:** `/root/generate_user_certificate.sh`
- **Validitate certificat:** 90 zile (conform best practices CA/Browser Forum)
- **Auto-renewal:** API regenereaza automat cand < 30 zile ramase
- **Certificate storage:** `/etc/ssl/icd360s-user-certs/<username>/`
- **Web sync:** `/var/www/icd360s-certs/`

---

## 2. APLICATIA FLUTTER

### Locatie Proiect
```
/Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter/
```

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
| flutter_local_notifications | ^18.0.1 | Notificari cross-platform (macOS/Linux/Android/iOS) |
| window_manager | ^0.5.1 | Window control desktop (maximize, minimize) |
| url_launcher | ^6.3.1 | Deschide URL-uri in browser extern |
| file_picker | ^10.3.8 | Selectie fisiere pentru atasamente |
| printing | ^5.13.4 | Dialog nativ de printare |
| pdf | ^3.11.1 | Generare PDF pentru print imagini |
| pdfrx | ^1.0.100 | Viewer PDF nativ (PDFium, functioneaza pe RDP) |
| http | ^1.2.0 | HTTP client pentru Certificate API |
| path_provider | ^2.1.5 | Directoare cross-platform app data |
| crypto | ^3.0.0 | SHA-256 hashing master password |
| intl | 0.20.2 | Formatare data/ora |
| path | ^1.9.0 | Manipulare cai fisiere |
| cunning_document_scanner | ^1.4.0 | Document scanner (auto-crop, edge detection, Android/iOS) |
| cupertino_icons | ^1.0.8 | iOS-style icons |

### Localizare (i18n)
| Limba | Fisier | Status |
|-------|--------|--------|
| English | `lib/l10n/app_en.arb` | Complet |
| Romanian | `lib/l10n/app_ro.arb` | Complet |
| German | - | Suportat in LocaleProvider (fara .arb inca) |
| Russian | - | Suportat in LocaleProvider (fara .arb inca) |
| Ukrainian | - | Suportat in LocaleProvider (fara .arb inca) |

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
| MasterPasswordService | `master_password_service.dart` | Autentificare master password (SHA-256) |
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
| BlacklistDetailsWindow | `blacklist_details_window.dart` | Status IP blacklists (29 IPv4 + 14 IPv6 providers) |
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
- `appDataPath` - Director date aplicatie (settings, cache, certificates)
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
- **Modificari:** Suport mTLS, porturi custom (10993 IMAP, 465 SMTP)
- **Include:** IMAP client, SMTP client, POP3 client, MIME handling, codecs, email server discovery
- **Dependinte proprii:** trebuie rulat `flutter pub get` separat

### Securitate
- **EXCLUSIVE ACCESS:** Port 10993 (IMAP) + 465 (SMTP) - DOAR aplicatia ICD360S
- **mTLS Enforced:** Client certificate authentication obligatorie
- **Server Whitelist:** DOAR mail.icd360s.de (validare in MailService + EmailAccount)
- **Per-User Certificates:** Certificat UNIC per user, downloadat la login, stocat doar in memorie
- **Certificate Validity:** 90 zile (auto-renewal la < 30 zile via PHP API)
- **Thunderbird/Outlook:** BLOCATI (porturile 993, 587 disable pe server)
- **Master Password:** SHA-256 hash, stocat in `.master_password_hash`
- **Passwords:** Criptate cu Keychain (macOS/iOS) / Credential Manager (Windows) / EncryptedSharedPreferences (Android)
- **Fallback Password Storage:** Double base64 cu salt (cand secure storage esueaza)
- **Auto-Lock:** Dupa 15 minute inactivitate
- **Single Instance:** Lock file cu TTL 5 secunde (doar desktop)

### Keyboard Shortcuts
| Shortcut (macOS) | Shortcut (Windows) | Actiune |
|------------------|-------------------|---------|
| Delete / Backspace | Delete | Sterge email |
| Cmd+N | Ctrl+N | Compose |
| Cmd+R | F5 / Ctrl+R | Refresh |

### Auto-Update
- **Check interval:** La pornire + la fiecare 5 minute
- **URL:** `https://mail.icd360s.de/updates/version.json`
- **Windows:** Download + silent install Inno Setup (`/VERYSILENT /SUPPRESSMSGBOXES`) + auto-restart
- **Android/iOS:** Deschide URL download in browser (APK install nativ)
- **macOS:** Download + DMG install

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
cd /Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter run -d macos
```

### Build Release
```bash
# macOS
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter build macos --release
# Output: build/macos/Build/Products/Release/icd360s_mail_client.app

# Linux (pe masina Linux)
flutter build linux --release
# Output: build/linux/x64/release/bundle/

# Windows (pe masina Windows)
flutter build windows --release
# Output: build/windows/x64/runner/Release/icd360s_mail_client.exe

# Android (necesita Android SDK)
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter build apk --release
# Output: build/app/outputs/flutter-apk/app-release.apk

# iOS (necesita macOS + Xcode)
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter build ios --release
# Output: build/ios/iphoneos/Runner.app
```

---

## 4. RELEASE WORKFLOW

**Urmeaza pasii in ordine!**

### PASUL 0: Verifica versiunea curenta
Inainte de orice, verifica ce versiune e acum in aplicatie:
```bash
# Din directorul proiectului Flutter:
cd /Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter

# Verifica versiunea curenta din cele 4 fisiere:
grep "version:" pubspec.yaml | head -1
grep "currentVersion" lib/services/update_service.dart
grep "mainWindowVersion" lib/views/main_window.dart
grep "MyAppVersion" windows/installer.iss | head -1
```
Toate 4 trebuie sa aiba ACEEASI versiune. Daca nu, corecteaza mai intai.

### PASUL 1: Actualizeaza Changelog in Aplicatie
```dart
// lib/views/changelog_window.dart
// Adauga noua versiune LA INCEPUT (inainte de versiunile existente)
// Versiunea anterioara devine non-NEW (scoate emoji-ul 🆕)

_buildSection(theme, '🆕 Version X.Y.Z - DD Luna YYYY', [
  'Feature noua',
  'Bug fix',
]),
const SizedBox(height: 16),
_buildSection(theme, 'Version VECHE...', [  // <- scoate 🆕 de la versiunea anterioara
```

**Prefix-uri changelog:** Feature | Bug | Refactor | Security | UI | Performance | Compatibility

### PASUL 2: Actualizeaza Versiunea (4 fisiere!)

**IMPORTANT:** Versiunea TREBUIE sa fie NOUA (mai mare decat cea curenta)! Daca versiunea curenta e 2.16.1, urmatoarea trebuie sa fie cel putin 2.16.2. Auto-update compara versiuni - aceeasi versiune = NICIUN update!

```yaml
# 1. pubspec.yaml (linia 5) - incrementeaza si BUILD number!
version: X.Y.Z+BUILD
```

```dart
// 2. lib/services/update_service.dart (linia 12)
static const String currentVersion = 'X.Y.Z';
```

```dart
// 3. lib/views/main_window.dart (~linia 1341) - cauta "mainWindowVersion"
l10n.mainWindowVersion('X.Y.Z'),
```

```pascal
// 4. windows/installer.iss (linia 2)
#define MyAppVersion "X.Y.Z"
```

### PASUL 3: Build Flutter Release
```bash
# APK (Android)
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter build apk --release
# Output: build/app/outputs/flutter-apk/app-release.apk

# macOS
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter build macos --release
# Output: build/macos/Build/Products/Release/icd360s_mail_client.app
```

### PASUL 4: Create Installer (optional)
```bash
# macOS DMG
hdiutil create -volname "ICD360S Mail Client" -srcfolder build/macos/Build/Products/Release/icd360s_mail_client.app -ov -format UDZO build/installer/ICD360S_MailClient_vX.Y.Z.dmg

# Windows: Inno Setup pe masina Windows
# Android: APK-ul e deja gata din PASUL 3
```

### PASUL 5: Upload pe Server
```bash
SSH_KEY="/Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter/vps_mail.icd360s.de"

# Upload APK
scp -i "$SSH_KEY" -P 36000 build/app/outputs/flutter-apk/app-release.apk root@mail.icd360s.de:/var/www/html/updates/ICD360S_MailClient_vX.Y.Z.apk

# Upload DMG (daca ai buildat macOS)
scp -i "$SSH_KEY" -P 36000 build/installer/ICD360S_MailClient_vX.Y.Z.dmg root@mail.icd360s.de:/var/www/html/updates/

# Update version.json (OBLIGATORIU - cu versiunea NOUA!)
ssh -i "$SSH_KEY" -p 36000 root@mail.icd360s.de "cat > /var/www/html/updates/version.json << 'EOF'
{
  \"version\": \"X.Y.Z\",
  \"download_url\": \"https://mail.icd360s.de/updates/ICD360S_MailClient_Setup_vX.Y.Z.exe\",
  \"download_url_macos\": \"https://mail.icd360s.de/updates/ICD360S_MailClient_vX.Y.Z.dmg\",
  \"download_url_android\": \"https://mail.icd360s.de/updates/ICD360S_MailClient_vX.Y.Z.apk\",
  \"changelog\": \"Descriere scurta a versiunii\"
}
EOF"

# Verifica version.json
ssh -i "$SSH_KEY" -p 36000 root@mail.icd360s.de "cat /var/www/html/updates/version.json"
```

### PASUL 6: Update changelog.json pe Server
**IMPORTANT:** changelog.json pe server este SEPARAT de changelog_window.dart! Trebuie actualizat SI PE SERVER!

```bash
# Adauga noua versiune in changelog.json pe server (Python one-liner)
ssh -i "$SSH_KEY" -p 36000 root@mail.icd360s.de "python3 -c \"
import json
with open('/var/www/html/updates/changelog.json', 'r') as f:
    data = json.load(f)
# Scoate emoji NEW de la versiunea veche
if data['versions'] and data['versions'][0]['title'].startswith('\U0001f195'):
    data['versions'][0]['title'] = data['versions'][0]['title'].replace('\U0001f195 ', '')
# Adauga versiunea noua LA INCEPUT
data['versions'].insert(0, {
    'title': '\U0001f195 Version X.Y.Z - DD Mon YYYY',
    'entries': ['Feature 1', 'Feature 2']
})
with open('/var/www/html/updates/changelog.json', 'w') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
print('Done')
\""

# Verifica changelog.json
ssh -i "$SSH_KEY" -p 36000 root@mail.icd360s.de "python3 -c \"
import json
with open('/var/www/html/updates/changelog.json') as f:
    d = json.load(f)
for v in d['versions'][:3]:
    print(v['title'])
\""
```

### PASUL 7: Actualizeaza CLAUDE.md
- Actualizeaza `Versiune Curenta` la inceputul fisierului
- Actualizeaza `Actualizat` data
- Adauga noua versiune in tabelul `ISTORIC VERSIUNI` (sectiunea 8)

### Checklist Release
```
[] 0. Verifica versiunea curenta in toate 4 fisierele
[] 1. changelog_window.dart - adauga noua versiune LA INCEPUT (scoate 🆕 de la cea veche)
[] 2. pubspec.yaml - version: X.Y.Z+BUILD (incrementeaza BUILD number!)
[] 3. update_service.dart - currentVersion = 'X.Y.Z'
[] 4. main_window.dart - l10n.mainWindowVersion('X.Y.Z') (~linia 1341)
[] 5. installer.iss - #define MyAppVersion "X.Y.Z" (doar pentru Windows)
[] 6. flutter build apk --release (si/sau macos/windows)
[] 7. Creeaza DMG (macOS) sau Inno Setup (Windows) daca e cazul
[] 8. scp upload APK/DMG/EXE pe server
[] 9. ssh update version.json pe server (cu TOATE download URLs!)
[] 10. ssh update changelog.json pe server (adauga versiunea noua!)
[] 11. CLAUDE.md - actualizeaza versiunea, data si istoricul
[] 12. Verifica: ssh cat /var/www/html/updates/version.json
[] 13. Verifica: ssh changelog.json are versiunea noua
```

**Working Directory:** `/Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter`
**SSH Key:** `/Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter/vps_mail.icd360s.de`
**Flutter:** `/Users/ionut-claudiuduinea/Development/flutter/bin/flutter`

### RELEASE CU AGENTI PARALELI (Rapid - 2-3 minute)

In loc sa faci fiecare pas secvential, lanseaza agenti in paralel:

**FAZA 1 — Pregatire (paralel):**
- **Agent 1**: Schimba versiunea in cele 4 fisiere (pubspec.yaml, update_service.dart, main_window.dart, installer.iss)
- **Agent 2**: Actualizeaza changelog_window.dart (fallback local)
- **Agent 3**: Actualizeaza CLAUDE.md (versiune, data, istoric)

**FAZA 2 — Build (dupa Faza 1):**
- **Build APK**: `flutter build apk --release`
- **Build macOS** (optional): `flutter build macos --release`

**FAZA 3 — Deploy (paralel, dupa build):**
- **Agent 4**: Upload APK/DMG pe server via scp
- **Agent 5**: Update version.json pe server via ssh
- **Agent 6**: Update changelog.json pe server via ssh

**FAZA 4 — Verificare (paralel):**
- **Agent 7**: Verifica version.json + changelog.json pe server
- **Agent 8**: Verifica versiunea in cele 4 fisiere local

**Timp total:** ~2-3 minute (vs 5-10 minute secvential)

---

## 5. CONTURI EMAIL SERVER

**Total:** 42 conturi email (40 certificate mTLS)

| Email | UID | Status |
|-------|-----|--------|
| icd@icd360s.de | 1000 | Principal |
| vmail@icd360s.de | 5000 | System (fara cert mTLS) |
| inwx@icd360s.de | 5001 | Activ |
| hetzner@icd360s.de | 5002 | Activ |
| mitglied@icd360s.de | 5003 | Activ |
| kundigung@icd360s.de | 5004 | Activ |
| widerrufsrecht@icd360s.de | 5005 | Activ |
| kontakt@icd360s.de | 5006 | Activ |
| datenschutz@icd360s.de | 5009 | Activ |
| paypal@icd360s.de | 5014 | Activ |
| spenden@icd360s.de | 5015 | Activ |
| test1@icd360s.de | 5016 | Test |
| test2@icd360s.de | 5017 | Test |
| in@icd360s.de | 5018 | Activ |
| out@icd360s.de | 5019 | Activ |
| m.c.weber@icd360s.de | 5020 | Activ |
| a.menning@icd360s.de | 5021 | Activ |
| sponsoring@icd360s.de | 5022 | Activ |
| whatsapp@icd360s.de | 5023 | Activ |
| telegram@icd360s.de | 5024 | Activ |
| tiktok@icd360s.de | 5025 | Activ (fara cert mTLS) |
| facebook@icd360s.de | 5026 | Activ |
| finanzamt@icd360s.de | 5027 | Activ |
| notar@icd360s.de | 5028 | Activ |
| vereinregister@icd360s.de | 5029 | Activ |
| claudeai@icd360s.de | 5030 | Test (parola: 12345678901) |
| netflix@icd360s.de | 5031 | Activ |
| dev@icd360s.de | 5032 | Activ |
| test3@icd360s.de | 5033 | Test |
| android@icd360s.de | 5034 | Test (parola: 12345678901) |
| anacrnovsanin@icd360s.de | 5035 | Activ |
| 51060@icd360s.de | 5036 | Activ (cont numeric) |
| 10868@icd360s.de | 5037 | Activ (cont numeric) |
| 36422@icd360s.de | 5038 | Activ (cont numeric, primeste CNP Santander eClaims) |
| deutschepost@icd360s.de | 5039 | Activ |
| reporting@icd360s.de | 5040 | Activ |
| info@icd360s.de | 5041 | Activ |
| jasminaug@icd360s.de | 5042 | Activ (parola: 12345678901) |
| 92179@icd360s.de | 5043 | Activ (cont numeric) |
| github@icd360s.de | 5044 | Activ (parola: 12345678901) |
| microsoft@icd360s.de | 5045 | Activ (parola: 12345678901) |
| 82872@icd360s.de | 5046 | Activ (cont numeric, parola: 12345678901) |

### Adaugare Cont Nou pe Server
```bash
# Conectare SSH
SSH_KEY="/Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter/vps_mail.icd360s.de"
ssh -i "$SSH_KEY" -p 36000 root@mail.icd360s.de

# Creare user
useradd -m -d /home/USER -s /sbin/nologin -u UID USER

# Setare parola
echo "USER:PAROLA" | chpasswd

# Creare Maildir
mkdir -p /home/USER/Maildir/{cur,new,tmp}
chown -R USER:USER /home/USER/Maildir
chmod -R 700 /home/USER/Maildir

# Generare certificat mTLS (90 zile, auto-renewal la < 30 zile)
/root/generate_user_certificate.sh USER

# Sync certificate la web directory
/root/sync_certs_to_www.sh
```

---

## 6. CONFIGURARI SERVER

### Postfix (/etc/postfix/main.cf)
```
myhostname = mail.icd360s.de
mydomain = icd360s.de
home_mailbox = Maildir/
smtpd_tls_security_level = may
smtpd_tls_chain_files = /etc/postfix/ssl/ecdsa-combined.pem, /etc/postfix/ssl/rsa-combined.pem
smtpd_tls_protocols = >=TLSv1
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_CAfile = /etc/ssl/certs/icd360s-client-ca.pem
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_rbl_client zen.spamhaus.org=127.0.0.[2..11], reject_rbl_client bl.spamcop.net, reject_rhsbl_helo dbl.spamhaus.org, reject_rhsbl_sender dbl.spamhaus.org
```

**mTLS Whitelist:** `/etc/postfix/tls_clients`
```
# ICD360S Mail Client fingerprint
58:04:D3:67:92:77:74:D6:80:B3:01:72:BD:2A:36:65:0B:37:A4:24:83:2F:C2:BD:A7:AD:99:99:84:24:CC:7B PERMIT
```

### HAProxy (mTLS Enforcement Layer)
- **Version:** 3.0.5 (long-term support pana Q2 2029)
- **Role:** TRUE mTLS enforcement - respinge conexiuni fara certificat client valid
- **Frontend Ports:** 10993 (IMAP), 465 (SMTP) - `verify required`
- **Backend:** Dovecot localhost:10994, Postfix localhost:10465
- **Certificate:** `/etc/letsencrypt/live/mail.icd360s.de/combined.pem`
- **CA:** `/etc/ssl/certs/icd360s-combined-ca.pem`
- **Blocking:** SSL alert 116 (certificate_required) - respinge instant fara certificat client
- **Logging:** UDP via rsyslog (`log 127.0.0.1:514 local0 info`), log-format cu `%ci` (real client IP)
- **Log file:** `/var/log/haproxy.log` (via rsyslog, works through chroot)

### Dovecot (Backend)
- **Protocol:** IMAP + LMTP (POP3 disabled)
- **Port:** 10994 (localhost only, plain IMAP - HAProxy face SSL termination)
- **Public Ports:** TOATE disabled (993, 143 = 0)
- **Access:** DOAR prin HAProxy (localhost connection)
- **Quota:** 500 MB per cont (global), Trash +100 MB bonus, 10% grace, exceeded message custom
- **Process limits:** `default_process_limit = 1024`, `default_client_limit = 4096`, `service imap { process_limit = 1024 }`
- **Debug:** Dezactivat (`auth_debug = no`, `mail_debug = no`)

### fail2ban (/etc/fail2ban/jail.d/) - 11 jails
**Global config** (`/etc/fail2ban/jail.local`):
- **banaction:** `firewallcmd-rich-rules` (native firewalld, nu iptables)
- **ignoreip:** 127.0.0.1/8, ::1, 10.10.10.0/24, 10.10.20.0/24
- **Incremental banning:** `bantime.increment = true`, exponential formula, `bantime.maxtime = 4w`, `overalljails = true`

**Jails:**
| Jail | maxretry | bantime | Logpath | Ce prinde |
|------|----------|---------|---------|-----------|
| sshd | 3 | 24h | /var/log/secure | Failed SSH logins |
| dovecot | 5 | 24h | systemd journal | Failed IMAP auth |
| postfix-sasl | 5 | 24h | /var/log/maillog | Failed SMTP auth |
| postfix-ssl | 3 | 48h | /var/log/maillog | SSL errors, STARTTLS failures |
| postfix-rbl | 2 | 1w | /var/log/maillog | RBL-listed senders (Spamhaus, SpamCop) |
| postfix-ddos | 3 | 48h | /var/log/maillog | SMTP flood/abuse |
| postfix-nonsmtp | 2 | 1w | /var/log/maillog | HTTP/SOCKS bots on SMTP port |
| haproxy-mtls | 10 | 1w | /var/log/haproxy.log | SSL handshake failures (no cert) |
| nginx-scanner | 2 | 48h | error.log + mail error.log | Web scanners (.env, .git, phpinfo, wp-*) |
| nginx-proxy | 1 | 1w | /var/log/nginx/access.log | CONNECT/SOCKS proxy attempts |
| recidive | 3 (in 48h) | 1w | /var/log/fail2ban.log | Repeat offenders across all jails |

### Nginx (/etc/nginx/conf.d/mail.icd360s.de.conf)
- **Document Root:** `/var/www/html/`
- **Updates:** `/var/www/html/updates/`
- **Certificate API:** `/var/www/html/api/get-certificate.php`
- **Log Upload:** `/var/www/html/logs/upload.php`
- **PHP Whitelist:** DOAR `get-certificate.php` si `upload.php` - toate celelalte `.php` = 404
- **Hidden files:** `/.env`, `/.git`, `/.aws` etc. = 404 (blocheaza scanere)
- **Root page:** `GET /` = 404 (nu exista index page)
- **Catch-all:** `/etc/nginx/conf.d/default.conf` - hostname-uri necunoscute = 444 (drop)
- **Security headers:** HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

### Firewalld (nftables backend)
- **Manager:** firewalld (AlmaLinux 10 default, nftables backend)
- **Zone:** public (default)
- **Services allowed:** http, https, smtp
- **Ports allowed:** 465/tcp (SMTP mTLS), 10993/tcp (IMAP mTLS), 36000/tcp (SSH rate-limited)
- **Rate limiting SSH:** max 5 new connections/min per IP (IPv4 + IPv6)
- **Rate limiting SMTP:** max 10 new connections/min per IP
- **Port 22:** INCHIS (SSH mutat pe 36000)
- **Blocked IPs (manual):** 3.143.33.63, 139.162.186.99, 152.32.192.230, 212.23.222.58, 194.165.16.167, 77.83.39.0/24, 80.94.95.0/24, 165.154.129.188, 178.16.53.160, 91.92.243.144, 78.153.140.148, 3.131.220.121 (reject)
- **Dynamic rules:** ~128 rich rules total (manual + fail2ban dynamic bans)
- **Config:** `firewall-cmd --list-all` pentru status complet

### Rspamd (Anti-Spam - inlocuieste SpamAssassin)
- **Version:** 3.14.3
- **Milter:** localhost:11332 (integrat in Postfix)
- **Controller:** localhost:11334 (web UI, password encrypted cu `rspamadm pw`)
- **Actions:** score >=3 greylist, >=4 add header (X-Spam: Yes), >=8 reject
- **Bayesian classifier:** Redis backend (`/etc/rspamd/local.d/classifier-bayes.conf`), autolearn enabled
- **Redis:** Valkey pe localhost:6379 (`/etc/rspamd/local.d/redis.conf`)
- **Module phishing:** OpenPhish + PhishTank enabled
- **Module fuzzy_check:** rspamd.com fuzzy storage (detectie spam global)
- **Module DKIM/DMARC/ARC:** Verificare autenticitate email
- **Domain blacklist:** `/etc/rspamd/local.d/blacklist_domains.map` (15 domenii scam)
- **Domain whitelist:** `/etc/rspamd/local.d/whitelist_domains.map` (coeo-inkasso.de, coeo-com.cloud.nospamproxy.com)
- **Multimap:** `/etc/rspamd/local.d/multimap.conf` - BLACKLIST_FROM_DOMAIN (score +10) + WHITELIST_FROM_DOMAIN (score -15)
- **Disabled RBLs:** dnswl.org (RCVD_IN_DNSWL_*), mailspike.net, SenderScore (timeout-prone, cauzeaza false greylisting)
- **Disabled modules:** reputation (SenderScore DNS monitoring spam)
- **Additional modules:** url_reputation.conf, replies.conf (reply tracking)
- **Config dir:** `/etc/rspamd/local.d/` (14 config files)
- **Backup SpamAssassin:** `/root/backup-before-rspamd/`

### Postfix Hardening (25 Feb 2026, updated 24 Mar 2026)
- **smtpd_helo_required:** yes
- **HELO restrictions:** reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname
- **Sender restrictions:** reject_non_fqdn_sender, reject_unknown_sender_domain
- **RBL:** Spamhaus ZEN, SpamCop, Spamhaus DBL (domain blacklist)
- **disable_vrfy_command:** yes (ascunde existenta conturilor)
- **reject_unauth_pipelining:** da (anti-spam)
- **message_size_limit:** 50 MB (52428800 bytes, ~37 MB real attachment limit due to base64 overhead)
- **Dual cert:** ECDSA + RSA pe port 25 (`smtpd_tls_chain_files`), negociere automata per client
- **TLS inbound (port 25):** `smtpd_tls_protocols = >=TLSv1` (compatibilitate servere vechi, ex: guvern)
- **TLS mandatory:** `smtpd_tls_mandatory_protocols = >=TLSv1.2`
- **TLS outbound:** `smtp_tls_protocols = >=TLSv1.2`
- **DANE/TLSA:** `2 1 1` (pin pe Let's Encrypt CA intermediaries R12 + E8, supravietuieste cert renewal)
- **Banner:** `$myhostname ESMTP` (ascuns numele software-ului Postfix)

### SSH Hardening (25 Feb 2026)
- **Port:** 36000 (non-standard, portul 22 INCHIS)
- **SELinux:** `semanage port -a -t ssh_port_t -p tcp 36000`
- **PermitRootLogin:** prohibit-password (doar SSH key)
- **PasswordAuthentication:** no
- **Config:** `/etc/ssh/sshd_config` + `/etc/ssh/sshd_config.d/*.conf`

### Rsyslog
- **HAProxy UDP listener:** `module(load="imudp")` + `input(type="imudp" port="514" address="127.0.0.1")`
- **HAProxy log:** `/etc/rsyslog.d/haproxy.conf` → `/var/log/haproxy.log`

### Logrotate
- **Config:** `/etc/logrotate.d/rsyslog` (maillog, messages, secure, cron, spooler)
- **Rotation:** weekly, rotate 4, compress, delaycompress

### Swap
- **File:** `/swapfile` 2 GB (persistent via `/etc/fstab`)

### Certificate PKI (Private)
- **CA Certificate:** `/etc/ssl/certs/icd360s-client-ca.pem`
- **User Certificates:** `/etc/ssl/icd360s-user-certs/<username>/cert.pem`
- **User Keys:** `/etc/ssl/icd360s-user-certs/<username>/key.pem`
- **Validitate:** 90 zile (regenerare automata la < 30 zile)
- **Script generare:** `/root/generate_user_certificate.sh`
- **Script sync:** `/root/sync_certs_to_www.sh`
- **PHP API:** `/var/www/html/api/get-certificate.php`
- **Python API (backup):** `/root/cert_api.py`

---

## 6b. FISIERE CONFIGURARE SERVER (Referinta Rapida)

| Fisier | Scop |
|--------|------|
| `/etc/postfix/main.cf` | Configurare Postfix principala |
| `/etc/postfix/ssl/ecdsa-combined.pem` | ECDSA key+chain combinat pentru Postfix |
| `/etc/postfix/ssl/rsa-combined.pem` | RSA key+chain combinat pentru Postfix |
| `/etc/letsencrypt/live/mail.icd360s.de/` | Certificat ECDSA (Let's Encrypt E8) |
| `/etc/letsencrypt/live/mail.icd360s.de-rsa/` | Certificat RSA (Let's Encrypt R12) |
| `/etc/letsencrypt/renewal-hooks/deploy/postfix-dual-cert.sh` | Hook auto-regenerare PEMs la renewal |
| `/etc/rspamd/local.d/redis.conf` | Rspamd Redis connection (Valkey 127.0.0.1:6379) |
| `/etc/rspamd/local.d/classifier-bayes.conf` | Rspamd Bayesian learning config |
| `/etc/rspamd/local.d/blacklist_domains.map` | Domenii spam blocate (15 domenii) |
| `/etc/rspamd/local.d/whitelist_domains.map` | Domenii whitelisted (coeo-inkasso.de) |
| `/etc/rspamd/local.d/multimap.conf` | Blacklist (+10) si whitelist (-15) rules |
| `/etc/rspamd/local.d/worker-controller.inc` | Rspamd controller (password encrypted) |
| `/etc/rspamd/local.d/rbl.conf` | RBL-uri dezactivate (SenderScore, dnswl, mailspike) |
| `/etc/rspamd/local.d/reputation.conf` | Modul reputation dezactivat |
| `/etc/rspamd/local.d/url_reputation.conf` | URL reputation tracking |
| `/etc/rspamd/local.d/replies.conf` | Reply tracking |
| `/etc/haproxy/haproxy.cfg` | HAProxy mTLS config |
| `/etc/nginx/conf.d/mail.icd360s.de.conf` | Nginx mail vhost (PHP whitelist) |
| `/etc/nginx/conf.d/default.conf` | Nginx catch-all (444 drop) |

---

## 7. TROUBLESHOOTING

### IP Blocat de fail2ban
```bash
# Verifica IP-uri banate
fail2ban-client status dovecot

# Unban IP
fail2ban-client set dovecot unbanip IP_ADDRESS
```

### Verificare Servicii
```bash
systemctl status postfix dovecot nginx fail2ban haproxy rspamd
```

### Verificare Logs
```bash
# Mail logs
tail -f /var/log/maillog

# fail2ban logs
tail -f /var/log/fail2ban.log

# HAProxy logs
tail -f /var/log/haproxy.log

# Rspamd logs
tail -f /var/log/rspamd/rspamd.log

# Firewall status
firewall-cmd --list-all

# fail2ban - toate jailurile (11 total)
fail2ban-client status
fail2ban-client status sshd
fail2ban-client status dovecot
fail2ban-client status postfix-sasl
fail2ban-client status postfix-ssl
fail2ban-client status postfix-rbl
fail2ban-client status postfix-ddos
fail2ban-client status postfix-nonsmtp
fail2ban-client status haproxy-mtls
fail2ban-client status nginx-scanner
fail2ban-client status nginx-proxy
fail2ban-client status recidive
```

### Testare Conexiune IMAP (mTLS)
```bash
# Port 10993 cu certificat client (portul 993 este DISABLED!)
openssl s_client -connect mail.icd360s.de:10993 -cert client-cert.pem -key client-key.pem
```

### Verificare Certificat User
```bash
# Pe server:
openssl x509 -in /etc/ssl/icd360s-user-certs/USERNAME/cert.pem -noout -dates -subject
```

### Verificare DANE/TLSA
```bash
# Verifica TLSA records
dig _25._tcp.mail.icd360s.de TLSA +short

# Verifica fingerprint certificat actual vs TLSA
# ECDSA:
openssl x509 -in /etc/letsencrypt/live/mail.icd360s.de/chain.pem -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex
# RSA:
openssl x509 -in /etc/letsencrypt/live/mail.icd360s.de-rsa/chain.pem -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex
```
**IMPORTANT:** TLSA records sunt tip `2 1 1` (pin pe CA intermediate). NU trebuie actualizate la reinnoire cert — doar daca Let's Encrypt schimba CA intermediary.

### Verificare Dual Certificate
```bash
# Test ECDSA (default):
echo "QUIT" | openssl s_client -connect 127.0.0.1:25 -starttls smtp 2>&1 | grep "server-signature"
# Test RSA fallback:
echo "QUIT" | openssl s_client -connect 127.0.0.1:25 -starttls smtp -sigalgs RSA-PSS+SHA256 2>&1 | grep "server-signature"
```

---

## 8. ISTORIC VERSIUNI (Changelog Sumar)

| Versiune | Data | Highlights |
|----------|------|------------|
| 2.17.9 | 5 Apr 2026 | Android FAB compose button (+ jos-dreapta), compose mutat din titleBar pe mobil |
| 2.17.8 | 5 Apr 2026 | Android UI hamburger menu, GDPR consent opt-in, permisiuni native notificari, dialog actualizare Android, release cu agenti paraleli |
| 2.17.7 | 5 Apr 2026 | Android UI: hamburger menu button vizibil pe mobil, sidebar toggle expand/compact, GDPR consent opt-in, permisiuni native notificari (Android 13+/iOS/macOS), dialog actualizare pe Android |
| 2.17.2 | 4 Apr 2026 | GrapheneOS Fix: locale fallback (AppLocalizations null = ecran gri), l10nOf() helper in 12 views, CupertinoLocalizations, Process.runSync blocat pe Android, ErrorWidget.builder, scanner doar iOS |
| 2.17.1 | 4 Apr 2026 | GrapheneOS Compatibility: Impeller dezactivat (Skia), edge-to-edge display, APK signing v2+v3, R8 minify dezactivat |
| 2.17.0 | 3 Apr 2026 | Security Hardening (25 fix-uri): certificate validation MITM prevention, auto-update SHA-256 hash, master password salted 100K iterations, IMAP/SMTP connection leak fix, Process.runSync→async, fetchEmails concurrency guard, settings.json write lock, .gitignore secrets |
| 2.16.1 | 22 Feb 2026 | URL Fix (link-uri lungi nu se mai rup - 8bit encoding + rejoin broken URLs), DSN Delivery Status Notifications (RFC 3461) |
| 2.16.0 | 18 Feb 2026 | Document Scanner (auto-crop, edge detection, perspective correction pe Android/iOS), Cross-Platform support complet |
| 2.15.6 | 1 Feb 2026 | Clean Footer (eliminat CPU/RAM/Ports/SPF/DKIM/IPv4/IPv6 din footer), Server Diagnostics (verificari conectivitate trimise in log spre server) |
| 2.15.5 | 1 Feb 2026 | Server Changelog (changelog se incarca de pe server, actualizari fara rebuild), VC++ Redistributable inclus in installer (instalare automata) |
| 2.15.4 | 1 Feb 2026 | SSL Certificate Fix - Rezolvat CERTIFICATE_VERIFY_FAILED pe anumite masini Windows (Flutter certificate store issue), VM Compatibility |
| 2.15.3 | 28 Ian 2026 | RDP Compatibility - Eliminat WebView (crash pe RDP), External Browser, HTML to Text conversion |
| 2.15.2 | 28 Ian 2026 | False Notifications Fix - cache per-cont pentru notificari email |
| 2.15.1 | 28 Ian 2026 | Log Upload UTF-8 Fix (caractere Unicode), Dynamic Version (nu mai e hardcoded) |
| 2.15.0 | 28 Ian 2026 | PDF Viewer Nativ (PDFium integrat, functioneaza pe RDP), Certificate Auto-Download la adaugare cont, Multi-Account Certificate Fix |
| 2.13.0 | 22 Ian 2026 | Email Auto-Complete (TO field suggestions dupa 3 litere), Storage Quota 100MB per cont, Quota Indicator vizual (cerc colorat: Verde/Albastru/Galben/Rosu) |
| 2.11.0 | 22 Ian 2026 | Certificate Expiry Monitor, Code Cleanup (zero warnings), Batch generation 25 users, Server hardening (email users /sbin/nologin, 813 IPs banned), Production stability |
| 2.10.0 | 22 Ian 2026 | CRITICAL FIX - Per-User Certificates (eliminata vulnerabilitate CVSS 9.8 extragere cert din .exe), certificat UNIC per user downloadat la login, ZERO hardcoding |
| 2.9.0 | 22 Ian 2026 | mTLS EXCLUSIVE MODE - Port 10993 IMAP + 465 SMTP (Thunderbird/Outlook BLOCATI), client cert obligatoriu, AUTO-MIGRATION 993->10993 + 587->465 |
| 2.8.4 | 22 Ian 2026 | CC Vizibil la Primire - vezi CC cand primesti email, TO complet |
| 2.8.3 | 22 Ian 2026 | CC/BCC Support - trimite copie (CC) si copie ascunsa (BCC), explicatii campuri |
| 2.8.2 | 22 Ian 2026 | Multiple Recipients - trimite email la max 25 destinatari simultan |
| 2.8.1 | 21 Ian 2026 | Dependencies Update - 24 packages actualizate (fluent_ui 4.13, flutter_secure_storage 10.0) |
| 2.8.0 | 21 Ian 2026 | HTML Email Rendering cu WebView2, auto-detect HTML vs plain text |
| 2.7.9 | 21 Ian 2026 | Clickable Links in email body, deschide in browser integrat |
| 2.7.8 | 21 Ian 2026 | Trash Auto-Delete (30 zile), Countdown indicator, Log auto-scroll |
| 2.7.7 | 21 Ian 2026 | Sidebar fix - numele conturilor apare corect |
| 2.7.6 | 21 Ian 2026 | Account Connection Status (verde/rosu/portocaliu in sidebar) |
| 2.7.5 | 21 Ian 2026 | Background update check la fiecare 5 minute |
| 2.7.4 | 21 Ian 2026 | Footer version fix |
| 2.7.3 | 21 Ian 2026 | Auto-update silentios cu progress, auto-restart |
| 2.7.2 | 21 Ian 2026 | Add Account UX simplificat (@icd360s.de default), Auth fix |
| 2.7.1 | 21 Ian 2026 | Stabilitate, bug fixes |
| 2.7.0 | 17 Ian 2026 | Windows Credential Manager, Print, Factory Reset, Single Instance |
| 2.6.0 | 17 Ian 2026 | Attachments, Windows Notifications, Auto-Lock |
| 2.5.x | 17 Ian 2026 | Log Upload, IPv6 Blacklist, Account fixes |
| 2.4.0 | 17 Ian 2026 | Enhanced Monitoring, DSN Headers |
| 2.3.0 | 17 Ian 2026 | Auto-Update, Integrated Browser, Installer |
| 2.0.0 | 16 Ian 2026 | Migrare completa C# WPF -> Flutter |

**Changelog complet:** Vezi `lib/views/changelog_window.dart` sau `https://mail.icd360s.de/updates/changelog.json`

---

## 9. ANDROID CONFIGURATION

### Namespace & Bundle ID
- **Package:** `de.icd360s.mailclient`
- **Min SDK:** Flutter default
- **Compile SDK:** Flutter default
- **Java:** VERSION_17

### Signing (Release)
- **Keystore:** `android/upload-keystore.jks`
- **Config:** `android/key.properties`
- **DN:** `CN=ICD360S e.V., OU=Development, O=ICD360S e.V., L=Neu-Ulm, ST=Bayern, C=DE`
- **Algorithm:** RSA 2048-bit, validity 10000 days
- **Alias:** `upload`
- **Gradle:** `android/app/build.gradle.kts` (citeste key.properties, configureaza signingConfigs)

### Permisiuni (AndroidManifest.xml)
- `android.permission.INTERNET`

### Core Library Desugaring
- Enabled in build.gradle.kts pentru suport API-uri Java 8+ pe SDK-uri vechi
- Dependency: `com.android.tools:desugar_jdk_libs:2.1.4`

### APK Download
- **URL:** `https://mail.icd360s.de/updates/ICD360S_MailClient_v<VERSION>.apk`
- **QR Code:** `build/app/outputs/flutter-apk/ICD360S_MailClient_QR.png`

---

## 10. iOS CONFIGURATION

### Bundle
- **Bundle ID:** `de.icd360s.mailclient` (setat in Xcode project)
- **Display Name:** `ICD360S Mail` (Info.plist)
- **Platform:** iOS 13.0+ (Podfile)

### Code Signing
- **Team ID:** B42ZX94AKL
- **Apple ID:** icd360s@icloud.com

### Orientations
- Portrait, Landscape Left, Landscape Right (iPhone)
- Toate 4 orientarile (iPad)

---

## 11. macOS CONFIGURATION

### Code Signing
- **Apple ID:** icd360s@icloud.com
- **Team ID:** B42ZX94AKL
- **Certificate:** Apple Development: icd360s@icloud.com (5NQX7V2JQ3)
- **Sandbox:** Dezactivat (ENABLE_APP_SANDBOX = NO) pentru Keychain access fara restrictii

---

## 12. TODO / PLANIFICAT

- [x] **mTLS Implementation** - COMPLET (22 Ian 2026) - HAProxy port 10993 IMAP + 465 SMTP cu verify required
- [x] **Security Hardening** - COMPLET (22 Ian 2026) - Email users /sbin/nologin, firewall cleanup, 813 IPs banned
- [x] **Cross-Platform Support** - COMPLET (5 Feb 2026) - macOS, Linux, Android, iOS support via PlatformService
- [x] **Certificate Rotation 90 zile** - COMPLET (14 Feb 2026) - Toate 33 certificate regenerate cu 90 zile validitate
- [x] **Android APK Signing** - COMPLET (14 Feb 2026) - Keystore generat, APK semnat si uploadat pe server
- [x] **Auto-Update Mobile** - COMPLET (14 Feb 2026) - Deschide URL in browser pentru APK install
- [x] **Rspamd (Anti-Spam)** - COMPLET (25 Feb 2026) - Inlocuit SpamAssassin, fuzzy hashing, phishing detection, domain blacklist
- [x] **Firewall Hardening** - COMPLET (25 Feb 2026) - firewalld cu rate limiting SSH (5/min) + SMTP (10/min), port 22 inchis
- [x] **Postfix Hardening** - COMPLET (25 Feb 2026) - RBL (Spamhaus, SpamCop), HELO required, reject non-FQDN
- [x] **SSH Port Change** - COMPLET (25 Feb 2026) - Port 22 -> 36000, SELinux configured
- [x] **fail2ban Recidive** - COMPLET (25 Feb 2026) - 4 jails, maxretry=5, recidive ban 1 week for repeat offenders
- [x] **fail2ban Comprehensive** - COMPLET (14 Mar 2026) - 11 jails total, incremental banning, firewallcmd-rich-rules, overalljails
- [x] **HAProxy Logging** - COMPLET (14 Mar 2026) - UDP logging cu real client IP (%ci), rsyslog, works through chroot
- [x] **Nginx Hardening** - COMPLET (14 Mar 2026) - PHP whitelist, hidden files blocked, catch-all 444, security headers
- [x] **Dovecot Tuning** - COMPLET (14 Mar 2026, updated 24 Mar) - process_limit 1024, client_limit 4096, protocols imap+lmtp, debug disabled
- [x] **Postfix TLS Hardening** - COMPLET (14 Mar 2026) - Minimum TLSv1.2, banner ascuns
- [x] **Rspamd Cleanup** - COMPLET (14 Mar 2026) - Disabled SenderScore, dnswl.org, mailspike.net (false greylisting)
- [x] **Swap** - COMPLET (14 Mar 2026) - 2 GB swap file creat (/swapfile)
- [x] **Log Compression** - COMPLET (14 Mar 2026) - logrotate cu compress + delaycompress (529MB -> 34MB)
- [x] **Rspamd Bayesian + Redis** - COMPLET (15 Mar 2026) - Spam learning functional cu Valkey/Redis backend, autolearn enabled
- [x] **Dual Certificate ECDSA+RSA** - COMPLET (15 Mar 2026) - Postfix serveste ECDSA (modern) si RSA (legacy) simultan, certbot renewal hook automat
- [x] **DANE/TLSA Fix** - COMPLET (15 Mar 2026) - Migrat de la `3 1 1` (pin cert) la `2 1 1` (pin CA) — supravietuieste cert renewal fara update DNS
- [x] **Rspamd Security** - COMPLET (15 Mar 2026) - Controller password encrypted, businessworking.com.br adaugat in blacklist
- [x] **Rspamd Whitelist** - COMPLET (22 Mar 2026) - coeo-inkasso.de whitelisted (multimap score -15), whitelist_domains.map creat
- [x] **Postfix 50MB Limit** - COMPLET (22 Mar 2026) - message_size_limit crescut de la 25MB la 50MB pentru trimiteri interne
- [x] **New Accounts** - COMPLET (22 Mar 2026, updated 3 Apr 2026) - reporting (5040), info (5041), jasminaug (5042), 92179 (5043) create cu mTLS
- [x] **DNS Retry Fix** - COMPLET (24 Mar 2026) - CertificateService retry cu network detection, abort cycle cand DNS e down
- [x] **Security Hardening v2.17.0** - COMPLET (3 Apr 2026) - 25 fix-uri: certificate validation MITM, auto-update SHA-256, master password salted, IMAP/SMTP leak fix, Process.run async, fetchEmails guard, settings write lock, .gitignore secrets
- [ ] Backup automat pe server
- [ ] Email search functionality
- [ ] Calendar integration
- [ ] SELinux Enforcing mode (requires policy tuning)
- [ ] Android/iOS testing si polish
- [ ] Localizare completa German/Russian/Ukrainian (.arb files)

---

## NOTE

- **Aplicatia conecteaza DOAR la mail.icd360s.de** - server whitelist hardcodat in MailService + EmailAccount
- **Passwords stocate in Keychain (macOS/iOS) / Credential Manager (Windows) / EncryptedSharedPreferences (Android)** - nu in plain text
- **Auto-update verifica la pornire + la fiecare 5 minute** - https://mail.icd360s.de/updates/version.json
- **Certificat per-user:** Downloadat la login, stocat DOAR in memorie (nu pe disk), unic per user
- **Certificat validitate:** 90 zile (server auto-renews la < 30 zile remaining)
- **Development OS:** macOS 26.2 (Darwin 25.2.0)

---

## DEVELOPMENT TOOLS (Cai importante - macOS)

| Tool | Cale |
|------|------|
| **Flutter** | `/Users/ionut-claudiuduinea/Development/flutter/bin/flutter` |
| **CocoaPods (pod)** | `/opt/homebrew/bin/pod` |
| **Homebrew** | `/opt/homebrew/bin` |
| **Android SDK** | `/Users/ionut-claudiuduinea/Library/Android/sdk` |
| **Android Studio JDK** | `/Applications/Android Studio.app/Contents/jbr/Contents/Home` |
| **apksigner** | `/Users/ionut-claudiuduinea/Library/Android/sdk/build-tools/36.1.0/apksigner` |
| **keytool** | `/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/keytool` |

**IMPORTANT pentru build:** Trebuie adaugat Homebrew in PATH:
```bash
export PATH="/opt/homebrew/bin:$PATH"
```

**IMPORTANT pentru Android tools:** Trebuie setat JAVA_HOME:
```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
```

---

## SETUP DEVELOPMENT (Prima rulare pe masina noua)

### Cerinte preliminare (macOS)
```bash
# Instaleaza CocoaPods (necesar pentru macOS/iOS builds)
brew install cocoapods
```

### 1. Instaleaza dependintele fork-ului enough_mail
```bash
cd /Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter/enough_mail_fork
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter pub get
```

### 2. Instaleaza dependintele proiectului principal
```bash
cd /Users/ionut-claudiuduinea/Documents/mail-client/ICD360S.MailClient.Flutter
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter pub get
```

### 3. Verifica ca nu sunt erori
```bash
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter analyze
```

### 4. Ruleaza aplicatia
```bash
# macOS
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter run -d macos

# Android (device conectat sau emulator)
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter run -d <device-id>

# iOS (device conectat sau simulator)
/Users/ionut-claudiuduinea/Development/flutter/bin/flutter run -d <iphone-id>

# sau deschide app-ul deja compilat
open build/macos/Build/Products/Debug/icd360s_mail_client.app
```

**Nota:** Fork-ul `enough_mail_fork` e in `./enough_mail_fork` (in proiect), NU in directorul parinte.

---

## FISIERE IMPORTANTE (Quick Reference)

| Fisier | Scop |
|--------|------|
| `pubspec.yaml` | Dependinte, versiune aplicatie, `msix_version` (Windows MSIX package) |
| `lib/services/update_service.dart:12` | `currentVersion` constant |
| `lib/views/main_window.dart:1341` | Versiune afisata in footer |
| `windows/installer.iss:2` | Versiune installer Windows |
| `android/key.properties` | Credentiale signing Android |
| `android/upload-keystore.jks` | Keystore signing Android |
| `android/app/build.gradle.kts` | Configurare build Android |
| `ios/Podfile` | Configurare iOS dependencies |
| `ios/Runner/Info.plist` | Configurare iOS app |
| `vps_mail.icd360s.de` | SSH key pentru server |
| `enough_mail_fork/` | Fork local enough_mail cu mTLS |
| `certificates/` | Certificat CA + client (development) |
| `assets/logo.png` | Logo aplicatie |
| `changelog.json` | Changelog data |
