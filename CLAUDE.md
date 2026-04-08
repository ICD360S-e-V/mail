# ICD360S Mail Client - Documentatie

**Actualizat:** 7 Aprilie 2026
**Versiune Curenta:** 2.20.4 (Cross-Platform)

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

**Urmeaza pasii in ordine. NU sari peste niciunul.**

### Pre-flight checks (ÎNAINTE de a începe)

```bash
# 1. Asigura-te ca esti pe main si totul este sincronizat
git status                    # working tree clean
git pull origin main          # latest

# 2. Verifica ca nu exista build-uri esuate recente pe main
gh api repos/ICD360S-e-V/mail/actions/runs?branch=main\&per_page=1 --jq '.workflow_runs[0] | {status, conclusion}'

# 3. Asigura-te ca cineva poate aproba environment-ul production
#    (tu sau review-er-ul listed in Settings > Environments > production)

# 4. Verifica versiunea ULTIMA deploy-ata pe server
curl -sf https://mail.icd360s.de/updates/version.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'
```

### PASUL 0: Verifica versiunea curenta in repo
```bash
grep "version:" pubspec.yaml | head -1
grep "currentVersion" lib/services/update_service.dart
grep "mainWindowVersion" lib/views/main_window.dart
grep "MyAppVersion" windows/installer.iss | head -1
```
Toate 4 trebuie sa aiba ACEEASI versiune. Daca nu, sincronizeaza-le inainte.

### PASUL 1: Decide noua versiune (semver)

| Schimbare | Bump |
|-----------|------|
| Bug fix sau security patch | PATCH (X.Y.**Z+1**) |
| Feature nou backwards-compatible | MINOR (X.**Y+1**.0) |
| Breaking change | MAJOR (**X+1**.0.0) |

Exemplu: 2.20.3 → 2.20.4 (bug fix)

### PASUL 2: Bump versiune in 4 fisiere

**IMPORTANT:** Versiunea TREBUIE sa fie NOUA (mai mare). Build-number+1 in pubspec.yaml.

```yaml
# 1. pubspec.yaml
version: X.Y.Z+BUILD
```
```dart
// 2. lib/services/update_service.dart
static const String currentVersion = 'X.Y.Z';
```
```dart
// 3. lib/views/main_window.dart (~linia 1362, cauta "mainWindowVersion")
l10n.mainWindowVersion('X.Y.Z'),
```
```pascal
// 4. windows/installer.iss
#define MyAppVersion "X.Y.Z"
```

### PASUL 3: Adauga entry in changelog_window.dart

```dart
// lib/views/changelog_window.dart
// Adauga LA INCEPUT (cu emoji NEW), scoate emoji-ul de la versiunea anterioara
_buildSection(theme, '🆕 Version X.Y.Z - DD MMM YYYY', [
  'Bug fix - ...',
  'Security - ...',
]),
const SizedBox(height: 16),
_buildSection(theme, 'Version X.Y.Z-1 - DD MMM YYYY', [  // <- scoate 🆕
  ...
]),
```

**Prefix-uri:** Feature | Bug fix | Security | Refactor | UI | Performance | Compatibility

### PASUL 4: Update CLAUDE.md
- Schimba `**Versiune Curenta:** X.Y.Z` la inceputul fisierului
- Adauga rand nou in tabelul `## 9. ISTORIC VERSIUNI` (insert LA INCEPUT, dupa header)

### PASUL 5: Commit + Push toate modificarile
```bash
git add pubspec.yaml \
        lib/services/update_service.dart \
        lib/views/main_window.dart \
        lib/views/changelog_window.dart \
        windows/installer.iss \
        CLAUDE.md
git commit -m "release(X.Y.Z): bump version + changelog"
git push origin main
```

### PASUL 6: Creeaza tag-ul (declanseaza CI/CD automat)

**CRITICAL:** Tag-ul TREBUIE creat DUPA push, altfel CI/CD construieste o versiune fara modificari.

```bash
# Verifica ca commit-ul tau e ultimul pe main
git log -1 --oneline

# Creeaza tag-ul si push
git tag vX.Y.Z
git push origin vX.Y.Z
```

Asta declanseaza `.github/workflows/build-all-platforms.yml` care:
1. Build complet pe toate platformele (Linux, Windows, macOS, iOS, Android x5 flavors + AAB)
2. Creeaza GitHub Release (tag-ul devine release public)
3. Job `Deploy to VPS` asteapta APROBARE manuala in environment `production`

### PASUL 7: Asteapta CI/CD build sa termine
```bash
# Get last run ID (probabil tag-ul tau)
RUN_ID=$(gh api repos/ICD360S-e-V/mail/actions/runs?per_page=1 --jq '.workflow_runs[0].id')
echo "Run: $RUN_ID"

# Verifica statusul tuturor job-urilor:
gh api repos/ICD360S-e-V/mail/actions/runs/$RUN_ID/jobs \
  --jq '.jobs[] | "\(.name): \(.conclusion // .status)"'
```

Asteapta pana toate job-urile arata:
- `Detect Changes: success`
- `Linux: success`
- `Windows: success`
- `Apple (iOS + macOS): success`
- `Android (universal/fdroid/googleplay/samsung/huawei + AAB): success` (×6)
- `Android Cache Save: success`
- `Release: success`
- `Deploy to VPS: waiting` ← acum trebuie aprobat

**Daca un job esueaza:** verifica log-ul cu `gh run view --repo ICD360S-e-V/mail --job=<job_id> --log-failed`. Repara codul, push, fortzeaza tag-ul la commit-ul nou (`git tag -f vX.Y.Z && git push -f origin vX.Y.Z`), re-trigger workflow.

### PASUL 8: APROBA deploy-ul in environment `production`

```bash
ENV_ID=$(gh api repos/ICD360S-e-V/mail/actions/runs/$RUN_ID/pending_deployments --jq '.[0].environment.id')
gh api repos/ICD360S-e-V/mail/actions/runs/$RUN_ID/pending_deployments -X POST \
  -F "environment_ids[]=$ENV_ID" \
  -f state="approved" \
  -f comment="release vX.Y.Z"
```

Sau din GitHub UI: **Actions tab → run-ul curent → Review deployments → production → Approve and deploy**.

### PASUL 9: Asteapta deploy-ul sa termine cu success

**CRITICAL:** NU treci la PASUL 10 daca deploy-ul nu e success. Daca PASUL 10 ruleaza pe binare vechi, hash-urile vor fi GRESITE iar in-app updater-ul va respinge update-ul.

```bash
# Asteapta:
while true; do
  S=$(gh api repos/ICD360S-e-V/mail/actions/runs/$RUN_ID/jobs \
    --jq '.jobs[] | select(.name == "Deploy to VPS") | "\(.status) \(.conclusion // "running")"')
  echo "$(date +%H:%M:%S) Deploy: $S"
  echo "$S" | grep -qE "completed (success|failure)" && break
  sleep 15
done
```

Trebuie sa vezi `completed success`. Daca `failure`, NU CONTINUA — verifica log-ul deploy-ului si rezolva.

### PASUL 10: Calculeaza SHA-256 pentru TOATE platformele (de pe server!)

**CRITICAL:** Hash-urile trebuie calculate pe binarele DEJA UPLOADATE pe server, NU pe build artifacts locali. CI/CD-ul deja a deploy-at fisierele dupa approval (PASUL 9).

```bash
ssh -i <SSH_KEY> -p 36000 root@mail.icd360s.de "
echo 'WIN:' \$(sha256sum /var/www/html/downloads/mail/windows/icd360s-mail-setup.exe | awk '{print \$1}')
echo 'MAC:' \$(sha256sum /var/www/html/downloads/mail/macos/icd360s-mail.dmg | awk '{print \$1}')
echo 'AND:' \$(sha256sum /var/www/html/downloads/mail/android/universal/app-arm64-v8a-universal-release.apk | awk '{print \$1}')
echo 'LIN:' \$(sha256sum /var/www/html/downloads/mail/linux/icd360s-mail.AppImage | awk '{print \$1}')
echo 'IOS:' \$(sha256sum /var/www/html/downloads/mail/ios/icd360s-mail.ipa | awk '{print \$1}')
echo 'TIMESTAMPS:'
ls -la /var/www/html/downloads/mail/macos/ /var/www/html/downloads/mail/windows/
"
```

**Verifica timestamp-urile** — trebuie sa fie din ULTIMELE MINUTE (nu fisierele vechi). Daca timestamp-ul e vechi, deploy-ul nu a uploadat sau a esuat — NU continua.

### PASUL 11: Update version.json pe server cu HASH-URI PER PLATFORMA

**CRITICAL:** Trebuie OBLIGATORIU `sha256_macos`, `sha256_android`, `sha256_linux`, `sha256_ios` SEPARAT, nu doar `sha256` (care e folosit doar pentru Windows). Daca lipsesc, in-app updater-ul foloseste hash-ul Windows pentru toate platformele si toate update-urile non-Windows esueaza cu "file corrupted or tampered". Acest bug a fost introdus in v2.20.0 si fixat in v2.20.3.

```bash
ssh -i <SSH_KEY> -p 36000 root@mail.icd360s.de "cat > /var/www/html/updates/version.json << 'EOF'
{
  \"version\": \"X.Y.Z\",
  \"download_url\": \"https://mail.icd360s.de/downloads/mail/windows/icd360s-mail-setup.exe\",
  \"download_url_macos\": \"https://mail.icd360s.de/downloads/mail/macos/icd360s-mail.dmg\",
  \"download_url_android\": \"https://mail.icd360s.de/downloads/mail/android/universal/app-arm64-v8a-universal-release.apk\",
  \"download_url_linux\": \"https://mail.icd360s.de/downloads/mail/linux/icd360s-mail.AppImage\",
  \"download_url_ios\": \"https://mail.icd360s.de/downloads/mail/ios/icd360s-mail.ipa\",
  \"changelog\": \"Descriere scurta\",
  \"sha256\": \"<HASH_WINDOWS>\",
  \"sha256_macos\": \"<HASH_MACOS>\",
  \"sha256_android\": \"<HASH_ANDROID>\",
  \"sha256_linux\": \"<HASH_LINUX>\",
  \"sha256_ios\": \"<HASH_IOS>\"
}
EOF"
```

### PASUL 12: Update changelog.json pe Server

User-ii care apasa "View Changelog" in app citesc din `https://mail.icd360s.de/updates/changelog.json` (NU din `changelog_window.dart` hardcodat — acela e doar fallback offline). TREBUIE actualizat aici dupa fiecare release, altfel utilizatorii nu vor vedea entry-ul nou.

**IMPORTANT:** Entry-ul aici trebuie sa fie IDENTIC (sau cel putin echivalent) cu cel din `changelog_window.dart` — aceeasi titlu, aceleasi bullet points. Inconsistenta confuzeaza user-ii.

```bash
ssh -i <SSH_KEY> -p 36000 root@mail.icd360s.de "python3 << 'PYEOF'
import json
with open('/var/www/html/updates/changelog.json', 'r') as f:
    data = json.load(f)
# Scoate emoji NEW de la versiunea anterioara
if data['versions'] and data['versions'][0]['title'].startswith('\U0001f195'):
    data['versions'][0]['title'] = data['versions'][0]['title'].replace('\U0001f195 ', '')
# Adauga noua versiune la inceput
data['versions'].insert(0, {
    'title': '\U0001f195 Version X.Y.Z - DD MMM YYYY',
    'entries': ['Bug fix - ...', 'Security - ...']
})
with open('/var/www/html/updates/changelog.json', 'w') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
PYEOF"
```

### PASUL 13: Verifica post-release (smoke test)

```bash
# 1. Server arata noua versiune in version.json
curl -sf https://mail.icd360s.de/updates/version.json | python3 -c '
import json,sys
d = json.load(sys.stdin)
print(f\"version: {d[\"version\"]}\")
print(f\"sha256 (win): {d.get(\"sha256\", \"MISSING\")[:16]}...\")
print(f\"sha256_macos: {d.get(\"sha256_macos\", \"MISSING\")[:16]}...\")
print(f\"sha256_linux: {d.get(\"sha256_linux\", \"MISSING\")[:16]}...\")
print(f\"sha256_android: {d.get(\"sha256_android\", \"MISSING\")[:16]}...\")
print(f\"sha256_ios: {d.get(\"sha256_ios\", \"MISSING\")[:16]}...\")
'

# 2. Server arata noua versiune in changelog.json (primul element trebuie sa aiba 🆕 si versiunea noua)
curl -sf https://mail.icd360s.de/updates/changelog.json | python3 -c '
import json,sys
d = json.load(sys.stdin)
print(d["versions"][0]["title"])
for e in d["versions"][0]["entries"][:3]:
    print(f"  - {e}")
'

# 3. Hash-urile din version.json sunt valide vs binarele actuale (cross-check)
ssh -i <SSH_KEY> -p 36000 root@mail.icd360s.de "
SERVER_MAC=\$(sha256sum /var/www/html/downloads/mail/macos/icd360s-mail.dmg | awk '{print \$1}')
JSON_MAC=\$(python3 -c 'import json; print(json.load(open(\"/var/www/html/updates/version.json\"))[\"sha256_macos\"])')
[ \"\$SERVER_MAC\" = \"\$JSON_MAC\" ] && echo '✓ macOS hash match' || echo '❌ macOS hash MISMATCH'
"
```

Daca oricare dintre verificarile de mai sus esueaza → NU anunta release-ul, repara mai intai.

### PASUL 14: Test in app (manual)

1. **Pe device-ul tau cu app-ul vechi**: deschide app-ul, asteapta auto-update check (max 5 min) sau apasa Refresh.
2. Confirma ca app-ul arata "New version available".
3. Click Install update → urmareste log-ul: download, SHA-256 verify, install, restart.
4. Dupa restart, verifica versiunea din footer arata X.Y.Z.
5. Adauga un cont si verifica conexiunea IMAP/SMTP merge (cert mTLS chain valid).

Daca update-ul esueaza pe device-ul tau → reverteste sau lanseaza un hotfix.

---

### Checklist Release (printable)
```
PRE-FLIGHT
[] git status clean, pe main, sincronizat cu origin
[] CI verde pe main (ultimul build)
[] Reviewer-ul environment production e disponibil sa aprobe

CODE
[] 0. Versiunea curenta sincronizata in toate 4 fisierele
[] 1. Decis bump (PATCH/MINOR/MAJOR)
[] 2. Bump in 4 fisiere: pubspec.yaml, update_service.dart, main_window.dart, installer.iss
[] 3. changelog_window.dart - entry nou LA INCEPUT (cu 🆕), scos 🆕 de la cea anterioara
[] 4. CLAUDE.md - "Versiune Curenta" + tabel ISTORIC VERSIUNI updated

GIT
[] 5. git commit + git push origin main
[] 6. git tag vX.Y.Z + git push origin vX.Y.Z

CI/CD
[] 7. Toate build job-urile success (gh api .../jobs)
[] 8. APROBAT "Deploy to VPS" in environment production
[] 9. Deploy completat cu success (NU doar started!)

SERVER
[] 10. SHA-256 calculate pentru TOATE 5 binarele DUPA deploy success
[] 11. version.json updated cu HASH-URI PER PLATFORMA:
       - sha256 (Windows)
       - sha256_macos
       - sha256_linux
       - sha256_android
       - sha256_ios
[] 12. changelog.json updated pe server (intrare identica cu changelog_window.dart)

VERIFICATION
[] 13. curl version.json → versiune corecta + toate 5 hash-urile prezente
[] 14. curl changelog.json → primul entry are 🆕 + versiunea noua
[] 15. Cross-check: hash din version.json == sha256sum din binar real
[] 16. Test in app: trigger update check → install → confirm versiune noua + IMAP merge
```

### Common bugs din experienta (lessons learned)

| Bug | Cauza | Versiunea introdusa | Versiunea fix |
|-----|-------|---------------------|----------------|
| `file corrupted or tampered` la auto-update non-Windows | `version.json` are doar `sha256` (Windows), lipseste `sha256_macos`/`_linux`/`_android`/`_ios`. App-ul citea hash-ul Windows pentru toate platformele. | v2.20.0 | v2.20.3 |
| User-ii vad doar versiuni vechi cand apasa "View Changelog" | Forgot to update `changelog.json` pe server (era doar in `changelog_window.dart` local) | v2.20.0 | v2.20.1 |
| `Authentication failed` la cert API in app | `get-certificate.php` apela `doveadm` direct, dar PHP-FPM ruleaza ca apache user care n-are acces la auth-client socket Dovecot. Necesita sudoers + `sudo doveadm` | v2.20.0 | hotfix server-side |
| `mTLS REJECTED: Certificate not for mail.icd360s.de` | `badCertificateCallback` e chemat pentru fiecare cert din chain, nu doar leaf. Codul respingea intermediate-ul. | v2.20.0 | v2.20.4 |
| `mTLS Unknown issuer` | Compararea DN: codul folosea format RFC 4514 (`CN=R3,O=...`), Dart returneaza format slash (`/CN=R3/O=...`) | v2.18 | v2.20.2 |
| Deploy stuck in "waiting" indefinit | Uitat sa aprobi environment-ul `production` | always | manual fix |
| CI builds fara modificarile mele | Tag pushed inainte ca commit-ul sa fie pe origin/main | always | force-push tag dupa commit |
| Connection refused la mail.icd360s.de:10993 din IPv6 | HAProxy `bind *:10993` se lega doar pe IPv4 in acest setup. Trebuie explicit `bind 0.0.0.0:10993,:::10993` | v2.20.1 | server config |
| 17 conturi cu parole inaccesibile dupa upgrade v2.5→v2.20 | Migration logic doar pentru un format intermediate XOR, nu pentru hostname-XOR original | v2.20.0 | v2.20.1 (parțial — pasword garbage) |

### Rollback (in caz de release stricat)

Daca o versiune e deploy-ata si descopera dupa ca e bug-uita:

```bash
# 1. Revert la versiunea anterioara (X.Y.Z-1) in version.json pe server
ssh -i <SSH_KEY> -p 36000 root@mail.icd360s.de "
# Verifica daca exista backup
ls /var/www/html/updates/version.json.bak* 2>/dev/null
# Sau pune versiunea anterioara manual (cu hash-urile binarelor anterioare)
"

# 2. Daca binarele anterioare au fost suprascrise, trebuie reconstruite din git tag-ul anterior
git checkout vX.Y.Z-1
# Trigger workflow_dispatch pe acel tag
gh api repos/ICD360S-e-V/mail/actions/workflows/build-all-platforms.yml/dispatches -X POST -f ref="vX.Y.Z-1"

# 3. Notifica user-ii daca au facut deja update la versiunea bug-uita
# (nu exista notification mechanism - manual prin email/in-app announcement)
```

**Lectie:** Pastreaza backup-uri pe server pentru ULTIMELE 2-3 binare per platforma, pentru a putea face rollback rapid fara rebuild.

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
| 2.20.4 | 8 Apr 2026 | Bug fix: mTLS chain validation accepts intermediate/root LE CAs (was rejecting the entire chain because intermediate cert subject didn't contain mail.icd360s.de) |
| 2.20.3 | 8 Apr 2026 | Bug fix: update SHA-256 verification reads platform-specific hash field (was always reading Windows hash, breaking macOS/Linux/Android/iOS updates) |
| 2.20.2 | 8 Apr 2026 | CRITICAL fix: TLS issuer DN format mismatch (slash vs comma) was rejecting all valid Let's Encrypt certs in v2.20.0/2.20.1, breaking IMAP/SMTP/HTTPS. Shared le_issuer_check helper. |
| 2.20.1 | 8 Apr 2026 | Bug fixes: v2.5.x XOR-password migration, update progress throttle, trash cleanup spam, l10n warning spam, log header version |
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





