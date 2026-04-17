# Changelog

All notable changes to this project will be documented in this file.
Generated automatically from [Conventional Commits](https://www.conventionalcommits.org/).

- - -
## v2.47.22 - 2026-04-17
#### Bug Fixes
- include trailing \n after END marker + stricter email validation - (72c2b91) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.21 - 2026-04-17
#### Bug Fixes
- auto re-request Faza 3 approval when cert is lost from storage - (959ff82) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.20 - 2026-04-16
#### Bug Fixes
- key lookup only on complete emails + multipart text extraction - (1b4280c) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.19 - 2026-04-16
#### Bug Fixes
- reduce log upload interval to 2 minutes for real-time diagnostics - (7b3da27) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.18 - 2026-04-16
#### Bug Fixes
- CRLF for MIME parser + mTLS diagnostic logging for Android - (1aaf781) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.17 - 2026-04-16
#### Bug Fixes
- OCB MAC failure (1 byte stripped by trim) + inner MIME text extraction - (d5d8b84) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.16 - 2026-04-16
#### Bug Fixes
- use decodeContentBinary for PGP ciphertext (part.text doesn't exist) - (a1d2c3f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.15 - 2026-04-16
#### Bug Fixes
- use raw part.text for PGP ciphertext extraction (OCB MAC failure on large msgs) - (2e7b9c2) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.14 - 2026-04-16
#### Bug Fixes
- parse inner MIME after PGP decrypt (was showing raw headers) - (12d5351) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.13 - 2026-04-16
#### Bug Fixes
- clean PGP armor extracted from MIME (CRLF + preamble caused FormatException) - (c42d402) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.12 - 2026-04-16
#### Bug Fixes
- make diagCallback public (was private, inaccessible from pgp_key_service) - (627035f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.11 - 2026-04-16
#### Bug Fixes
- log actual dart_pg decrypt errors + worker key fingerprint - (e79c7c3) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.10 - 2026-04-16
#### Bug Fixes
- await setActiveAccount before fetchEmails (decrypt race) - (d9d45dc) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.9 - 2026-04-16
#### Bug Fixes
- setActiveAccount awaits key load before starting worker - (be5e3f8) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.8 - 2026-04-16
#### Bug Fixes
- always republish pubkey + force fresh fetch on compose - (c353c3f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.7 - 2026-04-16
#### Bug Fixes
- 5-minute TTL on recipient pubkey cache - (aab7238) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.6 - 2026-04-16
#### Bug Fixes
- pubkey reconciliation compares full armor, not just primary fp - (e458c45) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.5 - 2026-04-16
#### Bug Fixes
- PGP sync runs early + pubkey fetch uses sender's mTLS client - (e1cf10e) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.4 - 2026-04-16
#### Bug Fixes
- reconcile published pubkey with local private key on startup - (0d3fc40) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.3 - 2026-04-16
#### Bug Fixes
- MtlsClientPool reads from MasterVault, not PortableSecureStorage - (6857abb) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.2 - 2026-04-16
#### Bug Fixes
- use PortableSecureStorage.instance singleton (was calling private ctor) - (745e22d) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.1 - 2026-04-16
#### Bug Fixes
- remove one-shot flag from PGP blob migration — sync on every startup - (b185cd8) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.47.0 - 2026-04-16
#### Features
- per-account MtlsClientPool eliminates SecurityContext races - (6be5aa3) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.46.3 - 2026-04-16
#### Bug Fixes
- cert-first strategy in _ensureCertForAccount (was 401 spam at startup) - (b7ca0a4) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.46.2 - 2026-04-16
#### Bug Fixes
- PGP migration uploads use wrong cert → 401 mTLS required on Android - (75d8e01) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.46.1 - 2026-04-15
#### Bug Fixes
- add missing PgpSyncService.hasServerBlob (used by migration) - (d8efa63) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.46.0 - 2026-04-15
#### Features
- automatic zero-knowledge PGP key sync across devices (ProtonMail pattern) - (eefde0b) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.15 - 2026-04-15
#### Bug Fixes
- RangeError on empty NavigationPane + PGP split-brain on re-upload - (0fdfd6f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.14 - 2026-04-15
#### Bug Fixes
- duplicate email sent on Android when user taps Send repeatedly - (e05d319) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.13 - 2026-04-15
#### Bug Fixes
- Android freeze opening Sent — batch delivery status instead of per-email - (f77c84c) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.12 - 2026-04-15
#### Bug Fixes
- RangeError on Android when DNS lookup returns empty list - (e0440e7) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.11 - 2026-04-15
#### Bug Fixes
- sync currentVersion with pubspec — was stuck at 2.45.8 causing update loop - (9eb03ec) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.8 - 2026-04-14
#### Bug Fixes
- remove edge_detection — incompatible with AGP 8.x (no namespace) - (e91b6a9) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.7 - 2026-04-14
#### Bug Fixes
- import showModalBottomSheet from material (not in fluent_ui) - (da7249e) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.3 - 2026-04-14
#### Bug Fixes
- edge_detection version ^3.0.2 doesn't exist, use ^1.1.3 (latest on pub.dev) - (c44d27c) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.2 - 2026-04-14
#### Bug Fixes
- remove const from Icons using Colors.red (Fluent UI Colors not const) - (0b05237) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.1 - 2026-04-14
#### Bug Fixes
- apply research findings — bottom sheet on mobile, GrapheneOS fallback - (e248d86) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.45.0 - 2026-04-14
#### Features
- attachment source picker (file vs camera) in compose window - (4ce67e8) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.44.0 - 2026-04-14
#### Features
- delivery status icon + always-visible delete button in email list - (d68d523) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.43.2 - 2026-04-14
#### Bug Fixes
- move Switch Account button from sidebar to header (next to Settings) - (116bcaf) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.43.1 - 2026-04-14
#### Bug Fixes
- remove unread count from window title (privacy leak) - (683a384) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.43.0 - 2026-04-14
#### Features
- account switcher replaces PaneItemExpander - single active account - (07f1b84) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.42.0 - 2026-04-14
#### Features
- UI polish - compose FAB icon-only, version in header, quota removed (security) - (928c65f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.41.1 - 2026-04-13
#### Bug Fixes
- replace ButtonState.all with WidgetStatePropertyAll for FAB style - (ddd0bee) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.41.0 - 2026-04-13
#### Features
- UI redesign — floating compose FAB, header consolidation, server info dialog - (12d644e) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.22 - 2026-04-13
#### Bug Fixes
- auto-generate changelog.json from CHANGELOG.md on every deploy - (d486034) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.21 - 2026-04-13
#### Bug Fixes
- descriptive tag messages with grouped changelog for releases - (1c6e002) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.20 - 2026-04-13
#### Bug Fixes
- add missing v2.40.17 to changelog and enable refactor bump - (786af00) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.19 - 2026-04-13
#### Bug Fixes
- accounts not visible after master password until dark mode toggle - (b1bda7b) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.18 - 2026-04-13
#### Bug Fixes
- log PGP key fetch errors and add negative cache with 30s expiry - (4309e8f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.17 - 2026-04-13
#### Code Refactoring
- make saveDraft account parameter required per best practice - (8f68f5c) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.16 - 2026-04-13
#### Bug Fixes
- drafts saved to wrong account (compose From vs navigation selection) - (c86286f) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.15 - 2026-04-13
#### Bug Fixes
- include UID in FETCH criteria so message.uid is always populated - (06271f6) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.14 - 2026-04-13
#### Bug Fixes
- per-account mutex in IMAP pool prevents command interleaving - (0690236) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.13 - 2026-04-13
#### Bug Fixes
- per-account PGP keys instead of singleton for all 36 accounts - (a96740d) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.12 - 2026-04-13
#### Bug Fixes
- undefined 'folders' variable in _loadFoldersForAccount log line - (286ce49) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.11 - 2026-04-13
#### Bug Fixes
- IMAP connection pool to prevent "Too many open files" (errno 24) - (508a290) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.10 - 2026-04-13
#### Performance Improvements
- skip DoH after first failure — eliminates 2-3s delay per request - (197a77a) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.9 - 2026-04-13
#### Bug Fixes
- DoH uses only Quad9 (remove Cloudflare fallback for lookupServerA) - (62e1756) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.8 - 2026-04-13
#### Bug Fixes
- PGP key init runs in background — no longer blocks email loading - (a6f6a5e) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.7 - 2026-04-13
#### Bug Fixes
- draft delete button always visible (not just on hover) - (3b93a0d) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.4 - 2026-04-13
#### Bug Fixes
- auto-init PGP key at login — enables E2EE indicators in compose - (3cfc5e4) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.3 - 2026-04-13
#### Bug Fixes
- PIN vault MAC — always sync PHC salt with vault salt after unlock - (c478403) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.2 - 2026-04-13
#### Bug Fixes
- add missing PgpKeyService import in main_window.dart - (1af1072) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -

## v2.40.1 - 2026-04-13
#### Bug Fixes
- CHANGELOG separator — cocogitto expects '- - -' not '---' - (281cede) - Claude Code, *Claude Opus 4.6 (1M context)*
- PIN vault MAC error — sync PHC salt with vault salt after deleteAndRecreate - (c585602) - Claude Code, *Claude Opus 4.6 (1M context)*
- lock order (clearCerts before vault.lock) + masterKey debug logging - (370d583) - Claude Code, *Claude Opus 4.6 (1M context)*

- - -


## v2.39.9 — 2026-04-12

### Bug Fixes

- add Copy Logs button on PIN screen and master password dialog (`179211b`)

- - -

## v2.39.8 — 2026-04-12

### Bug Fixes

- add debug logging to unlockWithKey for PIN vault MAC investigation (`1c93fc8`)

- - -

## v2.39.7 — 2026-04-12

### Bug Fixes

- vault MAC error after reset — delete stale vault and recreate (`9d8121f`)

- - -

## v2.39.6 — 2026-04-12

### Bug Fixes

- PIN setup — _wipeKeys() no longer destroys masterKey cache (`66f8e7e`)

- - -

## v2.39.5 — 2026-04-12

### Bug Fixes

- PIN setup — don't zero masterKey before PIN can cache it (`da7a634`)

### Documentation

- add kontakt@icd360s.de contact email (`f04ff4a`)
- update About (Neu-Ulm, VR 201335), service notice, AGPL contributing (`fd771ec`)
- MIT license + professional About section with legal compliance (`301dc75`)
- add member plan details — unlimited receive, 500MB, send limits (`d41b732`)
- add download links with QR codes + update About section (`2b874d0`)
- modern README with badges, feature grid, architecture (`84dd952`)
- comprehensive README for public repository (`6b21853`)

### License

- switch from MIT to AGPL-3.0 (`abcea15`)

- - -

## v2.39.4 — 2026-04-12

### Bug Fixes

- replace RadioButton with ComboBox — RadioButton API incompatible with fluent_ui 4.x (`d6b8f83`)

- - -

## v2.39.3 — 2026-04-12

### Bug Fixes

- build errors — missing import, icon name, RadioButton API, type cast (`f0506e7`)

- - -

## v2.39.2 — 2026-04-12

### Performance Improvements

- A3 — PGP decrypt offloaded to persistent background isolate (`ee386b7`)

- - -

## v2.39.1 — 2026-04-12

### Bug Fixes

- A1 review — revoke token hashed client-side, remove subject_hint leak (`831626f`)

- - -

## v2.39.0 — 2026-04-12

### Features

- A1 — password-protected email for external recipients (`1177593`)

- - -

## v2.38.2 — 2026-04-12

### Bug Fixes

- E2EE third review — 7 remaining issues fixed (`8fc4b0f`)

- - -

## v2.38.1 — 2026-04-12

### Bug Fixes

- E2EE Phase 2 — fix 15 issues from security review (`f904d57`)

- - -

## v2.38.0 — 2026-04-12

### Features

- E2EE Phase 2 — auto-encrypt outbound internal mail (`dac017a`)

- - -

## v2.37.1 — 2026-04-12

### Bug Fixes

- rewrite E2EE Phase 1 — fix 17 issues from security review (`9fe2e57`)

### Deps

- auto-update pubspec.lock [skip ci] (`a12edbd`)

- - -

## v2.37.0 — 2026-04-12

### Features

- E2EE Phase 1 — OpenPGP key management + decrypt on fetch (`da3aec9`)

- - -

## v2.36.1 — 2026-04-12

### Bug Fixes

- build errors + settings UI for notification privacy and PIN management (`2ef2ba7`)

- - -

## v2.36.0 — 2026-04-12

### Security Fixes

- notification privacy levels — hide email content on lock screen (`9686679`)

- - -

## v2.35.0 — 2026-04-12

### Features

- remote device revocation — admin revokes, app auto-wipes + locks (`f8b3fa8`)

- - -

## v2.34.0 — 2026-04-12

### Features

- RAM-only session cache — zero disk artifacts, instant navigation (`6a3304c`)

- - -

## v2.33.0 — 2026-04-12

### Security Fixes

- harden PIN unlock — Argon2id KDF, persistent attempts, lockout delays (`85beb05`)

- - -

## v2.32.0 — 2026-04-12

### Features

- PIN unlock with randomized keypad (6-digit, anti-shoulder-surf) (`238e4e9`)

- - -

## v2.31.3 — 2026-04-12

### Bug Fixes

- update-pubspec-version.sh now also updates currentVersion in update_service.dart (`03d515a`)

- - -

## v2.31.2 — 2026-04-12

### Bug Fixes

- convert cog lightweight tags to annotated tags for Release job (`9e95c6f`)

- - -

## v2.31.1 — 2026-04-12

### Bug Fixes

- add factory reset button on lock screen with typed RESET confirmation (`a5a1510`)

- - -

## v2.31.0 — 2026-04-12

### Security Fixes

- comprehensive audit — 12 fixes across 16 files (`51dc344`)

- - -

## v2.30.8 — 2026-04-11

### Bug Fixes

- v2.30.8 — filter \NoSelect mailboxes at IMAP LIST time (`ee5c3f7`)

- - -

## v2.30.7 — 2026-04-11

### Hotfixes

- v2.30.7 — phantom folder fails entire account with networkError (`97f7b2f`)

- - -

## v2.30.6 — 2026-04-11

### Hotfixes

- v2.30.6 — MasterVault uint16 memory_KiB overflow corrupted header (`0577ba6`)

- - -

## v2.30.5 — 2026-04-11

### Hotfixes

- v2.30.5 — MasterVault unmodifiable SensitiveBytes on first unlock (`ce4f241`)

- - -

## v2.30.4 — 2026-04-11

### Hotfixes

- v2.30.4 — MasterVault.write before unlock on first master pwd set (`f6ea6eb`)

- - -

## v2.30.3 — 2026-04-11

### Hotfixes

- v2.30.3 — Faza 3 cert install hung on 'Approved! Downloading…' (`5b0b08a`)

- - -

## v2.30.2 — 2026-04-11

### Release

- v2.30.2 — multi-account cert + HTML fragments + security health (`703bab7`)

- - -

## v2.30.1 — 2026-04-11

### Deps

- auto-update pubspec.lock [skip ci] (`633645c`)

- - -

## v2.30.0 — 2026-04-11

### Features

- MasterVault — Argon2id+HKDF+AES-GCM cert storage — B5 (v2.30.0) (`eec38e0`)

- - -

## v2.29.1 — 2026-04-11

### Bug Fixes

- SmtpAuthExternalCommand nullable response.code (v2.29.1) (`80f395a`)

- - -

## v2.29.0 — 2026-04-11

### Features

- SASL EXTERNAL via Dovecot submission — A3.2.5 (v2.29.0) (`fd4f254`)

- - -

## v2.28.2 — 2026-04-11

### Bug Fixes

- SASL EXTERNAL continuation + Faza 3 cert restore (v2.28.2) (`f10e826`)

- - -

## v2.28.1 — 2026-04-11

### Bug Fixes

- DMG /Applications symlink + migration timeout (v2.28.1) (`c3267ea`)

- - -

## v2.28.0 — 2026-04-11

### Features

- mTLS auth + replay protection on heartbeat/can-send — B1 (v2.28.0) (`8e0528f`)

- - -

## v2.27.1 — 2026-04-11

### Bug Fixes

- rolling auto-lock inactivity timer — C2 (v2.27.1) (`8dbe0e2`)

- - -

## v2.27.0 — 2026-04-11

### Features

- passwordless flow with admin push approval — A3 phase 3 (v2.27.0) (`19f966d`)

- - -

## v2.26.1 — 2026-04-11

### Bug Fixes

- _authenticate parameter type EmailAccount not MailAccount (v2.26.1) (`45f89ed`)

- - -

## v2.26.0 — 2026-04-11

### Features

- SASL EXTERNAL cert-based auth — A3 phase 2 (v2.26.0) (`ef3338e`)

- - -

## v2.25.0 — 2026-04-11

*Version bump.*

- - -

## v2.24.4 — 2026-04-11

### Bug Fixes

- macOS — open DMG in Finder, let user drag-and-drop install (`0cb6d34`)

- - -

## v2.24.3 — 2026-04-11

*Version bump.*

- - -

## v2.24.2 — 2026-04-11

### Bug Fixes

- cooldown register-device failures (no spam on every fetch) (`a59a5c6`)

- - -

## v2.24.1 — 2026-04-11

### Features

- detect single-device lockout via repeated IMAP auth failures (`7311608`)

- - -

## v2.24.0 — 2026-04-11

### Bug Fixes

- replace deprecated Node 20 actions (`e1737f1`)

### Features

- show device limit reached dialog (`068b67b`)
- pre-flight canSend() check before SMTP send (`d25e414`)
- wire device registration + heartbeat into EmailProvider (`e9d071f`)
- add DeviceRegistrationService for backend integration (`1f09824`)

- - -

## v2.23.5 — 2026-04-10

### Bug Fixes

- use actual macOS bundle ID (com.example.icd360sMailClient) (`00dabc1`)

- - -

## v2.23.4 — 2026-04-10

### Bug Fixes

- separate PEM parse from persistence in cert expiry monitor (`f66b144`)

### Code Refactoring

- use PortableSecureStorage in lib/views/factory_reset_dialog.dart (`94d5c2e`)
- use PortableSecureStorage in lib/utils/phishing_detector.dart (`8f6f048`)
- use PortableSecureStorage in lib/services/account_service.dart (`048da4a`)
- use PortableSecureStorage in lib/services/master_password_service.dart (`7e0a8dc`)
- use PortableSecureStorage in lib/services/certificate_service.dart (`9486b53`)
- use PortableSecureStorage in lib/services/certificate_expiry_monitor.dart (`ac7f781`)
- use PortableSecureStorage in lib/services/version_baseline.dart (`7fcc608`)

### Features

- add PortableSecureStorage with macOS file backend (`9adb245`)

- - -

## v2.23.3 — 2026-04-10

### Features

- split build steps into smaller named units for visual progress (`8bd61d1`)

- - -

## v2.23.2 — 2026-04-10

### Features

- add rich GITHUB_STEP_SUMMARY for all platform build jobs (`cd1095b`)

- - -

## v2.23.1 — 2026-04-10

### Bug Fixes

- use legacy login keychain (usesDataProtectionKeychain: false) in lib/views/factory_reset_dialog.dart (`a846bdd`)
- use legacy login keychain (usesDataProtectionKeychain: false) in lib/utils/phishing_detector.dart (`397b1c9`)
- use legacy login keychain (usesDataProtectionKeychain: false) in lib/services/account_service.dart (`c974e28`)
- use legacy login keychain (usesDataProtectionKeychain: false) in lib/services/master_password_service.dart (`805eb7b`)
- use legacy login keychain (usesDataProtectionKeychain: false) in lib/services/certificate_service.dart (`b59ce11`)
- use legacy login keychain (usesDataProtectionKeychain: false) in lib/services/certificate_expiry_monitor.dart (`17cba82`)
- use legacy login keychain (usesDataProtectionKeychain: false) in lib/services/version_baseline.dart (`75c18ea`)
- correctly extract annotated tag message for release notes (`98bc8ba`)
- use annotated tag message as GitHub Release body (`8313a21`)

### Features

- add manual update check button in footer (`384e385`)

- - -

## v2.23.0 — 2026-04-10

### Bug Fixes

- handle nullable tbsCertificate from basic_utils (`8553980`)
- pin appimagetool to 1.9.1 with SHA-256 verification (`d2d64ae`)
- mark CRAM-MD5 as deprecated, fix copy-paste bugs (`6610b68`)
- validate APOP arguments against CRLF injection (`9fdb4d3`)
- validate POP3 PASS argument against CRLF injection (`9dbdad4`)
- validate POP3 USER argument against CRLF injection (`3e961d9`)
- convert HTML to plain text on forward (`161fe25`)
- UTS #39 Highly Restrictive + whole-script confusable detection (`bde40cd`)
- sign Safe Browsing DB with ECDSA + add anti-tampering checks (`643161f`)
- validate APPIMAGE env var before overwriting + atomic update (`fa7a909`)
- verify macOS .app bundle before install + strip quarantine (`d87206d`)
- replace nslookup with DoH for SPF/DKIM checks (`6964ac1`)
- update IMAP port in diagnostics log (993 → 10993) (`1632224`)
- correct IMAP port in ConnectionMonitor (993 → 10993) (`582801f`)
- wrap legacy password hashes in PBKDF2 at app startup (`e1e0021`)
- move version baseline from plaintext file to secure storage (`66eb352`)
- move REQUEST_INSTALL_PACKAGES to universal flavor only (`6ebd4f9`)
- use utf8.encode and empty authzid in AUTH PLAIN (`e9fadbf`)
- use utf8.encode instead of .codeUnits in AUTH LOGIN (`cbf2521`)
- enforce TLS before POP3 authentication (`6026f4c`)
- enforce TLS before IMAP authentication (`badc550`)
- enforce TLS before SMTP authentication (`9d1ba99`)
- add TLS enforcement guard and fix STARTTLS isSecure tracking (`a5236fa`)
- hook certificate expiry parsing into download and restore (`87998d9`)
- parse real certificate expiry from PEM instead of guessing (`e479237`)
- correct certificate validation logic in onBadCertificate (`9e9faeb`)
- redact PII in compose_window log messages (`5304737`)
- redact sender email in notification log messages (`48bfa53`)
- redact PII in email_provider log messages (`90f32dd`)
- add PII safety net to LoggerService (`f6ee546`)
- pass link display text for phishing detection in HTML emails (`532a776`)
- replace regex HTML sanitizer with DOM-based allowlist (`35c4f0a`)
- require DMARC pass before whitelisting trusted domains (`5d3e500`)
- remove HTTP fallback, fix email leak, close sockets in discovery (`c9d150e`)
- prevent IMAP command injection in LOGIN, SETMETADATA, SETQUOTA (`b7a449d`)
- match SafeHtmlRenderer onLinkTap signature (`0ba51dc`)

### Features

- add HTML to plain text converter for safe forwarding (`d63c16e`)
- add DoH DNS client with self-hosted privacy endpoint (`29ce1ae`)
- add port status indicators to footer (`a14efc9`)
- add universal flavor manifest with REQUEST_INSTALL_PACKAGES (`d4ca56d`)
- add centralized PII redaction for diagnostic logs (`42fecb0`)
- offline Safe Browsing via local hash prefix DB (zero URLs to Google) (`2fc6d95`)
- integrate PhishingDetector into link confirmation dialog (`e6724b7`)
- multi-layer phishing detector (local heuristics + Google Safe Browsing) (`1a1afba`)
- pass display text to link tap handler for phishing detection (`fc23933`)
- phishing link detection — confirm dialog before opening URLs (1.3) (`1c248a2`)

- - -

## v2.22.2 — 2026-04-10

### Bug Fixes

- migrate to file_picker 11.x API (remove .platform getter) (`c8d627e`)
- await skipEntitlementsChecks (file_picker 11.x) (`addc0c5`)
- relaunch via persistent script file + nohup (Sparkle pattern) (`32c96d6`)

### Deps

- auto-update pubspec.lock [skip ci] (`ebf453e`)
- bump file_picker ^10.3.8 → ^11.0.2 (adds skipEntitlementsChecks for macOS) (`d1b01a8`)

### Release

- bump currentVersion to 2.22.2 (`96aff60`)
- 2.22.2 (`fde9fc6`)

- - -

## v2.22.1 — 2026-04-10

### Release

- bump currentVersion to 2.22.1 (`b968edc`)
- 2.22.1 (`0f8d659`)

- - -

## v2.22.0 — 2026-04-10

### Bug Fixes

- skip file_picker entitlement check on unsandboxed builds (`482978a`)
- correct method name _openUrlInExternalBrowser (`d3c0ca6`)

### Deps

- auto-update pubspec.lock [skip ci] (`baef280`)
- re-trigger lockfile update (`5b49195`)
- trigger lockfile auto-update workflow (`f9cbc76`)
- add flutter_widget_from_html_core for secure HTML email rendering (`2c54c0a`)
- bump the pub-minor-patch group with 2 updates (`7f92e88`)

### Features

- HTML rendering with remote content blocking + load toggle (`f75819f`)
- secure HTML renderer with remote content blocking (`4c8c083`)

### Release

- bump currentVersion to 2.22.0 (`fbc4846`)
- bump to 2.22.0 (HTML email rendering) (`f04b3c7`)

- - -

## v2.21.5 — 2026-04-10

### Bug Fixes

- footer version from UpdateService.currentVersion (`08ff298`)
- bump installer version to 2.21.5 (`4e97a6e`)

### Release

- bump currentVersion to 2.21.5 (`ca2f8a4`)
- bump to 2.21.5 (`9655f80`)

- - -

## v2.21.4 — 2026-04-10

### Release

- bump currentVersion to 2.21.4 (`721d895`)

### Revert

- file_picker back to ^10.3.8 (11.x has breaking API + lockfile mismatch) (`a0cf33a`)

- - -

## v2.21.3 — 2026-04-10

### Bug Fixes

- show real exception in attachment-pick error toast (`ee0b58b`)

### Release

- bump currentVersion to 2.21.3 (`a9448f4`)
- bump file_picker 10.3.8 → 11.0.2 (macOS 26 picker fix) (`a2702e2`)

- - -

## v2.21.2 — 2026-04-09

### Bug Fixes

- remove keychain-access-groups from debug entitlements (`97e6e62`)
- remove keychain-access-groups (broken on ad-hoc signed builds, -34018) (`d130175`)

### Release

- bump currentVersion to 2.21.2 (`2057b3b`)
- bump to 2.21.2 (macOS keychain entitlement fix) (`591e68f`)

- - -

## v2.21.1 — 2026-04-09

### Bug Fixes

- rename pid local + correct shell quoting (`5ea447d`)
- rename pid local to avoid self-shadowing (`f0b98af`)
- wait for parent exit before relaunch (Sparkle pattern) (`9ea2c68`)

### Release

- bump currentVersion to 2.21.1 (`bec1024`)
- bump to 2.21.1 (macOS relaunch fix) (`7915e06`)

- - -

## v2.21.0 — 2026-04-08

### Bug Fixes

- block CRLF/NUL header injection in compose addHeader/setHeader (`d4fcb58`)
- clear cert cache on session lock (M7) (`12fa532`)
- restore client cert cache from secure storage on unlock (M7) (`fc074ca`)
- persist client cert to platform secure storage; clear cache on lock (`517e112`)
- defensive limits for multipart parser (CVE-2024-7999 class) (`667866c`)
- replace invalid Modified UTF-7 with U+FFFD instead of leaking raw bytes (`9afd31c`)
- extend Android pin-set expiration to 2030-01-01 (`2493db7`)
- in-flight dedup for checkForUpdates and downloadAndInstallAuto (`c2c286b`)
- hide stack trace from ErrorWidget in release builds (CWE-209) (`a153e78`)
- seal rate-limit state with AES-GCM and keystore-bound key (`999d918`)
- set Android visibility=private to redact lock screen content (`0ccfa05`)
- exclude main window from screen capture (WDA_EXCLUDEFROMCAPTURE) (`3b5b072`)
- set NSWindow.sharingType = .none to block legacy capture (`27941d7`)
- block screen capture via secureTextEntry layer hack (`aa4a946`)
- privacy blur on background + screenshot detection (`9f0938a`)
- set FLAG_SECURE to block screenshots and screen capture (`12ed3cd`)
- verify ECDSA P-256 signature on version.json (offline key) (`47bfdfd`)
- verify ECDSA P-256 signature on version.json (offline key) (`2166fb6`)
- pin version baseline on first checkForUpdates call (`dc85782`)
- enforce monotonic version baseline (rollback protection) (`ce8717b`)
- install Android APK via PackageInstaller.Session (`b85bf0d`)
- pin HTTPS to ISRG roots in changelog_service (`6b1a1ad`)
- pin HTTPS to ISRG roots in log_upload_service (`2944873`)
- pin HTTPS to ISRG roots in update_service (`8c2f501`)
- pin HTTPS to ISRG roots in certificate_service (`09eb908`)
- use pinned ISRG context for mTLS connections (`ab4e228`)
- pin ISRG Root YE/YR (Gen Y) on iOS (`3ccdabb`)
- pin ISRG Root YE/YR (Gen Y) on Android (`8a821cc`)
- also accept ISRG (Gen Y root organization name) (`0e7687d`)
- validate LE issuer by Organization, not hardcoded CN list (`6b3f0d9`)
- migrate credential KDF to PBKDF2-600k with auto re-encryption (`84b4f4e`)
- migrate master password hash to PHC pbkdf2-sha256 600k (`a1426a8`)
- strip bidi controls from attachment filenames (`98933f3`)
- sanitize bidi controls in inbox list display (`61bad74`)
- sanitize bidi controls in email viewer headers (`0c93c7b`)
- use constant-time comparison for password hash verification (`2e50a22`)
- prevent CRLF injection in mailbox path quoting (`1e2000a`)
- prevent CRLF injection in mailbox path quoting (`b7f02f6`)
- cap literal size at 50 MiB to prevent OOM DoS (`ee4796e`)

### Code Refactoring

- delegate AES-GCM to shared helpers (`ad4c113`)
- extract AES-GCM helpers into shared module (`3fbcf65`)

### Documentation

- expand workflow with pre-flight checks, post-release verification, rollback procedure, and lessons-learned table (`eda682b`)
- rewrite workflow with CI/CD steps + per-platform SHA-256 + changelog.json server warning (lessons from v2.20.x bugs) (`6bcdaf4`)

### Features

- add monotonic version baseline for rollback protection (`cd09897`)
- install updates via PackageInstaller.Session (no TOCTOU) (`de87c8b`)
- add pinned SecurityContext factory with ISRG root PEMs (`8ad951e`)
- add bidi sanitizer to defeat Trojan Source spoofing (`f668d39`)

- - -

## v2.20.4 — 2026-04-08

### Release

- update CLAUDE.md (`5c3e75b`)
- add changelog entry (`fd5c3ac`)
- bump installer (`5e8ed9c`)
- bump main_window (`cce396c`)
- bump update_service (`282d638`)
- bump pubspec (`2a8cbb6`)
- fix mtls chain validation — accept intermediate/root LE CAs (`07aed77`)

- - -

## v2.20.3 — 2026-04-08

### Release

- update CLAUDE.md (`f725d40`)
- add changelog entry (`838287c`)
- bump installer.iss (`d893ada`)
- bump main_window (`33275fd`)
- bump pubspec (`fd60090`)
- fix update SHA-256 to read platform-specific hash field (`1b0717e`)

- - -

## v2.20.2 — 2026-04-08

### Bug Fixes

- use le_issuer_check helper in changelog_service (`6c8b608`)
- use le_issuer_check helper in log_upload_service (`95b0901`)
- use le_issuer_check helper in update_service + bump 2.20.2 (`c07f1b5`)
- use le_issuer_check helper in certificate_service (`51ea2bf`)
- use le_issuer_check helper in mtls_service (`270f678`)
- add le_issuer_check helper — parses Dart slash-format DN correctly (`e0a0724`)

### Release

- update CLAUDE.md (`a6dbe0a`)
- add changelog entry (`9da710a`)
- bump installer.iss (`4b0cd65`)
- bump main_window (`66c3669`)
- bump pubspec (`305a563`)

- - -

## v2.20.1 — 2026-04-08

### Bug Fixes

- log 'not initialized' warning only once per session, not on every call (`f68a936`)
- throttle progress callback (percent change OR 250ms) — eliminates UI rebuild flood during download (`5d02bd5`)
- use UpdateService.currentVersion in log header (was hardcoded 2.5.0) (`49369f8`)
- skip cleanTrash if certs not loaded — eliminates 20+ stack trace spam on startup (`86a024b`)
- add v2.5 hostname-XOR fallback decryption — restore password access for users upgrading from v2.5.x (`6af62e7`)

### Release

- update CLAUDE.md version and history (`2d3e2b7`)
- add changelog entry (`7a53dd5`)
- bump installer.iss (`01edd75`)
- bump main_window.dart (`e630e11`)
- bump update_service.dart (`0a78cf7`)
- bump pubspec.yaml (`f95ba24`)

- - -

## v2.20.0 — 2026-04-08

### Bug Fixes

- remove const from widgets using Colors.red (fluent_ui non-const getter) (`ada776a`)
- use specific auth-error phrases instead of broad substring match (L3) (`787e3c3`)
- replace check-then-set lock with atomic future chain (L2) (`b2e386b`)
- add draftUid to _saveToSentFolder + sendEmailAsync — fixes compile error from C3 refactor (`d4b2f8f`)
- persist master password rate limit + exponential lockout (fixes H2 — restart-bypass) (`44f26bc`)
- use safeAttachmentFileName in email_viewer — prevents path traversal (H1) (`eca2708`)
- use safeAttachmentFileName in attachment_viewer_window — prevents path traversal (H1) (`b97ada1`)
- add safeAttachmentFileName helper — prevents path traversal in attachment downloads (H1) (`9565e91`)
- prevent IMAP injection via _imapQuote() at all 3 search sites (Message-ID x2, Subject x1) — fixes C3 (`554f816`)

### Code Refactoring

- pass _lastDraftUid to send, enabling UID-based draft deletion (option C for C3) (`ae0802b`)
- forward draftUid to sendEmailWithAttachmentsAsync (option C for C3) (`e751ba0`)
- delete drafts by UID after send (eliminates SUBJECT search), log Message-ID fallback usage — option C for C3 (`9aba31d`)

### Deps

- add pointycastle for AES-256-GCM credential fallback encryption (M4) (`4dfa5ab`)

### Release

- update CLAUDE.md version and history (`1d46ca6`)
- add changelog entry — mass security hardening 24 fixes (`e12806b`)
- bump installer.iss (`2c5671f`)
- bump main_window.dart (`88a5717`)
- bump update_service.dart (`1808b5e`)
- bump pubspec.yaml (`f0d4a46`)

### Security Fixes

- use exact DN issuer match instead of substring (L8) (`f8079a5`)
- remove cleartext MX probe — leaked user IP to recipient servers (L7) (`6b3379b`)
- remove blanket -keep io.flutter.** rules to restore obfuscation (L6) (`314c2ef`)
- minSdk 24 + disable V1 signing — defeats Janus CVE-2017-13156 (L5) (`f7d3906`)
- gitignore csr/crt/cer/env/secrets/firebase configs (L4) (`264357b`)
- GPG-sign AppImage with ED25519 key from secrets (M10) (`8a0d139`)
- publish ICD360S AppImage signing public key (ED25519, M10) (`82f437d`)
- declare libsecret-1-0 / libsecret runtime dep in .deb and .rpm (M9) (`c4465bd`)
- pass Android signing secrets via env vars, eliminate heredoc interpolation (M7) (`3474ddc`)
- add factory reset button in main window top bar (M6) — post-login, with typed DELETE confirmation (`2c77edf`)
- remove factory reset button from lock screen (M6) — now post-login only (`b2b4b33`)
- add factory reset dialog with typed DELETE confirmation (M6) (`76711ad`)
- wipe AccountService session key + mTLS certs on app lock (M4) (`7563fd8`)
- unlock AccountService session on master-password verify success (M4) (`ba37c60`)
- replace XOR fallback with AES-256-GCM keyed by master password (M4) (`51debc4`)
- pin update download URL to https://mail.icd360s.de — defense vs version.json compromise (M3) (`74771bc`)
- bump IPHONEOS_DEPLOYMENT_TARGET to 15.0 in all 3 build configs (`c2f2079`)
- bump minimum deployment target to iOS 15 (out of EOL, enables NSPinnedDomains) (`a1833a6`)
- NSPinnedDomains for mail.icd360s.de — parity with Android pin set (M2) (`4133a53`)
- replace dead R3/R10 pins with X2 + offline backup pin (RFC 7469 compliant) — fixes M1 (`3fe7407`)
- gitignore windows/redist/*.exe (downloaded fresh in CI per H5) (`4d06142`)
- remove vc_redist.x64.exe from repo — now downloaded in CI from Microsoft with SHA-256 pin (H5) (`1e32317`)
- download VC++ Redistributable from Microsoft with SHA-256 pin (H5) (`3295cb0`)
- verify APK signing cert via MainActivity MethodChannel before install (H4) (`6f91213`)
- MethodChannel for APK signature verification before self-install (H4) (`5201575`)
- add dependabot config — automated PRs for SHA-pinned action updates and pub deps (`ccc5b8e`)
- pin all GitHub Actions to commit SHAs (fixes H3 — supply chain risk from floating tags) (`efcf070`)

- - -

## v2.19.0 — 2026-04-07

### Release

- restore CLAUDE.md with 2.19.0 entry — fixes empty file from broken Python heredoc (`66ad134`)
- restore changelog_window.dart with 2.19.0 entry — fixes empty file from broken Python heredoc (`511df77`)
- update CLAUDE.md version and history (`e62ae80`)
- add changelog entry for CI/CD security hardening (`272a90f`)
- bump installer.iss (`63a71ef`)
- bump main_window.dart (`6eeebc4`)
- bump update_service.dart (`8f75c4f`)
- bump pubspec.yaml (`7d9ef26`)

- - -

## v2.18.0 — 2026-04-07

### Bug Fixes

- pass account password to certificate API in main_window re-download loop (`f13f78e`)
- pass account password to certificate API at all 5 call sites in email_provider (`d6ba206`)
- require password parameter in certificate API calls — server now authenticates via Dovecot (`077b782`)
- redact CLAUDE.md — remove all server IPs, ports, configs, credentials, email accounts, paths, and Apple IDs (`4a8dfab`)
- replace hardcoded server IPs with DNS lookup in health check (`000433c`)
- replace predictable XOR key derivation with per-install random secret in fallback storage (`7761557`)
- remove password length logging — info disclosure (`7c651c5`)
- update port diagnostics log to match corrected connection_monitor ports (`7d3654f`)
- check correct ports (443, 465, 993) — remove SSH/HTTP probes that trigger fail2ban (`d42e0f7`)
- fix TLS validation + use anonymous device ID (no PII) in log_upload_service (`3724e12`)
- replace weak issuer substring matching with exact DN validation in certificate_service (`2f816e1`)
- fix TLS bypass in update downloads — validate issuer DN + make SHA-256 mandatory (`1d563a0`)
- replace weak substring issuer matching with exact DN validation in mTLS (`bb933dc`)
- enable R8/ProGuard — minify + shrink resources in release build (`470d3b7`)
- add network_security_config.xml — certificate pinning + block cleartext (`1547708`)
- add allowBackup=false, fullBackupContent=false, networkSecurityConfig (`4c01a63`)
- use Random.secure() for salt + add rate limiting (5 attempts, 60s lockout) (`b2055d8`)
- remove .claude/settings.local.json — exposes server commands and paths (`b64102b`)
- remove VPS SSH public key — prevents server fingerprinting (`a41bd1f`)
- remove CA serial file — leaks internal PKI state (`4bc7748`)
- update .gitignore — block .vscode/, .claude/settings.local.json, certs srl, ssh pub keys, temp files (`f06eef0`)
- remove .vscode/settings.json — leaks developer paths (`1126821`)
- remove stale version_temp.json — info disclosure (`a16b2e8`)

### Documentation

- update workflow with CI/CD automation, mandatory SHA-256 step, and per-platform hash uploads (`0771548`)

### Release

- update CLAUDE.md version and changelog (`6f5c6f8`)
- bump version in installer.iss (`70864f3`)
- bump version in main_window.dart (`587cbb0`)
- bump version in update_service.dart (`217e3cf`)
- bump version in pubspec.yaml (`8a569ff`)
- add changelog for security audit release (`c60b209`)

### Security Fixes

- non-root deploy user with rrsync, pinned host key, environment protection (fixes C1+C2+H3) — restored from corrupted commit (`60eb247`)
- non-root deploy user with rrsync restriction, pinned host key, environment protection (fixes C1 + C2 + H3) (`5669d43`)

- - -

## v2.17.11 — 2026-04-06

### Bug Fixes

- Android auto-update downloads APK and triggers system installer directly (`aa01919`)
- Android auto-update downloads APK and triggers system installer directly (`34eb1c8`)
- platform-specific auto-update (macOS DMG install, Linux AppImage replace, Windows unchanged) (`8b27aec`)
- DNS caching (prevents macOS FD exhaustion), batch notifyListeners (eliminates UI rebuild spam) (`a413be2`)
- DNS caching (prevents macOS FD exhaustion), batch notifyListeners (eliminates UI rebuild spam) (`0189e2f`)

### Release

- v2.17.11 - DNS cache, UI rebuild fix, auto-update all platforms (`09e1de3`)
- v2.17.11 - DNS cache, UI rebuild fix, auto-update all platforms (`65142d1`)
- v2.17.11 - DNS cache, UI rebuild fix, auto-update all platforms (`aa6ce5b`)
- v2.17.11 - DNS cache, UI rebuild fix, auto-update all platforms (`1eb3dd7`)
- v2.17.11 - DNS cache, UI rebuild fix, auto-update all platforms (`c012f99`)

- - -

## v2.17.10 — 2026-04-06

### Bug Fixes

- ad-hoc sign macOS app for Keychain access (fixes -34018 errSecMissingEntitlement) (`2a586d0`)
- add keychain-access-groups to DebugProfile entitlements (`b7eb235`)
- add keychain-access-groups entitlement for flutter_secure_storage (-34018) (`c424060`)
- detect-changes hash includes enough_mail_fork, deploy all split-per-abi APKs (`3d677dc`)
- remove deprecated Quick Launch icon, use WizardIsTaskSelected instead of IsTaskSelected (`fa73b4d`)
- correct keystore path (relative to android/app/) and strip heredoc indentation (`6b00aa4`)
- add keystore decode + key.properties for Android signing (`777a761`)
- add libsecret-1-dev for flutter_secure_storage_linux (`04f0e6e`)
- update Flutter to 3.41.4 (flutter_lints 6.0 requires Dart 3.8+) (`7c30fe6`)

### Release

- v2.17.10 - macOS Keychain fix, Windows installer fix, Android split-per-abi deploy (`7c3b303`)
- v2.17.10 - macOS Keychain fix, Windows installer fix, Android split-per-abi deploy (`6febf9b`)
- v2.17.10 - macOS Keychain fix, Windows installer fix, Android split-per-abi deploy (`38908d5`)
- v2.17.10 - macOS Keychain fix, Windows installer fix, Android split-per-abi deploy (`78b34b6`)
- v2.17.10 - macOS Keychain fix, Windows installer fix, Android split-per-abi deploy (`79bde86`)

### Sync

- update version to 2.17.9 and changelog (`16264d1`)
- update version to 2.17.9 and changelog (`460d9ce`)
- update version to 2.17.9 and changelog (`4d02f2d`)
- update version to 2.17.9 and changelog (`22d5d88`)
- update version to 2.17.9 and changelog (`0418640`)

