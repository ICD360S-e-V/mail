import 'package:fluent_ui/fluent_ui.dart';
import '../utils/l10n_helper.dart';
import '../services/changelog_service.dart';

/// Changelog window - fetches from server, falls back to local
class ChangelogWindow extends StatefulWidget {
  const ChangelogWindow({super.key});

  @override
  State<ChangelogWindow> createState() => _ChangelogWindowState();
}

class _ChangelogWindowState extends State<ChangelogWindow> {
  List<ChangelogSection>? _sections;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadChangelog();
  }

  Future<void> _loadChangelog() async {
    final result = await ChangelogService.fetchChangelog()
        .timeout(const Duration(seconds: 5), onTimeout: () => null);
    if (mounted) {
      setState(() {
        _sections = result;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 700
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          const Icon(FluentIcons.info, size: 24),
          const SizedBox(width: 12),
          Text(l10n.changelogDialogTitle),
        ],
      ),
      content: _loading
          ? const Center(child: ProgressRing())
          : _buildContent(theme),
      actions: [
        FilledButton(
          child: Text(l10n.changelogButtonClose),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ],
    );
  }

  Widget _buildContent(FluentThemeData theme) {
    final sections = _sections;
    if (sections != null && sections.isNotEmpty) {
      return SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (int i = 0; i < sections.length; i++) ...[
              if (i > 0) const SizedBox(height: 16),
              _buildSection(theme, sections[i].title, sections[i].entries),
            ],
          ],
        ),
      );
    }
    return _buildFallbackContent(theme);
  }

  Widget _buildFallbackContent(FluentThemeData theme) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSection(theme, '🆕 Version 2.20.1 - 8 Apr 2026', [
            'Bug fix - Migration: passwords from v2.5.x (hostname-XOR) now properly migrated to AES-GCM',
            'Bug fix - Update download: throttle progress callback (no more UI rebuild flood)',
            'Bug fix - Trash cleanup: skip silently if certificates not yet loaded (no more 20+ stack trace spam)',
            'Bug fix - Localization: log not-initialized warning only once per session',
            'Bug fix - Log header: use actual app version (was hardcoded 2.5.0)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.20.0 - 7 Apr 2026', [
            'Security - IMAP injection fix: SUBJECT and Message-ID search now properly quoted (RFC 3501)',
            'Security - Drafts deleted by UID after send (no more SUBJECT search)',
            'Security - Path traversal fix: attachment filenames sanitized (basename + Windows reserved checks)',
            'Security - Master password rate limit persisted to disk + exponential lockout (1m → 5m → 1h → 24h)',
            'Security - Android: APK signing certificate verified before self-install (MethodChannel)',
            'Security - Android: ProGuard rules narrowed (no more blanket io.flutter.** keep)',
            'Security - Android: V1 signing disabled, minSdk 24, defeats Janus CVE-2017-13156',
            'Security - Android: certificate pinning with backup pin (RFC 7469 compliant), removed dead R3/R10',
            'Security - iOS: NSPinnedDomains for mail.icd360s.de (parity with Android)',
            'Security - iOS: minimum deployment target raised to iOS 15 (out of EOL)',
            'Security - Update download URL pinned to https://mail.icd360s.de (defense vs version.json compromise)',
            'Security - Fallback credential storage: AES-256-GCM keyed by master password (was XOR)',
            'Security - In-memory session key wiped on app lock; mTLS certs cleared too',
            'Security - Factory Reset moved off lock screen, requires typed DELETE confirmation',
            'Security - GitHub Actions all pinned to commit SHAs (supply chain defense + Dependabot)',
            'Security - VC++ Redistributable downloaded fresh from Microsoft with SHA-256 pin (no longer in repo)',
            'Security - Linux .deb/.rpm declare libsecret runtime dep (system keyring on Linux)',
            'Security - Linux AppImage GPG-signed with ED25519 key (verifiable with appimagetool --validate)',
            'Security - CI/CD: secrets passed via env vars not heredoc interpolation (prevents injection)',
            'Security - changelog_service: exact DN issuer match instead of substring',
            'Security - SettingsService: atomic future chain replaces racy check-then-set lock',
            'Security - Auth error matching tightened (no more "no"/"bad" substring false positives)',
            'Security - .gitignore: csr/crt/cer/env/firebase configs/notes blocked',
            'Security - SMTP MX probe removed (was leaking user IP cleartext to recipient servers)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.19.0 - 7 Apr 2026', [
            'Security - CI/CD: non-root deploy user with restricted rrsync (write-only to downloads dir)',
            'Security - CI/CD: SSH host key pinned (eliminates ssh-keyscan TOFU/MITM bypass)',
            'Security - CI/CD: production environment with required reviewer for deploys',
            'Security - CI/CD: workflow-level least-privilege permissions (contents: read)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.18.0 - 6 Apr 2026', [
            'Security - Certificate API now requires password authentication (Dovecot backend)',
            'Security - TLS certificate validation: exact issuer DN matching (prevents MITM)',
            'Security - Auto-update: SHA-256 hash verification mandatory, TLS issuer validation',
            'Security - Master password: CSPRNG salt (Random.secure) + rate limiting (5 attempts, 60s lockout)',
            'Security - Android: allowBackup=false, network_security_config with certificate pinning, R8/ProGuard enabled',
            'Security - Fallback password storage: per-install random key instead of predictable XOR',
            'Security - Server health: DNS lookup instead of hardcoded IPs',
            'Security - Log upload: anonymous device ID (no PII), TLS validation fixed',
            'Security - Connection monitor: correct ports (443, 465, 993), removed SSH/HTTP probes',
            'Security - Removed sensitive files from repo (.vscode, certificates, SSH keys, .claude settings)',
            'Security - CLAUDE.md redacted: removed all server IPs, ports, configs, credentials, email accounts',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.11 - 6 Apr 2026', [
            'Performance - DNS caching (previne FD exhaustion pe macOS, fallback pe IP cached)',
            'Performance - UI rebuild batching (notifyListeners o singura data per ciclu, nu per-cont)',
            'Fix - macOS auto-update: download DMG, install .app, relaunch automat',
            'Fix - Linux auto-update: download AppImage, replace executabil, relaunch automat',
            'Fix - Android auto-update: download APK, deschide system installer direct',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.10 - 6 Apr 2026', [
            'Fix - macOS Keychain access: ad-hoc signing + keychain-access-groups entitlement (fixes -34018)',
            'Fix - Windows installer: WizardIsTaskSelected, eliminat Quick Launch deprecated',
            'Fix - Android: deploy toate arhitecturile split-per-abi (arm64, armeabi, x86_64)',
            'Fix - Linux: adaugat libsecret-1-dev pentru flutter_secure_storage',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.9 - 5 Apr 2026', [
            'UI - Android FAB compose button (+ jos-dreapta, stil Gmail/Outlook)',
            'UI - Compose mutat din titleBar pe mobil (mai mult spatiu)',
            'UI - Buton albastru cu shadow, rounded corners',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.8 - 5 Apr 2026', [
            'UI - Android: hamburger menu button vizibil in titleBar',
            'UI - Sidebar toggle expand/compact pe mobil',
            'UI - Dialog actualizare cu changelog pe Android/iOS',
            'Security - GDPR consent opt-in (checkbox-uri nebifate default)',
            'Security - Permisiuni native notificari: Android 13+ POST_NOTIFICATIONS, iOS, macOS',
            'Compatibility - PaneDisplayMode.auto pe desktop, compact/expanded pe mobil',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.7 - 5 Apr 2026', [
            'Bugfix - Small fixes',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.6 - 5 Apr 2026', [
            'Bugfix - Small fixes',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.5 - 4 Apr 2026', [
            'Bugfix - Small fixes',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.4 - 4 Apr 2026', [
            'Bugfix - Small fixes',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.3 - 4 Apr 2026', [
            'UI - Android sidebar: minimal mode (hamburger menu) in loc de compact',
            'UI - Numele conturilor si folderele se vad complet pe ecrane mici',
            'UI - Sidebar se deschide ca drawer overlay cand apesi hamburger icon',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.2 - 4 Apr 2026', [
            'Compatibility - GrapheneOS: locale fallback (AppLocalizations null pe custom ROMs = ecran gri)',
            'Compatibility - l10nOf() helper cu English fallback in toate cele 12 views',
            'Compatibility - GlobalCupertinoLocalizations.delegate adaugat',
            'Compatibility - Process.runSync blocat pe Android (SELinux GrapheneOS)',
            'Compatibility - ErrorWidget.builder arata erori in loc de ecran gri',
            'Compatibility - ProGuard rules pentru flutter_secure_storage',
            'Compatibility - Document scanner doar pe iOS (fara Google Play dependency)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.1 - 4 Apr 2026', [
            'Compatibility - Impeller dezactivat (Skia fallback pentru GrapheneOS)',
            'Compatibility - Edge-to-edge display (eliminat dungi negre pe notch/cutout)',
            'Fix - APK signing v2+v3 pentru compatibilitate Android 9+',
            'Fix - R8 minify dezactivat (evita striparea claselor necesare)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.17.0 - 3 Apr 2026', [
            'Security - Certificate validation: verificare issuer Let\'s Encrypt + hostname (previne MITM)',
            'Security - Auto-update: verificare SHA-256 hash la download (previne code injection)',
            'Security - Master password: 100K iterații SHA-256 cu salt unic (previne rainbow tables)',
            'Security - Password fallback: XOR cu cheie derivată din machine info (înlocuiește base64)',
            'Security - updateAccount: validare server/ports (aceeași ca addAccount)',
            'Security - SMTP SIZE: conversie corectă bytes→KB conform RFC 1870',
            'Bug - IMAP/SMTP connection leak: disconnect în catch/finally pe toate error paths',
            'Bug - HttpClient leak: try/finally în changelog, log_upload, update service',
            'Bug - removeAccount: resetare _currentAccount la ștergere cont activ',
            'Bug - fetchEmails: null safety după await (eliminat force-unwrap)',
            'Bug - email_viewer: context capturat înainte de Navigator.pop() (Reply/Forward)',
            'Bug - auth_wrapper: mounted check după fiecare await+setState',
            'Bug - Lock file: cleanup la SIGINT/SIGTERM (previne false "already running")',
            'Performance - Process.runSync→Process.run async (nu mai blochează UI pe Windows)',
            'Performance - Compose window: timer rebuild 1s→10s',
            'Performance - fetchEmails: guard anti-concurență (_isFetching)',
            'Refactor - EmailProvider: dispose(), _disposed flag, fire-and-forget catchError',
            'Refactor - Certificate expiry monitor: tracking real 90 zile (nu hardcodat 365)',
            'Refactor - Settings: write lock pentru race condition settings.json',
            'Refactor - Timer leak fix în log_upload (cancel înainte de recreare)',
            'Fix - MSIX version sincronizat cu app version (2.16.1.0)',
            'Fix - .gitignore: exclus key.properties, certificates, SSH keys',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.16.1 - 22 Feb 2026', [
            '🔗 URL Fix - Link-urile lungi nu se mai rup în email (8bit encoding, rejoin broken URLs)',
            '📧 DSN (Delivery Status Notification) - Notificări automate de livrare email (RFC 3461)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.16.0 - 15 Feb 2026', [
            '📷 Document Scanner - Scanare documente cu camera (auto-crop, edge detection, perspective correction) pe Android și iOS',
            '🌍 Cross-Platform - Suport complet macOS, Windows, Linux, Android, iOS',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.15.6 - 1 Feb 2026', [
            '🔧 Clean Footer - Eliminat indicatori din footer (CPU/RAM/Ports/SPF/DKIM/IPv4/IPv6)',
            '📊 Server Diagnostics - Verificări conectivitate trimise în log spre server pentru diagnoză',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.15.5 - 1 Feb 2026', [
            '🌐 Server Changelog - Changelog-ul se încarcă de pe server (actualizări fără rebuild)',
            '📦 VC++ Redistributable - Installer include Visual C++ Runtime (instalare automată)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.15.4 - 1 Feb 2026', [
            '🔧 SSL Certificate Fix - Rezolvat CERTIFICATE_VERIFY_FAILED pe anumite mașini Windows',
            '🖥️ VM Compatibility - Aplicația funcționează corect pe orice mașină virtuală Windows',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.15.3 - 28 Ian 2026', [
            '🖥️ RDP Compatibility - Eliminat WebView complet (crash pe RDP sessions)',
            '🌐 External Browser - Link-uri deschise în browser extern (funcționează pe RDP)',
            '📧 HTML to Text - Emailuri HTML convertite la plain text (fără WebView)',
            '🗑️ Code Cleanup - Eliminat webview_windows dependency + web_browser_window.dart',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.15.2 - 28 Ian 2026', [
            '🐛 False Notifications Fix - Nu mai apar notificări la schimbarea contului (cache per-cont)',
          ]),
          const SizedBox(height: 16),
          _buildSection(theme, 'Version 2.0.0 - 16 Ian 2026', [
            'Complete rewrite from C# WPF to Flutter/Dart',
            'Modern Fluent Design System (Windows 11 style)',
          ]),
        ],
      ),
    );
  }

  Widget _buildSection(
      FluentThemeData theme, String title, List<String> items) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: theme.typography.subtitle?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        ...items.map((item) => Padding(
              padding: const EdgeInsets.only(left: 16, bottom: 4),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('• '),
                  Expanded(child: Text(item, style: theme.typography.body)),
                ],
              ),
            )),
      ],
    );
  }
}


