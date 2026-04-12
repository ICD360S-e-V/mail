<p align="center">
  <img src="assets/logo.png" width="120" alt="ICD360S Mail">
</p>

<h1 align="center">ICD360S Mail</h1>

<p align="center">
  <strong>Secure, end-to-end encrypted email client for desktop and mobile</strong>
</p>

<p align="center">
  <a href="https://github.com/ICD360S-e-V/mail/releases/latest"><img src="https://img.shields.io/github/v/release/ICD360S-e-V/mail?style=flat-square" alt="Latest Release"></a>
  <a href="https://github.com/ICD360S-e-V/mail/actions"><img src="https://img.shields.io/github/actions/workflow/status/ICD360S-e-V/mail/build-all-platforms.yml?style=flat-square&label=build" alt="Build Status"></a>
  <a href="https://github.com/ICD360S-e-V/mail/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ICD360S-e-V/mail?style=flat-square" alt="License"></a>
</p>

<p align="center">
  Built with Flutter | Windows, macOS, Linux, Android, iOS
</p>

---

## What is ICD360S Mail?

A security-first email client built for [ICD360S e.V.](https://icd360s.de), a German nonprofit. Designed to protect email communication with end-to-end encryption, mutual TLS authentication, and zero local data storage.

**Your emails are never stored on your device.** They are fetched live over mTLS and displayed in memory only. No forensic artifact remains after the app closes.

## Security Features

### End-to-End Encryption (OpenPGP)
- **Internal mail** (@icd360s.de to @icd360s.de): automatically encrypted client-side before sending. The server never sees plaintext.
- **Incoming mail**: encrypted at rest on the server with recipient's PGP public key (zero-access model).
- **External recipients**: optional password-protected encrypted email with a secure web reader (AES-256-GCM, PBKDF2 key derivation, client-side decryption via WebCrypto API).
- **WKD** (Web Key Directory) for automatic key discovery by external clients (Thunderbird, etc.).

### Authentication & Access Control
- **Mutual TLS (mTLS)**: per-user client certificates. No passwords on the wire.
- **SASL EXTERNAL**: passwordless IMAP/SMTP authentication via certificate CN.
- **Device approval**: admin-controlled device registration with single-device enforcement.
- **Remote revocation**: admin revokes a device, app auto-wipes credentials and locks.

### App Security
- **Master password**: Argon2id (64 MiB, 3 iterations) vault encryption (Bitwarden architecture).
- **PIN unlock**: 6-digit PIN with randomized keypad (anti-shoulder-surfing, anti-smudge). Argon2id 19 MiB KDF, progressive lockout.
- **Auto-lock**: 5-minute inactivity timeout. All keys wiped from memory.
- **RAM-only cache**: emails exist only in process memory. Zero disk artifacts. Wiped on lock.
- **Hardened Runtime**: enabled on macOS (blocks DYLD injection).

### Threat Detection
- **ClamAV scanning**: server-side antivirus on all attachments with real-time UI status (pending/scanning/clean/infected).
- **Threat intelligence**: DMARC/DKIM/SPF validation, DNS blacklist checks, sender reputation scoring.
- **Phishing detection**: Safe Browsing hash prefix database with ECDSA signature verification.
- **Safe HTML rendering**: full CSS sanitizer (blocks `url()`, `var()`, `expression()` tracking), no WebView.

### Network Security
- **Certificate pinning**: ISRG (Let's Encrypt) roots only on all platforms.
- **DNS-over-HTTPS**: Quad9 (RFC 8484 wireformat) + Cloudflare fallback. No cleartext DNS.
- **DANE + DNSSEC + MTA-STS**: transport-level email security on the server.

### Privacy
- **Notification privacy**: configurable content level (none / sender only / full).
- **No telemetry**: zero analytics, zero tracking, zero CDN dependencies.
- **PII redaction**: personal data stripped from diagnostic logs.
- **GDPR compliant**: data minimization by design.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     ICD360S Mail App                          │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────┐  │
│  │ Master  │  │   PIN    │  │  PGP    │  │   Threat     │  │
│  │ Vault   │  │ Unlock   │  │ Key     │  │   Intel      │  │
│  │(Argon2) │  │(Random   │  │ Service │  │  (DMARC/     │  │
│  │         │  │ Keypad)  │  │(dart_pg)│  │   DKIM/SPF)  │  │
│  └────┬────┘  └────┬─────┘  └────┬────┘  └──────┬───────┘  │
│       │            │             │               │          │
│  ┌────┴────────────┴─────────────┴───────────────┴───────┐  │
│  │              RAM-Only Session Cache                    │  │
│  │         (zero disk, wiped on lock/close)               │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│                    mTLS + DoH                                │
└──────────────────────────┼───────────────────────────────────┘
                           │
┌──────────────────────────┼───────────────────────────────────┐
│                  mail.icd360s.de                              │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────┐  │
│  │HAProxy  │  │ Dovecot  │  │Postfix  │  │  PGP SMTP    │  │
│  │(mTLS    │  │ (IMAP    │  │(MTA +   │  │  Proxy       │  │
│  │frontend)│  │  SASL    │  │ rspamd) │  │  (aiosmtpd)  │  │
│  │         │  │  EXT)    │  │         │  │              │  │
│  └─────────┘  └──────────┘  └─────────┘  └──────────────┘  │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────┐  │
│  │ClamAV   │  │ Valkey   │  │ WKD     │  │  Secure Mail │  │
│  │(AV scan)│  │ (cache)  │  │ (keys)  │  │  Reader      │  │
│  └─────────┘  └──────────┘  └─────────┘  └──────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Platforms

| Platform | Format | Auto-Update |
|----------|--------|-------------|
| **Windows** | Inno Setup `.exe` | ECDSA-signed version check |
| **macOS** | `.dmg` (ad-hoc signed, Hardened Runtime) | ECDSA-signed version check |
| **Linux** | `.deb`, `.rpm`, `.AppImage` (GPG-signed), `.tar.gz` | ECDSA-signed version check |
| **Android** | APK (universal, Samsung, Google Play, Huawei, F-Droid) + AAB | ECDSA-signed version check |
| **iOS** | `.ipa` (ad-hoc) | ECDSA-signed version check |

## Building from Source

### Prerequisites
- Flutter SDK 3.41+
- Dart SDK 3.6+
- For Android: Java 17, Android SDK
- For iOS/macOS: Xcode 15+
- For Linux: `libgtk-3-dev`, `libsecret-1-dev`, `libjsoncpp-dev`
- For Windows: Visual Studio 2022 with C++ workload

### Build

```bash
# Clone
git clone https://github.com/ICD360S-e-V/mail.git
cd mail

# Get dependencies
flutter pub get

# Run (desktop)
flutter run -d macos    # or: windows, linux

# Build release
flutter build macos --release
flutter build windows --release
flutter build linux --release
flutter build apk --release
flutter build ipa --release
```

## Versioning

Automated with [cocogitto](https://github.com/cocogitto/cocogitto). Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Version Bump | Example |
|--------|-------------|---------|
| `fix:` | Patch | `fix: repair IMAP reconnect` |
| `feat:` | Minor | `feat: add calendar sync` |
| `security:` | Minor | `security: fix cert validation` |
| `feat!:` | Major | `feat!: new auth protocol` |
| `ci:`, `docs:`, `chore:` | No release | `ci: update workflow` |

## Tech Stack

- **Framework**: Flutter (Dart)
- **UI**: Microsoft Fluent Design (`fluent_ui`)
- **Email**: `enough_mail` (custom fork with SASL EXTERNAL)
- **Crypto**: `dart_pg` (OpenPGP), `cryptography` (Argon2id, HKDF, AES-GCM), `pointycastle` (PBKDF2)
- **Server**: AlmaLinux 10, Dovecot, Postfix, HAProxy, nginx, rspamd, ClamAV, Valkey

## Security Audit

The codebase has been through a comprehensive security audit with **39 issues identified and fixed** across 3 review rounds, covering:

- Certificate validation bypass (critical)
- CSS tracking pixel prevention
- Password hashing upgrade (PBKDF2 → Argon2id)
- DNS poisoning prevention (DoH)
- mTLS endpoint authentication
- Attachment scanning
- PGP/MIME RFC 3156 compliance
- BCC privacy in encrypted mail
- TOFU key verification

## License

See [LICENSE](LICENSE) for details.

## About ICD360S e.V.

ICD360S e.V. is a German nonprofit (eingetragener Verein) based in Berlin. This mail client was built to provide secure, privacy-respecting email communication for its members.

- Website: [icd360s.de](https://icd360s.de)
- Mail: [mail.icd360s.de](https://mail.icd360s.de)
