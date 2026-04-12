<div align="center">
  <img src="assets/logo.png" width="140" alt="ICD360S Mail">
  <h1>ICD360S Mail</h1>
  <p><strong>Secure, end-to-end encrypted email client</strong></p>
  <p>Built with Flutter for Windows, macOS, Linux, Android & iOS</p>

  <br/>

  [![Release](https://img.shields.io/github/v/release/ICD360S-e-V/mail?style=for-the-badge&logo=github&color=0078D4)](https://github.com/ICD360S-e-V/mail/releases/latest)
  [![Build](https://img.shields.io/github/actions/workflow/status/ICD360S-e-V/mail/build-all-platforms.yml?style=for-the-badge&label=build&color=107C10)](https://github.com/ICD360S-e-V/mail/actions)
  [![License](https://img.shields.io/github/license/ICD360S-e-V/mail?style=for-the-badge&color=3F51B5)](LICENSE)
  <br/>
  [![Flutter](https://img.shields.io/badge/Flutter-3.41+-02569B?style=for-the-badge&logo=flutter&logoColor=white)](https://flutter.dev)
  [![Dart](https://img.shields.io/badge/Dart-3.6+-0175C2?style=for-the-badge&logo=dart&logoColor=white)](https://dart.dev)
  [![OpenPGP](https://img.shields.io/badge/OpenPGP-RFC_9580-333333?style=for-the-badge&logo=gnuprivacyguard&logoColor=white)](https://www.rfc-editor.org/rfc/rfc9580)
</div>

---

## About

ICD360S Mail is a security-first email client built for [ICD360S e.V.](https://icd360s.de), a German nonprofit. It provides end-to-end encrypted email communication with a zero-knowledge architecture.

**Your emails are never stored on your device.** They are fetched live over mutually authenticated TLS and displayed in memory only. No forensic artifact remains after the app closes.

---

## Features

### Encryption

| | Feature | Details |
|---|---|---|
| | **E2EE Internal Mail** | OpenPGP (Ed25519 + X25519). Client encrypts before sending. Server never sees plaintext. |
| | **Zero-Access at Rest** | Incoming mail encrypted with recipient's PGP key on the server before storage. |
| | **Password-Protected Email** | Send encrypted email to anyone. Recipient opens a secure link, enters password, reads in browser. AES-256-GCM + PBKDF2, 100% client-side decryption. |
| | **WKD Key Discovery** | External clients (Thunderbird) auto-discover your public key via Web Key Directory. |

### Authentication

| | Feature | Details |
|---|---|---|
| | **Mutual TLS** | Per-user client certificates. No passwords on the wire. |
| | **Device Approval** | Admin-controlled device registration. Single-device enforcement. |
| | **Remote Revocation** | Admin revokes a device — app auto-wipes credentials and locks instantly. |
| | **PIN Unlock** | 6-digit PIN with randomized keypad layout. Defeats shoulder surfing, smudge attacks, thermal imaging. |

### Protection

| | Feature | Details |
|---|---|---|
| | **ClamAV Scanning** | Server-side antivirus on all attachments. Real-time UI: pending, scanning, clean, infected. |
| | **Threat Intelligence** | DMARC, DKIM, SPF validation. DNS blacklist checks. Sender reputation scoring. |
| | **Phishing Detection** | Safe Browsing hash prefix database with ECDSA signature verification. |
| | **CSS Sanitizer** | Blocks `url()`, `var()`, `expression()` tracking in HTML emails. No WebView. |

### Privacy

| | Feature | Details |
|---|---|---|
| | **RAM-Only Cache** | Emails exist only in process memory. Zero disk. Wiped on lock. |
| | **DNS-over-HTTPS** | Quad9 (RFC 8484 wireformat) + Cloudflare fallback. No cleartext DNS. |
| | **Notification Privacy** | Configurable: minimal / sender only / full content on lock screen. |
| | **No Telemetry** | Zero analytics. Zero tracking. Zero CDN dependencies. |

---

## Architecture

```
                        ┌─────────────────────────┐
                        │     ICD360S Mail App     │
                        │                         │
                        │  Master Vault (Argon2id) │
                        │  PGP Keys (Ed25519)     │
                        │  PIN (Randomized Keypad) │
                        │  RAM-Only Email Cache    │
                        │  Threat Intelligence     │
                        │  ClamAV Scan UI         │
                        └────────────┬────────────┘
                                     │
                              mTLS + DoH
                                     │
                        ┌────────────┴────────────┐
                        │    mail.icd360s.de       │
                        │                         │
                        │  HAProxy (mTLS frontend) │
                        │  Dovecot (SASL EXTERNAL) │
                        │  Postfix + rspamd        │
                        │  PGP SMTP Proxy          │
                        │  ClamAV + Valkey         │
                        │  WKD + Secure Reader     │
                        └─────────────────────────┘
```

---

## Platforms

| Platform | Formats | Signing |
|:---|:---|:---|
| **Windows** | Inno Setup `.exe` | ECDSA signature verification |
| **macOS** | `.dmg` | Ad-hoc + Hardened Runtime |
| **Linux** | `.deb` `.rpm` `.AppImage` `.tar.gz` | AppImage GPG-signed |
| **Android** | APK (universal, Samsung, Google Play, Huawei, F-Droid) + AAB | Keystore signed |
| **iOS** | `.ipa` | Ad-hoc |

---

## Security Audit

The codebase has been through **3 comprehensive security review rounds** with **39 issues identified and fixed**, including:

- Critical certificate validation bypass
- CSS tracking pixel prevention (Proton + Tuta pattern)
- Password hashing upgrade (PBKDF2 to Argon2id)
- DNS poisoning prevention via DoH
- PGP/MIME RFC 3156 compliance
- BCC privacy in encrypted mail
- TOFU key substitution detection

---

## Building from Source

```bash
# Prerequisites: Flutter 3.41+, Dart 3.6+

git clone https://github.com/ICD360S-e-V/mail.git
cd mail
flutter pub get

# Run
flutter run -d macos       # or: windows, linux

# Build release
flutter build macos --release
flutter build windows --release
flutter build linux --release
flutter build apk --release
```

<details>
<summary><strong>Platform-specific requirements</strong></summary>

| Platform | Requirements |
|:---|:---|
| Android | Java 17, Android SDK |
| iOS/macOS | Xcode 15+ |
| Linux | `libgtk-3-dev`, `libsecret-1-dev`, `libjsoncpp-dev` |
| Windows | Visual Studio 2022 with C++ workload |

</details>

---

## Versioning

Automated with [cocogitto](https://github.com/cocogitto/cocogitto) using [Conventional Commits](https://www.conventionalcommits.org/):

```
fix:      → patch    (2.39.0 → 2.39.1)
feat:     → minor    (2.39.0 → 2.40.0)
security: → minor    (2.39.0 → 2.40.0)
feat!:    → major    (2.39.0 → 3.0.0)
```

Every push to `main` with a releasable commit automatically bumps the version, creates a tag, and triggers a full multi-platform build.

---

## Tech Stack

| Layer | Technology |
|:---|:---|
| Framework | Flutter (Dart) |
| UI | Microsoft Fluent Design (`fluent_ui`) |
| Email | `enough_mail` (custom fork with SASL EXTERNAL) |
| Encryption | `dart_pg` (OpenPGP RFC 9580), `cryptography` (Argon2id, HKDF), `pointycastle` (AES-GCM, PBKDF2) |
| Server | AlmaLinux 10, Dovecot, Postfix, HAProxy, nginx, rspamd, ClamAV, Valkey, MariaDB |

---

## About ICD360S e.V.

ICD360S e.V. is a German nonprofit (*eingetragener Verein*) based in Berlin. This mail client was built to provide secure, privacy-respecting email communication for its members.

<div align="center">
  <a href="https://icd360s.de"><strong>icd360s.de</strong></a>
</div>
