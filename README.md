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

## Download

> All downloads are served over HTTPS from `mail.icd360s.de` with ECDSA-signed version verification.

### Desktop

<table>
<tr>
<td align="center" width="200">
<br/>
<a href="https://mail.icd360s.de/downloads/mail/windows/icd360s-mail-setup.exe"><strong>Windows</strong></a><br/>
<sub>Inno Setup Installer (.exe)</sub><br/><br/>
<a href="https://mail.icd360s.de/downloads/mail/windows/icd360s-mail-setup.exe">
<img src="https://img.shields.io/badge/Download-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows"/>
</a><br/><br/>
<img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=https://mail.icd360s.de/downloads/mail/windows/icd360s-mail-setup.exe" width="120" alt="QR Windows"/>
</td>
<td align="center" width="200">
<br/>
<a href="https://mail.icd360s.de/downloads/mail/macos/icd360s-mail.dmg"><strong>macOS</strong></a><br/>
<sub>DMG (Ad-hoc + Hardened Runtime)</sub><br/><br/>
<a href="https://mail.icd360s.de/downloads/mail/macos/icd360s-mail.dmg">
<img src="https://img.shields.io/badge/Download-macOS-000000?style=for-the-badge&logo=apple&logoColor=white" alt="macOS"/>
</a><br/><br/>
<img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=https://mail.icd360s.de/downloads/mail/macos/icd360s-mail.dmg" width="120" alt="QR macOS"/>
</td>
<td align="center" width="200">
<br/>
<strong>Linux</strong><br/>
<sub>DEB, RPM, AppImage, tar.gz</sub><br/><br/>
<a href="https://mail.icd360s.de/downloads/mail/linux/icd360s-mail.deb">
<img src="https://img.shields.io/badge/DEB-Download-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="DEB"/>
</a>
<a href="https://mail.icd360s.de/downloads/mail/linux/icd360s-mail.rpm">
<img src="https://img.shields.io/badge/RPM-Download-0B57A4?style=flat-square&logo=redhat&logoColor=white" alt="RPM"/>
</a><br/>
<a href="https://mail.icd360s.de/downloads/mail/linux/icd360s-mail.AppImage">
<img src="https://img.shields.io/badge/AppImage-Download-333333?style=flat-square&logo=linux&logoColor=white" alt="AppImage"/>
</a>
<a href="https://mail.icd360s.de/downloads/mail/linux/icd360s-mail-linux.tar.gz">
<img src="https://img.shields.io/badge/tar.gz-Download-555555?style=flat-square" alt="tar.gz"/>
</a><br/><br/>
<img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=https://mail.icd360s.de/downloads/mail/linux/icd360s-mail.AppImage" width="120" alt="QR Linux"/>
</td>
</tr>
</table>

### Mobile

<table>
<tr>
<td align="center" width="250">
<br/>
<strong>Android</strong><br/>
<sub>APK — multiple flavors</sub><br/><br/>
<a href="https://mail.icd360s.de/downloads/mail/android/universal/app-arm64-v8a-universal-release.apk">
<img src="https://img.shields.io/badge/Universal_(ARM64)-Download-3DDC84?style=for-the-badge&logo=android&logoColor=white" alt="Android Universal"/>
</a><br/>
<a href="https://mail.icd360s.de/downloads/mail/android/fdroid/app-arm64-v8a-fdroid-release.apk">
<img src="https://img.shields.io/badge/F--Droid_(ARM64)-Download-1976D2?style=flat-square&logo=fdroid&logoColor=white" alt="F-Droid"/>
</a>
<a href="https://mail.icd360s.de/downloads/mail/android/samsung/app-arm64-v8a-samsung-release.apk">
<img src="https://img.shields.io/badge/Samsung_(ARM64)-Download-1428A0?style=flat-square&logo=samsung&logoColor=white" alt="Samsung"/>
</a><br/>
<a href="https://mail.icd360s.de/downloads/mail/android/huawei/app-arm64-v8a-huawei-release.apk">
<img src="https://img.shields.io/badge/Huawei_(ARM64)-Download-C71A36?style=flat-square&logo=huawei&logoColor=white" alt="Huawei"/>
</a>
<a href="https://mail.icd360s.de/downloads/mail/android/googleplay/app-arm64-v8a-googleplay-release.apk">
<img src="https://img.shields.io/badge/Google_Play_(ARM64)-Download-414141?style=flat-square&logo=googleplay&logoColor=white" alt="Google Play"/>
</a><br/><br/>
<img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=https://mail.icd360s.de/downloads/mail/android/universal/app-arm64-v8a-universal-release.apk" width="120" alt="QR Android"/>
</td>
<td align="center" width="250">
<br/>
<strong>iOS</strong><br/>
<sub>IPA (Ad-hoc sideload)</sub><br/><br/>
<a href="https://mail.icd360s.de/downloads/mail/ios/icd360s-mail.ipa">
<img src="https://img.shields.io/badge/Download-iOS-000000?style=for-the-badge&logo=apple&logoColor=white" alt="iOS"/>
</a><br/><br/>
<img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=https://mail.icd360s.de/downloads/mail/ios/icd360s-mail.ipa" width="120" alt="QR iOS"/>
</td>
</tr>
</table>

<details>
<summary><strong>Other Android architectures (ARMv7, x86_64)</strong></summary>

| Flavor | ARMv7 | x86_64 |
|:---|:---|:---|
| Universal | [Download](https://mail.icd360s.de/downloads/mail/android/universal/app-armeabi-v7a-universal-release.apk) | [Download](https://mail.icd360s.de/downloads/mail/android/universal/app-x86_64-universal-release.apk) |
| F-Droid | [Download](https://mail.icd360s.de/downloads/mail/android/fdroid/app-armeabi-v7a-fdroid-release.apk) | [Download](https://mail.icd360s.de/downloads/mail/android/fdroid/app-x86_64-fdroid-release.apk) |
| Samsung | [Download](https://mail.icd360s.de/downloads/mail/android/samsung/app-armeabi-v7a-samsung-release.apk) | [Download](https://mail.icd360s.de/downloads/mail/android/samsung/app-x86_64-samsung-release.apk) |
| Google Play | [Download](https://mail.icd360s.de/downloads/mail/android/googleplay/app-armeabi-v7a-googleplay-release.apk) | [Download](https://mail.icd360s.de/downloads/mail/android/googleplay/app-x86_64-googleplay-release.apk) |
| Huawei | [Download](https://mail.icd360s.de/downloads/mail/android/huawei/app-armeabi-v7a-huawei-release.apk) | [Download](https://mail.icd360s.de/downloads/mail/android/huawei/app-x86_64-huawei-release.apk) |
| Google Play AAB | — | [Download AAB](https://mail.icd360s.de/downloads/mail/android/googleplay/icd360s-mail.aab) |

</details>

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

[ICD360S e.V.](https://icd360s.de) is a registered German nonprofit (*eingetragener Verein*) based in Berlin.

This email client is designed for **professional communication** — both within the association and with external institutions, organizations, and individuals. Members use their `@icd360s.de` address to communicate securely with government agencies, partners, legal contacts, and each other.

### Membership Benefits

Every active member receives a free, secure email account:

| | Benefit |
|---|---|
| | **Unlimited** incoming emails |
| | **500 MB** mailbox storage per account |
| | **10 emails/day** sending limit (3 per hour) |
| | **End-to-end encrypted** communication with all members |
| | **Cross-platform** access — Windows, macOS, Linux, Android, iOS |
| | **Professional @icd360s.de** email address |

### How to Get Access

1. Become a member of ICD360S e.V.
2. The administrator creates your email account and approves your device.
3. The app generates your encryption keys automatically on first login.
4. Start communicating — internally encrypted, externally professional.

The service is **free for all active members**. When a membership ends, the administrator revokes access and the app automatically wipes all credentials from the device.

> This service is provided exclusively to members of ICD360S e.V. as part of their membership, in compliance with German nonprofit law (BGB §§21-79, AO §§51-68) and GDPR/DSGVO. Running a member email service is a [routine practice](https://www.ccc.de) among German nonprofits. No TKG telecommunications registration is required for internal member services.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE).

If you use this code, please credit **ICD360S e.V.** as the original author.

<div align="center">
  <br/>
  <a href="https://icd360s.de"><strong>icd360s.de</strong></a>
  <br/><br/>
</div>
