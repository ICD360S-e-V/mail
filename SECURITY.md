# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ICD360S Mail, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Send an encrypted email to:

**security@icd360s.de**

You can encrypt your report using our WKD-published public key, discoverable automatically by any OpenPGP-compatible client.

Include:
- A description of the vulnerability
- Steps to reproduce
- Affected versions (if known)
- Any potential impact assessment

### Response Timeline

| Stage | Timeline |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

---

## Scope

### In Scope

- The ICD360S Mail client application (this repository)
- End-to-end encryption implementation (OpenPGP, key management, vault)
- Authentication and authorization (mTLS, device approval, PIN unlock)
- Secure storage (master vault, key sync, credential handling)
- Data leakage or privacy violations (PII in logs, unintended network requests)
- Attachment handling and scanning
- HTML rendering and phishing detection

### Out of Scope

- The operational mail server infrastructure (report to security@icd360s.de directly)
- Denial of service attacks
- Social engineering
- Issues in third-party dependencies (report upstream, then notify us)

---

## Cryptographic Standards

| Component | Algorithm | Standard |
|---|---|---|
| Signing | Ed25519 (EdDSA) | RFC 8032 |
| Encryption | X25519 / ECDH | RFC 7748 |
| Message format | OpenPGP | RFC 9580, RFC 3156 |
| Vault key derivation | Argon2id | RFC 9106 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Key sync derivation | HKDF-SHA256 | RFC 5869 |
| Transport security | TLS 1.2+ (FUTURE policy) | RFC 8446 |

---

## Security Model

### What We Protect Against

- **Server compromise**: E2EE ensures the server cannot read internal mail content, even if fully compromised.
- **Credential theft**: Master vault uses Argon2id; credentials never leave the device unencrypted.
- **Key substitution (MITM)**: Persistent TOFU database tracks recipient key fingerprints across sessions. Internal keys are auto-trusted (server-managed); external key changes trigger user confirmation.
- **Device loss**: Remote revocation instantly wipes all credentials. PIN with randomized keypad prevents shoulder surfing.
- **Log exposure**: Automatic PII redaction strips email addresses, IPs, phone numbers, and subjects from all diagnostic logs before storage or upload.

### What We Do Not Protect Against

- **Subject line visibility**: Subject lines are visible in outer SMTP headers (standard PGP/MIME limitation).
- **Metadata analysis**: Sender, recipient, date, and message size are visible to the mail server and network observers.
- **Compromised endpoint**: If the device itself is compromised (root access, malware), encryption cannot help.
- **External recipients**: E2EE only applies between `@icd360s.de` addresses. External emails are sent in cleartext (or via optional password-protected links).

---

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous releases | No |

---

## Recognition

We appreciate responsible disclosure. Contributors who report valid vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).
