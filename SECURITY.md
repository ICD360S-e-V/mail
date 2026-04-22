# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ICD360S Mail, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Send an encrypted email to:

**security@icd360s.de**

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

### Scope

The following are in scope:
- The ICD360S Mail client application (this repository)
- The cryptographic implementation (OpenPGP, key management, vault encryption)
- Authentication and authorization flows (mTLS, device approval, PIN)
- Data leakage or privacy violations

The following are out of scope:
- The operational mail server infrastructure (report to security@icd360s.de directly)
- Denial of service attacks
- Social engineering

### Recognition

We appreciate responsible disclosure. Contributors who report valid vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous releases | No |
