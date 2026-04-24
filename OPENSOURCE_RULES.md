# Open Source Documentation Rules

Checklist for ICD360S Mail — AGPL-3.0 nonprofit project (German e.V.)

## MANDATORY (Legally Required)

| # | Item | File | Status | Notes |
|---|------|------|--------|-------|
| 1 | License full text | `LICENSE` | | AGPL-3.0, must be in repo root |
| 2 | SPDX headers in source files | Each `.dart` file | | `// SPDX-License-Identifier: AGPL-3.0-or-later` |
| 3 | Source code access link in app | In-app UI | | AGPL Section 13: network users must be offered source code |
| 4 | Prominent modification notices | `LICENSE` / source | | AGPL Sections 4, 5: state modifications and dates |
| 5 | Privacy Policy / Datenschutzerklarung | Website or in-app | | GDPR: if processing personal data |
| 6 | Impressum / Legal Notice | Website | | German TMG/DDG: full name, address, contact, VR number |

## RECOMMENDED (Best Practices)

| # | Item | File | Notes |
|---|------|------|-------|
| 7 | Project description + install | `README.md` | What it does, how to build, download links |
| 8 | Security vulnerability reporting | `SECURITY.md` | How to report, response timeline, scope |
| 9 | Accessibility statement | `ACCESSIBILITY.md` | WCAG level, known limitations, contact |
| 10 | Contribution guidelines | `CONTRIBUTING.md` | How to report bugs, coding standards, PR process |
| 11 | Code of conduct | `CODE_OF_CONDUCT.md` | Contributor Covenant or similar |
| 12 | Changelog | `CHANGELOG.md` | Version history, categorized by Added/Changed/Fixed/Security |
| 13 | Bug report template | `.github/ISSUE_TEMPLATE/bug_report.yml` | Structured form for bug reports |
| 14 | Feature request template | `.github/ISSUE_TEMPLATE/feature_request.yml` | Structured form for feature requests |
| 15 | PR template | `.github/PULL_REQUEST_TEMPLATE.md` | Checklist for pull requests |
| 16 | Dependency updates | `.github/dependabot.yml` | Automated security updates |

## OPTIONAL (Nice to Have)

| # | Item | File | Notes |
|---|------|------|-------|
| 17 | Authors / contributors list | `AUTHORS` | Optional — git log is authoritative |
| 18 | Roadmap | `ROADMAP.md` | Planned features and timeline |
| 19 | Support info | `SUPPORT.md` | How to get help |
| 20 | Citation info | `CITATION.cff` | For academic references |
| 21 | Editor config | `.editorconfig` | Consistent coding style |
| 22 | SBOM | Auto-generated | Software Bill of Materials (mandatory EU 2027) |

## README Rules (What to Include / Exclude)

### INCLUDE in public README:
- What the app does (user-facing description)
- Download links and platform support
- High-level feature list (user benefits, not implementation)
- Build instructions for contributors
- Cryptographic standards used (algorithms, RFCs)
- License and contribution terms
- Links to SECURITY.md, ACCESSIBILITY.md, CONTRIBUTING.md

### NEVER include in public README:
- Server IP addresses, hostnames, or port numbers
- Specific server software names and versions
- Firewall rules or security tool configurations
- Database schemas or API endpoint paths
- Admin panel URLs
- Deployment scripts or CI/CD secrets setup
- Internal infrastructure topology
- Security audit details with specific vulnerabilities found
- Personnel information or internal team structure

### Principle:
Describe WHAT the system does and WHY, never HOW the server is configured.
A public README is a landing page for users, not an operations manual.

## German-Specific Notes

- **Impressum**: Required on any website/service. Must include: organization name + legal form (e.V.), full address, email, phone, Vereinsregister number and court.
- **AGPL warranty disclaimer**: Not fully enforceable in Germany — liability cannot be excluded for gross negligence or damage to life/body/health under BGB.
- **GDPR**: If the app processes personal data (email addresses, logs), a privacy policy is legally required.
- **EU CRA (2026-2027)**: Nonprofit development is exempt from the Cyber Resilience Act, provided all earnings after costs are used for nonprofit objectives.
- **BFSG/EAA (Accessibility)**: Does not apply to internal-use apps for nonprofit members. Only applies to consumer-facing commercial digital services.

## Sources

- [GNU AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)
- [REUSE Specification](https://reuse.software/spec-3.3/)
- [OpenSSF Best Practices Badge](https://www.bestpractices.dev/en/criteria/0)
- [GitHub Community Standards](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories)
- [Keep a Changelog](https://keepachangelog.com/)
- [Contributor Covenant](https://www.contributor-covenant.org/)
- [German Impressum Law (TMG/DDG)](https://www.ionos.com/digitalguide/websites/digital-law/a-case-for-thinking-global-germanys-impressum-laws/)
- [GDPR and Open Source](https://www.termsfeed.com/blog/gdpr-open-source/)
- [EU CRA Open Source Exemption](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source)
