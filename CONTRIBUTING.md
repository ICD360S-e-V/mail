# Contributing to ICD360S Mail

Thank you for your interest in contributing to ICD360S Mail.

## Reporting Bugs

1. Check existing [issues](https://github.com/ICD360S-e-V/mail/issues) to avoid duplicates
2. Open a new issue using the bug report template
3. Include: steps to reproduce, expected vs actual behavior, app version, platform

## Suggesting Features

Open an issue using the feature request template. Describe the problem you want to solve, not just the solution.

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:
   - `fix:` for bug fixes
   - `feat:` for new features
   - `security:` for security improvements
   - `docs:` for documentation
4. Run `flutter analyze` before submitting
5. Submit a pull request with a clear description

## Development Setup

```bash
git clone https://github.com/ICD360S-e-V/mail.git
cd mail
flutter pub get
flutter run
```

Requirements: Flutter 3.41+, Dart 3.6+

## Code Style

- Follow the [Dart style guide](https://dart.dev/effective-dart/style)
- Use `flutter analyze` to check for issues
- Prefer clear code over comments

## Security Vulnerabilities

Do NOT report security vulnerabilities as public issues. See [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0](LICENSE).
