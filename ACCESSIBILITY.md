# Accessibility Statement

ICD360S Mail is designed following **WCAG 2.1 Level AA** guidelines to ensure usability for people with disabilities.

## What We Do

- **Screen reader support**: All interactive elements (buttons, inputs, status indicators) have descriptive labels for TalkBack (Android) and VoiceOver (iOS/macOS)
- **Keyboard navigation**: Full keyboard access on desktop platforms via Fluent UI's built-in focus management
- **High contrast mode**: Dedicated high-contrast themes for both light and dark modes
- **Font scaling**: Respects system font size preferences on all platforms
- **Color independence**: Status indicators use text labels alongside colors, not color alone
- **Decorative elements**: Non-informative icons are hidden from assistive technology per WCAG 1.1.1

## Known Limitations

- HTML email rendering relies on `flutter_widget_from_html_core` which may not fully expose all HTML semantics to screen readers
- Some third-party dialog components may have limited keyboard trap management
- Right-to-left (RTL) language support has not been tested

## Feedback

If you encounter accessibility barriers, please report them:

- **Email**: kontakt@icd360s.de
- **GitHub Issues**: [Open an issue](https://github.com/ICD360S-e-V/mail/issues)

We are committed to improving accessibility and welcome all feedback.
