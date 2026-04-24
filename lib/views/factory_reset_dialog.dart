// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import '../services/account_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import '../services/portable_secure_storage.dart';

/// Factory Reset dialog with typed-confirmation phrase.
///
/// SECURITY (M6): The previous implementation placed the Factory Reset button
/// on the master-password LOCK screen — accessible pre-authentication. An
/// attacker with brief physical access (30 seconds with the app locked) could
/// wipe all data with two clicks, losing accounts, credentials, and settings.
/// That was a sabotage vector with no barrier.
///
/// This version:
///   1. Is NOT available on the lock screen (only post-login from the main UI)
///   2. Requires the user to type the exact phrase "DELETE" to enable the
///      destructive action (prevents click-through from habit)
///   3. Scopes secure-storage deletion to our own keys only (no blanket
///      `FlutterSecureStorage.deleteAll()` which could theoretically affect
///      other data in shared namespaces)
class FactoryResetDialog {
  static const String _confirmationPhrase = 'DELETE';

  /// Show the factory reset dialog. Returns true if the user actually reset.
  static Future<bool> show(BuildContext context) async {
    final accountService = AccountService();
    // Load the current account list so we know which secure-storage keys to remove
    try {
      await accountService.loadAccountsAsync();
    } catch (_) {
      // If loading fails, continue — the reset will still clean up what it can
    }
    final accountUsernames =
        accountService.accounts.map((a) => a.username).toList();

    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: true,
      builder: (ctx) => _ConfirmPhraseDialog(
        phrase: _confirmationPhrase,
        accountCount: accountUsernames.length,
      ),
    );

    if (confirmed != true) return false;

    // The user typed DELETE and confirmed. Perform the reset.
    try {
      await _performReset(accountUsernames);

      LoggerService.log('RESET', '✓✓✓ FACTORY RESET COMPLETE - restarting app...');

      // Restart/exit the app
      final platform = PlatformService.instance;
      if (platform.isDesktop) {
        final exePath = Platform.resolvedExecutable;
        await Process.start(exePath, [], mode: ProcessStartMode.detached);
        exit(0);
      } else {
        SystemNavigator.pop();
      }
      return true;
    } catch (ex, stackTrace) {
      LoggerService.logError('RESET', ex, stackTrace);
      if (context.mounted) {
        await showDialog(
          context: context,
          builder: (ctx) => ContentDialog(
            title: const Text('Reset failed'),
            content: Text('Factory reset encountered an error: $ex'),
            actions: [
              Button(
                child: const Text('OK'),
                onPressed: () => Navigator.of(ctx).pop(),
              ),
            ],
          ),
        );
      }
      return false;
    }
  }

  /// Perform the actual data deletion. Split out so the UI flow is testable.
  static Future<void> _performReset(List<String> accountUsernames) async {
    final platform = PlatformService.instance;
    final appDataPath = platform.appDataPath;

    // 1. SCOPE-LIMITED secure storage deletion — only delete keys we own.
    //    NOT FlutterSecureStorage.deleteAll() because that can affect other
    //    keys in shared namespaces on some platforms.
    // PortableSecureStorage uses native storage on iOS/Android/Windows/
    // Linux and AES-GCM file backend on macOS (no Keychain calls).
    final storage = PortableSecureStorage.instance;
    for (final username in accountUsernames) {
      try {
        await storage.delete(key: 'icd360s_mail_password_$username');
        LoggerService.log('RESET', '✓ Deleted secure storage key for $username');
      } catch (ex) {
        LoggerService.log('RESET', '⚠ Could not delete key for $username: $ex');
      }
    }

    // 2. Wipe the in-memory session key (M4)
    AccountService.lockSession();

    // 3. Delete master password hash + rate limit state
    for (final name in [
      '.master_password_hash',
      '.master_password_attempts',
      '.passwords',
      '.passwords.salt',
      '.enc_key',
      'accounts.json',
      'settings.json',
      'email_history.json',
      'trash_dates.json',
    ]) {
      final f = File(p.join(appDataPath, name));
      if (await f.exists()) {
        try {
          await f.delete();
          LoggerService.log('RESET', '✓ Deleted $name');
        } catch (ex) {
          LoggerService.log('RESET', '⚠ Could not delete $name: $ex');
        }
      }
    }

    // 4. Delete the entire app data folder (removes any leftover files)
    final appFolder = Directory(appDataPath);
    if (await appFolder.exists()) {
      try {
        await appFolder.delete(recursive: true);
        LoggerService.log('RESET', '✓ Deleted app data folder');
      } catch (ex) {
        LoggerService.log('RESET', '⚠ Could not delete app data folder: $ex');
      }
    }
  }
}

/// Private stateful dialog that enables the destructive button only when the
/// user has typed the exact confirmation phrase.
class _ConfirmPhraseDialog extends StatefulWidget {
  final String phrase;
  final int accountCount;

  const _ConfirmPhraseDialog({
    required this.phrase,
    required this.accountCount,
  });

  @override
  State<_ConfirmPhraseDialog> createState() => _ConfirmPhraseDialogState();
}

class _ConfirmPhraseDialogState extends State<_ConfirmPhraseDialog> {
  final _controller = TextEditingController();
  bool _matches = false;

  @override
  void initState() {
    super.initState();
    _controller.addListener(() {
      final matches = _controller.text == widget.phrase;
      if (matches != _matches) {
        setState(() => _matches = matches);
      }
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ContentDialog(
      title: Row(
        children: [
          ExcludeSemantics(child: Icon(FluentIcons.warning, color: Colors.red, size: 24)),
          const SizedBox(width: 8),
          const Text('Factory Reset'),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'This will PERMANENTLY delete:',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          Text('  • ${widget.accountCount} account(s) and their credentials'),
          const Text('  • Master password'),
          const Text('  • All settings and cached data'),
          const Text('  • Email history and trash countdowns'),
          const SizedBox(height: 16),
          Text(
            'This action CANNOT be undone.',
            style: TextStyle(fontWeight: FontWeight.bold, color: Colors.red),
          ),
          const SizedBox(height: 16),
          Text('Type ${widget.phrase} to confirm:'),
          const SizedBox(height: 8),
          TextBox(
            controller: _controller,
            placeholder: widget.phrase,
            autofocus: true,
          ),
        ],
      ),
      actions: [
        Button(
          child: const Text('Cancel'),
          onPressed: () => Navigator.of(context).pop(false),
        ),
        FilledButton(
          style: ButtonStyle(
            backgroundColor: WidgetStateProperty.resolveWith((states) {
              if (!_matches || states.contains(WidgetState.disabled)) {
                return Colors.grey;
              }
              return Colors.red;
            }),
          ),
          onPressed: _matches ? () => Navigator.of(context).pop(true) : null,
          child: const Text('Reset Everything'),
        ),
      ],
    );
  }
}