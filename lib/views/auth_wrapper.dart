// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:fluent_ui/fluent_ui.dart';
import 'package:path_provider/path_provider.dart';
import 'package:window_manager/window_manager.dart';
import '../services/master_password_service.dart';
import '../services/settings_service.dart';
import '../services/log_upload_service.dart';
import '../services/notification_service.dart';
import '../services/logger_service.dart';
import '../services/platform_service.dart';
import 'add_account_dialog.dart';
import 'first_run_consent_dialog.dart';
import 'master_password_dialog.dart';
import 'main_window.dart';

/// Authentication wrapper - shows master password dialog at startup
class AuthWrapper extends StatefulWidget {
  const AuthWrapper({super.key});

  @override
  State<AuthWrapper> createState() => _AuthWrapperState();
}

class _AuthWrapperState extends State<AuthWrapper> {
  bool _isAuthenticated = false;
  bool _isChecking = true;

  @override
  void initState() {
    super.initState();
    // Wait for first frame to be rendered before showing dialogs
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _checkAuthentication();
    });
  }

  Future<void> _checkAuthentication() async {
    // Check if first run
    if (SettingsService.isFirstRun()) {
      // Show consent dialog first
      if (mounted) {
        final consent = await showDialog<Map<String, bool>>(
          context: context,
          barrierDismissible: false,
          builder: (context) => const FirstRunConsentDialog(),
        );

        if (consent != null) {
          // Save preferences
          await SettingsService.saveSettings(
            autoUpdateEnabled: consent['autoUpdate'] ?? true,
            loggingEnabled: consent['logging'] ?? true,
            notificationsEnabled: consent['notifications'] ?? true,
          );

          // Enable logging if user consented
          LogUploadService.setLoggingEnabled(consent['logging'] ?? true);
          if (consent['logging'] == true) {
            LogUploadService.startAutoUpload();
          }

          // Enable notifications if user consented
          NotificationService.setNotificationsEnabled(consent['notifications'] ?? true);
        }
      }
    } else {
      // Load existing settings
      final loggingEnabled = await SettingsService.getLoggingEnabled();
      LogUploadService.setLoggingEnabled(loggingEnabled);
      if (loggingEnabled) {
        LogUploadService.startAutoUpload();
      }

      // Load notifications preference
      final notificationsEnabled = await SettingsService.getNotificationsEnabled();
      NotificationService.setNotificationsEnabled(notificationsEnabled);
    }

    // Check if master password is required
    final hasPassword = await MasterPasswordService.hasMasterPassword();

    if (!hasPassword) {
      // First-time setup — set master password, then add first account
      if (mounted) {
        final result = await _showMasterPasswordDialog();
        if (result && mounted && await _hasNoAccounts()) {
          await _showFirstAccountWizard();
        }
        if (mounted) {
          setState(() {
            _isAuthenticated = result;
            _isChecking = false;
          });
        }
      }
    } else {
      // Cold start — master password required
      if (mounted) {
        setState(() => _isChecking = false);
        final result = await _showMasterPasswordDialog();
        if (mounted) {
          setState(() => _isAuthenticated = result);
        }
      }
    }
  }

  bool _showingPasswordScreen = false;

  Future<bool> _showMasterPasswordDialog() async {
    setState(() => _showingPasswordScreen = true);
    final completer = _passwordCompleter = Completer<bool>();
    final result = await completer.future;

    if (result && PlatformService.instance.isDesktop) {
      try {
        await windowManager.maximize();
        LoggerService.log('WINDOW', 'Window maximized after authentication');
      } catch (ex, stackTrace) {
        LoggerService.logError('WINDOW', ex, stackTrace);
      }
    }

    return result;
  }

  Completer<bool>? _passwordCompleter;

  void _onPasswordResult(bool success) {
    _passwordCompleter?.complete(success);
    _passwordCompleter = null;
    if (mounted) {
      setState(() {
        _showingPasswordScreen = false;
        _isAuthenticated = success;
      });
    }
  }

  Future<bool> _hasNoAccounts() async {
    try {
      final dir = await getApplicationSupportDirectory();
      final file = File('${dir.path}/accounts.json');
      if (!await file.exists()) return true;
      final content = await file.readAsString();
      final list = jsonDecode(content) as List<dynamic>;
      return list.isEmpty;
    } catch (_) {
      return true;
    }
  }

  Future<void> _showFirstAccountWizard() async {
    if (!mounted) return;
    LoggerService.log('WIZARD', 'First-run: showing add account wizard');
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AddAccountDialog(),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_isChecking) {
      // Show loading screen while checking - use ScaffoldPage with solid background
      return const ScaffoldPage(
        content: Center(
          child: ProgressRing(),
        ),
      );
    }

    if (!_isAuthenticated || _showingPasswordScreen) {
      return MasterPasswordDialog(onResult: _onPasswordResult);
    }

    // Authenticated - show main window
    return const MainWindow();
  }
}