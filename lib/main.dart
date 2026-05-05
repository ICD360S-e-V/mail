// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:no_screenshot/no_screenshot.dart';
import 'package:safe_device/safe_device.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:flutter/foundation.dart' show kReleaseMode;
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';
import 'package:path/path.dart' as p;
import 'generated/app_localizations.dart';
import 'providers/theme_provider.dart';
import 'providers/locale_provider.dart';
import 'providers/email_provider.dart';
import 'services/notification_service.dart';
import 'services/logger_service.dart';
import 'services/master_vault.dart';
import 'services/localization_service.dart';
import 'services/macos_bundle_migration.dart';
import 'services/platform_service.dart';
import 'views/auth_wrapper.dart';

/// Error app shown when another instance is already running
class _SingleInstanceErrorApp extends StatelessWidget {
  const _SingleInstanceErrorApp();

  @override
  Widget build(BuildContext context) {
    return const FluentApp(
      debugShowCheckedModeBanner: false,
      home: Center(
        child: Padding(
          padding: EdgeInsets.all(40),
          child: Text(
            'ICD360S Mail Client is already running!\n\n'
            'Please close the other instance first.\n\n'
            'This window will close automatically...',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 18, color: Colors.white),
          ),
        ),
      ),
    );
  }
}

/// Error app shown when the app crashes at startup — shows actual error instead of grey screen
class _CrashErrorApp extends StatelessWidget {
  final String error;
  const _CrashErrorApp(this.error);

  @override
  Widget build(BuildContext context) {
    return WidgetsApp(
      color: const Color(0xFF1E1E1E),
      debugShowCheckedModeBanner: false,
      builder: (context, _) => Directionality(
        textDirection: TextDirection.ltr,
        child: Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text(
                'ICD360S Mail Client',
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Color(0xFFFFFFFF), decoration: TextDecoration.none),
              ),
              const SizedBox(height: 24),
              const Text(
                'App Error — Please report this:',
                style: TextStyle(fontSize: 16, color: Color(0xFFFF6B6B), decoration: TextDecoration.none),
              ),
              const SizedBox(height: 16),
              Expanded(
                child: SingleChildScrollView(
                  child: Text(
                    error,
                    style: const TextStyle(fontSize: 12, color: Color(0xFFCCCCCC), decoration: TextDecoration.none, fontFamily: 'monospace'),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

void main() async {
  // Global error handler — catches crashes on custom ROMs (GrapheneOS etc.)
  // Shows actual error on screen instead of grey screen
  runZonedGuarded(() async {
    try {
      await _appMain();
    } catch (ex, stack) {
      LoggerService.logError('FATAL_MAIN', ex, stack);
      runApp(_CrashErrorApp('$ex\n\n$stack'));
    }
  }, (error, stack) {
    LoggerService.logError('FATAL_ZONE', error, stack);
  });
}

Future<void> _checkDeviceIntegrity() async {
  try {
    if (Platform.isAndroid || Platform.isIOS) {
      final isRooted = await SafeDevice.isJailBroken;
      final isEmulator = await SafeDevice.isRealDevice == false;
      if (isRooted) {
        LoggerService.logWarning('INTEGRITY',
            '⚠ Device is rooted/jailbroken — increased risk of key extraction');
      }
      if (isEmulator) {
        LoggerService.logWarning('INTEGRITY',
            '⚠ Running on emulator — not a physical device');
      }
    } else if (Platform.isMacOS) {
      final result = await Process.run('/usr/bin/csrutil', ['status']);
      if (result.exitCode == 0) {
        final output = (result.stdout as String).trim();
        if (output.contains('disabled')) {
          LoggerService.logWarning('INTEGRITY',
              '⚠ macOS SIP is disabled — system integrity compromised');
        }
      }
    } else if (Platform.isWindows) {
      final kernel32 = ffi.DynamicLibrary.open('kernel32.dll');
      final isDebuggerPresent = kernel32
          .lookupFunction<ffi.Int32 Function(), int Function()>('IsDebuggerPresent');
      if (isDebuggerPresent() != 0) {
        LoggerService.logWarning('INTEGRITY',
            '⚠ Debugger attached (IsDebuggerPresent=true)');
      }
    } else if (Platform.isLinux) {
      final statusFile = File('/proc/self/status');
      if (await statusFile.exists()) {
        final content = await statusFile.readAsString();
        final tracerMatch = RegExp(r'TracerPid:\s*(\d+)').firstMatch(content);
        if (tracerMatch != null && tracerMatch.group(1) != '0') {
          LoggerService.logWarning('INTEGRITY',
              '⚠ Debugger attached (TracerPid=${tracerMatch.group(1)})');
        }
      }
    }
    // Frida detection on Android/Linux (requires /proc filesystem)
    if (Platform.isAndroid || Platform.isLinux) {
      final mapsFile = File('/proc/self/maps');
      if (await mapsFile.exists()) {
        final maps = await mapsFile.readAsString();
        if (maps.contains('frida') || maps.contains('gadget')) {
          LoggerService.logWarning('INTEGRITY',
              '⚠ Frida/hooking framework detected in process memory maps');
        }
      }
    }
  } catch (e) {
    LoggerService.log('INTEGRITY', 'Device integrity check skipped: $e');
  }
}

Future<void> _appMain() async {
  WidgetsFlutterBinding.ensureInitialized();

  // SECURITY (B5, v2.30.0): enable platform-native crypto acceleration
  // for Argon2id / AES-GCM / HKDF used by MasterVault. On macOS this
  // routes Argon2id through CommonCrypto and gets ~100x speedup vs
  // the pure Dart implementation, bringing unlock latency from
  // ~2-3 seconds to ~200 ms with the Bitwarden-recommended 64 MiB /
  // 3 iters / 4 threads parameters.
  FlutterCryptography.enable();

  // Initialize libsodium on all platforms (SecureKey, pwhash).
  MasterVault.sodium = await SodiumSumoInit.init();

  // SECURITY: Prevent screenshots and screen recording on all platforms.
  // Android: FLAG_SECURE (also set natively in MainActivity.kt)
  // iOS: UITextField isSecureTextEntry layer trick
  // Windows: SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)
  // macOS: NSWindow.sharingType = .none
  final noScreenshot = NoScreenshot.instance;
  await noScreenshot.screenshotOff();

  // SECURITY: Device integrity check (root/jailbreak on mobile,
  // SIP/debugger on desktop). Warn but don't block — user may have
  // legitimate reasons (developer device, pentesting).
  await _checkDeviceIntegrity();

  // One-time macOS bundle ID migration (com.example.icd360sMailClient
  // → de.icd360s.mailclient, introduced in v2.25.0). MUST run before
  // any code that calls `getApplicationSupportDirectory()` or any
  // other path_provider entry point — otherwise the new bundle dir
  // is read while empty and the user appears to be logged out.
  // No-op on non-macOS platforms.
  await MacOSBundleMigration.runIfNeeded();

  // Global Flutter error handler — replaces grey screen with visible error
  // In release mode, Flutter shows grey screen by default; this overrides it
  FlutterError.onError = (details) {
    LoggerService.logError('FLUTTER_ERROR', details.exception, details.stack ?? StackTrace.current);
  };

  // ErrorWidget.builder runs whenever a widget throws during build.
  //
  // SECURITY: in release builds we MUST NOT render the exception
  // string or the stack trace into the visible UI. They contain
  // internal class names, file paths, line numbers and sometimes
  // user-controlled values that may include credentials or tokens
  // (information disclosure → CWE-209). FlutterError.onError above
  // already logs the full details via LoggerService for diagnosis.
  //
  // In debug builds we keep the rich error screen so developers can
  // see what went wrong on the spot.
  ErrorWidget.builder = (FlutterErrorDetails details) {
    LoggerService.logError(
      'ERROR_WIDGET',
      details.exception,
      details.stack ?? StackTrace.current,
    );
    if (kReleaseMode) {
      return Directionality(
        textDirection: TextDirection.ltr,
        child: Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(24),
          alignment: Alignment.center,
          child: const Text(
            'Something went wrong',
            style: TextStyle(
              fontSize: 16,
              color: Color(0xFFCCCCCC),
              decoration: TextDecoration.none,
            ),
          ),
        ),
      );
    }
    return Directionality(
      textDirection: TextDirection.ltr,
      child: Container(
        color: const Color(0xFF1E1E1E),
        padding: const EdgeInsets.all(24),
        child: SingleChildScrollView(
          child: Text(
            'ICD360S Error:\n${details.exception}\n\n${details.stack}',
            style: const TextStyle(
              fontSize: 12,
              color: Color(0xFFFF6B6B),
              decoration: TextDecoration.none,
            ),
          ),
        ),
      ),
    );
  };

  final platform = PlatformService.instance;

  // Initialize platform-specific paths (needed for iOS/Android)
  try {
    await platform.initialize();
  } catch (ex) {
    LoggerService.logError('PLATFORM_INIT', ex, StackTrace.current);
  }

  // SINGLE INSTANCE CHECK - only on desktop (mobile OS handles this)
  if (platform.isDesktop) {
    final appDataPath = platform.appDataPath;
    final lockFile = File(p.join(appDataPath, '.app_lock'));

    if (await lockFile.exists()) {
      try {
        final lockContent = await lockFile.readAsString();
        final lockTime = int.tryParse(lockContent) ?? 0;
        final now = DateTime.now().millisecondsSinceEpoch;
        final ageSeconds = (now - lockTime) / 1000;

        if (ageSeconds < 5) {
          LoggerService.log('SINGLE_INSTANCE', 'App already running (lock age: ${ageSeconds.toStringAsFixed(1)}s)');
          runApp(const _SingleInstanceErrorApp());
          await Future.delayed(const Duration(seconds: 3));
          exit(1);
        } else {
          LoggerService.log('SINGLE_INSTANCE', 'Stale lock file detected (age: ${ageSeconds.toStringAsFixed(1)}s) - deleting');
          await lockFile.delete();
        }
      } catch (_) {
        await lockFile.delete();
      }
    }

    final dir = lockFile.parent;
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    final lockTimestamp = DateTime.now().millisecondsSinceEpoch.toString();
    await lockFile.writeAsString(lockTimestamp);
    LoggerService.log('SINGLE_INSTANCE', 'Lock file created');

    // Clean up lock file on exit (SIGINT, SIGTERM)
    ProcessSignal.sigint.watch().listen((_) async {
      try { await lockFile.delete(); } catch (_) {}
      exit(0);
    });
    if (!Platform.isWindows) {
      ProcessSignal.sigterm.watch().listen((_) async {
        try { await lockFile.delete(); } catch (_) {}
        exit(0);
      });
    }
  }

  // Initialize notifications (wrapped for GrapheneOS/custom ROM compatibility)
  try {
    await NotificationService.initialize();
  } catch (ex) {
    LoggerService.logError('NOTIFICATION_INIT', ex, StackTrace.current);
  }

  // Initialize window manager (desktop only)
  if (platform.isDesktop) {
    await windowManager.ensureInitialized();

    const windowOptions = WindowOptions(
      size: Size(1200, 800),
      center: true,
      skipTaskbar: false,
      titleBarStyle: TitleBarStyle.normal,
      title: 'Mail Client by ICD360S e.V gemeinnützige Verein',
    );

    await windowManager.waitUntilReadyToShow(windowOptions, () async {
      await windowManager.setTitle(
          'Mail Client by ICD360S e.V gemeinnützige Verein');
      await windowManager.show();
      await windowManager.focus();
    });
  }

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => ThemeProvider()),
        ChangeNotifierProvider(create: (_) => LocaleProvider()),
        ChangeNotifierProvider(create: (_) => EmailProvider()),
      ],
      child: Consumer2<ThemeProvider, LocaleProvider>(
        builder: (context, themeProvider, localeProvider, _) {
          // Initialize LocalizationService after first build
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (context.mounted) {
              final l10n = AppLocalizations.of(context);
              if (l10n != null) {
                LocalizationService.instance.setLocalizations(l10n);
              }
            }
          });

          return FluentApp(
            title: 'Mail Client by ICD360S e.V gemeinnützige Verein',
            debugShowCheckedModeBanner: false,

            // Theme
            themeMode: themeProvider.themeMode,
            theme: FluentThemeData(
              brightness: Brightness.light,
              accentColor: Colors.blue,
              scaffoldBackgroundColor: const Color(0xFFF3F3F3),
            ),
            darkTheme: FluentThemeData(
              brightness: Brightness.dark,
              accentColor: Colors.blue,
              scaffoldBackgroundColor: const Color(0xFF1E1E1E),
            ),
            // Localization — include FluentLocalizations for Android/custom ROM compatibility
            locale: localeProvider.currentLocale,
            supportedLocales: LocaleProvider.supportedLocales,
            localizationsDelegates: const [
              AppLocalizations.delegate,
              FluentLocalizations.delegate,
              GlobalMaterialLocalizations.delegate,
              GlobalWidgetsLocalizations.delegate,
              GlobalCupertinoLocalizations.delegate,
            ],
            localeResolutionCallback: (locale, supportedLocales) {
              // Handle null locale
              if (locale == null) return supportedLocales.first;

              // Check if device locale is supported
              for (var supportedLocale in supportedLocales) {
                if (supportedLocale.languageCode == locale.languageCode) {
                  return supportedLocale;
                }
              }

              // Fallback to English
              return supportedLocales.first;
            },

            home: const SafeArea(child: AuthWrapper()),
          );
        },
      ),
    );
  }
}
