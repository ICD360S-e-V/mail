// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:io';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart';
import '../utils/l10n_helper.dart';
import '../services/logger_service.dart';
import '../services/update_service.dart';

/// Log viewer window for debugging
class LogViewerWindow extends StatefulWidget {
  const LogViewerWindow({super.key});

  @override
  State<LogViewerWindow> createState() => _LogViewerWindowState();
}

class _LogViewerWindowState extends State<LogViewerWindow> {
  late List<String> _logs;
  final ScrollController _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    // Get real logs from LoggerService
    _logs = LoggerService.getLogs().toList();

    // Auto-scroll to bottom after build (show latest logs first)
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _scrollToBottom();
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 100),
        curve: Curves.easeOut,
      );
    }
  }

  void _copyLogs(BuildContext context) {
    final l10n = l10nOf(context);
    final metadata = '''
${l10n.logViewerMetadataHeader}
${l10n.logViewerMetadataVersion(UpdateService.currentVersion)}
${l10n.logViewerMetadataPlatform(Platform.operatingSystem, Platform.operatingSystemVersion)}
${l10n.logViewerMetadataTimestamp(DateTime.now().toString())}
${l10n.logViewerMetadataTotalEntries(_logs.length)}
${l10n.logViewerMetadataSeparator}

''';
    final allLogs = metadata + _logs.join('\n');
    Clipboard.setData(ClipboardData(text: allLogs));

    LoggerService.log('LOG_VIEWER', l10n.logViewerLogsCopied(_logs.length));
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final l10n = l10nOf(context);

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 900
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          const Tooltip(
            message: 'Log viewer',
            child: Icon(FluentIcons.code, size: 24),
          ),
          const SizedBox(width: 12),
          Text(l10n.logViewerDialogTitle),
        ],
      ),
      content: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: const Color(0xFF1E1E1E),
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: theme.inactiveBackgroundColor),
        ),
        child: ListView.builder(
          controller: _scrollController,
          itemCount: _logs.length,
          itemBuilder: (context, index) {
            final log = _logs[index];
            Color logColor = Colors.white;

            // Color code by log type
            if (log.contains('[ERROR]')) {
              logColor = Colors.red;
            } else if (log.contains('[WARNING]')) {
              logColor = Colors.orange;
            } else if (log.contains('[SECURITY]')) {
              logColor = Colors.yellow;
            } else if (log.contains('[TRASH_CLEANUP]')) {
              logColor = Colors.magenta;
            } else if (log.contains('[AUTH_ERROR]')) {
              logColor = Colors.red.light;
            } else if (log.contains('[STARTUP]') || log.contains('✓')) {
              logColor = Colors.green;
            }

            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: SelectableText(
                log,
                style: TextStyle(
                  fontFamily: 'Consolas',
                  fontSize: 12,
                  color: logColor,
                ),
              ),
            );
          },
        ),
      ),
      actions: [
        Button(
          child: Text(l10n.logViewerButtonClearLogs),
          onPressed: () {
            LoggerService.clearLogs();
            setState(() => _logs = []);
          },
        ),
        Button(
          onPressed: () => _copyLogs(context),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Tooltip(
                message: 'Copy logs',
                child: Icon(FluentIcons.copy, size: 14),
              ),
              const SizedBox(width: 6),
              Text(l10n.logViewerButtonCopyAll),
            ],
          ),
        ),
        FilledButton(
          child: Text(l10n.logViewerButtonClose),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ],
    );
  }
}

