// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:typed_data';
import 'dart:io';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:pdfrx/pdfrx.dart';
import 'package:printing/printing.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:path/path.dart' as p;
import '../generated/app_localizations.dart';
import '../utils/l10n_helper.dart';
import '../utils/safe_filename.dart';
import '../services/logger_service.dart';
import '../services/notification_service.dart';
import '../services/platform_service.dart';

/// Integrated viewer for PDF and images (native PDFium rendering)
class AttachmentViewerWindow extends StatefulWidget {
  final String fileName;
  final Uint8List fileData;

  const AttachmentViewerWindow({
    super.key,
    required this.fileName,
    required this.fileData,
  });

  @override
  State<AttachmentViewerWindow> createState() => _AttachmentViewerWindowState();
}

class _AttachmentViewerWindowState extends State<AttachmentViewerWindow> {
  PdfViewerController? _pdfController;
  bool _pdfReady = false;
  String? _pdfError;

  @override
  void initState() {
    super.initState();
    _initPdfViewer();
  }

  Future<void> _initPdfViewer() async {
    final ext = widget.fileName.toLowerCase().split('.').last;

    if (ext == 'pdf') {
      try {
        _pdfController = PdfViewerController();
        LoggerService.log('PDF_VIEWER', 'Initializing native PDFium viewer for ${widget.fileName}');
        setState(() => _pdfReady = true);
      } catch (ex, stackTrace) {
        LoggerService.logError('PDF_VIEWER', ex, stackTrace);
        setState(() => _pdfError = ex.toString());
      }
    }
  }

  @override
  void dispose() {
    // PdfViewerController doesn't need explicit dispose
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = l10nOf(context);
    final ext = widget.fileName.toLowerCase().split('.').last;
    final isImage = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].contains(ext);
    final isPdf = ext == 'pdf';

    return ContentDialog(
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width > 600
            ? 900
            : MediaQuery.of(context).size.width * 0.95,
        maxHeight: MediaQuery.of(context).size.height * 0.9,
      ),
      title: Row(
        children: [
          ExcludeSemantics(
            child: Icon(
              isPdf ? FluentIcons.document : FluentIcons.photo2,
              size: 20,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              widget.fileName,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
      content: _buildContent(isPdf, isImage, l10n),
      actions: [
        // Download button
        Tooltip(
          message: 'Download',
          child: IconButton(
            icon: const Icon(FluentIcons.download, size: 20),
            onPressed: () => _downloadFile(l10n),
          ),
        ),

        // Print button
        Tooltip(
          message: 'Print',
          child: IconButton(
            icon: const Icon(FluentIcons.print, size: 20),
            onPressed: () => _printFile(isPdf, isImage, l10n),
          ),
        ),

        // Close button
        Tooltip(
          message: 'Close',
          child: FilledButton(
            child: const Icon(FluentIcons.chrome_close, size: 20),
            onPressed: () => Navigator.of(context).pop(),
          ),
        ),
      ],
    );
  }

  Widget _buildContent(bool isPdf, bool isImage, AppLocalizations l10n) {
    if (isPdf) {
      if (_pdfError != null) {
        return Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Semantics(
                label: 'Error',
                child: Icon(FluentIcons.error, size: 48, color: Colors.errorPrimaryColor),
              ),
              const SizedBox(height: 16),
              Text('PDF Error: $_pdfError'),
            ],
          ),
        );
      }

      if (!_pdfReady) {
        return Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const ProgressRing(),
              const SizedBox(height: 16),
              Text(l10n.attachmentViewerLoadingPdf),
            ],
          ),
        );
      }

      // Native PDFium viewer - responsive sizing
      final screenSize = MediaQuery.of(context).size;
      final pdfWidth = screenSize.width > 900 ? 850.0 : screenSize.width * 0.85;
      final pdfHeight = screenSize.height > 850 ? 700.0 : screenSize.height * 0.7;
      return SizedBox(
        width: pdfWidth,
        height: pdfHeight,
        child: PdfViewer.data(
          widget.fileData,
          sourceName: widget.fileName,
          controller: _pdfController,
          params: PdfViewerParams(
            enableTextSelection: true,
            maxScale: 5.0,
            minScale: 0.5,
            scrollByMouseWheel: 1.0,
            pageDropShadow: const BoxShadow(
              color: Color(0x33000000),
              blurRadius: 4,
              offset: Offset(2, 2),
            ),
          ),
        ),
      );
    }

    if (isImage) {
      return Center(
        child: InteractiveViewer(
          minScale: 0.5,
          maxScale: 4.0,
          child: Image.memory(
            widget.fileData,
            fit: BoxFit.contain,
            semanticLabel: 'Attachment preview',
          ),
        ),
      );
    }

    return Center(
      child: Text(l10n.attachmentViewerUnsupportedType),
    );
  }

  Future<void> _downloadFile(AppLocalizations l10n) async {
    try {
      // Cross-platform downloads path
      final platform = PlatformService.instance;
      final downloadsPath = platform.downloadsPath;

      // SECURITY: Sanitize the filename — it comes from attacker-controlled
      // MIME headers and could otherwise be an absolute path or contain
      // `..` traversal sequences (path traversal vulnerability).
      final safeName = safeAttachmentFileName(widget.fileName);
      final file = File(p.join(downloadsPath, safeName));
      await file.writeAsBytes(widget.fileData);
      NotificationService.showSuccessToast(
        l10n.attachmentViewerSuccessDownloaded,
        l10n.attachmentViewerSuccessSavedTo(file.path),
      );
      LoggerService.log('VIEWER', 'Downloaded: $safeName (original: ${widget.fileName})');
    } catch (ex) {
      NotificationService.showErrorToast(l10n.attachmentViewerErrorDownload, ex.toString());
    }
  }

  Future<void> _printFile(bool isPdf, bool isImage, AppLocalizations l10n) async {
    try {
      if (isImage) {
        // Convert image to PDF and print
        final pdf = pw.Document();
        final image = pw.MemoryImage(widget.fileData);

        pdf.addPage(
          pw.Page(
            pageFormat: PdfPageFormat.a4,
            build: (context) => pw.Center(
              child: pw.Image(image, fit: pw.BoxFit.contain),
            ),
          ),
        );

        await Printing.layoutPdf(
          onLayout: (format) async => pdf.save(),
        );
        NotificationService.showSuccessToast(
          l10n.attachmentViewerSuccessPrint,
          l10n.attachmentViewerSuccessPrintDialogOpened,
        );
        LoggerService.log('VIEWER', 'Print dialog opened for image: ${widget.fileName}');
      } else if (isPdf) {
        // Print PDF directly
        await Printing.layoutPdf(
          onLayout: (format) async => widget.fileData,
        );
        NotificationService.showSuccessToast(
          l10n.attachmentViewerSuccessPrint,
          l10n.attachmentViewerSuccessPrintDialogOpened,
        );
        LoggerService.log('VIEWER', 'Print dialog opened for PDF: ${widget.fileName}');
      }
    } catch (ex, stackTrace) {
      LoggerService.logError('PRINT', ex, stackTrace);
      NotificationService.showErrorToast(l10n.attachmentViewerErrorPrint, ex.toString());
    }
  }
}
