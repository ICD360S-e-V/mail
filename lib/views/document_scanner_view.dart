// SPDX-FileCopyrightText: 2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Full-screen custom document scanner. Fully offline (OpenCV via ffi),
// no Google Play Services, works on GrapheneOS.
//
// UX flow:
//   1. Camera opens, back-facing.
//   2. Every ~500ms we take a still, run OpenCV edge detection, and
//      draw the detected quad as a green overlay on the live preview.
//   3. When the QuadStabilizer reports 3 consecutive stable detections,
//      the last still is kept as the capture, haptic buzz fires, and
//      we jump to the confirm screen.
//   4. Manual "Capture" button is a fallback if auto-detect never
//      locks (bad lighting, low contrast). Uses the last quad if any,
//      otherwise the caller falls back to no-crop.
//   5. Confirm screen shows the perspective-warped result. User taps
//      Use to accept (returns file path to caller) or Retry to restart.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:camera/camera.dart';
import 'package:fluent_ui/fluent_ui.dart' as fluent;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:opencv_dart/opencv_dart.dart' as cv;
import 'package:path_provider/path_provider.dart';

import '../services/document_scanner_service.dart';
import '../services/logger_service.dart';

class DocumentScannerView extends StatefulWidget {
  const DocumentScannerView({super.key});

  /// Push the scanner and await a File path (JPEG). Returns null if the
  /// user cancelled or an unrecoverable error occurred.
  static Future<String?> open(BuildContext context) {
    return Navigator.of(context, rootNavigator: true).push<String>(
      MaterialPageRoute(
        fullscreenDialog: true,
        builder: (_) => const DocumentScannerView(),
      ),
    );
  }

  @override
  State<DocumentScannerView> createState() => _DocumentScannerViewState();
}

class _DocumentScannerViewState extends State<DocumentScannerView>
    with WidgetsBindingObserver {
  static const _detectInterval = Duration(milliseconds: 500);

  CameraController? _controller;
  bool _initialising = true;
  String? _fatalError;

  final _stabilizer = QuadStabilizer();
  DocumentQuad? _lastQuad;
  Size? _lastFrameSize; // pixel dims of the still being analysed
  Timer? _detectTimer;
  bool _detectionBusy = false;
  bool _capturing = false;

  Uint8List? _lastStillBytes; // most recent still we detected on

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initCamera();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _detectTimer?.cancel();
    _controller?.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final c = _controller;
    if (c == null || !c.value.isInitialized) return;
    if (state == AppLifecycleState.inactive) {
      _detectTimer?.cancel();
      c.dispose();
    } else if (state == AppLifecycleState.resumed) {
      _initCamera();
    }
  }

  Future<void> _initCamera() async {
    try {
      final cameras = await availableCameras();
      if (cameras.isEmpty) {
        setState(() {
          _initialising = false;
          _fatalError = 'No cameras available on this device.';
        });
        return;
      }
      final back = cameras.firstWhere(
        (c) => c.lensDirection == CameraLensDirection.back,
        orElse: () => cameras.first,
      );
      final controller = CameraController(
        back,
        ResolutionPreset.high,
        enableAudio: false,
        imageFormatGroup: ImageFormatGroup.jpeg,
      );
      await controller.initialize();
      try {
        await controller.setFocusMode(FocusMode.auto);
        await controller.setFlashMode(FlashMode.off);
      } catch (_) {
        // Not fatal — some devices don't support explicit focus/flash mode.
      }
      if (!mounted) {
        await controller.dispose();
        return;
      }
      setState(() {
        _controller = controller;
        _initialising = false;
      });
      _startDetectionLoop();
    } catch (ex, st) {
      LoggerService.logError('DOC_SCAN', ex, st);
      if (!mounted) return;
      setState(() {
        _initialising = false;
        _fatalError = 'Camera failed: $ex';
      });
    }
  }

  void _startDetectionLoop() {
    _detectTimer?.cancel();
    _detectTimer = Timer.periodic(_detectInterval, (_) => _detectOnce());
  }

  Future<void> _detectOnce() async {
    if (_detectionBusy || _capturing) return;
    final c = _controller;
    if (c == null || !c.value.isInitialized || c.value.isTakingPicture) return;
    _detectionBusy = true;
    try {
      final xfile = await c.takePicture();
      final bytes = await File(xfile.path).readAsBytes();
      // Best-effort cleanup of the ephemeral file — we keep only bytes.
      unawaited(File(xfile.path).delete().catchError((_) => File('')));
      final detection = await compute(_detectInIsolate, bytes);
      if (!mounted) return;
      _lastStillBytes = bytes;
      setState(() {
        _lastQuad = detection.quad;
        if (detection.frameWidth > 0 && detection.frameHeight > 0) {
          _lastFrameSize = Size(
            detection.frameWidth.toDouble(),
            detection.frameHeight.toDouble(),
          );
        }
      });
      if (_stabilizer.track(detection.quad)) {
        await _acceptCapture(bytes, detection.quad!);
      }
    } catch (ex, st) {
      LoggerService.logWarning('DOC_SCAN', 'detect frame failed: $ex\n$st');
    } finally {
      _detectionBusy = false;
    }
  }

  Future<void> _acceptCapture(Uint8List bytes, DocumentQuad quad) async {
    if (_capturing) return;
    _capturing = true;
    _detectTimer?.cancel();
    await HapticFeedback.mediumImpact();
    final warped = await compute(_warpInIsolate, _WarpJob(bytes, quad));
    if (!mounted) {
      _capturing = false;
      return;
    }
    final outBytes = warped ?? bytes; // fall back to raw still if warp fails
    final path = await _persistTemp(outBytes);
    if (!mounted) return;
    Navigator.of(context).pop(path);
  }

  Future<void> _manualCapture() async {
    if (_capturing) return;
    final bytes = _lastStillBytes;
    if (bytes == null) {
      final c = _controller;
      if (c == null) return;
      _capturing = true;
      _detectTimer?.cancel();
      final xfile = await c.takePicture();
      final fresh = await File(xfile.path).readAsBytes();
      unawaited(File(xfile.path).delete().catchError((_) => File('')));
      final detection = await compute(_detectInIsolate, fresh);
      if (detection.quad != null) {
        await _acceptCapture(fresh, detection.quad!);
      } else {
        // No detection — save the raw still, let the user use it as-is.
        final path = await _persistTemp(fresh);
        if (mounted) Navigator.of(context).pop(path);
      }
      return;
    }
    if (_lastQuad != null) {
      await _acceptCapture(bytes, _lastQuad!);
    } else {
      final path = await _persistTemp(bytes);
      if (mounted) Navigator.of(context).pop(path);
    }
  }

  Future<String> _persistTemp(Uint8List bytes) async {
    final dir = await getTemporaryDirectory();
    final path =
        '${dir.path}/icd_scan_${DateTime.now().millisecondsSinceEpoch}.jpg';
    await File(path).writeAsBytes(bytes, flush: true);
    return path;
  }

  @override
  Widget build(BuildContext context) {
    if (_initialising) {
      return const Scaffold(
        backgroundColor: Colors.black,
        body: Center(child: CircularProgressIndicator()),
      );
    }
    if (_fatalError != null) {
      return Scaffold(
        backgroundColor: Colors.black,
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(_fatalError!,
                    style: const TextStyle(color: Colors.white, fontSize: 16),
                    textAlign: TextAlign.center),
                const SizedBox(height: 24),
                fluent.FilledButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Close'),
                ),
              ],
            ),
          ),
        ),
      );
    }
    final c = _controller!;
    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: Stack(
          fit: StackFit.expand,
          children: [
            Center(
              child: AspectRatio(
                aspectRatio: c.value.aspectRatio,
                child: CameraPreview(c),
              ),
            ),
            if (_lastQuad != null && _lastFrameSize != null)
              IgnorePointer(
                child: LayoutBuilder(
                  builder: (context, constraints) => CustomPaint(
                    size: Size(constraints.maxWidth, constraints.maxHeight),
                    painter: _QuadOverlayPainter(
                      quad: _lastQuad!,
                      frameSize: _lastFrameSize!,
                    ),
                  ),
                ),
              ),
            Positioned(
              top: 12,
              left: 12,
              child: IconButton(
                icon: const Icon(Icons.close, color: Colors.white, size: 32),
                onPressed: () => Navigator.of(context).pop(),
              ),
            ),
            Positioned(
              bottom: 32,
              left: 0,
              right: 0,
              child: Column(
                children: [
                  Text(
                    _lastQuad == null
                        ? 'Aim at document…'
                        : 'Hold still — capturing…',
                    style: const TextStyle(color: Colors.white, fontSize: 16),
                  ),
                  const SizedBox(height: 16),
                  GestureDetector(
                    onTap: _manualCapture,
                    child: Container(
                      width: 72,
                      height: 72,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(color: Colors.white, width: 4),
                        color: Colors.white.withOpacity(0.15),
                      ),
                      child: const Icon(Icons.camera_alt,
                          color: Colors.white, size: 32),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _WarpJob {
  final Uint8List bytes;
  final DocumentQuad quad;
  _WarpJob(this.bytes, this.quad);
}

// Isolate entry points — must be top-level or static.
Future<DocumentDetection> _detectInIsolate(Uint8List bytes) =>
    DocumentScannerService.detectQuad(bytes);

Future<Uint8List?> _warpInIsolate(_WarpJob job) =>
    DocumentScannerService.warpCrop(job.bytes, job.quad);

class _QuadOverlayPainter extends CustomPainter {
  final DocumentQuad quad;
  final Size frameSize;

  _QuadOverlayPainter({required this.quad, required this.frameSize});

  @override
  void paint(Canvas canvas, Size size) {
    // Map quad from frame-space (pixel dims of still) to widget-space.
    final sx = size.width / frameSize.width;
    final sy = size.height / frameSize.height;
    Offset map(cv.Point2f p) => Offset(p.x * sx, p.y * sy);
    final path = Path()
      ..moveTo(map(quad.tl).dx, map(quad.tl).dy)
      ..lineTo(map(quad.tr).dx, map(quad.tr).dy)
      ..lineTo(map(quad.br).dx, map(quad.br).dy)
      ..lineTo(map(quad.bl).dx, map(quad.bl).dy)
      ..close();
    final stroke = Paint()
      ..color = const Color(0xFF4CD964)
      ..strokeWidth = 3
      ..style = PaintingStyle.stroke;
    final fill = Paint()
      ..color = const Color(0x334CD964)
      ..style = PaintingStyle.fill;
    canvas.drawPath(path, fill);
    canvas.drawPath(path, stroke);
    // Corner dots
    final dot = Paint()..color = const Color(0xFF4CD964);
    for (final p in [quad.tl, quad.tr, quad.br, quad.bl]) {
      canvas.drawCircle(map(p), 8, dot);
    }
  }

  @override
  bool shouldRepaint(covariant _QuadOverlayPainter old) =>
      old.quad != quad || old.frameSize != frameSize;
}
