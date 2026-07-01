// SPDX-FileCopyrightText: 2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fully-offline document scanner built on OpenCV (via opencv_dart).
// Replaces the ML-Kit-backed cunning_document_scanner so the flow works
// on GrapheneOS and does not send diagnostic telemetry to Google.
//
// Pipeline:
//   input JPEG bytes
//     → grayscale → Gaussian blur (5x5)
//     → Canny edge detection (75, 200)
//     → morphological dilate (closes gaps in edges)
//     → findContours
//     → filter contours: area > 15 % of image, quadrilateral (approxPolyDP)
//     → return largest remaining quad (or null)
//   warpCrop:
//     → getPerspectiveTransform(srcQuad → target rectangle sized by longest edges)
//     → warpPerspective
//     → JPEG-encode result

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:opencv_dart/opencv_dart.dart' as cv;

import 'logger_service.dart';

/// A quadrilateral with corners ordered clockwise starting top-left.
class DocumentQuad {
  final cv.Point2f tl;
  final cv.Point2f tr;
  final cv.Point2f br;
  final cv.Point2f bl;

  const DocumentQuad(this.tl, this.tr, this.br, this.bl);

  List<cv.Point2f> get corners => [tl, tr, br, bl];

  /// Axis-aligned bounding box area (used for stabilizer heuristics).
  double get area {
    final w = math.max(_dist(tl, tr), _dist(bl, br));
    final h = math.max(_dist(tl, bl), _dist(tr, br));
    return w * h;
  }

  /// Intersection-over-Union between this and other, using axis-aligned bbox.
  /// Not a perfect IoU for arbitrary quads, but adequate as a stability metric.
  double iouWith(DocumentQuad other) {
    final a = _bbox(this);
    final b = _bbox(other);
    final ix = math.max(0.0, math.min(a[2], b[2]) - math.max(a[0], b[0]));
    final iy = math.max(0.0, math.min(a[3], b[3]) - math.max(a[1], b[1]));
    final inter = ix * iy;
    final ua = (a[2] - a[0]) * (a[3] - a[1]);
    final ub = (b[2] - b[0]) * (b[3] - b[1]);
    final union = ua + ub - inter;
    if (union <= 0) return 0;
    return inter / union;
  }

  static double _dist(cv.Point2f a, cv.Point2f b) {
    final dx = a.x - b.x;
    final dy = a.y - b.y;
    return math.sqrt(dx * dx + dy * dy);
  }

  /// Returns [xmin, ymin, xmax, ymax].
  static List<double> _bbox(DocumentQuad q) {
    final xs = q.corners.map((p) => p.x);
    final ys = q.corners.map((p) => p.y);
    return [
      xs.reduce(math.min),
      ys.reduce(math.min),
      xs.reduce(math.max),
      ys.reduce(math.max),
    ];
  }
}

/// Tracks per-frame quad detections and reports when the document is
/// visually stable, following the Dynamsoft pattern (IoU + area delta
/// over N consecutive frames).
class QuadStabilizer {
  final double iouThreshold;
  final double areaDeltaThreshold;
  final int stableFrameCount;

  DocumentQuad? _lastQuad;
  int _consecutiveStable = 0;

  QuadStabilizer({
    this.iouThreshold = 0.85,
    this.areaDeltaThreshold = 0.15,
    this.stableFrameCount = 3,
  });

  /// Feed a new detection (or null if no quad found this frame).
  /// Returns true iff the stream has now been stable for [stableFrameCount].
  bool track(DocumentQuad? current) {
    if (current == null) {
      _consecutiveStable = 0;
      _lastQuad = null;
      return false;
    }
    final last = _lastQuad;
    if (last == null) {
      _lastQuad = current;
      _consecutiveStable = 1;
      return false;
    }
    final iou = last.iouWith(current);
    final areaDelta = (current.area - last.area).abs() / math.max(last.area, 1);
    _lastQuad = current;
    if (iou >= iouThreshold && areaDelta <= areaDeltaThreshold) {
      _consecutiveStable++;
    } else {
      _consecutiveStable = 1;
    }
    return _consecutiveStable >= stableFrameCount;
  }

  DocumentQuad? get lastStableQuad => _lastQuad;

  void reset() {
    _lastQuad = null;
    _consecutiveStable = 0;
  }
}

/// Result of one detection pass: the frame we analysed (in still-pixel
/// dims) plus the quad found in it (nullable).
class DocumentDetection {
  final int frameWidth;
  final int frameHeight;
  final DocumentQuad? quad;
  const DocumentDetection(this.frameWidth, this.frameHeight, this.quad);
}

class DocumentScannerService {
  /// Detect the largest quadrilateral contour in a JPEG-encoded image.
  /// Returns a [DocumentDetection] with the frame dims so the caller can
  /// map quad coordinates back to widget space, and a nullable quad.
  ///
  /// Costs ~30-80ms on a mid-range Android device for a 720p input, so it
  /// is safe to run on every 2nd-3rd preview frame at 15 fps effective.
  static Future<DocumentDetection> detectQuad(Uint8List jpegBytes) async {
    cv.Mat? src;
    cv.Mat? gray;
    cv.Mat? blurred;
    cv.Mat? edges;
    cv.Mat? kernel;
    cv.Mat? dilated;
    cv.VecVecPoint? contours;
    cv.Mat? hierarchy;
    int imgW = 0;
    int imgH = 0;
    try {
      src = cv.imdecode(jpegBytes, cv.IMREAD_COLOR);
      if (src.isEmpty) return DocumentDetection(0, 0, null);
      imgW = src.cols;
      imgH = src.rows;
      final imgArea = imgW * imgH;

      gray = cv.cvtColor(src, cv.COLOR_BGR2GRAY);
      blurred = cv.gaussianBlur(gray, (5, 5), 0);
      edges = cv.canny(blurred, 75, 200);
      kernel = cv.getStructuringElement(cv.MORPH_RECT, (3, 3));
      dilated = cv.dilate(edges, kernel);

      final (foundContours, foundHierarchy) = cv.findContours(
        dilated,
        cv.RETR_EXTERNAL,
        cv.CHAIN_APPROX_SIMPLE,
      );
      contours = foundContours;
      hierarchy = foundHierarchy;

      DocumentQuad? best;
      double bestArea = 0;
      for (final contour in contours) {
        final area = cv.contourArea(contour);
        if (area < imgArea * 0.15) continue;
        final peri = cv.arcLength(contour, true);
        final approx = cv.approxPolyDP(contour, 0.02 * peri, true);
        if (approx.length != 4) continue;
        if (area > bestArea) {
          bestArea = area;
          final pts = approx.map((p) => cv.Point2f(p.x.toDouble(), p.y.toDouble())).toList();
          best = _orderCorners(pts);
        }
      }
      return DocumentDetection(imgW, imgH, best);
    } catch (ex, st) {
      LoggerService.logError('DOC_SCAN', ex, st);
      return DocumentDetection(imgW, imgH, null);
    } finally {
      src?.dispose();
      gray?.dispose();
      blurred?.dispose();
      edges?.dispose();
      kernel?.dispose();
      dilated?.dispose();
      hierarchy?.dispose();
    }
  }

  /// Warp the source image so that [quad] fills a rectangular output whose
  /// dimensions match the longest edges. Returns JPEG-encoded bytes.
  static Future<Uint8List?> warpCrop(Uint8List jpegBytes, DocumentQuad quad) async {
    cv.Mat? src;
    cv.Mat? transform;
    cv.Mat? warped;
    try {
      src = cv.imdecode(jpegBytes, cv.IMREAD_COLOR);
      if (src.isEmpty) return null;

      final wTop = _dist(quad.tl, quad.tr);
      final wBot = _dist(quad.bl, quad.br);
      final hLeft = _dist(quad.tl, quad.bl);
      final hRight = _dist(quad.tr, quad.br);
      final outW = math.max(wTop, wBot).round();
      final outH = math.max(hLeft, hRight).round();
      if (outW < 32 || outH < 32) return null;

      final srcPts = cv.VecPoint2f.fromList(quad.corners);
      final dstPts = cv.VecPoint2f.fromList([
        cv.Point2f(0, 0),
        cv.Point2f(outW.toDouble() - 1, 0),
        cv.Point2f(outW.toDouble() - 1, outH.toDouble() - 1),
        cv.Point2f(0, outH.toDouble() - 1),
      ]);
      transform = cv.getPerspectiveTransform(srcPts, dstPts);
      warped = cv.warpPerspective(src, transform, (outW, outH));

      final (ok, encoded) = cv.imencode('.jpg', warped, params: cv.VecI32.fromList([cv.IMWRITE_JPEG_QUALITY, 92]));
      if (!ok) return null;
      return Uint8List.fromList(encoded);
    } catch (ex, st) {
      LoggerService.logError('DOC_SCAN', ex, st);
      return null;
    } finally {
      src?.dispose();
      transform?.dispose();
      warped?.dispose();
    }
  }

  /// Order 4 points clockwise from top-left: tl, tr, br, bl.
  /// Uses coordinate sum + diff heuristic (standard for perspective correction).
  static DocumentQuad _orderCorners(List<cv.Point2f> pts) {
    assert(pts.length == 4);
    // top-left has smallest x+y, bottom-right has largest x+y
    // top-right has smallest y-x (largest x-y), bottom-left has smallest x-y (largest y-x)
    pts.sort((a, b) => (a.x + a.y).compareTo(b.x + b.y));
    final tl = pts.first;
    final br = pts.last;
    final rest = [pts[1], pts[2]]..sort((a, b) => (a.x - a.y).compareTo(b.x - b.y));
    final bl = rest.first;
    final tr = rest.last;
    return DocumentQuad(tl, tr, br, bl);
  }

  static double _dist(cv.Point2f a, cv.Point2f b) {
    final dx = a.x - b.x;
    final dy = a.y - b.y;
    return math.sqrt(dx * dx + dy * dy);
  }
}
