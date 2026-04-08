import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    // SECURITY: Exclude this window from legacy screen-capture APIs.
    //
    // On macOS ≤14 (Sonoma) `sharingType = .none` blocks Cmd+Shift+4
    // window capture, screencapture(1), CGWindowListCreateImage and
    // most screen-recording tools. On macOS 15+ (Sequoia) the new
    // ScreenCaptureKit framework ignores this flag (rdar://-tracked
    // limitation, no public alternative as of April 2026), so it is
    // best-effort against modern capture but still hardens the
    // common case.
    self.sharingType = .none

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}
