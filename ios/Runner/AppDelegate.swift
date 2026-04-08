import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {

  // Tag used to find and remove the privacy blur overlay added when
  // the app resigns active. Random-ish to avoid colliding with any
  // unrelated subview tags.
  private let privacyBlurTag = 0x1CD36050

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)

    // SECURITY: detect manual screenshots and log them. iOS does NOT
    // permit blocking screenshots the way Android FLAG_SECURE does;
    // the best we can do is observe the system notification fired
    // *after* a screenshot is taken and surface it for audit /
    // user awareness. Sensitive content remains protected against
    // automatic background snapshots via the blur overlay below.
    NotificationCenter.default.addObserver(
      forName: UIApplication.userDidTakeScreenshotNotification,
      object: nil,
      queue: .main
    ) { _ in
      NSLog("[ICD360S][SECURITY] Screenshot detected by user")
    }

    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  // SECURITY: iOS automatically captures a snapshot of the visible
  // window when the app moves to the background, both to render the
  // multitasking-switcher thumbnail and to display the launch
  // animation. The snapshot is persisted to disk in
  // /var/mobile/Containers/.../Library/Caches/Snapshots/ until the OS
  // recycles it. Without intervention, that snapshot contains the
  // user's inbox, open email body, or master-password field.
  //
  // We add a fully opaque blur overlay just before the snapshot is
  // taken, and remove it once the app becomes active again. This is
  // the same pattern banking and messaging apps use.
  override func applicationWillResignActive(_ application: UIApplication) {
    super.applicationWillResignActive(application)
    guard let window = self.window else { return }
    if window.viewWithTag(privacyBlurTag) != nil { return }

    let blur = UIVisualEffectView(effect: UIBlurEffect(style: .systemThickMaterial))
    blur.frame = window.bounds
    blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    blur.tag = privacyBlurTag
    window.addSubview(blur)
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    super.applicationDidBecomeActive(application)
    guard let window = self.window else { return }
    window.viewWithTag(privacyBlurTag)?.removeFromSuperview()
  }
}
