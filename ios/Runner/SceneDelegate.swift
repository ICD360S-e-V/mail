// SPDX-FileCopyrightText: 2024-2026 ICD360S e.V.
// SPDX-License-Identifier: AGPL-3.0-or-later

import Flutter
import UIKit

class SceneDelegate: FlutterSceneDelegate {

  private let privacyBlurTag = 0x1CD36050

  override func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options connectionOptions: UIScene.ConnectionOptions
  ) {
    super.scene(scene, willConnectTo: session, options: connectionOptions)

    guard let windowScene = scene as? UIWindowScene,
          let window = windowScene.keyWindow else { return }

    let secureField = UITextField()
    secureField.isSecureTextEntry = true
    secureField.translatesAutoresizingMaskIntoConstraints = false
    window.addSubview(secureField)
    secureField.centerYAnchor.constraint(equalTo: window.centerYAnchor).isActive = true
    secureField.centerXAnchor.constraint(equalTo: window.centerXAnchor).isActive = true
    window.layer.superlayer?.addSublayer(secureField.layer)
    if let secureSublayer = secureField.layer.sublayers?.last {
      secureSublayer.addSublayer(window.layer)
      NSLog("[ICD360S][SECURITY] Secure capture protection enabled (UIScene)")
    }
  }

  override func sceneWillResignActive(_ scene: UIScene) {
    super.sceneWillResignActive(scene)
    guard let windowScene = scene as? UIWindowScene,
          let window = windowScene.keyWindow else { return }
    if window.viewWithTag(privacyBlurTag) != nil { return }

    let blur = UIVisualEffectView(effect: UIBlurEffect(style: .systemThickMaterial))
    blur.frame = window.bounds
    blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    blur.tag = privacyBlurTag
    window.addSubview(blur)
  }

  override func sceneDidBecomeActive(_ scene: UIScene) {
    super.sceneDidBecomeActive(scene)
    guard let windowScene = scene as? UIWindowScene,
          let window = windowScene.keyWindow else { return }
    window.viewWithTag(privacyBlurTag)?.removeFromSuperview()
  }
}
