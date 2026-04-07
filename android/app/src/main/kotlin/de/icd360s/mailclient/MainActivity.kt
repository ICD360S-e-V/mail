package de.icd360s.mailclient

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.MessageDigest

class MainActivity : FlutterActivity() {

    companion object {
        private const val APK_VERIFY_CHANNEL = "de.icd360s.mailclient/apk_verify"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Edge-to-edge display — eliminates black bars on notch/cutout devices
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            window.attributes.layoutInDisplayCutoutMode =
                WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // SECURITY: Method channel for APK signature verification before
        // self-installing an auto-update. The Dart side passes the path to
        // the downloaded APK and the expected SHA-256 of the signing
        // certificate (hardcoded in update_service.dart). If the APK is
        // unsigned or signed by a different certificate, we refuse to install.
        //
        // This is defense-in-depth on top of:
        //   - SHA-256 hash verification of the APK file (mandatory)
        //   - HTTPS + certificate pinning when downloading
        //   - Restricted CI/CD deploy (non-root, environment gate)
        //
        // Without this check, an attacker who somehow served a tampered APK
        // could exploit user habituation to "Install update?" dialogs.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, APK_VERIFY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "verifyApkSignature" -> {
                        val apkPath = call.argument<String>("apkPath")
                        val expectedSha256 = call.argument<String>("expectedCertSha256")
                        if (apkPath == null || expectedSha256 == null) {
                            result.error("INVALID_ARGS", "apkPath and expectedCertSha256 required", null)
                            return@setMethodCallHandler
                        }
                        try {
                            val actualHash = computeApkCertSha256(apkPath)
                            if (actualHash == null) {
                                result.success(mapOf(
                                    "verified" to false,
                                    "reason" to "could_not_extract_signature"
                                ))
                                return@setMethodCallHandler
                            }
                            val matches = actualHash.equals(expectedSha256, ignoreCase = true)
                            result.success(mapOf(
                                "verified" to matches,
                                "actualHash" to actualHash,
                                "reason" to if (matches) "ok" else "cert_mismatch"
                            ))
                        } catch (e: Exception) {
                            result.error("VERIFY_ERROR", e.message, null)
                        }
                    }
                    else -> result.notImplemented()
                }
            }
    }

    /**
     * Extract the SHA-256 of the APK's signing certificate using Android's
     * PackageManager API. This uses the same code path that Android itself
     * uses to verify signatures during install, so the hash will match what
     * a signed APK from the official keystore produces.
     *
     * Returns null if the APK has no parseable signature.
     */
    private fun computeApkCertSha256(apkPath: String): String? {
        val pm = packageManager
        val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNATURES)
        } ?: return null

        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = pkgInfo.signingInfo ?: return null
            // apkContentsSigners returns the certs from APK Signing Block (v2/v3),
            // or falls back to v1 if only v1 is present.
            if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION")
            pkgInfo.signatures
        }

        if (signatures.isNullOrEmpty()) return null

        // Use the first signer's cert (we only sign with one key)
        val certBytes = signatures[0].toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(certBytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
