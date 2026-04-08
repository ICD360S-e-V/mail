package de.icd360s.mailclient

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileInputStream
import java.io.IOException
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

        // SECURITY: FLAG_SECURE blocks screenshots, screen recording,
        // recent-apps thumbnails, screen mirroring/casting, and prevents
        // accessibility-service screen reading. Standard for apps that
        // display sensitive content (banking, encrypted messaging, mail
        // with private credentials and message bodies).
        //
        // Tradeoff: developers cannot take screenshots through normal UI
        // for bug reports — use `adb exec-out screencap -p > out.png`
        // instead, which bypasses FLAG_SECURE on debuggable builds.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
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
                    "installApk" -> {
                        val apkPath = call.argument<String>("path")
                        val expectedCertSha256 = call.argument<String>("expectedCertSha256")
                        if (apkPath == null || expectedCertSha256 == null) {
                            result.error("INVALID_ARGS", "path and expectedCertSha256 required", null)
                            return@setMethodCallHandler
                        }
                        installApkViaSession(apkPath, expectedCertSha256, result)
                    }
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

    /**
     * Install an APK securely via PackageInstaller.Session.
     *
     * SECURITY: Eliminates the TOCTOU window present in the legacy
     * `am start INSTALL_PACKAGE` flow:
     *
     *   - The APK file lives in our app-private cache directory
     *     (`context.cacheDir`) which is /data/data/de.icd360s.mailclient/cache/.
     *     No other app on the device can read or write this path on any
     *     supported Android version (minSdk=24).
     *   - Bytes are streamed directly into a kernel-side
     *     PackageInstaller.Session via `openWrite()`. The session is
     *     committed atomically; no other process can substitute the
     *     payload after our verification step.
     *   - The signing certificate is re-verified inside this method
     *     immediately before commit, so the cert check and the install
     *     reference the same on-disk bytes.
     */
    private fun installApkViaSession(
        apkPath: String,
        expectedCertSha256: String,
        result: MethodChannel.Result,
    ) {
        val ctx = applicationContext

        // 1. Defense-in-depth cert verification (Dart already verified bytes SHA-256
        //    upstream; this rechecks the X.509 signing cert against the pinned hash).
        val actualCert = try {
            computeApkCertSha256(apkPath)
        } catch (e: Exception) {
            result.error("CERT_ERROR", e.message, null)
            return
        }
        if (actualCert == null) {
            result.success(mapOf("ok" to false, "reason" to "no_signature"))
            return
        }
        if (!actualCert.equals(expectedCertSha256, ignoreCase = true)) {
            result.success(
                mapOf(
                    "ok" to false,
                    "reason" to "cert_mismatch",
                    "actual" to actualCert,
                ),
            )
            return
        }

        // 2. Open install session
        val packageInstaller = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(
            PackageInstaller.SessionParams.MODE_FULL_INSTALL,
        )
        params.setAppPackageName(ctx.packageName)

        val sessionId = try {
            packageInstaller.createSession(params)
        } catch (e: IOException) {
            result.success(
                mapOf(
                    "ok" to false,
                    "reason" to "create_session_failed",
                    "error" to (e.message ?: ""),
                ),
            )
            return
        }

        val session = try {
            packageInstaller.openSession(sessionId)
        } catch (e: Exception) {
            result.success(
                mapOf(
                    "ok" to false,
                    "reason" to "open_session_failed",
                    "error" to (e.message ?: ""),
                ),
            )
            return
        }

        // 3. Stream APK bytes into the session
        try {
            val apkFile = File(apkPath)
            val sizeBytes = apkFile.length()
            session.openWrite("base.apk", 0, sizeBytes).use { out ->
                FileInputStream(apkFile).use { input ->
                    input.copyTo(out)
                }
                session.fsync(out)
            }
        } catch (e: Exception) {
            try {
                session.abandon()
            } catch (_: Exception) { }
            session.close()
            result.success(
                mapOf(
                    "ok" to false,
                    "reason" to "stream_failed",
                    "error" to (e.message ?: ""),
                ),
            )
            return
        }

        // 4. Register a one-shot broadcast receiver for install status, then commit.
        //    The single MethodChannel `result` is completed exactly once when the
        //    final status (success or terminal failure) arrives.
        val action = "${ctx.packageName}.INSTALL_RESULT.$sessionId"
        var completed = false

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (completed) return
                val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                when (status) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        // Android wants the user to confirm via system dialog —
                        // launch the activity intent the system handed back.
                        @Suppress("DEPRECATION")
                        val confirm =
                            intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                        if (confirm != null) {
                            confirm.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            try {
                                context.startActivity(confirm)
                            } catch (e: Exception) {
                                completed = true
                                try { context.unregisterReceiver(this) } catch (_: Exception) {}
                                File(apkPath).delete()
                                result.success(
                                    mapOf(
                                        "ok" to false,
                                        "reason" to "confirm_dialog_failed",
                                        "error" to (e.message ?: ""),
                                    ),
                                )
                            }
                        } else {
                            completed = true
                            try { context.unregisterReceiver(this) } catch (_: Exception) {}
                            File(apkPath).delete()
                            result.success(
                                mapOf("ok" to false, "reason" to "no_confirm_intent"),
                            )
                        }
                        // Stay registered until terminal status arrives.
                    }
                    PackageInstaller.STATUS_SUCCESS -> {
                        completed = true
                        try { context.unregisterReceiver(this) } catch (_: Exception) {}
                        File(apkPath).delete()
                        result.success(mapOf("ok" to true))
                    }
                    else -> {
                        completed = true
                        try { context.unregisterReceiver(this) } catch (_: Exception) {}
                        File(apkPath).delete()
                        result.success(
                            mapOf(
                                "ok" to false,
                                "reason" to "install_failed",
                                "status" to status,
                                "message" to (msg ?: ""),
                            ),
                        )
                    }
                }
            }
        }

        val filter = IntentFilter(action)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ctx.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            ctx.registerReceiver(receiver, filter)
        }

        val statusIntent = Intent(action).setPackage(ctx.packageName)
        val pendingFlags =
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        val pendingIntent = PendingIntent.getBroadcast(
            ctx,
            sessionId,
            statusIntent,
            pendingFlags,
        )

        try {
            session.commit(pendingIntent.intentSender)
        } catch (e: Exception) {
            completed = true
            try { ctx.unregisterReceiver(receiver) } catch (_: Exception) {}
            try { session.abandon() } catch (_: Exception) {}
            File(apkPath).delete()
            result.success(
                mapOf(
                    "ok" to false,
                    "reason" to "commit_failed",
                    "error" to (e.message ?: ""),
                ),
            )
        } finally {
            session.close()
        }
    }
}
