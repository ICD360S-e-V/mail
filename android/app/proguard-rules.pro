# ICD360S Mail Client — ProGuard / R8 rules
#
# SECURITY NOTE (L6): The Flutter Gradle plugin and each Flutter package
# already ship `consumer-rules.pro` files that keep only the classes that R8
# would otherwise wrongly strip. We DO NOT add blanket `-keep class
# io.flutter.** { *; }` rules here, because that defeats most of R8's
# obfuscation for the entire Flutter engine surface area — including the
# code that handles credentials, mTLS, and update verification. Keep this
# file minimal and add narrow rules only when a package's stack trace shows
# a missing class.

# flutter_secure_storage — keep its native binding classes (it uses reflection
# to load AndroidX security crypto APIs that R8 cannot trace).
-keep class com.it_nomads.fluttersecurestorage.** { *; }
-keep class androidx.security.crypto.** { *; }

# flutter_local_notifications — uses reflection on its own model classes,
# plus GSON for serializing notification payloads.
-keep class com.dexterous.** { *; }
-keep class com.google.gson.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# BouncyCastle — used as the JCE provider on older Android by some plugins.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Google Play Core — referenced by Flutter engine for split installs but not
# present on GrapheneOS / non-Play devices. Suppress warnings only; the
# classes themselves do not need to be kept since we don't use deferred
# components.
-dontwarn com.google.android.play.core.**

# General: keep native method names (JNI binding requirement).
-keepclasseswithmembernames class * {
    native <methods>;
}
