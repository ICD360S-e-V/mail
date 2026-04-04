# Flutter secure storage - prevent R8 from stripping crypto classes
-keep class com.it_nomads.fluttersecurestorage.** { *; }
-keep class androidx.security.crypto.** { *; }

# Flutter local notifications - prevent R8 from stripping notification classes
-keep class com.dexterous.** { *; }

# Prevent R8 from stripping Flutter engine classes
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# Keep GSON (used by flutter_local_notifications)
-keep class com.google.gson.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# Keep BouncyCastle (used by flutter_secure_storage)
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Google Play Core (referenced by Flutter engine, not needed on GrapheneOS)
-dontwarn com.google.android.play.core.**

# General: keep all native methods
-keepclasseswithmembernames class * {
    native <methods>;
}
