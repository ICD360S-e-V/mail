import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val keystoreProperties = Properties()
val keystorePropertiesFile = rootProject.file("key.properties")
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {
    namespace = "de.icd360s.mailclient"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "de.icd360s.mailclient"
        // SECURITY (L5): minSdk 24 (Android 7 Nougat, 2016) — required to
        // safely disable V1 (JAR) signing and rely solely on APK Signature
        // Scheme v2/v3/v4. V1 signing is vulnerable to CVE-2017-13156 (Janus)
        // on devices running Android 5 or 6. Modern signing schemes verify
        // entire APK content blocks, not just individual ZIP entries.
        // Anyone still on Android <7 is on a device with massive unpatched
        // vulnerabilities and should not be a target for new app updates.
        minSdk = 24
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    flavorDimensions += "store"
    productFlavors {
        create("universal") {
            dimension = "store"
            // Universal APK - no store-specific config
        }
        create("fdroid") {
            dimension = "store"
            applicationIdSuffix = ".fdroid"
        }
        create("googleplay") {
            dimension = "store"
            applicationIdSuffix = ".gplay"
        }
        create("samsung") {
            dimension = "store"
            applicationIdSuffix = ".samsung"
        }
        create("huawei") {
            dimension = "store"
            applicationIdSuffix = ".huawei"
        }
    }

    signingConfigs {
        create("release") {
            keyAlias = keystoreProperties["keyAlias"] as String?
            keyPassword = keystoreProperties["keyPassword"] as String?
            storeFile = keystoreProperties["storeFile"]?.let { file(it as String) }
            storePassword = keystoreProperties["storePassword"] as String?
            // SECURITY (L5): V1 (JAR) signing DISABLED to defeat CVE-2017-13156
            // (Janus), which only applies to devices that fall back to V1.
            // We require minSdk = 24 (Android 7+) so V2 signature scheme is
            // always available — see defaultConfig.minSdk above.
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}

flutter {
    source = "../.."
}
