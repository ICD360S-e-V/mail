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
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        create("release") {
            keyAlias = keystoreProperties["keyAlias"] as String?
            keyPassword = keystoreProperties["keyPassword"] as String?
            storeFile = keystoreProperties["storeFile"]?.let { file(it as String) }
            storePassword = keystoreProperties["storePassword"] as String?
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true
        }
    }

    // Product flavors for different distribution channels
    flavorDimensions += "store"
    productFlavors {
        create("universal") {
            dimension = "store"
            // Direct distribution (sideload / mail.icd360s.de)
            // No store-specific changes needed
        }
        create("fdroid") {
            dimension = "store"
            // F-Droid: no proprietary dependencies, builds from source
            applicationIdSuffix = ".fdroid"
        }
        create("googleplay") {
            dimension = "store"
            // Google Play: AAB required, Google handles app signing
        }
        create("huawei") {
            dimension = "store"
            // Huawei AppGallery: standard APK, no HMS required
            applicationIdSuffix = ".huawei"
        }
        create("samsung") {
            dimension = "store"
            // Samsung Galaxy Store: standard APK
            applicationIdSuffix = ".samsung"
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}

flutter {
    source = "../.."
}
