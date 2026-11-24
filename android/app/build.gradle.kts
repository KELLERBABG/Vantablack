plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.globalghost.net"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.globalghost.net"
        minSdk = 26
        targetSdk = 34
        versionCode = 218
        versionName = "2.1.8"
    }

    signingConfigs {
        create("release") {
            val envStore = System.getenv("ANDROID_KEYSTORE_PATH")
            if (!envStore.isNullOrBlank()) {
                storeFile = file(envStore.trim())
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")?.trim('\r', '\n')
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")?.trim()
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")?.trim('\r', '\n')
            } else {
                storeFile = file("vantablack.keystore")
                storePassword = "vantablack_mesh_key"
                keyAlias = "vantablack"
                keyPassword = "vantablack_mesh_key"
            }
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("release")
        }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        jniLibs.useLegacyPackaging = false
    }
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
