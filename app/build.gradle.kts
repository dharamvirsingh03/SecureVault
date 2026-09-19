import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    // No org.jetbrains.kotlin.android here: AGP 9 applies the Kotlin Gradle plugin itself, and
    // applying it explicitly is now an error. The Compose compiler plugin and KSP are still
    // applied separately, and both still need the Kotlin version in the catalog.
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "app.securevault"
    // Compose 1.12 (BOM 2026.08.00) requires compileSdk 37.
    compileSdk = 37

    defaultConfig {
        applicationId = "app.securevault"
        // 28 is the floor: BiometricPrompt with a CryptoObject, setUnlockedDeviceRequired and
        // StrongBox all arrived in Android 9, and every one of them is load-bearing here.
        minSdk = 28
        // Deliberately one behind compileSdk. Targeting a platform whose behaviour changes have
        // not been tested on a device would be a claim this project cannot back up.
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    testOptions {
        unitTests {
            // Deliberately NOT isReturnDefaultValues = true.
            //
            // That flag makes every un-stubbed android.jar method return null/0 instead of
            // throwing, which would silently hollow out the org.json calls these tests exist to
            // exercise. Instead a real org.json implementation is on the unit-test classpath
            // (see testImplementation below); the mockable android.jar is appended last, so the
            // real one wins. A test that touches an Android API with no JVM implementation now
            // fails loudly, which is what we want from a security test suite.
            isIncludeAndroidResources = true
        }
    }
}

// Module-level KSP configuration. This belongs here, not inside android.defaultConfig -- the KSP
// extension is a sibling of `android`, and nesting it there fails at configuration time.
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
    arg("room.incremental", "true")
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // The shared SecureVault core: crypto, vault model and portable feature logic.
    implementation(project(":core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    implementation(libs.androidx.biometric)

    // Argon2id. The only native dependency in the project. Ships JNI .so files; see
    // README.md "Dependency notes" for the ABI and maintenance caveats.
    implementation(libs.argon2kt)

    // QR generation for the recovery kit, and scanning for TOTP enrolment. Both run offline.
    implementation(libs.zxing.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.mlkit.barcode)

    testImplementation(libs.junit)
    // In-memory ItemStore/FolderStore, shared with :core's own repository tests.
    testImplementation(testFixtures(project(":core")))
    // Real org.json on the unit-test classpath, in place of the android.jar stub.
    testImplementation(libs.json)
}
