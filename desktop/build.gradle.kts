import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    // Version-less, for the same reason as :core -- AGP puts the Kotlin plugin on the shared
    // buildscript classpath and rejects a second versioned request.
    id("org.jetbrains.kotlin.jvm")
    alias(libs.plugins.compose.desktop)
    alias(libs.plugins.kotlin.compose)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)

    // org.json is compileOnly in :core because Android supplies it in the platform. A JVM build
    // has to bring it for real.
    implementation(libs.json)

    // Argon2id in pure Java. No JNI, so no ABI or UnsatisfiedLinkError surface -- the failure mode
    // that makes argon2kt the project's biggest supply-chain concern on Android does not exist
    // here. Must produce byte-identical output to Android; that is what the vectors are for.
    implementation(libs.bouncycastle)

    implementation(libs.sqlite.jdbc)
    implementation(libs.pdfbox)

    testImplementation(libs.junit)
    testImplementation(testFixtures(project(":core")))
}

compose.desktop {
    application {
        mainClass = "app.securevault.desktop.MainKt"

        nativeDistributions {
            // One module, two installers. Which one you can build depends on the host: jpackage
            // produces a .deb on Linux and an .msi on Windows; it does not cross-compile.
            targetFormats(TargetFormat.Deb, TargetFormat.Msi)
            packageName = "securevault"
            packageVersion = "1.0.0"
            vendor = "SecureVault"
            description = "Local-first, offline-first password manager"
            copyright = "SecureVault"

            // Trim the bundled runtime to what is actually used. java.sql for SQLite, jdk.crypto
            // for the JCE providers, java.desktop for Compose and the clipboard.
            includeAllModules = false
            modules("java.sql", "java.naming", "java.desktop", "jdk.crypto.ec", "jdk.unsupported")

            windows {
                packageVersion = "1.0.0"
                menuGroup = "SecureVault"
                // Start Menu entry yes, desktop shortcut no -- a password manager does not need
                // to plant an icon on someone's desktop.
                menu = true
                shortcut = false
                dirChooser = true
                // Stable across versions so an upgrade replaces the install rather than sitting
                // beside it. Generated once for this application; never reuse it for another.
                upgradeUuid = "8f3d5a41-6c29-4b7e-9a1d-2e5c7b04f6d3"
                iconFile.set(project.file("src/main/resources/securevault.ico"))
                // Program Files by default. User vault data lives in %LOCALAPPDATA%\\SecureVault
                // and is never written here -- see PlatformPaths.
            }

            linux {
                packageName = "securevault"
                debMaintainer = "securevault@localhost"
                menuGroup = "Utility;Security"
                appCategory = "utils"
                iconFile.set(project.file("src/main/resources/securevault.png"))
                // User data never goes here. It lives under $XDG_DATA_HOME/securevault.
                installationPath = "/opt/securevault"
                shortcut = true
                debPackageVersion = "1.0.0"
            }
        }
    }
}
