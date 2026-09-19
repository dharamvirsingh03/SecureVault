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
            targetFormats(TargetFormat.Deb)
            packageName = "securevault"
            packageVersion = "1.0.0"
            vendor = "SecureVault"
            description = "Local-first, offline-first password manager"
            copyright = "SecureVault"

            // Trim the bundled runtime to what is actually used. java.sql for SQLite, jdk.crypto
            // for the JCE providers, java.desktop for Compose and the clipboard.
            includeAllModules = false
            modules("java.sql", "java.naming", "java.desktop", "jdk.crypto.ec", "jdk.unsupported")

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
