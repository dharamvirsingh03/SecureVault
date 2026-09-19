plugins {
    // Applied WITHOUT a version, deliberately.
    //
    // The root build script declares the Android Gradle Plugin, which puts AGP -- and, since
    // AGP 9, the Kotlin Gradle Plugin it now bundles -- on the buildscript classpath shared by
    // every project in this build. Requesting org.jetbrains.kotlin.jvm with an explicit version
    // asks Gradle to reconcile that request against a plugin it cannot read a version from, and
    // it refuses rather than guess:
    //
    //   "the plugin is already on the classpath with an unknown version,
    //    so compatibility cannot be checked"
    //
    // Applying it version-less uses the Kotlin plugin already on that classpath -- the same one
    // compiling the Android module. That is the point: one Kotlin toolchain for the whole build,
    // which is exactly what pinning a second version here would break.
    id("org.jetbrains.kotlin.jvm")

    // Lets :app and :desktop run the *same* Argon2 vectors against their own backends, rather
    // than each keeping its own copy of the expected values.
    `java-test-fixtures`
}

// The shared SecureVault core: crypto, vault model, and the portable feature logic.
//
// Plain Kotlin/JVM on purpose, so both the Android app and the Linux desktop app can consume it.
// Nothing in this module may import android.* or androidx.* -- if a platform capability is needed,
// it is expressed here as an interface and implemented on each side.
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
    // api, not implementation: StateFlow and suspend functions are part of :core's public surface
    // (VaultIndex.items, every ItemRepository method), so consumers need coroutines on their
    // compile classpath too.
    api(libs.kotlinx.coroutines.core)

    // compileOnly, not implementation. Android supplies org.json in the platform, and leaking this
    // artifact onto the Android classpath would produce duplicate classes. Each consumer brings
    // its own: the desktop module declares it for real, Android inherits the platform's.
    compileOnly(libs.json)

    testImplementation(libs.junit)
    testImplementation(libs.json)
    testFixturesImplementation(libs.junit)
    testFixturesApi(libs.kotlinx.coroutines.core)
}
