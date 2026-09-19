package app.securevault

import android.app.Application
import app.securevault.core.crypto.Kdf
import app.securevault.di.ServiceLocator
import app.securevault.platform.Argon2KtBackend

/**
 * No analytics SDK, no crash reporter, no network client is initialised here -- there is nothing
 * to initialise. The app makes exactly one kind of outbound request, the breach-check range
 * lookup, and only after the user switches it on.
 */
class SecureVaultApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Before anything can open or create a vault. Without this the core would see no Argon2
        // implementation and behave as it does on a device whose native library will not load:
        // new vaults on PBKDF2 with a warning, existing Argon2id vaults refusing to open. That is
        // the correct failure mode, but it must never be reached by forgetting this line.
        Kdf.installArgon2Backend(Argon2KtBackend())
        ServiceLocator.appVersion = runCatching {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "1.0.0"
        }.getOrDefault("1.0.0")
        ServiceLocator.autoLock(this)
    }
}
