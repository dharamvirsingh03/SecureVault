package app.securevault.platform

import android.content.Context
import app.securevault.core.crypto.BiometricKeyStore
import app.securevault.core.vault.VaultManager
import app.securevault.data.db.VaultDatabase
import java.io.File

/**
 * Android's wiring for the portable [VaultManager].
 *
 * This is the whole of what used to be the `VaultManager(Context)` convenience constructor. It
 * supplies four platform facts -- where files live, where protected app state lives, what backs
 * convenience unlock, and where the database's files are -- and nothing else. No vault logic lives
 * here, and none was duplicated: there is exactly one VaultManager, in :core.
 */
fun androidVaultManager(context: Context): VaultManager = VaultManager(
    filesDir = context.filesDir,
    store = SealedStore(context, "vault"),
    biometricKeyStore = BiometricKeyStore(),
    databaseCloser = { VaultDatabase.closeAndClear() },
    // Room keeps the database, its write-ahead log and its journal side by side. All three have to
    // go, which is why this lists files rather than naming one.
    databaseFiles = {
        File(context.filesDir.parentFile, "databases")
            .listFiles { f -> f.name.startsWith(VaultDatabase.NAME) }
            ?.toList()
            .orEmpty()
    }
)
