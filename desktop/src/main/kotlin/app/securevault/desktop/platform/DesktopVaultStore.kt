package app.securevault.desktop.platform

import app.securevault.core.crypto.SealedStateCorruptException
import app.securevault.platform.DurableFile
import app.securevault.platform.VaultStore
import java.io.File

/**
 * The desktop's [VaultStore]: small pieces of app state that are not vault contents.
 *
 * Android backs this with a non-exportable Android Keystore key. **Linux has no equivalent, and
 * this does not pretend otherwise.** There is no device key a local attacker cannot also reach:
 * anything this process can decrypt without user interaction, a process running as the same user
 * can decrypt too. Encrypting these files under a key stored beside them would look like security
 * and provide none.
 *
 * So state is written as plain JSON with 0600 permissions, and the honest consequences are:
 *
 *  - Settings and the failed-attempt counter are readable and editable by the user's own account.
 *    An attacker with that much access can reset the lockout. Android concedes the same for a
 *    rooted device; on Linux the bar is lower, and SECURITY.md says so rather than burying it.
 *  - **No secret is kept here.** Not the master password, not the vault key, not item contents.
 *    The wrapped vault key for convenience unlock goes to [SecretServiceStore] or nowhere.
 *
 * Writes go through [DurableFile] for the same reason as the vault header: a half-written counter
 * is a counter that silently resets.
 */
class DesktopVaultStore(private val dir: File = Paths.stateDir) : VaultStore {

    override fun getString(name: String): String? {
        val file = fileFor(name)
        val previous = DurableFile.previous(file)
        val source = when {
            file.exists() -> file
            previous.exists() -> previous
            else -> return null
        }
        return try {
            source.readText(Charsets.UTF_8)
        } catch (e: Exception) {
            // Present but unreadable is not the same as absent, and must not be defaulted away.
            throw SealedStateCorruptException("App state '$name' could not be read", e)
        }
    }

    override fun putString(name: String, value: String) {
        val file = fileFor(name)
        DurableFile.write(file, value.toByteArray(Charsets.UTF_8))
        Paths.restrict(file)
        Paths.restrict(DurableFile.previous(file))
    }

    override fun remove(name: String) = DurableFile.deleteAll(fileFor(name))

    override fun clearAll() {
        dir.listFiles()?.forEach { it.delete() }
    }

    private fun fileFor(name: String) = File(Paths.secured(dir), "$name.json")
}
