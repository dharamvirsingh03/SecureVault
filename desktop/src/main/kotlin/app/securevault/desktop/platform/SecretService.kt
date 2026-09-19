package app.securevault.desktop.platform

import java.util.concurrent.TimeUnit

/**
 * Optional convenience unlock via the freedesktop Secret Service (GNOME Keyring, KWallet's bridge).
 *
 * Reached through `secret-tool`, the libsecret command-line client, rather than by embedding a
 * D-Bus stack. That is a real Secret Service integration -- `secret-tool` talks the actual
 * protocol -- and it keeps a large, hard-to-audit dependency out of a password manager. The cost
 * is an external binary, which is why [availability] exists and why every failure is a *reported*
 * failure rather than a fallback.
 *
 * **What is stored: the wrapped vault key and nothing else.** Never the master password, never the
 * raw vault key, never vault contents. The wrapped key is useless without the master password that
 * unwraps it; keeping it here only removes the need to type that password every time.
 *
 * **What this is not.** It is not hardware-backed. GNOME Keyring on a typical Ubuntu desktop
 * unlocks with the login password and holds its secrets in process memory; there is no equivalent
 * of Android's StrongBox or of a key that cannot be exported. Anything describing this as
 * hardware-protected would be wrong, and the UI does not.
 *
 * If the service is missing, locked, or errors: convenience unlock is simply unavailable and the
 * master password path is untouched. There is no plaintext fallback file -- not a weaker one, not
 * a hidden one, none.
 */
class SecretServiceStore(private val label: String = "SecureVault wrapped vault key") {

    sealed interface Availability {
        data object Available : Availability
        data class Unavailable(val reason: String) : Availability
    }

    /**
     * Probes for `secret-tool` and a reachable collection.
     *
     * Deliberately distinguishes "not installed" from "installed but the keyring is locked or
     * absent", because the user's next step differs: install a package, or unlock their keyring.
     */
    fun availability(): Availability {
        val probe = runCatching { run(listOf("secret-tool", "--version"), null) }.getOrNull()
            ?: return Availability.Unavailable(
                "secret-tool is not installed. Install libsecret-tools to enable convenience unlock."
            )
        if (probe.exitCode != 0) {
            return Availability.Unavailable("secret-tool did not run correctly.")
        }
        if (System.getenv("DBUS_SESSION_BUS_ADDRESS").isNullOrBlank()) {
            return Availability.Unavailable(
                "No D-Bus session bus. This usually means a headless session, where no keyring is running."
            )
        }
        // A lookup for a key we do not expect to exist: exit code 1 means "no such secret", which
        // proves the service answered. Anything else means it did not.
        val result = runCatching { lookup(PROBE_KEY) }.getOrNull()
        return if (result == null) {
            Availability.Unavailable(
                "The keyring did not respond. It may be locked -- unlock it and try again."
            )
        } else {
            Availability.Available
        }
    }

    /** @return true when the secret was stored. Never throws; failure means unavailable. */
    fun store(key: String, value: String): Boolean = runCatching {
        run(listOf("secret-tool", "store", "--label=$label", ATTRIBUTE, key), value).exitCode == 0
    }.getOrDefault(false)

    /** @return the stored value, "" when absent, or null when the service could not be reached. */
    fun lookup(key: String): String? = runCatching {
        val result = run(listOf("secret-tool", "lookup", ATTRIBUTE, key), null)
        when (result.exitCode) {
            0 -> result.output.trim()
            1 -> ""           // reached the service; no such secret
            else -> null
        }
    }.getOrNull()

    fun clear(key: String): Boolean = runCatching {
        run(listOf("secret-tool", "clear", ATTRIBUTE, key), null).exitCode == 0
    }.getOrDefault(false)

    private data class Result(val exitCode: Int, val output: String)

    private fun run(command: List<String>, stdin: String?): Result {
        val process = ProcessBuilder(command).redirectErrorStream(false).start()
        stdin?.let { process.outputStream.bufferedWriter().use { w -> w.write(it) } }
        if (stdin == null) runCatching { process.outputStream.close() }
        val output = process.inputStream.bufferedReader().use { it.readText() }
        val finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            // A prompt the user never answered, most likely. Not an error worth a stack trace.
            return Result(exitCode = -1, output = "")
        }
        return Result(process.exitValue(), output)
    }

    private companion object {
        const val ATTRIBUTE = "securevault"
        const val PROBE_KEY = "availability-probe"
        const val TIMEOUT_SECONDS = 20L
    }
}
