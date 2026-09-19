package app.securevault.desktop.platform

/**
 * Optional OS-protected storage for convenience unlock.
 *
 * **Only ever holds the wrapped vault key.** Never the master password, never the raw vault key,
 * never vault contents. The wrapped key is useless without the master password that unwraps it;
 * keeping it here removes the need to retype that password every time, and nothing more.
 *
 * Every implementation must fail as *unavailable*, never as a weaker fallback. If the OS mechanism
 * is missing, locked or broken, convenience unlock simply does not exist for that session and the
 * master password works exactly as before. There is no plaintext fallback file on any platform.
 */
interface SecureStorage {

    sealed interface Availability {
        data object Available : Availability
        data class Unavailable(val reason: String) : Availability
    }

    /** A short name for the UI: "GNOME Keyring", "Windows DPAPI". */
    val displayName: String

    /**
     * What this actually protects against, in plain language.
     *
     * Present because the honest answer differs per platform and is easy to overstate. Neither
     * implementation is hardware-backed, and neither is equivalent to Android's StrongBox.
     */
    val protectionSummary: String

    fun availability(): Availability
    fun store(key: String, value: String): Boolean
    /** The stored value, "" when absent, or null when the service could not be reached. */
    fun lookup(key: String): String?
    fun clear(key: String): Boolean

    companion object {
        fun forThisPlatform(): SecureStorage =
            if (Platform.isWindows) WindowsCredentialStore() else SecretServiceStore()
    }
}
