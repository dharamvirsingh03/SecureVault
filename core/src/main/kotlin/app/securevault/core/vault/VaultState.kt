package app.securevault.core.vault

/**
 * What is actually on this device.
 *
 * These three are not interchangeable and the app must never collapse them. The old code read the
 * header with `runCatching{}.getOrNull()`, so a damaged header and no header at all produced the
 * same `null`. That is dangerous in exactly the situation where a user most needs the truth: if
 * the app says "no vault here" to someone whose header is merely damaged, the obvious next move
 * is to create a new one -- and the honest answer, "your data is still there, restore from a
 * backup or a recovery code", never gets offered.
 */
sealed interface VaultState {

    /** No vault has been created on this device. Setup is safe. */
    data object Absent : VaultState

    /**
     * A vault exists and its header parsed. Says nothing about whether the password is right.
     *
     * [recoveredFromPreviousCopy] means the live header was unreadable and the preserved crash-
     * window copy was used instead. That is a rollback, and it is never silent: if the user had
     * just changed their master password, the recovered header expects the *old* one, and being
     * told "wrong password" without explanation would be indistinguishable from data loss.
     */
    data class Present(
        val metadata: VaultMetadata,
        val recoveredFromPreviousCopy: Boolean = false
    ) : VaultState {
        val rollbackWarning: String?
            get() = if (!recoveredFromPreviousCopy) null else
                "SecureVault recovered your vault header from a backup copy after the main one " +
                    "was found damaged. If you changed your master password very recently, that " +
                    "change may have been lost -- try your previous password. Your encrypted " +
                    "items are unaffected."
    }

    /**
     * A vault exists but something about it cannot be read. Creating a new vault from here would
     * hide recoverable data, so the UI must not offer setup in this state.
     */
    data class Corrupt(val reason: Reason, val detail: String) : VaultState {
        enum class Reason {
            /** The header file is present but is not parseable JSON, or is missing fields. */
            UNREADABLE_HEADER,

            /** The header declares a format version this build does not know how to open. */
            UNSUPPORTED_VERSION,

            /** Encrypted app state (lockout counters, settings) will not decrypt. */
            SEALED_STATE
        }

        /** Wording safe to show a user: no internals, no reassurance the app cannot back up. */
        val userMessage: String
            get() = when (reason) {
                Reason.UNREADABLE_HEADER ->
                    "The vault header on this device is damaged. Your encrypted items may still " +
                        "be intact. Do not create a new vault -- restore from a backup file or " +
                        "use a recovery code instead."
                Reason.UNSUPPORTED_VERSION ->
                    "This vault was created by a newer version of SecureVault. Update the app " +
                        "rather than creating a new vault."
                Reason.SEALED_STATE ->
                    "SecureVault's protected app state could not be read. This can happen if the " +
                        "device's screen lock was removed or the app data was modified. Unlocking " +
                        "is temporarily restricted as a precaution."
            }
    }
}
