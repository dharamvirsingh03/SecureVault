package app.securevault.platform

import app.securevault.core.crypto.SealedStateCorruptException

/**
 * Small encrypted key-value storage for app state that is not vault content but still must not be
 * readable or editable by anything else: failed-attempt counters, the biometric-wrapped key, the
 * settings that control locking.
 *
 * The contract that matters is on [getString]. Absent and unreadable are different answers and
 * must never collapse into one, because the caller's safe response to each is opposite: a missing
 * attempt counter means a fresh install and gets a default, while an unreadable one means someone
 * or something has damaged it and must not hand out a clean slate.
 *
 * Existing as an interface also lets the vault lifecycle be unit tested without a Keystore.
 */
interface VaultStore {

    /**
     * @return the stored value, or null if nothing was ever stored under [name].
     * @throws SealedStateCorruptException if a value exists but cannot be decrypted.
     */
    fun getString(name: String): String?

    fun putString(name: String, value: String)

    fun remove(name: String)

    fun clearAll()
}
