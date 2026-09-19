package app.securevault

import app.securevault.core.crypto.SealedStateCorruptException
import app.securevault.platform.VaultStore

/**
 * In-memory [VaultStore] for JVM tests, with a switch to simulate the case that matters most:
 * state that is present but unreadable.
 */
class TestVaultStore : VaultStore {

    private val values = mutableMapOf<String, String>()

    /** Keys that will throw as if their file were damaged or the device key had changed. */
    val corrupt = mutableSetOf<String>()

    override fun getString(name: String): String? {
        if (name in corrupt) throw SealedStateCorruptException("simulated corruption of '$name'")
        return values[name]
    }

    override fun putString(name: String, value: String) {
        values[name] = value
    }

    override fun remove(name: String) {
        values.remove(name)
    }

    override fun clearAll() {
        values.clear()
    }

    fun has(name: String) = values.containsKey(name)
}
