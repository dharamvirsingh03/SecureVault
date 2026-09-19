package app.securevault.core.vault

import app.securevault.core.crypto.KeyDomain
import app.securevault.core.crypto.KeyHierarchy
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Live keys for an unlocked vault. Exists only in memory, only while unlocked.
 *
 * Nothing outside this class keeps a copy of the VEK. Locking zeroes every derived key that was
 * actually created and marks the session dead, so a stale reference fails loudly instead of
 * quietly decrypting.
 */
/*
 * Visibility note.
 *
 * Phase 2 had to widen these to public: VaultSession moved into :core while VaultManager and
 * VaultRestorer -- its only legitimate callers -- were still in :app, and `internal` does not
 * cross a module boundary.
 *
 * Both callers are now in :core as well, so both members are `internal` again. Raw access to the
 * vault encryption key is reachable from exactly two classes in one module, which is where it
 * was before the extraction started and where it should stay. :core's own tests can still reach
 * them, because a module's test source set shares its `internal` visibility.
 */
class VaultSession internal constructor(
    val vaultId: String,
    private val vek: ByteArray
) {
    private val dead = AtomicBoolean(false)

    private val itemKeyLazy = lazy { KeyHierarchy.subkey(aliveVek(), KeyDomain.ITEMS) }
    private val attachmentKeyLazy = lazy { KeyHierarchy.subkey(aliveVek(), KeyDomain.ATTACHMENTS) }
    private val metadataKeyLazy = lazy { KeyHierarchy.subkey(aliveVek(), KeyDomain.METADATA) }
    private val databaseKeyLazy = lazy { KeyHierarchy.subkey(aliveVek(), KeyDomain.DATABASE) }

    val itemKey: ByteArray by itemKeyLazy
    val attachmentKey: ByteArray by attachmentKeyLazy
    val metadataKey: ByteArray by metadataKeyLazy
    val databaseKey: ByteArray by databaseKeyLazy

    @Volatile
    var lastActivityAt: Long = System.currentTimeMillis()
        private set

    val isAlive: Boolean get() = !dead.get()

    fun touch() {
        lastActivityAt = System.currentTimeMillis()
    }

    /** Per-attachment key, so one leaked attachment key cannot open the others. */
    fun attachmentKeyFor(attachmentId: String): ByteArray =
        KeyHierarchy.subkey(aliveVek(), KeyDomain.ATTACHMENTS, attachmentId)

    fun backupKey(): ByteArray = KeyHierarchy.subkey(aliveVek(), KeyDomain.BACKUP)

    /** Only the vault manager needs the raw VEK -- to rewrap it on password change or backup. */
    /**
     * A copy of the vault encryption key, for rewrapping it under a new password or a recovery
     * code. The caller owns the copy and must zero it.
     *
     * `internal`, and worth keeping that way: this is the only route by which raw key bytes leave
     * a session.
     */
    internal fun exportVekForRewrap(): ByteArray = aliveVek().copyOf()

    fun destroy() {
        if (dead.compareAndSet(false, true)) {
            if (itemKeyLazy.isInitialized()) itemKeyLazy.value.fill(0)
            if (attachmentKeyLazy.isInitialized()) attachmentKeyLazy.value.fill(0)
            if (metadataKeyLazy.isInitialized()) metadataKeyLazy.value.fill(0)
            if (databaseKeyLazy.isInitialized()) databaseKeyLazy.value.fill(0)
            vek.fill(0)
        }
    }

    private fun aliveVek(): ByteArray {
        check(!dead.get()) { "Vault session has been locked" }
        return vek
    }
}
