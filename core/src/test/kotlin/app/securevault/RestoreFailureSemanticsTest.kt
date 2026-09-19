package app.securevault

import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.model.Fields
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultManager
import app.securevault.core.vault.VaultMetadata
import app.securevault.core.vault.VaultState
import app.securevault.data.repo.ItemRepository
import app.securevault.data.store.InMemoryFolderStore
import app.securevault.data.store.InMemoryItemStore
import app.securevault.feature.backup.BackupCodec
import app.securevault.feature.backup.RestoreFailure
import app.securevault.feature.backup.VaultRestorer
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.Base64

/**
 * Two properties, checked against as many failure modes as can be produced without a debugger.
 *
 * 1. **An existing vault is unchanged by a failed restore** -- compared by hashing the header,
 *    every attachment file and every stored ciphertext row before and after.
 * 2. **A failed restore leaves nothing that could become the next vault** -- checked through the
 *    restore journal, which is the mechanism that makes that true rather than an assumption.
 *
 * What cannot be tested here is stated plainly rather than faked: the JVM cannot kill a process
 * mid-write, so real crash safety is asserted only for the states the journal describes, and the
 * genuine interruption cases are listed in README.md as instrumentation work.
 */
class RestoreFailureSemanticsTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val backupPassword = "the backup master passphrase"
    private val livePassword = "the existing vault passphrase"
    private val codec = BackupCodec("1.0.0-test")
    private val vek = KeyHierarchy.generateVek()
    private val vaultId = "backed-up-vault"

    private val kdf = KdfParams(
        KdfAlgorithm.PBKDF2_HMAC_SHA256,
        Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
        pbkdf2Rounds = 1_000
    )

    private lateinit var files: File
    private lateinit var itemStore: InMemoryItemStore
    private lateinit var folderStore: InMemoryFolderStore
    private lateinit var repository: ItemRepository
    private lateinit var manager: VaultManager
    private lateinit var restorer: VaultRestorer

    @Before
    fun setUp() {
        files = temp.newFolder("files")
        itemStore = InMemoryItemStore()
        folderStore = InMemoryFolderStore()
        repository = ItemRepository(itemStore, folderStore)
        manager = VaultManager(
            filesDir = files,
            store = TestVaultStore(),
            biometricKeyStore = null,
            kdfParamsFactory = { KdfSelection(kdf, usedFallback = false) }
        )
        restorer = VaultRestorer(
            codec = codec,
            repository = repository,
            liveAttachmentsDir = File(files, "attachments"),
            stagingRoot = File(files, VaultRestorer.STAGING_DIR_NAME),
            journalFile = journal(),
            vaultHeaderExists = { manager.state() !is VaultState.Absent }
        )
    }

    private fun journal() = File(files, "vault/restore.journal")
    private fun header() = File(files, "vault/metadata.json")

    // ---- 1. the existing vault is sacrosanct -----------------------------------------------

    /** A fingerprint of everything that makes up the live vault. */
    private suspend fun vaultFingerprint(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        if (header().exists()) digest.update(header().readBytes())
        itemStore.rows.toSortedMap().forEach { (id, row) ->
            digest.update(id.toByteArray()); digest.update(row.ciphertext)
        }
        folderStore.rows.toSortedMap().forEach { (id, row) ->
            digest.update(id.toByteArray()); digest.update(row.ciphertext)
        }
        File(files, "attachments").listFiles()?.sortedBy { it.name }?.forEach {
            digest.update(it.name.toByteArray()); digest.update(it.readBytes())
        }
        return Base64.getEncoder().encodeToString(digest.digest())
    }

    private suspend fun withLiveVault(): String {
        manager.createVault("My real vault", livePassword.toCharArray(), enableRecovery = false)
        val session = manager.session.value!!
        repository.saveAll(
            session,
            listOf(
                VaultItem(
                    id = "live-1", type = ItemType.LOGIN,
                    payload = ItemPayload(
                        title = "Live login",
                        fields = mapOf(Fields.USERNAME to "me", Fields.PASSWORD to "live-secret")
                    )
                )
            )
        )
        File(files, "attachments").mkdirs()
        File(files, "attachments/live-att.enc").writeBytes(RandomSource.bytes(256))
        manager.lock()
        return vaultFingerprint()
    }

    @Test
    fun `every failure mode leaves an existing vault byte-identical`() = runBlocking {
        val before = withLiveVault()

        val attempts: List<Pair<String, () -> Unit>> = listOf(
            "wrong password" to { runBlocking { stage(goodBackup(), "not the password") } },
            "tampered backup" to {
                val bytes = goodBackup().also { it[it.size - 25] = (it[it.size - 25] + 1).toByte() }
                runBlocking { stage(bytes) }
            },
            "unsupported version" to {
                val bytes = goodBackup().also { it[7] = (BackupCodec.FORMAT_VERSION + 1).toByte() }
                runBlocking { stage(bytes) }
            },
            "not a backup" to { runBlocking { stage(ByteArray(400) { 0x5A }) } },
            "unavailable KDF" to { runBlocking { stage(argon2Backup()) } },
            "malformed archive" to { runBlocking { stage(ByteArray(8)) } },
            "orphaned folder reference" to { runBlocking { stage(orphanFolderBackup()) } },
            "missing attachment" to { runBlocking { stage(missingAttachmentBackup()) } },
            "duplicate item ids" to { runBlocking { stage(duplicateIdBackup()) } },
            "commit refused over an existing vault" to {
                runBlocking { commit(stage(goodBackup())) }
            }
        )

        attempts.forEach { (label, attempt) ->
            runCatching { attempt() }.also {
                assertTrue("$label should have failed", it.isFailure)
                assertTrue("$label threw the wrong type", it.exceptionOrNull() is RestoreFailure)
            }
            assertEquals("the live vault changed after: $label", before, vaultFingerprint())
        }

        // And it still opens, with its own password, holding its own data.
        val session = manager.unlockWithPassword(livePassword.toCharArray())
        assertEquals("Live login", repository.loadAll(session).single().title)
        assertFalse("a refused restore must not journal", journal().exists())
    }

    // ---- 2. an interrupted restore cannot become the next vault ------------------------------

    @Test
    fun `a journal without a header means the restore is purged, not inherited`() = runBlocking {
        // Exactly the state an interrupted commit leaves: records and attachments written under
        // the backup's key, journal open, header never reached.
        journal().parentFile!!.mkdirs()
        journal().writeText("""{"vaultId":"$vaultId","startedAt":1}""")
        File(files, "attachments").mkdirs()
        File(files, "attachments/ghost.enc").writeBytes(RandomSource.bytes(64))
        val session = manager.let {
            // Records written with a key no future vault will have.
            app.securevault.core.vault.VaultSession(vaultId, vek.copyOf())
        }
        repository.saveAll(
            session,
            listOf(VaultItem(id = "ghost", type = ItemType.LOGIN, payload = ItemPayload(title = "Ghost")))
        )
        assertEquals(1, itemStore.rows.size)

        val outcome = restorer.recoverInterruptedRestore()

        assertEquals(VaultRestorer.RecoveryOutcome.INTERRUPTED_RESTORE_PURGED, outcome)
        assertEquals("ghost records must not survive", 0, itemStore.rows.size)
        assertFalse("ghost attachments must not survive", File(files, "attachments/ghost.enc").exists())
        assertFalse(journal().exists())
        assertTrue(manager.state() is VaultState.Absent)
    }

    @Test
    fun `a journal alongside a committed header only clears the marker`() = runBlocking {
        // The window between the header landing and the journal being removed. Purging here would
        // destroy a vault that had in fact been restored successfully.
        manager.createVault("Committed", livePassword.toCharArray(), false)
        val session = manager.session.value!!
        repository.saveAll(
            session,
            listOf(VaultItem(id = "real", type = ItemType.LOGIN, payload = ItemPayload(title = "Real")))
        )
        journal().writeText("""{"vaultId":"x","startedAt":1}""")

        val outcome = restorer.recoverInterruptedRestore()

        assertEquals(VaultRestorer.RecoveryOutcome.MARKER_CLEARED, outcome)
        assertEquals("committed data must survive", 1, itemStore.rows.size)
        assertTrue(header().exists())
        assertFalse(journal().exists())
    }

    @Test
    fun `no journal means nothing is touched`() = runBlocking {
        val before = withLiveVault()
        assertEquals(VaultRestorer.RecoveryOutcome.NOTHING_TO_DO, restorer.recoverInterruptedRestore())
        assertEquals(before, vaultFingerprint())
    }

    @Test
    fun `a successful restore leaves no journal behind`() = runBlocking {
        commit(stage(goodBackup()))
        assertFalse(journal().exists())
        assertTrue(manager.state() is VaultState.Present)
    }

    @Test
    fun `a retry after a purge produces exactly one copy of everything`() = runBlocking {
        // First attempt: simulate debris plus an open journal.
        journal().parentFile!!.mkdirs()
        journal().writeText("""{"vaultId":"$vaultId","startedAt":1}""")
        File(files, "attachments").mkdirs()
        File(files, "attachments/stale.enc").writeBytes(RandomSource.bytes(32))

        restorer.recoverInterruptedRestore()
        commit(stage(goodBackup()))

        assertEquals("no duplicates, no leftovers", 2, itemStore.rows.size)
        assertFalse(File(files, "attachments/stale.enc").exists())
        val session = manager.unlockWithPassword(backupPassword.toCharArray())
        assertEquals(setOf("item-1", "item-2"), repository.loadAll(session).map { it.id }.toSet())
    }

    // ---- fixtures ----------------------------------------------------------------------------

    private val folders = listOf(app.securevault.core.model.Folder(id = "f1", name = "Money"))

    private fun metadata(params: KdfParams = kdf) = VaultMetadata(
        vaultId = vaultId,
        name = "Backed up vault",
        formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
        createdAt = 1_700_000_000_000,
        modifiedAt = 1_700_000_000_000,
        kdf = params,
        wrappedVek = KeyHierarchy.wrapVek(
            KeyHierarchy.deriveKek(backupPassword.toCharArray(), kdf), vek, vaultId
        ),
        recovery = null,
        keyFileRequired = false,
        backupId = "b1"
    )

    private fun items() = listOf(
        VaultItem(
            id = "item-1", type = ItemType.LOGIN, folderId = "f1",
            payload = ItemPayload(title = "Bank", fields = mapOf(Fields.PASSWORD to "p"))
        ),
        VaultItem(id = "item-2", type = ItemType.SECURE_NOTE, payload = ItemPayload(title = "Note"))
    )

    private fun build(
        meta: VaultMetadata = metadata(),
        itemList: List<VaultItem> = items(),
        folderList: List<app.securevault.core.model.Folder> = folders
    ): ByteArray {
        val out = ByteArrayOutputStream()
        codec.create(meta, codec.backupKeyFrom(vek), itemList, folderList, emptyList(), out)
        return out.toByteArray()
    }

    private fun goodBackup() = build()

    private fun argon2Backup() = build(meta = metadata(kdf.copy(algorithm = KdfAlgorithm.ARGON2ID)))

    private fun orphanFolderBackup() = build(
        itemList = listOf(
            VaultItem(id = "o", type = ItemType.LOGIN, folderId = "nope", payload = ItemPayload(title = "O"))
        ),
        folderList = emptyList()
    )

    private fun missingAttachmentBackup() = build(
        itemList = listOf(
            VaultItem(
                id = "m", type = ItemType.LOGIN,
                payload = ItemPayload(
                    title = "M",
                    attachments = listOf(
                        app.securevault.core.model.AttachmentRef("gone", "g.bin", "application/octet-stream", 1, 0)
                    )
                )
            )
        ),
        folderList = emptyList()
    )

    private fun duplicateIdBackup() = build(
        itemList = listOf(
            VaultItem(id = "same", type = ItemType.LOGIN, payload = ItemPayload(title = "A")),
            VaultItem(id = "same", type = ItemType.LOGIN, payload = ItemPayload(title = "B"))
        ),
        folderList = emptyList()
    )

    private suspend fun stage(bytes: ByteArray, pass: String = backupPassword) =
        restorer.stage({ ByteArrayInputStream(bytes) }, pass.toCharArray())

    private suspend fun commit(staged: app.securevault.feature.backup.StagedRestore) =
        restorer.commit(
            staged = staged,
            password = backupPassword.toCharArray(),
            currentState = manager.state(),
            installHeader = { manager.installRestoredHeader(it) }
        )
}
