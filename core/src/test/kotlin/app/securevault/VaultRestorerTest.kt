package app.securevault

import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.StreamAead
import app.securevault.core.model.Fields
import app.securevault.core.model.Folder
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
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Restore, end to end, on the JVM.
 *
 * The property most of these tests are really about is the same one stated twice: **a restore that
 * does not finish must leave nothing behind**. Not a half-populated database, not a stray
 * attachment, not a header pointing at records that are not there. The commit ordering — records
 * and attachments first, header last — is what makes that true, and several tests below check it
 * by asserting that a failed restore leaves the app still seeing no vault at all.
 */
class VaultRestorerTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val password = "the backup master passphrase"
    private val codec = BackupCodec("1.0.0-test")
    private val vek = KeyHierarchy.generateVek()
    private val vaultId = "vault-to-restore"

    private val kdf = KdfParams(
        algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
        saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
        pbkdf2Rounds = 1_000
    )

    private val sourceMetadata by lazy {
        VaultMetadata(
            vaultId = vaultId,
            name = "Restored vault",
            formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
            createdAt = 1_700_000_000_000,
            modifiedAt = 1_700_000_000_000,
            kdf = kdf,
            wrappedVek = KeyHierarchy.wrapVek(
                KeyHierarchy.deriveKek(password.toCharArray(), kdf), vek, vaultId
            ),
            recovery = null,
            keyFileRequired = false,
            backupId = "backup-1"
        )
    }

    private lateinit var files: File
    private lateinit var itemStore: InMemoryItemStore
    private lateinit var folderStore: InMemoryFolderStore
    private lateinit var repository: ItemRepository
    private lateinit var manager: VaultManager
    private lateinit var restorer: VaultRestorer

    private val folders = listOf(Folder(id = "folder-1", name = "Money"))

    private fun items(withAttachment: app.securevault.core.model.AttachmentRef? = null) = listOf(
        VaultItem(
            id = "item-1",
            type = ItemType.LOGIN,
            folderId = "folder-1",
            payload = ItemPayload(
                title = "Bank",
                fields = mapOf(Fields.USERNAME to "jane", Fields.PASSWORD to "a-password"),
                tags = listOf("money", "critical"),
                attachments = listOfNotNull(withAttachment)
            )
        ),
        VaultItem(
            id = "item-2",
            type = ItemType.SECURE_NOTE,
            payload = ItemPayload(title = "Note", notes = "remember this")
        )
    )

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
            journalFile = File(files, "vault/restore.journal"),
            vaultHeaderExists = { manager.state() !is VaultState.Absent }
        )
    }

    private fun backupBytes(
        attachmentFiles: List<File> = emptyList(),
        itemList: List<VaultItem> = items()
    ): ByteArray {
        val out = ByteArrayOutputStream()
        codec.create(
            sourceMetadata, codec.backupKeyFrom(vek), itemList, folders, attachmentFiles, out
        )
        return out.toByteArray()
    }

    private fun stagingRoot() = File(files, VaultRestorer.STAGING_DIR_NAME)
    private fun header() = File(files, "vault/metadata.json")

    private suspend fun stage(bytes: ByteArray, pass: String = password) =
        restorer.stage({ ByteArrayInputStream(bytes) }, pass.toCharArray())

    private suspend fun commit(staged: app.securevault.feature.backup.StagedRestore, pass: String = password) =
        restorer.commit(
            staged = staged,
            password = pass.toCharArray(),
            currentState = manager.state(),
            installHeader = { manager.installRestoredHeader(it) }
        )

    // ---- success ------------------------------------------------------------------------------

    @Test
    fun `a valid backup restores and the vault opens normally`() = runBlocking {
        val staged = stage(backupBytes())
        assertEquals("Restored vault", staged.preview.vaultName)
        assertEquals(2, staged.preview.itemCount)
        assertEquals(1, staged.preview.folderCount)
        assertEquals(2, staged.preview.tagCount)
        // Staging must not have touched the vault yet.
        assertTrue(manager.state() is VaultState.Absent)
        assertEquals(0, itemStore.rows.size)

        val summary = commit(staged)
        assertEquals(2, summary.items)
        assertEquals(1, summary.folders)
        assertFalse(summary.replacedExistingVault)

        // Now a vault exists, and it is locked -- restore is not a way past authentication.
        assertTrue(manager.state() is VaultState.Present)
        assertEquals(null, manager.session.value)

        val session = manager.unlockWithPassword(password.toCharArray())
        assertTrue(session.isAlive)
        val restored = repository.loadAll(session).sortedBy { it.id }
        assertEquals(listOf("item-1", "item-2"), restored.map { it.id })
        assertEquals("a-password", restored.first().password)
        assertEquals("Money", repository.loadFolders(session).single().name)
    }

    @Test
    fun `the backup's own KDF parameters are preserved`() = runBlocking {
        commit(stage(backupBytes()))
        val restored = manager.metadata()!!
        assertEquals(kdf.algorithm, restored.kdf.algorithm)
        assertEquals(kdf.saltB64, restored.kdf.saltB64)
        assertEquals(kdf.pbkdf2Rounds, restored.kdf.pbkdf2Rounds)
        assertEquals(vaultId, restored.vaultId)
    }

    @Test
    fun `attachments are restored and stay associated with their item`() = runBlocking {
        // Build a real encrypted attachment against the source VEK, exactly as the app would.
        val ref = app.securevault.core.model.AttachmentRef(
            id = "att-1", fileName = "scan.bin", mimeType = "application/octet-stream",
            sizeBytes = 512, addedAt = 1_700_000_000_000
        )
        val plaintext = RandomSource.bytes(512)
        val encrypted = temp.newFile("att-1.enc")
        val key = KeyHierarchy.subkey(vek, app.securevault.core.crypto.KeyDomain.ATTACHMENTS, ref.id)
        encrypted.outputStream().use { out ->
            StreamAead.encrypt(
                key, ByteArrayInputStream(plaintext), out,
                "securevault:attachment:v1:${ref.id}".toByteArray()
            )
        }

        val staged = stage(backupBytes(listOf(encrypted), items(withAttachment = ref)))
        assertEquals(1, staged.preview.attachmentCount)
        commit(staged)

        val landed = File(files, "attachments/att-1.enc")
        assertTrue("the attachment must be in the live store", landed.exists())

        // And it still decrypts under the restored vault key, which proves the VEK carried across.
        val session = manager.unlockWithPassword(password.toCharArray())
        val item = repository.get(session, "item-1")!!
        assertEquals("scan.bin", item.payload.attachments.single().fileName)
        val out = ByteArrayOutputStream()
        StreamAead.decrypt(
            session.attachmentKeyFor(ref.id), landed.inputStream(), out,
            "securevault:attachment:v1:${ref.id}".toByteArray()
        )
        assertTrue(out.toByteArray().contentEquals(plaintext))
    }

    // ---- failures leave nothing behind ---------------------------------------------------------

    @Test
    fun `the wrong password produces no vault`() = runBlocking {
        val failure = assertThrows(RestoreFailure.AuthenticationFailed::class.java) {
            runBlocking { stage(backupBytes(), pass = "not the right passphrase") }
        }
        assertTrue(failure.userMessage.contains("altered or damaged"))
        assertNoTrace()
    }

    @Test
    fun `a corrupted authenticated backup produces no vault`() = runBlocking {
        val bytes = backupBytes()
        bytes[bytes.size - 30] = (bytes[bytes.size - 30] + 1).toByte()
        assertThrows(RestoreFailure.AuthenticationFailed::class.java) {
            runBlocking { stage(bytes) }
        }
        assertNoTrace()
    }

    @Test
    fun `wrong password and tampering are indistinguishable`() = runBlocking {
        val wrongPassword = runCatching { stage(backupBytes(), "wrong passphrase entirely") }
            .exceptionOrNull() as RestoreFailure
        val tampered = backupBytes().also { it[it.size - 30] = (it[it.size - 30] + 1).toByte() }
        val altered = runCatching { stage(tampered) }.exceptionOrNull() as RestoreFailure
        assertEquals(
            "these must not be tellable apart", wrongPassword.userMessage, altered.userMessage
        )
    }

    @Test
    fun `an unsupported backup version produces no vault`() = runBlocking {
        val bytes = backupBytes()
        bytes[7] = (BackupCodec.FORMAT_VERSION + 1).toByte()
        assertThrows(RestoreFailure.UnsupportedVersion::class.java) {
            runBlocking { stage(bytes) }
        }
        assertNoTrace()
    }

    @Test
    fun `a file that is not a backup produces no vault`() = runBlocking {
        assertThrows(RestoreFailure.NotABackup::class.java) {
            runBlocking { stage(ByteArray(256) { 0x41 }) }
        }
        assertNoTrace()
    }

    @Test
    fun `an unavailable KDF produces no vault and is not called corruption`() = runBlocking {
        // Argon2 genuinely cannot load on the JVM, so this is the real code path.
        val argonKdf = kdf.copy(algorithm = KdfAlgorithm.ARGON2ID)
        val argonMetadata = sourceMetadata.copy(kdf = argonKdf)
        val out = ByteArrayOutputStream()
        codec.create(argonMetadata, codec.backupKeyFrom(vek), items(), folders, emptyList(), out)

        val failure = assertThrows(RestoreFailure.KdfUnavailable::class.java) {
            runBlocking { stage(out.toByteArray()) }
        }
        assertTrue(failure.userMessage.contains("has not been declared corrupt"))
        assertNoTrace()
    }

    @Test
    fun `a backup whose items reference a missing folder fails validation`() = runBlocking {
        val orphaned = listOf(
            VaultItem(
                id = "x", type = ItemType.LOGIN, folderId = "folder-that-is-not-here",
                payload = ItemPayload(title = "Orphan")
            )
        )
        val out = ByteArrayOutputStream()
        codec.create(sourceMetadata, codec.backupKeyFrom(vek), orphaned, emptyList(), emptyList(), out)

        val failure = assertThrows(RestoreFailure.ValidationFailed::class.java) {
            runBlocking { stage(out.toByteArray()) }
        }
        assertTrue(failure.userMessage.contains("failed its checks"))
        assertNoTrace()
    }

    @Test
    fun `a backup missing an attachment file fails validation`() = runBlocking {
        val ref = app.securevault.core.model.AttachmentRef(
            "missing-att", "gone.bin", "application/octet-stream", 10, 0
        )
        val out = ByteArrayOutputStream()
        // Reference an attachment but ship no file for it.
        codec.create(
            sourceMetadata, codec.backupKeyFrom(vek),
            items(withAttachment = ref), folders, emptyList(), out
        )
        assertThrows(RestoreFailure.ValidationFailed::class.java) {
            runBlocking { stage(out.toByteArray()) }
        }
        assertNoTrace()
    }

    // ---- hostile archives -----------------------------------------------------------------------

    @Test
    fun `a crafted entry cannot escape staging`() = runBlocking {
        val sibling = File(files, "escaped.txt")
        sibling.delete()
        val hostile = craft(listOf("attachments/../../escaped.txt" to "owned".toByteArray()))

        // Either the guards drop the entry and validation then rejects it as unexpected, or the
        // restore fails outright. What must never happen is a write outside staging.
        runCatching { stage(hostile) }
        assertFalse("nothing may be written above staging", sibling.exists())
        assertNoTrace()
    }

    @Test
    fun `too many entries are rejected`() = runBlocking {
        val hostile = craft((0..10_050).map { "attachments/f$it.enc" to ByteArray(1) })
        runCatching { stage(hostile) }.exceptionOrNull().let { assertTrue(it is RestoreFailure) }
        assertNoTrace()
    }

    // ---- lifecycle --------------------------------------------------------------------------------

    @Test
    fun `cancelling removes staging entirely`() = runBlocking {
        val staged = stage(backupBytes())
        assertTrue(staged.stagingDirExists())
        restorer.discard(staged)
        assertFalse(staged.stagingDirExists())
        assertNoTrace()
    }

    @Test
    fun `committing removes staging too`() = runBlocking {
        val staged = stage(backupBytes())
        commit(staged)
        assertFalse(staged.stagingDirExists())
    }

    @Test
    fun `an existing vault is never overwritten`() = runBlocking {
        manager.createVault("The one I already have", "my current passphrase".toCharArray(), false)
        val headerBefore = header().readText()
        val staged = stage(backupBytes())

        assertThrows(RestoreFailure.VaultAlreadyExists::class.java) {
            runBlocking { commit(staged) }
        }
        assertEquals("the live header must be byte-identical", headerBefore, header().readText())
        // And the existing vault still opens with its own password.
        manager.lock()
        assertTrue(manager.unlockWithPassword("my current passphrase".toCharArray()).isAlive)
    }

    @Test
    fun `clearAllStaging removes leftovers from an interrupted run`() = runBlocking {
        stagingRoot().mkdirs()
        File(stagingRoot(), "abandoned").mkdirs()
        restorer.clearAllStaging()
        assertFalse(stagingRoot().exists())
    }

    /** No vault, no records, no staging, no attachments. */
    private fun assertNoTrace() {
        assertTrue("a failed restore must leave no vault", manager.state() is VaultState.Absent)
        assertFalse("no header may exist", header().exists())
        assertEquals("no records may have been written", 0, itemStore.rows.size)
        assertEquals(0, folderStore.rows.size)
        val leftovers = stagingRoot().listFiles()?.size ?: 0
        assertEquals("staging must be empty", 0, leftovers)
        val attachments = File(files, "attachments").listFiles()?.size ?: 0
        assertEquals("no attachment may have landed", 0, attachments)
    }

    private fun app.securevault.feature.backup.StagedRestore.stagingDirExists(): Boolean =
        stagingRoot().listFiles()?.isNotEmpty() == true

    /** A correctly authenticated backup carrying an attacker-chosen archive. */
    private fun craft(entries: List<Pair<String, ByteArray>>): ByteArray {
        val headerJson = org.json.JSONObject().apply {
            put("formatVersion", BackupCodec.FORMAT_VERSION)
            put("vaultId", vaultId)
            put("backupId", "crafted")
            put("createdAt", System.currentTimeMillis())
            put("appVersion", "1.0.0-test")
            put("kdf", kdf.toJson())
            put("wrappedVek", sourceMetadata.wrappedVek)
            put("keyFileRequired", false)
        }
        val headerBytes = headerJson.toString().toByteArray(Charsets.UTF_8)
        val body = ByteArrayOutputStream()
        ZipOutputStream(body).use { zip ->
            zip.putNextEntry(ZipEntry("vault.json"))
            zip.write("""{"schema":1,"items":[],"folders":[]}""".toByteArray())
            zip.closeEntry()
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name)); zip.write(content); zip.closeEntry()
            }
        }
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.writeInt(BackupCodec.MAGIC)
        data.writeInt(BackupCodec.FORMAT_VERSION)
        data.writeInt(headerBytes.size)
        data.write(headerBytes)
        data.flush()
        StreamAead.encrypt(
            codec.backupKeyFrom(vek), ByteArrayInputStream(body.toByteArray()), data,
            MessageDigest.getInstance("SHA-256").digest(headerBytes)
        )
        data.flush()
        return out.toByteArray()
    }
}
