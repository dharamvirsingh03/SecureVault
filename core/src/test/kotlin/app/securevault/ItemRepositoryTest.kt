package app.securevault

import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.VaultIntegrityException
import app.securevault.core.model.Fields
import app.securevault.core.model.Folder
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.TotpConfig
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultSession
import app.securevault.data.repo.ItemRepository
import app.securevault.data.store.InMemoryFolderStore
import app.securevault.data.store.InMemoryItemStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The repository contract, now that it is platform-neutral.
 *
 * These run against an in-memory store, but nothing security-relevant is faked: the encryption,
 * the per-row AAD binding and the record format are the real ones. Any storage backend -- Room on
 * Android, SQLite on the desktop -- has to satisfy exactly this behaviour, which is the point of
 * having moved the repository out of `:app`.
 */
class ItemRepositoryTest {

    private lateinit var itemStore: InMemoryItemStore
    private lateinit var folderStore: InMemoryFolderStore
    private lateinit var repository: ItemRepository
    private lateinit var session: VaultSession

    @Before
    fun setUp() {
        itemStore = InMemoryItemStore()
        folderStore = InMemoryFolderStore()
        repository = ItemRepository(itemStore, folderStore)
        session = VaultSession("vault-under-test", KeyHierarchy.generateVek())
    }

    private fun login() = VaultItem(
        id = "item-1",
        type = ItemType.LOGIN,
        folderId = "folder-1",
        favorite = true,
        payload = ItemPayload(
            title = "First National Bank",
            fields = mapOf(
                Fields.USERNAME to "jane.doe@example.com",
                Fields.PASSWORD to "hunter2-but-considerably-longer",
                Fields.URL to "https://firstnational.example"
            ),
            notes = "the joint account",
            tags = listOf("finance", "critical"),
            totp = TotpConfig(secretBase32 = "GEZDGNBVGY3TQOJQ")
        )
    )

    // ---- what reaches storage ----------------------------------------------------------------

    @Test
    fun `nothing identifying is written outside the ciphertext`() {
        runBlocking { repository.save(session, login()) }
        val row = itemStore.rows.getValue("item-1")

        // The row's plaintext columns are an id and three timestamps. Everything else -- title,
        // username, URL, type, folder, favourite, tags, TOTP secret -- is inside the blob.
        val blob = String(row.ciphertext, Charsets.ISO_8859_1)
        listOf(
            "First National Bank", "jane.doe@example.com", "hunter2-but-considerably-longer",
            "firstnational.example", "finance", "GEZDGNBVGY3TQOJQ", "the joint account", "LOGIN"
        ).forEach { secret ->
            assertFalse("'$secret' is readable in the stored row", blob.contains(secret))
        }
    }

    @Test
    fun `ciphertext cannot be moved between rows`() {
        runBlocking {
            repository.save(session, login())
            repository.save(session, VaultItem(id = "item-2", type = ItemType.SECURE_NOTE,
                payload = ItemPayload(title = "Note")))
        }
        // Each record is bound to its own id as additional authenticated data. Swapping the blobs
        // is tampering, not a way to read one item as another.
        val moved = itemStore.rows.getValue("item-1").copy(id = "item-2")
        runBlocking { itemStore.upsert(moved) }

        val survivors = runBlocking { repository.loadAll(session) }
        assertEquals("the swapped row must be dropped, not decoded", 1, survivors.size)
        assertEquals("item-1", survivors.single().id)
    }

    @Test
    fun `a wrong key yields nothing rather than garbage`() {
        runBlocking { repository.save(session, login()) }
        val other = VaultSession("vault-under-test", KeyHierarchy.generateVek())
        assertTrue(runBlocking { repository.loadAll(other) }.isEmpty())
    }

    @Test
    fun `tampered ciphertext is rejected by get`() {
        runBlocking { repository.save(session, login()) }
        val row = itemStore.rows.getValue("item-1")
        row.ciphertext[row.ciphertext.size - 1] = (row.ciphertext[row.ciphertext.size - 1] + 1).toByte()

        assertThrows(VaultIntegrityException::class.java) {
            runBlocking { repository.get(session, "item-1") }
        }
    }

    // ---- round trip fidelity ------------------------------------------------------------------

    @Test
    fun `every field survives a round trip`() {
        val original = login()
        runBlocking { repository.save(session, original) }
        val restored = runBlocking { repository.get(session, "item-1") }!!

        assertEquals(original.id, restored.id)
        assertEquals(original.type, restored.type)
        assertEquals(original.folderId, restored.folderId)
        assertEquals(original.favorite, restored.favorite)
        assertEquals(original.title, restored.title)
        assertEquals(original.username, restored.username)
        assertEquals(original.password, restored.password)
        assertEquals(original.url, restored.url)
        assertEquals(original.payload.notes, restored.payload.notes)
        assertEquals(original.payload.tags, restored.payload.tags)
        assertEquals(original.payload.totp?.secretBase32, restored.payload.totp?.secretBase32)
        assertEquals(original.createdAt, restored.createdAt)
    }

    @Test
    fun `save stamps the modification time and keeps creation time`() {
        val original = login()
        val saved = runBlocking { repository.save(session, original) }
        assertEquals(original.createdAt, saved.createdAt)
        assertTrue(saved.updatedAt >= original.createdAt)
    }

    @Test
    fun `folders round trip and their names are not stored in the clear`() {
        runBlocking { repository.saveFolder(session, Folder(id = "folder-1", name = "Money")) }
        assertFalse(
            String(folderStore.rows.getValue("folder-1").ciphertext, Charsets.ISO_8859_1)
                .contains("Money")
        )
        assertEquals("Money", runBlocking { repository.loadFolders(session) }.single().name)
    }

    // ---- store contract ------------------------------------------------------------------------

    @Test
    fun `markUsed touches only the timestamp`() {
        runBlocking { repository.save(session, login()) }
        val before = itemStore.rows.getValue("item-1").ciphertext.copyOf()

        runBlocking { repository.markUsed("item-1") }

        val after = itemStore.rows.getValue("item-1")
        assertTrue("ciphertext must not be rewritten", after.ciphertext.contentEquals(before))
        assertTrue(after.lastUsedAt != null)
    }

    @Test
    fun `delete and wipeAll remove what they say`() {
        runBlocking {
            repository.saveAll(session, listOf(login(),
                VaultItem(id = "item-2", type = ItemType.SECURE_NOTE, payload = ItemPayload(title = "N"))))
            repository.saveFolder(session, Folder(id = "folder-1", name = "Money"))

            assertEquals(2, repository.count())
            repository.delete("item-2")
            assertEquals(1, repository.count())
            assertNull(repository.get(session, "item-2"))

            repository.wipeAll()
            assertEquals(0, repository.count())
            assertTrue(repository.loadFolders(session).isEmpty())
        }
    }

    @Test
    fun `saveAll writes every item`() {
        val many = (1..25).map {
            VaultItem(id = "item-$it", type = ItemType.LOGIN,
                payload = ItemPayload(title = "Item $it", fields = mapOf(Fields.PASSWORD to "p$it")))
        }
        runBlocking { repository.saveAll(session, many) }
        val loaded = runBlocking { repository.loadAll(session) }
        assertEquals(25, loaded.size)
        assertEquals(many.map { it.id }.toSet(), loaded.map { it.id }.toSet())
    }
}
