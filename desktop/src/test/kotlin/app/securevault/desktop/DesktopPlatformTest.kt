package app.securevault.desktop

import app.securevault.core.crypto.SealedStateCorruptException
import app.securevault.desktop.platform.DesktopVaultStore
import app.securevault.desktop.platform.Paths
import app.securevault.desktop.platform.Platform
import app.securevault.desktop.platform.ScreenCapture
import app.securevault.desktop.platform.SecretServiceStore
import app.securevault.desktop.platform.SecureStorage
import app.securevault.desktop.platform.WindowsCredentialStore
import app.securevault.desktop.platform.SqliteStorage
import app.securevault.data.store.ItemRecord
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * The Linux-specific half of the platform layer.
 *
 * Deliberately includes the cases that are easy to leave untested because they are inconvenient:
 * a keyring that is not there, permissions on files nobody looks at, and what happens when state
 * is present but unreadable.
 */
class DesktopPlatformTest {

    @get:Rule
    val temp = TemporaryFolder()

    // ---- SQLite store ---------------------------------------------------------------------

    @Test
    fun `sqlite round trips ciphertext byte for byte`() = runBlocking {
        SqliteStorage(File(temp.root, "v.db")).use { storage ->
            val blob = ByteArray(512) { (it * 7).toByte() }
            val record = ItemRecord("item-1", 100L, 200L, null, blob)
            storage.items.upsert(record)

            val loaded = storage.items.getById("item-1")!!
            assertTrue("ciphertext must survive unchanged", loaded.ciphertext.contentEquals(blob))
            assertEquals(100L, loaded.createdAt)
            assertEquals(200L, loaded.updatedAt)
            assertNull(loaded.lastUsedAt)
        }
    }

    @Test
    fun `markUsed touches only the timestamp`() = runBlocking {
        SqliteStorage(File(temp.root, "v.db")).use { storage ->
            val blob = ByteArray(64) { 9 }
            storage.items.upsert(ItemRecord("a", 1L, 2L, null, blob))
            storage.items.markUsed("a", 12345L)

            val loaded = storage.items.getById("a")!!
            assertEquals(12345L, loaded.lastUsedAt)
            assertTrue(loaded.ciphertext.contentEquals(blob))
        }
    }

    @Test
    fun `upsert replaces and deleteAll clears`() = runBlocking {
        SqliteStorage(File(temp.root, "v.db")).use { storage ->
            storage.items.upsert(ItemRecord("a", 1L, 2L, null, ByteArray(8)))
            storage.items.upsert(ItemRecord("a", 1L, 3L, null, ByteArray(8) { 1 }))
            assertEquals(1, storage.items.count())
            assertEquals(3L, storage.items.getById("a")!!.updatedAt)

            storage.items.deleteAll()
            assertEquals(0, storage.items.count())
        }
    }

    @Test
    fun `the database has no column that could hold plaintext`() = runBlocking {
        SqliteStorage(File(temp.root, "v.db")).use { storage ->
            storage.items.upsert(ItemRecord("a", 1L, 2L, null, ByteArray(8)))
        }
        // An index or a searchable column would recreate on disk exactly what the encryption
        // exists to hide, so the schema is asserted rather than assumed.
        val sql = File(temp.root, "v.db").readBytes().toString(Charsets.ISO_8859_1)
        listOf("title", "username", "password", "url", "notes", "tag").forEach { forbidden ->
            assertFalse("schema must not contain a '$forbidden' column", sql.contains("$forbidden "))
        }
    }

    // ---- state store -----------------------------------------------------------------------

    @Test
    fun `state round trips and absent is not an error`() {
        val store = DesktopVaultStore(temp.newFolder("state"))
        assertNull(store.getString("attempts"))
        store.putString("attempts", """{"failures":2}""")
        assertEquals("""{"failures":2}""", store.getString("attempts"))
    }

    @Test
    fun `unreadable state is reported, not defaulted away`() {
        val dir = temp.newFolder("state2")
        val store = DesktopVaultStore(dir)
        store.putString("attempts", "{}")
        // Replace the file with a directory: present, but unreadable.
        val file = File(dir, "attempts.json")
        file.delete()
        file.mkdirs()

        assertThrows(SealedStateCorruptException::class.java) { store.getString("attempts") }
    }

    @Test
    fun `state files are owner-only where the filesystem supports it`() {
        val dir = temp.newFolder("state3")
        DesktopVaultStore(dir).putString("settings", "{}")
        val file = File(dir, "settings.json")
        assertTrue(file.exists())
        if (!Platform.isWindows) {
            val perms = Files.getPosixFilePermissions(file.toPath())
            assertFalse(PosixFilePermission.GROUP_READ in perms)
            assertFalse(PosixFilePermission.OTHERS_READ in perms)
        }
    }

    @Test
    fun `secured directories are owner-only where the filesystem supports it`() {
        val dir = Paths.secured(File(temp.root, "vaultdir"))
        assertTrue(dir.isDirectory)
        if (!Platform.isWindows) {
            val perms = Files.getPosixFilePermissions(dir.toPath())
            assertTrue(PosixFilePermission.OWNER_READ in perms)
            assertFalse(PosixFilePermission.GROUP_READ in perms)
            assertFalse(PosixFilePermission.OTHERS_READ in perms)
            assertFalse(PosixFilePermission.OTHERS_EXECUTE in perms)
        }
    }

    // ---- secret service --------------------------------------------------------------------

    @Test
    fun `secure storage reports unavailability rather than throwing`() {
        // On a build machine there is usually no session bus, no secret-tool and no PowerShell.
        // Whatever the answer, it must be a described state -- never an exception, and never a
        // silent fallback to storing something in a file.
        val storage = SecureStorage.forThisPlatform()
        when (val availability = storage.availability()) {
            is SecureStorage.Availability.Available -> Unit
            is SecureStorage.Availability.Unavailable ->
                assertTrue("the reason must be actionable", availability.reason.isNotBlank())
        }
        assertTrue(storage.displayName.isNotBlank())
        assertTrue(storage.protectionSummary.isNotBlank())
    }

    @Test
    fun `the platform picks the right secure storage implementation`() {
        val storage = SecureStorage.forThisPlatform()
        if (Platform.isWindows) {
            assertTrue(storage is WindowsCredentialStore)
            // The wording must never imply hardware protection: DPAPI is software protection
            // scoped to the Windows account, and Windows Hello is not used at all.
            assertTrue(storage.protectionSummary.contains("not hardware", ignoreCase = true))
        } else {
            assertTrue(storage is SecretServiceStore)
            assertTrue(storage.protectionSummary.contains("not hardware", ignoreCase = true))
        }
    }

    @Test
    fun `no plaintext fallback file is ever created`() {
        val before = temp.root.walkTopDown().filter { it.isFile }.count()
        SecureStorage.forThisPlatform().lookup("anything")
        val after = temp.root.walkTopDown().filter { it.isFile }.count()
        assertEquals("unavailable secure storage must write nothing", before, after)
    }

    @Test
    fun `screen capture status is honest on every platform`() {
        val status = ScreenCapture.detect()
        // No platform may claim protection. Windows names a real mechanism it does not use;
        // Linux states that none exists. Neither says SecureVault blocks screenshots.
        assertFalse(status.summary.contains("blocked", ignoreCase = true) &&
            !status.summary.contains("not blocked", ignoreCase = true))
        assertTrue(status.detail.isNotBlank())
        if (Platform.isWindows) {
            assertEquals(ScreenCapture.Session.WINDOWS, status.session)
            assertTrue(status.detail.contains("SetWindowDisplayAffinity"))
        }
    }

    // ---- XDG paths -------------------------------------------------------------------------

    @Test
    fun `data paths are under the user profile, never the install directory`() {
        val path = Paths.dataDir.absolutePath
        assertFalse("vault data must never live under /opt", path.startsWith("/opt"))
        assertFalse(path.startsWith("/usr"))
        assertFalse("nor under Program Files", path.contains("Program Files"))

        if (Platform.isWindows) {
            val local = System.getenv("LOCALAPPDATA").orEmpty()
            assertTrue(
                "expected %LOCALAPPDATA%\\SecureVault",
                path.contains("SecureVault") &&
                    (local.isBlank() || path.startsWith(local))
            )
            // LOCALAPPDATA, not APPDATA: roaming would copy the vault to a domain server on
            // every logon, which must be the user's deliberate choice, not a silent default.
            val roaming = System.getenv("APPDATA").orEmpty()
            if (roaming.isNotBlank() && local.isNotBlank() && roaming != local) {
                assertFalse("must not be in the roaming profile", path.startsWith(roaming))
            }
        } else {
            assertTrue(
                "expected an XDG-style per-user location",
                path.contains(System.getProperty("user.home")) ||
                    path.contains(System.getenv("XDG_DATA_HOME").orEmpty().ifBlank { "///never" })
            )
        }
    }

    @Test
    fun `every vault location sits inside the data directory`() {
        val root = Paths.dataDir.canonicalPath + File.separator
        listOf(Paths.vaultDir, Paths.attachmentsDir, Paths.stagingDir, Paths.stateDir,
            Paths.databaseFile.parentFile).forEach {
            assertTrue("${'$'}{it.canonicalPath} escaped the data directory",
                (it.canonicalPath + File.separator).startsWith(root))
        }
    }
}
