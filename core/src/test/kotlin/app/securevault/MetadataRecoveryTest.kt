package app.securevault

import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.RandomSource
import app.securevault.core.vault.VaultManager
import app.securevault.core.vault.VaultState
import app.securevault.platform.DurableFile
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.Base64

/**
 * The `.prev` header copy: when it exists, when it must not, and what it is allowed to do.
 *
 * The property that matters most is the one in `stale previous copy cannot resurrect an old
 * password`. A previous copy holds the vault key wrapped under whatever password was current when
 * it was written. If it survived past a confirmed write, damaging one file would reinstate a
 * password the user believed they had replaced -- a rollback attack on password revocation. So the
 * copy exists only inside the crash window of a write and is deleted the moment the new header is
 * read back successfully.
 */
class MetadataRecoveryTest {

    @get:Rule
    val temp = TemporaryFolder()

    private lateinit var files: File
    private lateinit var store: TestVaultStore
    private lateinit var manager: VaultManager

    private val first = "the first master passphrase"
    private val second = "an entirely different second passphrase"

    @Before
    fun setUp() {
        files = temp.newFolder("files")
        store = TestVaultStore()
        manager = VaultManager(
            filesDir = files,
            store = store,
            biometricKeyStore = null,
            kdfParamsFactory = {
                KdfSelection(
                    KdfParams(
                        KdfAlgorithm.PBKDF2_HMAC_SHA256,
                        Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
                        pbkdf2Rounds = 1_000
                    ),
                    usedFallback = false
                )
            }
        )
        runBlocking { manager.createVault("Test", first.toCharArray(), enableRecovery = false) }
    }

    private fun header() = File(files, "vault/metadata.json")
    private fun previous() = DurableFile.previous(header())
    private fun temp0() = DurableFile.temp(header())

    // 1 --------------------------------------------------------------------------------------
    @Test
    fun `normal update leaves no previous copy behind`() {
        runBlocking { manager.changeMasterPassword(first.toCharArray(), second.toCharArray()) }

        assertTrue(header().exists())
        assertFalse("a confirmed write must not leave a rollback point", previous().exists())
        assertFalse(temp0().exists())
        assertTrue(manager.state() is VaultState.Present)
    }

    // 2 --------------------------------------------------------------------------------------
    @Test
    fun `crash before rename leaves the committed header intact`() {
        val committed = header().readText()
        // A temp file written but never renamed: the state after a power cut mid-write.
        temp0().writeText("{ partial")

        assertEquals(committed, header().readText())
        val state = manager.state()
        assertTrue(state is VaultState.Present)
        assertFalse((state as VaultState.Present).recoveredFromPreviousCopy)
        // And the original password still works.
        manager.lock()
        assertTrue(runBlocking { manager.unlockWithPassword(first.toCharArray()) }.isAlive)
    }

    // 3 --------------------------------------------------------------------------------------
    @Test
    fun `crash after rename but before confirmation still opens the new header`() {
        val before = header().readText()
        // Simulate: new header committed, previous copy not yet deleted.
        previous().writeText(before)
        runBlocking { manager.changeMasterPassword(first.toCharArray(), second.toCharArray()) }
        val after = header().readText()
        previous().writeText(before)

        val state = manager.state()
        assertTrue(state is VaultState.Present)
        // The live header wins whenever it parses. The stale copy is never preferred.
        assertFalse((state as VaultState.Present).recoveredFromPreviousCopy)
        assertEquals(after, header().readText())
    }

    // 4 and 5 ---------------------------------------------------------------------------------
    @Test
    fun `corrupt new header falls back to a valid previous copy and says so`() {
        val good = header().readText()
        previous().writeText(good)
        header().writeText("}{ not json")

        val state = manager.state()
        assertTrue(state is VaultState.Present)
        val present = state as VaultState.Present
        assertTrue(present.recoveredFromPreviousCopy)
        // The rollback is announced rather than silent.
        assertNotNull(present.rollbackWarning)
        assertTrue(present.rollbackWarning!!.contains("previous password"))
    }

    // 6 --------------------------------------------------------------------------------------
    @Test
    fun `both copies corrupt reports corrupt, never absent`() {
        previous().writeText("also garbage")
        header().writeText("garbage")

        val state = manager.state()
        assertTrue("expected Corrupt, got $state", state is VaultState.Corrupt)
        assertEquals(
            VaultState.Corrupt.Reason.UNREADABLE_HEADER,
            (state as VaultState.Corrupt).reason
        )
    }

    @Test
    fun `missing header with a valid previous copy recovers`() {
        val good = header().readText()
        previous().writeText(good)
        header().delete()

        val state = manager.state()
        assertTrue(state is VaultState.Present)
        assertTrue((state as VaultState.Present).recoveredFromPreviousCopy)
    }

    // 7 --------------------------------------------------------------------------------------
    @Test
    fun `stale previous copy cannot resurrect an old password`() {
        val oldHeader = header().readText()
        runBlocking { manager.changeMasterPassword(first.toCharArray(), second.toCharArray()) }

        // The change confirmed, so nothing is left to roll back to.
        assertFalse(previous().exists())

        manager.lock()
        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.unlockWithPassword(first.toCharArray()) }
        }
        assertTrue(runBlocking { manager.unlockWithPassword(second.toCharArray()) }.isAlive)

        // Even if an attacker plants the old header as a previous copy, it is only consulted when
        // the live one is unreadable -- a rejected password is never a reason to roll back.
        previous().writeText(oldHeader)
        manager.lock()
        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.unlockWithPassword(first.toCharArray()) }
        }
    }

    @Test
    fun `previous copy holds no more than the live header does`() {
        val good = header().readText()
        previous().writeText(good)
        // Same class of data: a header, and headers carry no plaintext vault content.
        val json = org.json.JSONObject(previous().readText())
        assertFalse(json.has("password"))
        assertFalse(json.has("items"))
        assertTrue(json.has("wrappedVek"))
    }

    @Test
    fun `destroy removes the previous copy too`() {
        previous().writeText(header().readText())
        manager.destroyVault()
        assertFalse(previous().exists())
        assertFalse(header().exists())
    }
}
