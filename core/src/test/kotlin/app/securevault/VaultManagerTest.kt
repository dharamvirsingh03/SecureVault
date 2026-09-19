package app.securevault

import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.RandomSource
import app.securevault.core.vault.VaultClosedException
import app.securevault.core.vault.VaultLockedOutException
import app.securevault.core.vault.VaultManager
import app.securevault.core.vault.VaultNotUnlockedException
import app.securevault.core.vault.VaultState
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
 * Lifecycle tests for S1 (password change), S3 (destruction), S5 (vault state) and S7 (lockout
 * state corruption).
 *
 * These run on the JVM, so Argon2's native library is unavailable and the KDF is pinned to
 * low-cost PBKDF2. That is a deliberate substitution of *cost*, not of structure: the key
 * hierarchy, wrapping, AAD and lockout paths under test are identical either way.
 */
class VaultManagerTest {

    @get:Rule
    val temp = TemporaryFolder()

    private lateinit var files: File
    private lateinit var store: TestVaultStore
    private lateinit var manager: VaultManager

    private val cheapKdf = {
        KdfSelection(
            params = KdfParams(
                algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
                saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(KdfParams.SALT_BYTES)),
                pbkdf2Rounds = 1_000
            ),
            usedFallback = false
        )
    }

    @Before
    fun setUp() {
        files = temp.newFolder("files")
        store = TestVaultStore()
        manager = newManager()
    }

    private fun newManager() = VaultManager(
        filesDir = files,
        store = store,
        biometricKeyStore = null,
        kdfParamsFactory = cheapKdf
    )

    private fun create(password: String = "correct horse battery staple") = runBlocking {
        manager.createVault("Test vault", password.toCharArray(), enableRecovery = false)
    }

    // ---- S5: vault state -------------------------------------------------------------------

    @Test
    fun `absent before creation`() {
        assertTrue(manager.state() is VaultState.Absent)
    }

    @Test
    fun `present after creation`() {
        create()
        val state = manager.state()
        assertTrue(state is VaultState.Present)
        assertEquals("Test vault", (state as VaultState.Present).metadata.name)
    }

    @Test
    fun `damaged header reports corrupt, not absent`() {
        create()
        header().writeText("{ this is not json")

        val state = manager.state()
        assertTrue("expected Corrupt, got $state", state is VaultState.Corrupt)
        assertEquals(
            VaultState.Corrupt.Reason.UNREADABLE_HEADER,
            (state as VaultState.Corrupt).reason
        )
        // The critical consequence: setup must refuse rather than bury the existing vault.
        assertThrows(IllegalStateException::class.java) {
            runBlocking { manager.createVault("New", "another password".toCharArray(), false) }
        }
    }

    @Test
    fun `header from a newer format reports unsupported version`() {
        create()
        val json = org.json.JSONObject(header().readText())
        json.put("formatVersion", 99)
        header().writeText(json.toString())

        val state = manager.state()
        assertTrue(state is VaultState.Corrupt)
        assertEquals(
            VaultState.Corrupt.Reason.UNSUPPORTED_VERSION,
            (state as VaultState.Corrupt).reason
        )
    }

    // ---- S1: master password change --------------------------------------------------------

    @Test
    fun `password change is refused while locked`() {
        create()
        manager.lock()
        assertThrows(VaultNotUnlockedException::class.java) {
            runBlocking {
                manager.changeMasterPassword("correct horse battery staple".toCharArray(), "new one".toCharArray())
            }
        }
    }

    @Test
    fun `password change succeeds with the correct current password`() {
        create()
        runBlocking {
            manager.changeMasterPassword(
                "correct horse battery staple".toCharArray(),
                "an entirely new passphrase".toCharArray()
            )
        }
        manager.lock()

        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.unlockWithPassword("correct horse battery staple".toCharArray()) }
        }
        val session = runBlocking { manager.unlockWithPassword("an entirely new passphrase".toCharArray()) }
        assertTrue(session.isAlive)
    }

    @Test
    fun `wrong current password is rejected and counts as a failure`() {
        create()
        assertEquals(0, manager.attemptState().consecutiveFailures)

        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.changeMasterPassword("wrong password".toCharArray(), "new".toCharArray()) }
        }
        // The whole point of S1: this path is no longer a free, unrated oracle.
        assertEquals(1, manager.attemptState().consecutiveFailures)
    }

    @Test
    fun `password change respects an active lockout`() {
        create()
        // Four failures: three graceful, the fourth starts the delay.
        repeat(4) {
            runCatching {
                runBlocking { manager.changeMasterPassword("wrong".toCharArray(), "new".toCharArray()) }
            }
        }
        assertThrows(VaultLockedOutException::class.java) {
            runBlocking {
                manager.changeMasterPassword(
                    "correct horse battery staple".toCharArray(),
                    "new passphrase entirely".toCharArray()
                )
            }
        }
    }

    @Test
    fun `a failed password change leaves the old password working`() {
        create()
        runCatching {
            runBlocking { manager.changeMasterPassword("wrong".toCharArray(), "new".toCharArray()) }
        }
        manager.lock()
        val session = runBlocking { manager.unlockWithPassword("correct horse battery staple".toCharArray()) }
        assertTrue(session.isAlive)
    }

    @Test
    fun `successful password change clears the failure counter`() {
        create()
        runCatching {
            runBlocking { manager.changeMasterPassword("wrong".toCharArray(), "new".toCharArray()) }
        }
        assertEquals(1, manager.attemptState().consecutiveFailures)

        runBlocking {
            manager.changeMasterPassword(
                "correct horse battery staple".toCharArray(),
                "a brand new long passphrase".toCharArray()
            )
        }
        assertEquals(0, manager.attemptState().consecutiveFailures)
    }

    // ---- S7: lockout state corruption -------------------------------------------------------

    @Test
    fun `unreadable lockout state locks rather than resetting`() {
        create()
        store.corrupt += "attempts"

        assertTrue(manager.attemptStateIsCorrupt())
        val state = manager.attemptState()
        assertTrue("should be locked out, not reset", state.lockedUntil > System.currentTimeMillis())
        assertThrows(VaultLockedOutException::class.java) {
            runBlocking { manager.unlockWithPassword("correct horse battery staple".toCharArray()) }
        }
    }

    @Test
    fun `absent lockout state is a clean slate`() {
        create()
        store.remove("attempts")
        assertFalse(manager.attemptStateIsCorrupt())
        assertEquals(0, manager.attemptState().consecutiveFailures)
    }

    // ---- S3: shutdown and destruction -------------------------------------------------------

    @Test
    fun `close refuses further work`() {
        create()
        manager.close()
        assertThrows(VaultClosedException::class.java) { manager.state() }
        assertThrows(VaultClosedException::class.java) {
            runBlocking { manager.unlockWithPassword("correct horse battery staple".toCharArray()) }
        }
    }

    @Test
    fun `close locks the session`() {
        val session = create()
        manager.close()
        assertFalse(session.metadata.name.isEmpty())
        assertEquals(null, manager.session.value)
    }

    @Test
    fun `destroy closes the database before removing files`() {
        create()
        val closures = mutableListOf<String>()
        val instrumented = VaultManager(
            filesDir = files,
            store = store,
            biometricKeyStore = null,
            kdfParamsFactory = cheapKdf,
            databaseCloser = { closures += "closed" }
        )
        File(files, "attachments").mkdirs()
        File(files, "attachments/a.enc").writeText("ciphertext")

        val result = instrumented.destroyVault()

        assertEquals(listOf("closed"), closures)
        assertTrue(result.headerRemoved)
        assertTrue(result.attachmentsRemoved)
        assertTrue(result.sealedStateRemoved)
        assertTrue(result.complete)
        assertFalse(header().exists())
        assertFalse(File(files, "attachments").exists())
    }

    @Test
    fun `destroy still works on an already closed manager`() {
        create()
        manager.close()
        val result = manager.destroyVault()
        assertTrue(result.headerRemoved)
    }

    // ---- recovery -------------------------------------------------------------------------

    @Test
    fun `recovery code opens the vault and a wrong one does not`() {
        val created = runBlocking {
            manager.createVault("Recoverable", "the original passphrase".toCharArray(), enableRecovery = true)
        }
        val code = created.recoveryCode
        assertNotNull(code)
        manager.lock()

        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.unlockWithRecoveryCode("AAAA-BBBB-CCCC-DDDD".toCharArray()) }
        }
        val session = runBlocking { manager.unlockWithRecoveryCode(code!!.copyOf()) }
        assertTrue(session.isAlive)
    }

    @Test
    fun `a malformed recovery code is not a free probe`() {
        runBlocking {
            manager.createVault("Recoverable", "the original passphrase".toCharArray(), enableRecovery = true)
        }
        assertThrows(InvalidCredentialsException::class.java) {
            // '1' and '8' are not in the base32 alphabet.
            runBlocking { manager.unlockWithRecoveryCode("1111-8888".toCharArray()) }
        }
        assertEquals(1, manager.attemptState().consecutiveFailures)
    }

    private fun header() = File(files, "vault/metadata.json")
}
