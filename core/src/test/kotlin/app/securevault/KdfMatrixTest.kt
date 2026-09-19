package app.securevault

import app.securevault.core.crypto.Kdf
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.crypto.RandomSource
import app.securevault.core.vault.VaultManager
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
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
 * The four-case KDF matrix, pinned as tests.
 *
 * | situation                              | required behaviour                        |
 * |----------------------------------------|-------------------------------------------|
 * | new vault, Argon2 available            | Argon2id, no warning                      |
 * | new vault, Argon2 unavailable          | PBKDF2, warning surfaced to the user      |
 * | existing Argon2 vault, Argon2 missing  | refuse to unlock, KdfUnavailableException |
 * | existing PBKDF2 vault                  | PBKDF2, always                            |
 *
 * Row one cannot be tested here: the JVM has no Argon2 native library, which is precisely what
 * makes the other three testable. It is covered by inspection -- `Kdf.calibrate()` returns
 * ARGON2ID with `usedFallback = false` on every path where `isArgon2Available()` is true -- and is
 * listed as needing device verification in README.md.
 */
class KdfMatrixTest {

    @get:Rule
    val temp = TemporaryFolder()

    private lateinit var files: File
    private lateinit var store: TestVaultStore
    private val password = "a sufficiently long passphrase"

    @Before
    fun setUp() {
        files = temp.newFolder("files")
        store = TestVaultStore()
        Kdf.resetAvailabilityProbe()
    }

    private fun manager() = VaultManager(
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

    private fun header() = File(files, "vault/metadata.json")

    // --- row 2: new vault, Argon2 unavailable -------------------------------------------------

    @Test
    fun `a new vault falls back to PBKDF2 and the user is told`() {
        // The real calibrator, not the test factory: this is the production decision path.
        val real = VaultManager(filesDir = files, store = store, biometricKeyStore = null)
        val result = runBlocking { real.createVault("Fallback", password.toCharArray(), false) }

        assertEquals(KdfAlgorithm.PBKDF2_HMAC_SHA256, result.metadata.kdf.algorithm)
        assertNotNull("the fallback must never be silent", result.kdfFallbackWarning)
        assertTrue(result.kdfFallbackWarning!!.contains("PBKDF2"))
        assertTrue(result.kdfFallbackWarning.contains("weaker"))
    }

    // --- row 3: existing Argon2 vault on a device that cannot run Argon2 ----------------------

    @Test
    fun `an Argon2 vault refuses to open and does not fall back`() {
        val manager = manager()
        runBlocking { manager.createVault("Moved here", password.toCharArray(), false) }
        manager.lock()
        rewriteHeaderAlgorithmToArgon2()

        val error = assertThrows(KdfUnavailableException::class.java) {
            runBlocking { manager.unlockWithPassword(password.toCharArray()) }
        }
        assertEquals(KdfAlgorithm.ARGON2ID, error.algorithm)
        assertTrue(error.message!!.contains("cannot be opened here"))
        assertTrue(error.message!!.contains("Do not create a new vault"))
    }

    @Test
    fun `an unrunnable KDF is not recorded as a wrong password`() {
        val manager = manager()
        runBlocking { manager.createVault("Moved here", password.toCharArray(), false) }
        manager.lock()
        rewriteHeaderAlgorithmToArgon2()

        repeat(5) {
            runCatching { runBlocking { manager.unlockWithPassword(password.toCharArray()) } }
        }
        // Locking someone out of a vault they typed the right password for would be the wrong
        // response to a missing shared library.
        assertEquals(0, manager.attemptState().consecutiveFailures)
    }

    @Test
    fun `the header still reads on a device that cannot run its KDF`() {
        val manager = manager()
        runBlocking { manager.createVault("Moved here", password.toCharArray(), false) }
        rewriteHeaderAlgorithmToArgon2()

        // Being unable to execute a KDF must not stop the app describing the vault, or it could
        // not explain the problem or print a recovery kit.
        val metadata = manager().metadata()
        assertNotNull(metadata)
        assertEquals(KdfAlgorithm.ARGON2ID, metadata!!.kdf.algorithm)
        assertTrue(metadata.kdf.describe().contains("Argon2id"))
    }

    // --- row 4: existing PBKDF2 vault ---------------------------------------------------------

    @Test
    fun `a PBKDF2 vault stays PBKDF2 through unlock and password change`() {
        val manager = manager()
        runBlocking { manager.createVault("Steady", password.toCharArray(), false) }
        assertEquals(KdfAlgorithm.PBKDF2_HMAC_SHA256, manager.metadata()!!.kdf.algorithm)

        runBlocking {
            manager.changeMasterPassword(password.toCharArray(), "another long passphrase".toCharArray())
        }
        val after = manager.metadata()!!
        assertEquals(KdfAlgorithm.PBKDF2_HMAC_SHA256, after.kdf.algorithm)
        assertEquals(1_000, after.kdf.pbkdf2Rounds)

        manager.lock()
        assertTrue(runBlocking { manager.unlockWithPassword("another long passphrase".toCharArray()) }.isAlive)
    }

    @Test
    fun `nothing migrates a vault to a different KDF`() {
        val manager = manager()
        runBlocking { manager.createVault("Steady", password.toCharArray(), false) }
        val originalAlgorithm = manager.metadata()!!.kdf.algorithm
        val originalRounds = manager.metadata()!!.kdf.pbkdf2Rounds

        // Exercise every operation that rewrites the header.
        manager.enableRecovery()
        manager.disableRecovery()
        runBlocking {
            manager.changeMasterPassword(password.toCharArray(), "yet another passphrase here".toCharArray())
        }
        manager.lock()
        runBlocking { manager.unlockWithPassword("yet another passphrase here".toCharArray()) }

        val after = manager.metadata()!!
        assertEquals(originalAlgorithm, after.kdf.algorithm)
        assertEquals(originalRounds, after.kdf.pbkdf2Rounds)
    }

    @Test
    fun `a password change rerolls the salt and nothing else`() {
        val manager = manager()
        runBlocking { manager.createVault("Steady", password.toCharArray(), false) }
        val before = manager.metadata()!!.kdf

        runBlocking {
            manager.changeMasterPassword(password.toCharArray(), "a replacement passphrase".toCharArray())
        }
        val after = manager.metadata()!!.kdf

        assertFalse("a new salt is required", before.saltB64 == after.saltB64)
        assertEquals(before.algorithm, after.algorithm)
        assertEquals(before.memoryKib, after.memoryKib)
        assertEquals(before.iterations, after.iterations)
        assertEquals(before.parallelism, after.parallelism)
        assertEquals(before.pbkdf2Rounds, after.pbkdf2Rounds)
        assertEquals(before.outputBytes, after.outputBytes)
    }

    /** Simulates a vault created on a device where Argon2 worked, opened on one where it does not. */
    private fun rewriteHeaderAlgorithmToArgon2() {
        val json = JSONObject(header().readText())
        json.getJSONObject("kdf").put("alg", KdfAlgorithm.ARGON2ID.name)
        header().writeText(json.toString())
        // Remove the crash-window copy so the old header is not used as a fallback.
        File(header().parentFile, "metadata.json.prev").delete()
    }
}
