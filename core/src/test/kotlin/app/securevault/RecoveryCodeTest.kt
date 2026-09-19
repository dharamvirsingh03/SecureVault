package app.securevault

import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.vault.VaultManager
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
 * The recovery code is a second key to the vault, so it gets the scrutiny a second key deserves.
 *
 * Note what is deliberately *not* tested as a requirement: single use. A recovery code in this
 * design is a standing alternative credential, not a one-shot token -- it keeps working until the
 * user regenerates or disables it. That is a real trade-off rather than an oversight, and the
 * tests below pin the behaviour so it cannot drift into something weaker by accident.
 */
class RecoveryCodeTest {

    @get:Rule
    val temp = TemporaryFolder()

    private lateinit var files: File
    private lateinit var store: TestVaultStore
    private lateinit var manager: VaultManager

    private val password = "the original master passphrase"

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
    }

    private fun createWithRecovery(): CharArray = runBlocking {
        manager.createVault("Recoverable", password.toCharArray(), enableRecovery = true)
    }.recoveryCode!!

    // ---- entropy and generation --------------------------------------------------------------

    @Test
    fun `code carries 160 bits of entropy`() {
        assertEquals(20, KeyHierarchy.RECOVERY_CODE_BYTES)
        val code = KeyHierarchy.generateRecoveryCode()
        // 20 bytes -> 32 base32 characters -> 8 groups of 4 separated by 7 dashes.
        assertEquals(39, code.size)
        assertEquals(32, code.count { it != '-' })
        assertTrue(code.filter { it != '-' }.all { it in 'A'..'Z' || it in '2'..'7' })
    }

    @Test
    fun `codes are unique, which is what CSPRNG generation buys`() {
        val codes = (1..300).map { String(KeyHierarchy.generateRecoveryCode()) }.toSet()
        assertEquals(300, codes.size)
    }

    @Test
    fun `the code is never written to disk in the clear`() {
        val code = String(createWithRecovery())
        val onDisk = files.walkTopDown().filter { it.isFile }.joinToString("\n") { it.readText() }
        val ungrouped = code.replace("-", "")
        assertFalse("recovery code found verbatim on disk", onDisk.contains(code))
        assertFalse("recovery code found on disk without grouping", onDisk.contains(ungrouped))
        // What IS on disk is the salt and a wrapped key, which are useless without the code.
        assertTrue(File(files, "vault/metadata.json").readText().contains("recovery"))
    }

    @Test
    fun `the code is not in the in-memory app state store`() {
        val code = String(createWithRecovery())
        assertFalse(store.has("recovery"))
        listOf("settings", "attempts", "biometric").forEach { key ->
            assertFalse(store.getString(key).orEmpty().contains(code))
        }
    }

    // ---- authentication ---------------------------------------------------------------------

    @Test
    fun `valid code opens the vault`() {
        val code = createWithRecovery()
        manager.lock()
        assertTrue(runBlocking { manager.unlockWithRecoveryCode(code.copyOf()) }.isAlive)
    }

    @Test
    fun `lowercase and missing dashes are accepted`() {
        val code = createWithRecovery()
        manager.lock()
        val sloppy = String(code).lowercase().replace("-", " ").toCharArray()
        assertTrue(runBlocking { manager.unlockWithRecoveryCode(sloppy) }.isAlive)
    }

    @Test
    fun `invalid code is rejected`() {
        createWithRecovery()
        manager.lock()
        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.unlockWithRecoveryCode("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH".toCharArray()) }
        }
    }

    @Test
    fun `wrong length codes are rejected and look the same as wrong codes`() {
        createWithRecovery()
        manager.lock()
        listOf("", "AAAA", "AAAA-BBBB", String(createWithRecoveryCodeChars()) + "AAAA").forEach { candidate ->
            assertThrows(InvalidCredentialsException::class.java) {
                runBlocking { manager.unlockWithRecoveryCode(candidate.toCharArray()) }
            }
        }
    }

    private fun createWithRecoveryCodeChars() = KeyHierarchy.generateRecoveryCode()

    @Test
    fun `recovery attempts are rate limited like any other credential`() {
        createWithRecovery()
        manager.lock()
        repeat(4) {
            runCatching {
                runBlocking { manager.unlockWithRecoveryCode("AAAA-BBBB-CCCC-DDDD".toCharArray()) }
            }
        }
        assertThrows(app.securevault.core.vault.VaultLockedOutException::class.java) {
            runBlocking { manager.unlockWithRecoveryCode("AAAA-BBBB-CCCC-DDDD".toCharArray()) }
        }
    }

    // ---- lifecycle --------------------------------------------------------------------------

    @Test
    fun `a code stays valid until it is replaced -- documented, not single use`() {
        val code = createWithRecovery()
        manager.lock()
        assertTrue(runBlocking { manager.unlockWithRecoveryCode(code.copyOf()) }.isAlive)
        manager.lock()
        assertTrue(
            "recovery codes are standing credentials by design",
            runBlocking { manager.unlockWithRecoveryCode(code.copyOf()) }.isAlive
        )
    }

    @Test
    fun `regenerating invalidates the previous code`() {
        val old = createWithRecovery()
        val new = manager.enableRecovery()
        manager.lock()

        assertThrows(InvalidCredentialsException::class.java) {
            runBlocking { manager.unlockWithRecoveryCode(old.copyOf()) }
        }
        assertTrue(runBlocking { manager.unlockWithRecoveryCode(new.copyOf()) }.isAlive)
    }

    @Test
    fun `disabling recovery removes the path entirely`() {
        val code = createWithRecovery()
        manager.disableRecovery()
        manager.lock()

        assertThrows(IllegalStateException::class.java) {
            runBlocking { manager.unlockWithRecoveryCode(code.copyOf()) }
        }
        // The master password is unaffected.
        assertTrue(runBlocking { manager.unlockWithPassword(password.toCharArray()) }.isAlive)
    }

    @Test
    fun `recovery survives a master password change`() {
        // The recovery block wraps the VEK, and a password change rewraps only the password path.
        // Anything else would silently invalidate a recovery kit the user has already printed.
        val code = createWithRecovery()
        runBlocking {
            manager.changeMasterPassword(password.toCharArray(), "a new long passphrase".toCharArray())
        }
        manager.lock()
        assertTrue(runBlocking { manager.unlockWithRecoveryCode(code.copyOf()) }.isAlive)
    }

    @Test
    fun `corrupted recovery metadata fails closed and leaves the password working`() {
        val code = createWithRecovery()
        val headerFile = File(files, "vault/metadata.json")
        val json = org.json.JSONObject(headerFile.readText())
        val recovery = json.getJSONObject("recovery")
        // Flip the wrapped key: still well-formed JSON, no longer openable.
        val wrapped = Base64.getDecoder().decode(recovery.getString("wrappedVek"))
        wrapped[wrapped.size - 1] = (wrapped[wrapped.size - 1] + 1).toByte()
        recovery.put("wrappedVek", Base64.getEncoder().encodeToString(wrapped))
        headerFile.writeText(json.toString())
        manager.lock()

        assertThrows(InvalidCredentialsException::class.java) {
            // The genuine code, against a header whose recovery block has been tampered with.
            runBlocking { manager.unlockWithRecoveryCode(code.copyOf()) }
        }
        assertTrue(runBlocking { manager.unlockWithPassword(password.toCharArray()) }.isAlive)
    }

    @Test
    fun `recovery is not enabled unless asked for`() {
        val result = runBlocking {
            manager.createVault("Plain", password.toCharArray(), enableRecovery = false)
        }
        assertEquals(null, result.recoveryCode)
        assertEquals(null, manager.metadata()!!.recovery)
        manager.lock()
        assertThrows(IllegalStateException::class.java) {
            runBlocking { manager.unlockWithRecoveryCode("AAAA-BBBB".toCharArray()) }
        }
    }

    @Test
    fun `enabling recovery requires an unlocked vault`() {
        runBlocking { manager.createVault("Plain", password.toCharArray(), enableRecovery = false) }
        manager.lock()
        assertThrows(app.securevault.core.vault.VaultNotUnlockedException::class.java) {
            manager.enableRecovery()
        }
        assertNotNull("sanity", manager.metadata())
    }
}
