package app.securevault

import app.securevault.core.crypto.Kdf
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.crypto.RandomSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * The core module ships no Argon2 implementation of its own, and this pins what that means.
 *
 * Extracting the crypto into `:core` introduced a way to get the four-case KDF matrix wrong that
 * did not exist before: an app could forget to install a backend and quietly behave as though the
 * native library had failed to load. These tests assert that the resulting behaviour is the
 * *documented* failure mode rather than anything softer -- a missing backend must look exactly
 * like a missing native library, never like a reason to use something weaker without saying so.
 */
class NoArgon2BackendTest {

    @Before
    fun setUp() {
        Kdf.resetAvailabilityProbe()
    }

    private fun pbkdf2Params() = KdfParams(
        algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
        saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
        pbkdf2Rounds = 1_000
    )

    @Test
    fun `with no backend installed Argon2 reports itself unavailable`() {
        assertFalse(Kdf.isArgon2Available())
        assertEquals(null, Kdf.argon2BackendName())
    }

    @Test
    fun `an Argon2 vault refuses to open rather than downgrading`() {
        val params = KdfParams(
            algorithm = KdfAlgorithm.ARGON2ID,
            saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16))
        )
        val error = assertThrows(KdfUnavailableException::class.java) {
            Kdf.deriveKey("a passphrase".toCharArray(), params)
        }
        assertEquals(KdfAlgorithm.ARGON2ID, error.algorithm)
        assertTrue(error.message!!.contains("Do not create a new vault"))
    }

    @Test
    fun `a new vault falls back to PBKDF2 and says so`() {
        val selection = Kdf.calibrate()
        assertEquals(KdfAlgorithm.PBKDF2_HMAC_SHA256, selection.params.algorithm)
        assertTrue(selection.usedFallback)
        assertTrue(selection.fallbackReason!!.contains("PBKDF2"))
    }

    @Test
    fun `PBKDF2 still works and stays deterministic`() {
        val params = pbkdf2Params()
        val a = Kdf.deriveKey("shared passphrase".toCharArray(), params)
        val b = Kdf.deriveKey("shared passphrase".toCharArray(), params)
        assertTrue(a.contentEquals(b))
        assertEquals(32, a.size)
    }
}
