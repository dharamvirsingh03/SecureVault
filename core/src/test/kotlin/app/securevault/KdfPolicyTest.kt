package app.securevault

import app.securevault.core.crypto.Kdf
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject
import java.util.Base64

/**
 * The KDF must never be guessed and never be quietly downgraded.
 *
 * These tests run on the JVM, where the Argon2 native library genuinely cannot load. That makes
 * this the ideal environment to assert the *absence* of a fallback: a vault whose header says
 * Argon2id must refuse to open rather than reach for PBKDF2.
 */
class KdfPolicyTest {

    private fun pbkdf2(rounds: Int = 1_000, salt: ByteArray = RandomSource.bytes(16)) = KdfParams(
        algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
        saltB64 = Base64.getEncoder().encodeToString(salt),
        pbkdf2Rounds = rounds
    )

    @Test
    fun `argon2 is genuinely unavailable in this environment`() {
        Kdf.resetAvailabilityProbe()
        assertFalse(
            "if this ever passes, the no-downgrade tests below stop proving anything",
            Kdf.isArgon2Available()
        )
    }

    @Test
    fun `an argon2 vault refuses to open rather than downgrading`() {
        val params = KdfParams(
            algorithm = KdfAlgorithm.ARGON2ID,
            saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16))
        )
        val error = assertThrows(KdfUnavailableException::class.java) {
            Kdf.deriveKey("a password".toCharArray(), params)
        }
        assertEquals(KdfAlgorithm.ARGON2ID, error.algorithm)
        // The message must tell the user not to start over, because their data is still there.
        assertTrue(error.message!!.contains("Do not create a new vault"))
    }

    @Test
    fun `calibration reports the fallback instead of hiding it`() {
        val selection = Kdf.calibrate()
        assertEquals(KdfAlgorithm.PBKDF2_HMAC_SHA256, selection.params.algorithm)
        assertTrue(selection.usedFallback)
        assertTrue(selection.fallbackReason!!.contains("PBKDF2"))
    }

    @Test
    fun `derivation is deterministic across devices for the same stored parameters`() {
        // "Device A" writes the header; "device B" reads it back and must land on the same key.
        val original = pbkdf2()
        val deviceB = KdfParams.fromJson(JSONObject(original.toJson().toString()))

        val a = Kdf.deriveKey("shared passphrase".toCharArray(), original)
        val b = Kdf.deriveKey("shared passphrase".toCharArray(), deviceB)
        assertTrue(a.contentEquals(b))
    }

    @Test
    fun `every parameter survives a round trip through the header`() {
        val original = pbkdf2(rounds = 12_345)
        val restored = KdfParams.fromJson(JSONObject(original.toJson().toString()))

        assertEquals(original.algorithm, restored.algorithm)
        assertEquals(original.saltB64, restored.saltB64)
        assertEquals(original.pbkdf2Rounds, restored.pbkdf2Rounds)
        assertEquals(original.outputBytes, restored.outputBytes)
        assertTrue(original.salt.contentEquals(restored.salt))
    }

    @Test
    fun `argon2 parameters survive a round trip even where argon2 cannot run`() {
        // Reading a header must not require being able to execute it -- otherwise a device that
        // cannot open a vault also could not explain why.
        val original = KdfParams(
            algorithm = KdfAlgorithm.ARGON2ID,
            saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
            memoryKib = 131_072, iterations = 4, parallelism = 3
        )
        val restored = KdfParams.fromJson(JSONObject(original.toJson().toString()))
        assertEquals(original, restored)
        assertTrue(restored.describe().contains("131072"))
    }

    @Test
    fun `a different salt gives a different key`() {
        val a = Kdf.deriveKey("same passphrase".toCharArray(), pbkdf2())
        val b = Kdf.deriveKey("same passphrase".toCharArray(), pbkdf2())
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `weakened parameters produce a different key rather than a weaker unlock`() {
        // The attack this rules out: edit the header to say "1 round" and crack it cheaply.
        val salt = RandomSource.bytes(16)
        val strong = pbkdf2(rounds = 50_000, salt = salt)
        val weakened = pbkdf2(rounds = 1, salt = salt)

        val vek = KeyHierarchy.generateVek()
        val kek = Kdf.deriveKey("passphrase".toCharArray(), strong)
        val wrapped = KeyHierarchy.wrapVek(kek, vek, "vault-1")

        val weakKek = Kdf.deriveKey("passphrase".toCharArray(), weakened)
        assertThrows(app.securevault.core.crypto.InvalidCredentialsException::class.java) {
            KeyHierarchy.unwrapVek(weakKek, wrapped, "vault-1")
        }
    }
}
