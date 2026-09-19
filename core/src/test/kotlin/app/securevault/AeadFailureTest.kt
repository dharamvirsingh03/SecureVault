package app.securevault

import app.securevault.core.crypto.Aead
import app.securevault.core.crypto.Kdf
import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.VaultIntegrityException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * S4: every way of getting decryption wrong produces the same exception with the same message.
 *
 * The uniformity is the security property here, not a tidiness preference. If "tag mismatch" and
 * "malformed input" were distinguishable, an attacker probing a stolen vault would learn which of
 * their modifications were structurally valid, which is a free filter on their search.
 */
class AeadFailureTest {

    private val key = RandomSource.bytes(32)
    private val sealed = Aead.seal(key, "the quick brown fox".toByteArray())

    private fun failureFrom(block: () -> Unit): VaultIntegrityException =
        assertThrows(VaultIntegrityException::class.java) { block() }

    @Test
    fun `wrong key`() {
        val e = failureFrom { Aead.open(RandomSource.bytes(32), sealed) }
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, e.message)
    }

    @Test
    fun `wrong password derived key`() {
        val params = KdfParams(
            algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
            saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
            pbkdf2Rounds = 1_000
        )
        val right = Kdf.deriveKey("right password".toCharArray(), params)
        val wrong = Kdf.deriveKey("wrong password".toCharArray(), params)
        val blob = Aead.seal(right, "secret".toByteArray())

        val e = failureFrom { Aead.open(wrong, blob) }
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, e.message)
    }

    @Test
    fun `modified ciphertext`() {
        val tampered = sealed.copyOf()
        tampered[Aead.NONCE_BYTES + 2] = (tampered[Aead.NONCE_BYTES + 2] + 1).toByte()
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, failureFrom { Aead.open(key, tampered) }.message)
    }

    @Test
    fun `modified nonce`() {
        val tampered = sealed.copyOf()
        tampered[0] = (tampered[0] + 1).toByte()
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, failureFrom { Aead.open(key, tampered) }.message)
    }

    @Test
    fun `modified tag`() {
        val tampered = sealed.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1] + 1).toByte()
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, failureFrom { Aead.open(key, tampered) }.message)
    }

    @Test
    fun `truncated ciphertext`() {
        assertEquals(
            VaultIntegrityException.GENERIC_MESSAGE,
            failureFrom { Aead.open(key, sealed.copyOf(sealed.size - 1)) }.message
        )
    }

    @Test
    fun `empty input`() {
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, failureFrom { Aead.open(key, ByteArray(0)) }.message)
    }

    @Test
    fun `malformed input shorter than a nonce`() {
        assertEquals(VaultIntegrityException.GENERIC_MESSAGE, failureFrom { Aead.open(key, ByteArray(5)) }.message)
    }

    @Test
    fun `wrong additional data`() {
        val bound = Aead.seal(key, "secret".toByteArray(), "row-1".toByteArray())
        assertEquals(
            VaultIntegrityException.GENERIC_MESSAGE,
            failureFrom { Aead.open(key, bound, "row-2".toByteArray()) }.message
        )
    }

    @Test
    fun `every failure mode is indistinguishable`() {
        val messages = buildSet {
            add(failureFrom { Aead.open(RandomSource.bytes(32), sealed) }.message)
            add(failureFrom { Aead.open(key, ByteArray(0)) }.message)
            add(failureFrom { Aead.open(key, sealed.copyOf(20)) }.message)
            add(failureFrom { Aead.open(key, sealed.copyOf().also { it[0]++ }) }.message)
        }
        assertEquals("all failures must look identical to the caller", 1, messages.size)
    }

    @Test
    fun `a wrong key size is a programming error, not an integrity failure`() {
        // This one should NOT be swallowed: it means the caller is broken, not the data.
        assertThrows(IllegalArgumentException::class.java) { Aead.open(ByteArray(16), sealed) }
    }

    @Test
    fun `valid data still opens`() {
        assertTrue(Aead.open(key, sealed).contentEquals("the quick brown fox".toByteArray()))
    }
}
