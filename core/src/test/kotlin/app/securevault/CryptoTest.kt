package app.securevault

import app.securevault.core.crypto.Aead
import app.securevault.core.crypto.Hkdf
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.StreamAead
import app.securevault.core.crypto.VaultIntegrityException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CryptoTest {

    @Test
    fun `aead round trips and rejects tampering`() {
        val key = RandomSource.bytes(32)
        val message = "correct horse battery staple".toByteArray()
        val sealed = Aead.seal(key, message, "context".toByteArray())

        assertTrue(Aead.open(key, sealed, "context".toByteArray()).contentEquals(message))

        val tampered = sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertThrows(VaultIntegrityException::class.java) {
            Aead.open(key, tampered, "context".toByteArray())
        }
    }

    @Test
    fun `aead binds additional data`() {
        val key = RandomSource.bytes(32)
        val sealed = Aead.seal(key, "secret".toByteArray(), "row-1".toByteArray())
        // Moving a record's ciphertext onto another row must fail rather than decrypt.
        assertThrows(VaultIntegrityException::class.java) {
            Aead.open(key, sealed, "row-2".toByteArray())
        }
    }

    @Test
    fun `wrong key never yields plaintext`() {
        val sealed = Aead.seal(RandomSource.bytes(32), "secret".toByteArray())
        assertThrows(VaultIntegrityException::class.java) {
            Aead.open(RandomSource.bytes(32), sealed)
        }
    }

    @Test
    fun `hkdf separates domains`() {
        val master = RandomSource.bytes(32)
        val a = Hkdf.derive(master, null, "domain-a")
        val b = Hkdf.derive(master, null, "domain-b")
        assertFalse(a.contentEquals(b))
        assertTrue(Hkdf.derive(master, null, "domain-a").contentEquals(a))
    }

    @Test
    fun `stream aead round trips across chunk boundaries`() {
        val key = RandomSource.bytes(32)
        val payload = RandomSource.bytes(StreamAead.CHUNK_SIZE * 2 + 1234)
        val sealed = ByteArrayOutputStream()
        StreamAead.encrypt(key, ByteArrayInputStream(payload), sealed, "aad".toByteArray())

        val opened = ByteArrayOutputStream()
        StreamAead.decrypt(key, ByteArrayInputStream(sealed.toByteArray()), opened, "aad".toByteArray())
        assertTrue(opened.toByteArray().contentEquals(payload))
    }

    @Test
    fun `truncated stream is rejected`() {
        val key = RandomSource.bytes(32)
        val payload = RandomSource.bytes(StreamAead.CHUNK_SIZE * 2)
        val sealed = ByteArrayOutputStream()
        StreamAead.encrypt(key, ByteArrayInputStream(payload), sealed, ByteArray(0))
        val truncated = sealed.toByteArray().copyOf(sealed.size() / 2)

        assertThrows(VaultIntegrityException::class.java) {
            StreamAead.decrypt(key, ByteArrayInputStream(truncated), ByteArrayOutputStream(), ByteArray(0))
        }
    }

    @Test
    fun `empty input still produces a verifiable stream`() {
        val key = RandomSource.bytes(32)
        val sealed = ByteArrayOutputStream()
        StreamAead.encrypt(key, ByteArrayInputStream(ByteArray(0)), sealed)
        val opened = ByteArrayOutputStream()
        StreamAead.decrypt(key, ByteArrayInputStream(sealed.toByteArray()), opened)
        assertEquals(0, opened.size())
    }
}
