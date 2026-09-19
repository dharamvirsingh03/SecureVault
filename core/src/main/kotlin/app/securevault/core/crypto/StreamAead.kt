package app.securevault.core.crypto

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Chunked AES-256-GCM for data too large to hold in memory: attachments and backup bodies.
 *
 * Layout: [magic][version][4-byte stream prefix] then repeated [4-byte length][1-byte final flag][sealed chunk]
 *
 * Each chunk has its own nonce (stream prefix + chunk counter) and its own tag. The chunk index
 * and the final-chunk flag are authenticated as additional data, so chunks cannot be reordered,
 * dropped, duplicated or truncated without decryption failing. Getting this wrong is the usual
 * mistake in hand-rolled "encrypt each block" schemes.
 */
object StreamAead {

    const val CHUNK_SIZE = 64 * 1024
    private const val TAG_BITS = 128
    private const val MAGIC = 0x53565354 // "SVST"
    private const val VERSION = 1
    private const val PREFIX_BYTES = 4
    private const val HEADER_BYTES = 12

    fun encrypt(key: ByteArray, input: InputStream, output: OutputStream, aad: ByteArray = ByteArray(0)) {
        require(key.size == Aead.KEY_BYTES)
        val prefix = RandomSource.bytes(PREFIX_BYTES)
        output.write(ByteBuffer.allocate(HEADER_BYTES).putInt(MAGIC).putInt(VERSION).put(prefix).array())

        val buffer = ByteArray(CHUNK_SIZE)
        var index = 0L
        while (true) {
            val read = readFully(input, buffer)
            val isLast = read < CHUNK_SIZE
            val chunk = buffer.copyOf(read)
            val sealed = transform(Cipher.ENCRYPT_MODE, key, prefix, index, isLast, chunk, aad)
            output.write(ByteBuffer.allocate(5).putInt(sealed.size).put(if (isLast) 1 else 0).array())
            output.write(sealed)
            chunk.fill(0)
            index++
            if (isLast) break
        }
        buffer.fill(0)
        output.flush()
    }

    fun decrypt(key: ByteArray, input: InputStream, output: OutputStream, aad: ByteArray = ByteArray(0)) {
        require(key.size == Aead.KEY_BYTES)
        val header = ByteArray(HEADER_BYTES)
        if (readFully(input, header) != HEADER_BYTES) throw VaultIntegrityException("Stream header truncated")
        val hb = ByteBuffer.wrap(header)
        if (hb.int != MAGIC) throw UnsupportedFormatException("Not a SecureVault stream")
        val version = hb.int
        if (version != VERSION) throw UnsupportedFormatException("Stream version $version is not supported")
        val prefix = ByteArray(PREFIX_BYTES).also { hb.get(it) }

        var index = 0L
        while (true) {
            val frame = ByteArray(5)
            if (readFully(input, frame) != 5) throw VaultIntegrityException("Stream ended mid-frame")
            val fb = ByteBuffer.wrap(frame)
            val length = fb.int
            val isLast = fb.get().toInt() == 1
            if (length < Aead.TAG_BYTES || length > CHUNK_SIZE + Aead.TAG_BYTES) {
                throw VaultIntegrityException("Chunk length out of range")
            }
            val sealed = ByteArray(length)
            if (readFully(input, sealed) != length) throw VaultIntegrityException("Chunk $index truncated")
            val plain = transform(Cipher.DECRYPT_MODE, key, prefix, index, isLast, sealed, aad)
            output.write(plain)
            plain.fill(0)
            index++
            if (isLast) break
        }
        output.flush()
    }

    private fun transform(
        mode: Int, key: ByteArray, prefix: ByteArray, index: Long,
        isLast: Boolean, data: ByteArray, aad: ByteArray
    ): ByteArray = try {
        val nonce = ByteBuffer.allocate(Aead.NONCE_BYTES).put(prefix).putLong(index).array()
        val chunkAad = ByteBuffer.allocate(9 + aad.size).putLong(index).put(if (isLast) 1 else 0).put(aad).array()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(chunkAad)
        cipher.doFinal(data)
    } catch (e: java.security.GeneralSecurityException) {
        // Same reasoning as Aead.open: one exception, one message, no detail about which of the
        // possible failures occurred.
        throw VaultIntegrityException(cause = e)
    } catch (e: RuntimeException) {
        throw VaultIntegrityException(cause = e)
    }

    private fun readFully(input: InputStream, buffer: ByteArray): Int {
        var total = 0
        while (total < buffer.size) {
            val r = input.read(buffer, total, buffer.size - total)
            if (r < 0) break
            total += r
        }
        return total
    }
}
