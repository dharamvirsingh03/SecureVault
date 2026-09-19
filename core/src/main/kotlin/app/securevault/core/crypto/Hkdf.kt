package app.securevault.core.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869). Used for domain separation: one vault key fans out into independent
 * subkeys so a weakness or nonce collision in one area cannot touch another.
 */
object Hkdf {

    private const val HASH_LEN = 32
    private const val ALG = "HmacSHA256"

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALG)
        mac.init(SecretKeySpec(salt ?: ByteArray(HASH_LEN), ALG))
        return mac.doFinal(ikm)
    }

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length <= 255 * HASH_LEN) { "requested length too large" }
        val mac = Mac.getInstance(ALG)
        mac.init(SecretKeySpec(prk, ALG))
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.reset()
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val take = minOf(HASH_LEN, length - offset)
            previous.copyInto(out, offset, 0, take)
            offset += take
            counter++
        }
        previous.fill(0)
        return out
    }

    fun derive(ikm: ByteArray, salt: ByteArray?, info: String, length: Int = Aead.KEY_BYTES): ByteArray {
        val prk = extract(salt, ikm)
        return try { expand(prk, info.toByteArray(Charsets.UTF_8), length) } finally { prk.fill(0) }
    }
}

/** Domain separation labels. Changing a label invalidates existing data -- version them instead. */
object KeyDomain {
    const val ITEMS = "securevault:v1:items"
    const val ATTACHMENTS = "securevault:v1:attachments"
    const val BACKUP = "securevault:v1:backup"
    const val METADATA = "securevault:v1:metadata"
    const val DATABASE = "securevault:v1:database"
}
