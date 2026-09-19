package app.securevault.core.crypto

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM. The only symmetric cipher used in this app.
 *
 * Wire format of a sealed blob: [12-byte nonce][ciphertext][16-byte tag]
 *
 * Nonces are always freshly random per encryption. With 96-bit random nonces a single key stays
 * within safe bounds well past any realistic vault size, and keys are additionally domain
 * separated (see Hkdf) so no single key encrypts everything.
 */
object Aead {

    const val KEY_BYTES = 32
    const val NONCE_BYTES = 12
    const val TAG_BYTES = 16
    private const val TAG_BITS = 128
    private const val TRANSFORM = "AES/GCM/NoPadding"

    fun seal(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        require(key.size == KEY_BYTES) { "key must be 256-bit" }
        val nonce = RandomSource.bytes(NONCE_BYTES)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        aad?.let { cipher.updateAAD(it) }
        return nonce + cipher.doFinal(plaintext)
    }

    /**
     * @throws VaultIntegrityException for every failure mode. Never returns partial data.
     *
     * Every path out of here that is not success throws the same exception with the same message.
     * A wrong key, a modified nonce, a flipped ciphertext bit, a truncated blob, empty input and
     * provider-specific errors are indistinguishable to the caller. That is the point: any
     * difference in what the app says back is a free oracle, and "the tag mismatched" versus
     * "the blob was malformed" tells an attacker which of their two guesses to keep working on.
     */
    fun open(key: ByteArray, blob: ByteArray, aad: ByteArray? = null): ByteArray {
        require(key.size == KEY_BYTES) { "key must be 256-bit" }
        if (blob.size < NONCE_BYTES + TAG_BYTES) throw VaultIntegrityException()
        return try {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(TAG_BITS, blob, 0, NONCE_BYTES)
            )
            aad?.let { cipher.updateAAD(it) }
            cipher.doFinal(blob, NONCE_BYTES, blob.size - NONCE_BYTES)
        } catch (e: GeneralSecurityException) {
            // AEADBadTagException, BadPaddingException (some providers report tag failures as the
            // parent type), IllegalBlockSizeException, ShortBufferException, NoSuchAlgorithm...
            throw VaultIntegrityException(cause = e)
        } catch (e: RuntimeException) {
            // GCMParameterSpec and doFinal can throw IllegalArgumentException or
            // IndexOutOfBoundsException on malformed input. Those are integrity failures too, and
            // letting them escape raw would both leak provider detail and crash the caller.
            throw VaultIntegrityException(cause = e)
        }
    }
}
