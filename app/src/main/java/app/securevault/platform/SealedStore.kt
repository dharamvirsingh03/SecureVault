package app.securevault.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import app.securevault.core.crypto.Aead
import app.securevault.core.crypto.SealedStateCorruptException
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * [VaultStore] backed by a non-exportable Android Keystore key.
 *
 * Deliberately not SharedPreferences. Nothing that belongs in the vault goes here either -- this
 * is for app state, and the key is a device key, not derived from the master password.
 *
 * The Keystore key intentionally does NOT require user authentication: lockout state has to be
 * readable *before* the user has authenticated, or it could not gate authentication in the first
 * place.
 */
class SealedStore(context: Context, private val namespace: String = "state") : VaultStore {

    companion object {
        private const val KEY_ALIAS = "securevault.state"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
    }

    private val dir = File(context.filesDir, "sealed").apply { mkdirs() }
    private val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun key(): SecretKey {
        (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private fun fileFor(name: String) = File(dir, "$namespace.$name.bin")

    override fun putString(name: String, value: String) {
        // Keystore keys are not extractable, so the Aead helper (which needs raw key bytes) does
        // not apply here; drive the Keystore cipher directly.
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val body = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        // Durable: attempt state that silently fails to persist is a lockout that silently resets.
        DurableFile.write(fileFor(name), cipher.iv + body)
    }

    /**
     * @throws SealedStateCorruptException when the file exists but will not decrypt.
     *
     * The previous implementation swallowed that case and returned null, which meant a damaged or
     * deleted attempt-state file handed the caller a clean slate. Failing loudly here is what lets
     * the vault treat it as the security event it is.
     */
    override fun getString(name: String): String? {
        val file = fileFor(name)
        if (!file.exists()) {
            // Fall back to the preserved previous copy before declaring the value absent -- a
            // write interrupted mid-rename can leave only that.
            val previous = DurableFile.previous(file)
            if (!previous.exists()) return null
            return decrypt(previous, name)
        }
        return try {
            decrypt(file, name)
        } catch (e: SealedStateCorruptException) {
            // One retry against the last known-good copy before giving up.
            val previous = DurableFile.previous(file)
            if (previous.exists()) decrypt(previous, name) else throw e
        }
    }

    private fun decrypt(file: File, name: String): String = try {
        val raw = file.readBytes()
        if (raw.size <= Aead.NONCE_BYTES) throw SealedStateCorruptException("Sealed state '$name' is truncated")
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(
            Cipher.DECRYPT_MODE, key(),
            GCMParameterSpec(128, raw, 0, Aead.NONCE_BYTES)
        )
        String(cipher.doFinal(raw, Aead.NONCE_BYTES, raw.size - Aead.NONCE_BYTES), Charsets.UTF_8)
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw SealedStateCorruptException("Sealed state '$name' cannot be read: device key changed", e)
    } catch (e: GeneralSecurityException) {
        throw SealedStateCorruptException("Sealed state '$name' failed to decrypt", e)
    } catch (e: RuntimeException) {
        throw SealedStateCorruptException("Sealed state '$name' is malformed", e)
    }

    override fun remove(name: String) {
        DurableFile.deleteAll(fileFor(name))
    }

    override fun clearAll() {
        dir.listFiles()?.forEach { it.delete() }
    }
}
