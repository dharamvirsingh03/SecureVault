package app.securevault.core.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Biometric unlock, done without ever storing the master password.
 *
 * A separate AES key lives in the Android Keystore (StrongBox when the device has it) and is
 * marked as requiring user authentication. The VEK is encrypted under that key; the resulting
 * ciphertext is ordinary app data and is useless on its own because the key itself cannot leave
 * the secure hardware.
 *
 * The key is invalidated automatically if the user enrols a new fingerprint or face, or removes
 * their device lock. When that happens biometric unlock switches off and the master password is
 * required again -- which is the correct behaviour, not an error to work around.
 */
class BiometricKeyStore : WrappedVekStore {

    companion object {
        private const val KEY_ALIAS = "securevault.biometric.vek"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun isEnrolled(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    override fun deleteKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }

    /** Creates a fresh hardware-backed key, replacing any previous one. */
    fun createKey(strongBoxPreferred: Boolean = true) {
        deleteKey()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(buildSpec(strongBoxPreferred))
        try {
            generator.generateKey()
        } catch (e: Exception) {
            if (strongBoxPreferred) {
                // Device advertised StrongBox but refused these parameters; fall back to TEE.
                generator.init(buildSpec(false))
                generator.generateKey()
            } else throw e
        }
    }

    private fun buildSpec(strongBox: Boolean): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            setUnlockedDeviceRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(true)
            }
        }.build()

    /** Cipher to hand to BiometricPrompt when enrolling. */
    override fun encryptCipher(): Cipher {
        if (!isEnrolled()) createKey()
        return Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, secretKey()) }
    }

    /** Cipher to hand to BiometricPrompt when unlocking. Null if the key was invalidated. */
    override fun decryptCipher(iv: ByteArray): Cipher? = try {
        Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv))
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        deleteKey()
        null
    }

    /** Call after BiometricPrompt succeeds, with the authenticated cipher it returns. */
    override fun sealVek(cipher: Cipher, vek: ByteArray): BiometricBlob =
        BiometricBlob(iv = cipher.iv, ciphertext = cipher.doFinal(vek))

    override fun openVek(cipher: Cipher, blob: BiometricBlob): ByteArray = try {
        cipher.doFinal(blob.ciphertext)
    } catch (e: Exception) {
        throw VaultIntegrityException("Biometric-wrapped key failed to decrypt", e)
    }

    private fun secretKey(): SecretKey =
        (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
}

/** Keystore ciphertext for the VEK. Safe to persist as app data; worthless without the Keystore. */
