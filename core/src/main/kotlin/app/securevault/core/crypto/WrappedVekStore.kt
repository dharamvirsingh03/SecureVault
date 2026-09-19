package app.securevault.core.crypto

import javax.crypto.Cipher

/** The vault key sealed under a platform-held key. Public data: useless without that key. */
data class BiometricBlob(val iv: ByteArray, val ciphertext: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is BiometricBlob && iv.contentEquals(other.iv) &&
            ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * iv.contentHashCode() + ciphertext.contentHashCode()
}

/**
 * Optional convenience unlock: somewhere to keep the vault encryption key wrapped under a key the
 * platform holds and the app cannot extract.
 *
 * Exists because [app.securevault.core.vault.VaultManager] needs it, not for symmetry. It is
 * nullable everywhere it is used: with no implementation, the master password remains the only way
 * in, which is the correct behaviour and the one the JVM tests already exercise.
 *
 * **The shape of this interface is inherited from Android and should be expected to change.** The
 * `Cipher` in these signatures is `javax.crypto.Cipher`, so it compiles on any JVM, but it exists
 * because Android Keystore hands back an authenticated `Cipher` from `BiometricPrompt` and the key
 * material never leaves the Keystore. Linux Secret Service works nothing like that -- it returns a
 * stored secret over D-Bus. When convenience unlock is implemented for the desktop, this interface
 * will very likely need a second look rather than a Secret Service implementation contorted into a
 * Cipher-shaped hole. The Ubuntu v1 plan passes null here, so that decision is not being made now.
 *
 * What every implementation must guarantee: the master password is never stored, the raw vault key
 * is never stored, and only the wrapped form is persisted.
 */
interface WrappedVekStore {

    /** Whether a platform key currently exists. False after invalidation. */
    fun isEnrolled(): Boolean

    /** Removes the platform key, so any wrapped copy of the vault key becomes unopenable. */
    fun deleteKey()

    /** A cipher for sealing. On Android this requires a successful biometric prompt. */
    fun encryptCipher(): Cipher

    /** Null when the key has been invalidated -- for example by a new biometric enrolment. */
    fun decryptCipher(iv: ByteArray): Cipher?

    fun sealVek(cipher: Cipher, vek: ByteArray): BiometricBlob

    fun openVek(cipher: Cipher, blob: BiometricBlob): ByteArray
}
