package app.securevault.core.crypto

/**
 * Thrown when authenticated decryption fails.
 *
 * Deliberately says nothing about *why*. A wrong key, a flipped bit, a truncated file and a
 * deliberately forged tag all produce the same exception with the same message, because any
 * difference between them is a signal an attacker can measure. Callers that need to distinguish
 * "wrong password" from "damaged file" do so from context they already hold, never from this.
 */
class VaultIntegrityException(
    message: String = GENERIC_MESSAGE,
    cause: Throwable? = null
) : Exception(message, cause) {
    companion object {
        const val GENERIC_MESSAGE = "Data failed integrity verification"
    }
}

/** Thrown when the supplied master password (or recovery code / key file) is wrong. */
class InvalidCredentialsException(message: String = "Credentials rejected") : Exception(message)

/** Thrown when a stored blob declares a format version this build cannot read. */
class UnsupportedFormatException(message: String) : Exception(message)

/**
 * Thrown when encrypted app state exists but cannot be decrypted -- a damaged file, or a Keystore
 * key that was invalidated or replaced. Distinct from "absent" on purpose: absent state is normal
 * and gets a default, whereas unreadable state is a signal and must never be silently defaulted.
 */
class SealedStateCorruptException(message: String, cause: Throwable? = null) : Exception(message, cause)
