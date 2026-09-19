package app.securevault.feature.backup

/**
 * Why a restore stopped.
 *
 * These are separate cases rather than one error string because the right thing to tell the user
 * is different in each, and in two of them the difference is security-relevant: a backup that
 * fails authentication must not be described in a way that helps someone distinguish "wrong
 * password" from "I altered this file and got caught", and a KDF this device cannot run must not
 * be reported as corruption -- the file is fine, the device is the problem.
 *
 * [userMessage] is the only thing shown. It deliberately carries no cryptographic detail.
 */
sealed class RestoreFailure(val userMessage: String) : Exception(userMessage) {

    /**
     * Authentication failed. Covers both a wrong password and a modified file, on purpose.
     *
     * Splitting these would hand an attacker with a stolen backup a free oracle: they could tell
     * whether a guessed password was right by whether the message changed. The wording admits both
     * possibilities rather than implying one.
     */
    data object AuthenticationFailed : RestoreFailure(
        "That backup could not be opened. Either the password is wrong, or the file has been " +
            "altered or damaged since it was written."
    )

    /** The container itself is not something this build knows how to read. */
    data class UnsupportedVersion(val detail: String) : RestoreFailure(
        "This backup was written by a different version of SecureVault and cannot be restored " +
            "here. Update the app and try again."
    )

    /** Not a SecureVault backup at all. */
    data object NotABackup : RestoreFailure(
        "That file is not a SecureVault backup."
    )

    /**
     * The backup names a key-derivation function this device cannot run.
     *
     * Explicitly not corruption, and explicitly not a wrong password.
     */
    data class KdfUnavailable(val algorithm: String) : RestoreFailure(
        "This backup requires $algorithm, a cryptographic algorithm that is not available on " +
            "this device. Your backup has not been declared corrupt and has not been changed. " +
            "Restore it on a device that supports $algorithm."
    )

    /** The file decrypted, but what came out does not reconstruct into a usable vault. */
    data class ValidationFailed(val reason: String) : RestoreFailure(
        "The backup opened, but the vault rebuilt from it failed its checks ($reason). Nothing " +
            "has been restored and your current vault is untouched."
    )

    /** Ran out of space, lost the file, could not write staging. */
    data class StorageFailed(val reason: String) : RestoreFailure(
        "Restore could not finish because of a storage problem ($reason). Nothing has been " +
            "restored and your current vault is untouched."
    )

    /** A vault already exists and the user has not chosen to replace it. */
    data object VaultAlreadyExists : RestoreFailure(
        "A vault already exists on this device. Restoring would replace it, which needs a " +
            "separate confirmation."
    )
}
