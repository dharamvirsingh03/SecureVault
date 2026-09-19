package app.securevault.platform

import app.securevault.core.crypto.Argon2Backend
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode

/**
 * Android's Argon2id, unchanged.
 *
 * This is the same `argon2kt` call the app has always made, moved behind [Argon2Backend] and
 * nothing more. The parameters, the mode and the output are identical to the build that passed
 * 167 tests and was exercised on a real phone -- the Android cryptographic implementation is
 * frozen, and extracting a shared core is not a reason to touch it.
 *
 * `argon2kt` ships JNI `.so` files in an Android AAR, which is why the desktop build cannot reuse
 * it and why this seam exists at all.
 */
class Argon2KtBackend : Argon2Backend {

    override val name = "argon2kt"

    private val argon2 by lazy { Argon2Kt() }

    override fun hash(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        outputBytes: Int
    ): ByteArray = argon2.hash(
        mode = Argon2Mode.ARGON2_ID,
        password = password,
        salt = salt,
        tCostInIterations = iterations,
        mCostInKibibyte = memoryKib,
        parallelism = parallelism,
        hashLengthInBytes = outputBytes
    ).rawHashAsByteArray()
}
