package app.securevault.desktop.platform

import app.securevault.core.crypto.Argon2Backend
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.generators.Argon2BytesGenerator

/**
 * Argon2id for the desktop, in pure Java.
 *
 * Bouncy Castle rather than a JNI binding, deliberately. `argon2kt` on Android ships native `.so`
 * files, and the failure mode that makes it this project's largest supply-chain concern -- an
 * `UnsatisfiedLinkError` on an unexpected ABI, silently pushing new vaults onto PBKDF2 -- simply
 * does not exist for a pure-Java implementation. There is no native library to fail to load.
 *
 * **This must produce byte-identical output to Android.** Argon2id is a specification: the same
 * password, salt, memory, iterations, parallelism, output length and version give the same bytes
 * from any correct implementation. That is what makes a vault created on a phone openable here.
 * It is also exactly the kind of claim that is cheap to assert and expensive to be wrong about,
 * which is why `Argon2BackendContract` holds this against vectors from the reference
 * implementation rather than against Android's output.
 *
 * Parameters are fixed to match what Android sends: Argon2**id**, version 0x13, no secret key,
 * no associated data.
 */
class BouncyCastleArgon2Backend : Argon2Backend {

    override val name = "bouncycastle-argon2id"

    override fun hash(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        outputBytes: Int
    ): ByteArray {
        // Argon2 requires at least 8 bytes of salt. Rejecting rather than padding: silently
        // accepting a short salt would weaken every vault created on this platform.
        require(salt.size >= MIN_SALT_BYTES) { "Argon2 salt must be at least $MIN_SALT_BYTES bytes" }
        require(outputBytes >= MIN_OUTPUT_BYTES) { "Argon2 output must be at least $MIN_OUTPUT_BYTES bytes" }
        require(memoryKib >= MIN_MEMORY_KIB) { "Argon2 memory cost is too low" }
        require(iterations >= 1 && parallelism >= 1) { "Argon2 cost parameters must be positive" }

        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .build()

        val generator = Argon2BytesGenerator().apply { init(parameters) }
        val out = ByteArray(outputBytes)
        generator.generateBytes(password, out)
        return out
    }

    private companion object {
        const val MIN_SALT_BYTES = 8
        const val MIN_OUTPUT_BYTES = 4
        const val MIN_MEMORY_KIB = 8
    }
}
