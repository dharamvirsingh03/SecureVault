package app.securevault.core.crypto

/**
 * The one piece of the key hierarchy that cannot be shared as code.
 *
 * Argon2id is a specification, not an implementation. Android uses `argon2kt`, which ships JNI
 * `.so` files in an Android AAR and will not run on a desktop JVM; the Linux build therefore needs
 * a different implementation. This interface is the seam between them, and it is deliberately as
 * narrow as possible -- six numbers in, one array out -- because every extra degree of freedom is
 * another way for two implementations to disagree.
 *
 * **Agreement is not assumed, it is tested.** Two correct Argon2id implementations given the same
 * password, salt, memory, iterations, parallelism, output length and version 0x13 produce the same
 * bytes. That is what makes a vault created on Android openable on Ubuntu. It is also exactly the
 * kind of claim that is easy to state and expensive to be wrong about, so both implementations are
 * held against the same fixed vectors (see `Argon2Vectors` in the test sources). Until those
 * vectors have actually been executed on both platforms, cross-platform compatibility is designed
 * for, not demonstrated.
 *
 * Implementations must:
 *  - use Argon2**id** (not i, not d)
 *  - use version 0x13 (19), the current one
 *  - pass no secret key and no associated data, since `argon2kt` exposes neither and a parameter
 *    one side cannot supply is a parameter that cannot be shared
 *  - return exactly [outputBytes] bytes
 *  - throw rather than fall back to anything else if they cannot run
 */
interface Argon2Backend {

    /** A short name for diagnostics. Never used to choose behaviour. */
    val name: String

    /**
     * @throws Exception if the implementation is unavailable on this device. Callers translate
     * that into [KdfUnavailableException]; they never substitute another algorithm.
     */
    fun hash(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        outputBytes: Int
    ): ByteArray
}
