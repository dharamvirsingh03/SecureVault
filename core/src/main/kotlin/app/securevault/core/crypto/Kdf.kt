package app.securevault.core.crypto

import org.json.JSONObject
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

enum class KdfAlgorithm {
    ARGON2ID,
    PBKDF2_HMAC_SHA256;

    /** Human name for anywhere the user is told which KDF their vault uses. */
    val displayName: String
        get() = when (this) {
            ARGON2ID -> "Argon2id"
            PBKDF2_HMAC_SHA256 -> "PBKDF2-HMAC-SHA256"
        }
}

/**
 * Thrown when a vault names a KDF this device cannot run.
 *
 * The important thing is what this is *not*: it is not a signal to try a different algorithm. A
 * vault's KDF is a property of that vault, recorded in its header, and the only correct response
 * to being unable to run it is to say so and stop. Substituting a weaker function would produce
 * the wrong key anyway -- but even if it did not, quietly reducing the cost of attacking someone's
 * vault because a shared library failed to load is not a trade this app gets to make.
 */
class KdfUnavailableException(val algorithm: KdfAlgorithm, cause: Throwable? = null) : Exception(
    "This vault uses ${algorithm.displayName}, which is not available on this device. " +
        "The vault cannot be opened here. Do not create a new vault -- your data is intact.",
    cause
)

/**
 * The outcome of choosing KDF parameters for a *new* vault.
 *
 * [usedFallback] exists so the choice can never be silent. Creating a vault under PBKDF2 because
 * the Argon2 native library would not load is a real reduction in how expensive it is to attack
 * that vault offline, and the person whose passwords are going in deserves to be told at the
 * moment it happens -- not to discover it later in a header they never read.
 */
data class KdfSelection(
    val params: KdfParams,
    val usedFallback: Boolean,
    val fallbackReason: String? = null
)

/**
 * Everything needed to re-derive the key-encryption key from a master password.
 *
 * These parameters are NOT secret: they travel with the vault, with encrypted backups, and on the
 * emergency recovery kit. Without them an otherwise valid backup is unopenable, which is exactly
 * why the recovery kit prints them.
 */
data class KdfParams(
    val algorithm: KdfAlgorithm,
    val saltB64: String,
    val memoryKib: Int = DEFAULT_MEMORY_KIB,
    val iterations: Int = DEFAULT_ITERATIONS,
    val parallelism: Int = DEFAULT_PARALLELISM,
    val pbkdf2Rounds: Int = DEFAULT_PBKDF2_ROUNDS,
    val outputBytes: Int = Aead.KEY_BYTES
) {
    val salt: ByteArray get() = Base64.getDecoder().decode(saltB64)

    fun toJson(): JSONObject = JSONObject().apply {
        put("alg", algorithm.name)
        put("salt", saltB64)
        put("m", memoryKib)
        put("t", iterations)
        put("p", parallelism)
        put("pbkdf2Rounds", pbkdf2Rounds)
        put("len", outputBytes)
    }

    /** Human readable form for the emergency recovery kit. */
    fun describe(): String = when (algorithm) {
        KdfAlgorithm.ARGON2ID ->
            "Argon2id  m=${memoryKib} KiB  t=$iterations  p=$parallelism  len=$outputBytes"
        KdfAlgorithm.PBKDF2_HMAC_SHA256 ->
            "PBKDF2-HMAC-SHA256  rounds=$pbkdf2Rounds  len=$outputBytes"
    }

    companion object {
        const val DEFAULT_MEMORY_KIB = 65_536      // 64 MiB
        const val DEFAULT_ITERATIONS = 3
        const val DEFAULT_PARALLELISM = 2
        const val DEFAULT_PBKDF2_ROUNDS = 600_000
        const val SALT_BYTES = 16

        fun newRandom(algorithm: KdfAlgorithm = KdfAlgorithm.ARGON2ID): KdfParams =
            KdfParams(
                algorithm = algorithm,
                saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(SALT_BYTES))
            )

        fun fromJson(json: JSONObject): KdfParams = KdfParams(
            algorithm = KdfAlgorithm.valueOf(json.getString("alg")),
            saltB64 = json.getString("salt"),
            memoryKib = json.optInt("m", DEFAULT_MEMORY_KIB),
            iterations = json.optInt("t", DEFAULT_ITERATIONS),
            parallelism = json.optInt("p", DEFAULT_PARALLELISM),
            pbkdf2Rounds = json.optInt("pbkdf2Rounds", DEFAULT_PBKDF2_ROUNDS),
            outputBytes = json.optInt("len", Aead.KEY_BYTES)
        )
    }
}

/**
 * Password-based key derivation.
 *
 * Argon2id is the default and is what protects a vault against offline cracking if someone steals
 * the encrypted database. PBKDF2-HMAC-SHA256 exists only as a fallback for the case where the
 * native Argon2 library cannot be loaded on a given ABI; vaults record which one they used so an
 * old vault keeps opening after the fallback goes away.
 */
object Kdf {

    /**
     * The platform's Argon2id implementation, installed once at startup.
     *
     * Null means no implementation is present, which is treated exactly as a native library that
     * will not load was treated before: new vaults fall back to PBKDF2 *with a warning*, and an
     * existing Argon2id vault refuses to open rather than silently downgrading. The four-case
     * matrix in SECURITY.md is unchanged.
     */
    @Volatile
    private var backend: Argon2Backend? = null

    /** Called once during application startup, before any vault operation. */
    fun installArgon2Backend(implementation: Argon2Backend) {
        backend = implementation
        resetAvailabilityProbe()
    }

    /** Which implementation is in use, for diagnostics and the vector tests. */
    fun argon2BackendName(): String? = backend?.name

    /**
     * Derives a key using exactly the algorithm named in [params].
     *
     * There is no fallback here and there must never be one. The algorithm is read from the
     * vault's own header; if it cannot be run, this throws [KdfUnavailableException] rather than
     * reaching for something else.
     */
    fun deriveKey(password: CharArray, params: KdfParams): ByteArray {
        val passwordBytes = SecureBytes.utf8(password)
        return try {
            when (params.algorithm) {
                KdfAlgorithm.ARGON2ID -> {
                    if (!isArgon2Available()) throw KdfUnavailableException(KdfAlgorithm.ARGON2ID)
                    try {
                        argon2id(passwordBytes, params)
                    } catch (e: UnsatisfiedLinkError) {
                        // The probe passed but this call failed: still a missing implementation,
                        // never a reason to switch algorithms.
                        throw KdfUnavailableException(KdfAlgorithm.ARGON2ID, e)
                    } catch (e: NoClassDefFoundError) {
                        throw KdfUnavailableException(KdfAlgorithm.ARGON2ID, e)
                    }
                }
                KdfAlgorithm.PBKDF2_HMAC_SHA256 -> pbkdf2(password, params)
            }
        } finally {
            passwordBytes.fill(0)
        }
    }

    private fun argon2id(password: ByteArray, params: KdfParams): ByteArray {
        val implementation = backend ?: throw KdfUnavailableException(KdfAlgorithm.ARGON2ID)
        return implementation.hash(
            password = password,
            salt = params.salt,
            memoryKib = params.memoryKib,
            iterations = params.iterations,
            parallelism = params.parallelism,
            outputBytes = params.outputBytes
        )
    }

    private fun pbkdf2(password: CharArray, params: KdfParams): ByteArray {
        val spec = PBEKeySpec(password, params.salt, params.pbkdf2Rounds, params.outputBytes * 8)
        return try {
            SecretKeyFactory.getInstance("PBKDF2withHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    @Volatile
    private var argon2Probe: Boolean? = null

    /**
     * True when the native Argon2 library loads on this device/ABI.
     *
     * Cached: this runs on the unlock path and a failing probe is slow and noisy. The answer
     * cannot change within a process -- a shared library does not appear mid-run.
     */
    fun isArgon2Available(): Boolean = argon2Probe ?: synchronized(this) {
        argon2Probe ?: runCatching {
            val probe = KdfParams(
                KdfAlgorithm.ARGON2ID, Base64.getEncoder().encodeToString(ByteArray(16)),
                memoryKib = 8, iterations = 1, parallelism = 1
            )
            argon2id("probe".toByteArray(), probe).also { it.fill(0) }
            true
        }.getOrDefault(false).also { argon2Probe = it }
    }

    /**
     * Resets the cached probe result.
     *
     * Public rather than internal only because `Kdf` now lives in `:core` while some of the tests
     * that exercise it live in `:app`; `internal` does not cross a module boundary. It is a test
     * seam and nothing in production calls it.
     */
    fun resetAvailabilityProbe() {
        argon2Probe = null
    }

    /**
     * Picks the heaviest Argon2id parameters this device can run inside [targetMillis].
     *
     * Cheap phones get weaker-but-usable parameters rather than a 6 second unlock; the chosen
     * values are stored with the vault so unlocking stays deterministic afterwards.
     */
    fun calibrate(targetMillis: Long = 1_000L, floorMemoryKib: Int = 19_456): KdfSelection {
        if (!isArgon2Available()) {
            return KdfSelection(
                params = KdfParams.newRandom(KdfAlgorithm.PBKDF2_HMAC_SHA256),
                usedFallback = true,
                fallbackReason = "The Argon2 native library did not load on this device, so this " +
                    "vault will use PBKDF2-HMAC-SHA256 instead. That is a working but weaker " +
                    "defence against someone attacking a stolen copy of your vault offline. " +
                    "The choice is recorded in the vault header and will not change later."
            )
        }
        val salt = RandomSource.bytes(KdfParams.SALT_BYTES)
        val saltB64 = Base64.getEncoder().encodeToString(salt)
        val candidates = intArrayOf(262_144, 131_072, 65_536, 32_768, floorMemoryKib)
        val probe = "calibration-probe".toCharArray()
        for (memory in candidates) {
            val params = KdfParams(KdfAlgorithm.ARGON2ID, saltB64, memoryKib = memory)
            val started = System.nanoTime()
            deriveKey(probe, params).fill(0)
            val elapsed = (System.nanoTime() - started) / 1_000_000
            if (elapsed <= targetMillis) return KdfSelection(params, usedFallback = false)
        }
        return KdfSelection(
            KdfParams(KdfAlgorithm.ARGON2ID, saltB64, memoryKib = floorMemoryKib),
            usedFallback = false
        )
    }
}
