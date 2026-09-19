package app.securevault.core.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The contract every [Argon2Backend] must satisfy, run identically on Android and on Linux.
 *
 * This class exists so the two implementations are never checked against each other -- only
 * against the same external expectations. Two implementations agreeing with one another proves
 * nothing if both are wrong in the same way.
 *
 * Subclass it once per platform and supply the backend.
 */
abstract class Argon2BackendContract {

    abstract fun backend(): Argon2Backend

    private fun hash(v: Argon2Vectors.Vector) = backend().hash(
        password = v.password.toByteArray(Charsets.UTF_8),
        salt = v.salt.toByteArray(Charsets.UTF_8),
        memoryKib = v.memoryKib,
        iterations = v.iterations,
        parallelism = v.parallelism,
        outputBytes = v.outputBytes
    )

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `matches the reference vectors`() {
        val populated = Argon2Vectors.populated
        assumeTrue(
            "No Argon2 vectors are populated yet. Until they are, cross-platform compatibility " +
                "is designed, not demonstrated. Generate them with:\n" +
                Argon2Vectors.ALL.joinToString("\n") { "  ${it.label}\n    ${it.referenceCommand}" },
            populated.isNotEmpty()
        )
        populated.forEach { vector ->
            assertEquals(
                "vector '${vector.label}' does not match the reference implementation. " +
                    "A mismatch here means vaults made on one platform will not open on the other.",
                vector.expectedHex.lowercase(),
                hex(hash(vector))
            )
        }
    }

    // --- properties that hold regardless of whether the vectors are filled in -----------------

    @Test
    fun `output length is honoured exactly`() {
        val v = Argon2Vectors.ALL.first()
        listOf(16, 32, 64).forEach { length ->
            assertEquals(length, hash(v.copy(outputBytes = length)).size)
        }
    }

    @Test
    fun `the same inputs always give the same bytes`() {
        val v = Argon2Vectors.ALL.first()
        assertEquals(hex(hash(v)), hex(hash(v)))
    }

    @Test
    fun `every parameter changes the output`() {
        val base = Argon2Vectors.ALL.first()
        val baseline = hex(hash(base))
        // If any of these came back equal, the backend is ignoring a parameter -- which is how a
        // vault ends up cheaper to attack than its header claims.
        assertNotEquals(baseline, hex(hash(base.copy(password = base.password + "x"))))
        assertNotEquals(baseline, hex(hash(base.copy(salt = "a-different-salt"))))
        assertNotEquals(baseline, hex(hash(base.copy(iterations = base.iterations + 1))))
        assertNotEquals(baseline, hex(hash(base.copy(memoryKib = base.memoryKib * 2))))
        assertNotEquals(baseline, hex(hash(base.copy(parallelism = base.parallelism + 1))))
    }

    @Test
    fun `an empty password is still hashed rather than rejected`() {
        val v = Argon2Vectors.ALL.first().copy(password = "")
        assertEquals(32, hash(v).size)
    }

    @Test
    fun `a short salt is rejected rather than silently padded`() {
        // Argon2 requires at least 8 bytes of salt. Silently accepting less would weaken every
        // vault created on that platform.
        assertThrows(Exception::class.java) {
            backend().hash("pw".toByteArray(), ByteArray(4), 16_384, 3, 1, 32)
        }
    }
}
