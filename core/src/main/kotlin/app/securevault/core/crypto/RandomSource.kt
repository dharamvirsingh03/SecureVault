package app.securevault.core.crypto

import java.security.SecureRandom

/**
 * The single source of randomness in the app. Everything that needs unpredictability -- salts,
 * nonces, keys, generated passwords -- goes through here. Never use kotlin.random.Random.
 */
object RandomSource {

    private val random: SecureRandom = SecureRandom()

    fun bytes(length: Int): ByteArray = ByteArray(length).also { random.nextBytes(it) }

    /** Uniform in [0, bound). SecureRandom.nextInt already rejects modulo bias. */
    fun int(bound: Int): Int {
        require(bound > 0) { "bound must be positive" }
        return random.nextInt(bound)
    }

    fun <T> pick(items: List<T>): T = items[int(items.size)]

    /** In-place Fisher-Yates with a CSPRNG. */
    fun <T> shuffle(items: MutableList<T>) {
        for (i in items.size - 1 downTo 1) {
            val j = int(i + 1)
            val tmp = items[i]; items[i] = items[j]; items[j] = tmp
        }
    }
}
