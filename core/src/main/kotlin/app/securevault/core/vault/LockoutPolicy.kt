package app.securevault.core.vault

import org.json.JSONObject
import kotlin.math.min
import kotlin.math.pow

/**
 * Local brute-force resistance.
 *
 * The real protection against offline attack is Argon2id, not this. This class defends the
 * on-device path: someone who picks up an unlocked phone and starts guessing. Its state is stored
 * encrypted under a Keystore key so it cannot be reset by editing a file, but an attacker with
 * root or a full device image can still bypass it. That is stated in the documentation rather
 * than papered over.
 */
data class AttemptState(
    val consecutiveFailures: Int = 0,
    val lockedUntil: Long = 0L,
    val lastFailureAt: Long = 0L
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("failures", consecutiveFailures)
        put("lockedUntil", lockedUntil)
        put("lastFailureAt", lastFailureAt)
    }

    companion object {
        fun fromJson(json: JSONObject) = AttemptState(
            consecutiveFailures = json.optInt("failures", 0),
            lockedUntil = json.optLong("lockedUntil", 0L),
            lastFailureAt = json.optLong("lastFailureAt", 0L)
        )
    }
}

data class LockoutConfig(
    /** Delays start after this many failures. */
    val gracefulAttempts: Int = 3,
    val baseDelayMillis: Long = 2_000L,
    val maxDelayMillis: Long = 5 * 60_000L,
    /** Opt-in only. Zero means never wipe, which is the default. */
    val wipeAfterFailures: Int = 0
)

class LockoutPolicy(private val config: LockoutConfig = LockoutConfig()) {

    /** Remaining lockout in milliseconds, or 0 when an attempt is allowed right now. */
    fun remainingLockMillis(state: AttemptState, now: Long = System.currentTimeMillis()): Long =
        (state.lockedUntil - now).coerceAtLeast(0L)

    fun onFailure(state: AttemptState, now: Long = System.currentTimeMillis()): AttemptState {
        val failures = state.consecutiveFailures + 1
        val over = failures - config.gracefulAttempts
        val delay = if (over <= 0) 0L else min(
            config.maxDelayMillis,
            (config.baseDelayMillis * 2.0.pow((over - 1).toDouble())).toLong()
        )
        return AttemptState(failures, if (delay > 0) now + delay else 0L, now)
    }

    fun onSuccess(): AttemptState = AttemptState()

    fun shouldWipe(state: AttemptState): Boolean =
        config.wipeAfterFailures > 0 && state.consecutiveFailures >= config.wipeAfterFailures

    fun attemptsBeforeWipe(state: AttemptState): Int? =
        if (config.wipeAfterFailures <= 0) null
        else (config.wipeAfterFailures - state.consecutiveFailures).coerceAtLeast(0)
}
