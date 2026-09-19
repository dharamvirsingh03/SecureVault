package app.securevault.desktop

import app.securevault.desktop.platform.DesktopLockSignals
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Auto-lock: **idle time, not elapsed time**.
 *
 * The bug these pin: the vault used to lock N seconds after unlocking regardless of what the user
 * was doing, because only keyboard events reset the timer and a mouse-driven session therefore
 * looked idle. The distinction between "N seconds since unlock" and "N seconds since the last
 * interaction" is the whole point, and `stays unlocked while the user keeps working` is the test
 * that would have caught it.
 *
 * Time is injected, so nothing here sleeps. A test that waited thirty seconds to prove a
 * thirty-second timeout would be slow and, worse, flaky enough that people would ignore it.
 */
class AutoLockTest {

    private var now = 1_000_000L
    private var monotonic = 1_000_000L
    private var locks = 0
    private var unlocked = true

    private fun signals(
        autoLockMillis: Long = 30_000L,
        lockOnFocusLoss: Boolean = true,
        lockOnSuspend: Boolean = true
    ) = DesktopLockSignals(
        scope = CoroutineScope(Job()),
        lock = { locks++; unlocked = false },
        settings = {
            DesktopLockSignals.LockSettings(autoLockMillis, lockOnFocusLoss, lockOnSuspend)
        },
        isUnlocked = { unlocked },
        wallClock = { now },
        monotonicMillis = { monotonic }
    )

    /** Advances both clocks together: ordinary time passing, no suspend. */
    private fun advance(millis: Long) {
        now += millis
        monotonic += millis
    }

    // ---- the reported bug ----------------------------------------------------------------

    @Test
    fun `stays unlocked while the user keeps working`() {
        val lock = signals(autoLockMillis = 30_000L)
        lock.resetIdle()

        // Ten minutes of continuous use: interaction every 10 seconds, ticking every second.
        repeat(60) {
            repeat(10) { advance(1_000); lock.tick() }
            lock.onInteraction()
        }

        assertEquals("active use must never lock the vault", 0, locks)
        assertTrue(unlocked)
    }

    @Test
    fun `locks only after the configured period of inactivity`() {
        val lock = signals(autoLockMillis = 30_000L)
        lock.resetIdle()

        // Work for a while, well past the timeout in total elapsed time.
        repeat(5) { advance(20_000); lock.onInteraction(); lock.tick() }
        assertEquals("100 seconds elapsed, but never 30 idle", 0, locks)

        // Then stop.
        advance(29_000)
        assertFalse("29 seconds idle is not yet the timeout", lock.tick())
        assertEquals(0, locks)

        advance(1_000)
        assertTrue("30 seconds idle must lock", lock.tick())
        assertEquals(1, locks)
    }

    @Test
    fun `a single interaction restarts the whole period`() {
        val lock = signals(autoLockMillis = 60_000L)
        lock.resetIdle()

        advance(59_000)
        assertFalse(lock.tick())

        lock.onInteraction()
        advance(59_000)
        assertFalse("the clock restarts from the interaction, not from unlock", lock.tick())
        assertEquals(0, locks)

        advance(1_000)
        assertTrue(lock.tick())
    }

    @Test
    fun `idle time is measured from the last interaction`() {
        val lock = signals()
        lock.resetIdle()
        advance(5_000)
        assertEquals(5_000L, lock.idleMillis())
        lock.onInteraction()
        assertEquals(0L, lock.idleMillis())
    }

    // ---- settings ---------------------------------------------------------------------------

    @Test
    fun `Never does not lock, however long the vault sits idle`() {
        val lock = signals(autoLockMillis = Long.MAX_VALUE)
        lock.resetIdle()

        // A week. Also checks the comparison does not overflow.
        repeat(7 * 24) { advance(3_600_000); lock.tick() }

        assertEquals("Never must mean never", 0, locks)
        assertTrue(unlocked)
    }

    @Test
    fun `Immediately locks on the first tick after an interaction`() {
        val lock = signals(autoLockMillis = 0L)
        lock.resetIdle()
        advance(1)
        assertTrue(lock.tick())
    }

    @Test
    fun `each configured timeout is honoured exactly`() {
        listOf(30_000L, 60_000L, 300_000L, 600_000L, 1_800_000L).forEach { timeout ->
            locks = 0; unlocked = true
            val lock = signals(autoLockMillis = timeout)
            lock.resetIdle()

            advance(timeout - 1_000)
            assertFalse("locked early at $timeout ms", lock.tick())
            advance(1_000)
            assertTrue("did not lock at $timeout ms", lock.tick())
        }
    }

    // ---- other signals -------------------------------------------------------------------------

    @Test
    fun `resume from suspend locks even when the idle timeout has not elapsed`() {
        val lock = signals(autoLockMillis = 600_000L)
        lock.resetIdle()

        // The heuristic: wall clock jumps, monotonic time does not.
        now += 3_600_000
        monotonic += 1_000
        assertTrue("a machine that slept must come back locked", lock.tick())
    }

    @Test
    fun `suspend detection can be turned off`() {
        val lock = signals(autoLockMillis = Long.MAX_VALUE, lockOnSuspend = false)
        lock.resetIdle()
        now += 3_600_000
        monotonic += 1_000
        assertFalse(lock.tick())
    }

    @Test
    fun `ordinary time passing is not mistaken for a suspend`() {
        val lock = signals(autoLockMillis = Long.MAX_VALUE)
        lock.resetIdle()
        repeat(100) { advance(1_000); assertFalse(lock.tick()) }
        assertEquals(0, locks)
    }

    @Test
    fun `focus loss locks only when that setting is on`() {
        signals(lockOnFocusLoss = false).onFocusLost()
        assertEquals(0, locks)
        signals(lockOnFocusLoss = true).onFocusLost()
        assertEquals(1, locks)
    }

    // ---- a locked vault ---------------------------------------------------------------------------

    @Test
    fun `an already locked vault is not locked again every second`() {
        unlocked = false
        val lock = signals(autoLockMillis = 30_000L)
        repeat(120) { advance(1_000); lock.tick() }
        assertEquals("lock() must not be called on a locked vault", 0, locks)
    }

    @Test
    fun `time spent at the lock screen does not count against the next session`() {
        unlocked = false
        val lock = signals(autoLockMillis = 30_000L)

        // An hour sitting locked.
        repeat(60) { advance(60_000); lock.tick() }

        // Now the user unlocks. The vault must not lock instantly because an hour "passed".
        unlocked = true
        lock.resetIdle()
        advance(29_000)
        assertFalse(lock.tick())
        assertEquals(0, locks)
    }
}
