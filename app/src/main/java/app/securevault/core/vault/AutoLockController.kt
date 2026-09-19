package app.securevault.core.vault

import android.app.Activity
import android.app.Application
import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Locks the vault when it should be locked: after inactivity, when the app leaves the foreground,
 * when the screen turns off, when the device locks.
 *
 * Each trigger is configurable on its own, because they are not the same risk. Someone who wants
 * a long inactivity timeout on a desk may still want an instant lock the moment the screen dies.
 *
 * Device lock is detected by polling [KeyguardManager.isDeviceLocked] on the existing one-second
 * tick rather than by listening for a broadcast. There is no reliable "device locked" broadcast:
 * ACTION_USER_PRESENT only fires on *unlock*, and ACTION_SCREEN_OFF is a different event -- a
 * device can lock without the screen turning off, and the screen can turn off without the device
 * locking. Polling a cheap synchronous getter once a second is the honest way to observe it.
 */
class AutoLockController(
    private val application: Application,
    private val vaultManager: VaultManager,
    private val scope: CoroutineScope
) {
    private var timerJob: Job? = null
    private var foregroundActivities = 0
    private var registered = false

    private val keyguardManager: KeyguardManager? =
        application.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF ->
                    if (vaultManager.settings().lockOnScreenOff) vaultManager.lock()
                // Always lock on shutdown, regardless of settings: there is no "keep unlocked
                // through a reboot" that makes sense.
                Intent.ACTION_SHUTDOWN -> vaultManager.lock()
            }
        }
    }

    fun start() {
        if (registered) return
        registered = true
        // RECEIVER_NOT_EXPORTED. Both actions are protected system broadcasts so this receiver is
        // technically exempt from the Android 14 flag requirement, but stating the intent
        // explicitly costs nothing and means the receiver stays unreachable from other apps if
        // the filter ever grows a non-protected action.
        ContextCompat.registerReceiver(
            application,
            screenReceiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SHUTDOWN)
            },
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: Activity) {
                foregroundActivities++
            }

            override fun onActivityStopped(activity: Activity) {
                foregroundActivities--
                if (foregroundActivities <= 0 && vaultManager.settings().lockOnBackground) {
                    vaultManager.lock()
                }
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityResumed(activity: Activity) = onUserInteraction()
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        })
        startTimer()
    }

    /** Call from the UI on meaningful interaction to push the inactivity deadline out. */
    fun onUserInteraction() {
        vaultManager.session.value?.touch()
    }

    /** True when the device's own lock screen is currently engaged. */
    fun deviceIsLocked(): Boolean = keyguardManager?.isDeviceLocked == true

    private fun startTimer() {
        timerJob?.cancel()
        timerJob = scope.launch {
            while (true) {
                delay(1_000)
                val session = vaultManager.session.value ?: continue
                val settings = vaultManager.settings()

                if (settings.lockOnDeviceLock && deviceIsLocked()) {
                    vaultManager.lock()
                    continue
                }

                val timeout = settings.autoLockMillis
                if (timeout == Long.MAX_VALUE) continue
                if (System.currentTimeMillis() - session.lastActivityAt >= timeout) {
                    vaultManager.lock()
                }
            }
        }
    }

    // There is deliberately no stop(). This controller lives for the life of the process, which is
    // the only correct lifetime for the thing that decides when the vault locks: a teardown path
    // would be unreachable (Android does not guarantee Application.onTerminate) and having one
    // would suggest the receiver and timer are torn down somewhere, which they are not. The
    // receiver is registered once, is RECEIVER_NOT_EXPORTED, and dies with the process.
}
