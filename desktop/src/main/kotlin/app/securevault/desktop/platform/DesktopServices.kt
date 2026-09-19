package app.securevault.desktop.platform

import app.securevault.core.model.AttachmentRef
import app.securevault.core.vault.VaultSession
import app.securevault.data.attachments.AttachmentStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.Desktop
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.io.File
import kotlin.math.abs

/**
 * Linux clipboard handling.
 *
 * **What Linux cannot do, stated plainly:** there is no equivalent of Android's
 * `EXTRA_IS_SENSITIVE`. Nothing marks a clipboard entry as secret, and clipboard managers
 * (GPaste, Klipper, the GNOME extensions people install) routinely keep history. SecureVault
 * cannot see them and cannot stop them. A password copied here may be retained by another
 * application after the timeout, and the timeout below does not change that.
 *
 * What it does do is clear the clipboard after the configured delay, and only if our value is
 * still there -- so a later copy by the user is never wiped out from under them.
 *
 * On X11 a clipboard's contents live in the owning application, so clearing works while
 * SecureVault runs and the value disappears when it exits. On Wayland the compositor mediates,
 * with broadly the same result. Neither reaches a clipboard manager that has already taken a copy.
 */
class DesktopClipboard(private val scope: CoroutineScope) {

    private val clipboard = runCatching { Toolkit.getDefaultToolkit().systemClipboard }.getOrNull()

    @Volatile
    private var lastCopied: String? = null

    /** @return a message for the UI, or null when the clipboard is unavailable. */
    fun copy(value: String, clearAfterSeconds: Int, label: String): String? {
        val board = clipboard ?: return null
        board.setContents(StringSelection(value), null)
        lastCopied = value

        if (clearAfterSeconds <= 0) {
            return "$label copied. Clipboard clearing is off, so it stays until something replaces it."
        }
        scope.launch {
            delay(clearAfterSeconds * 1000L)
            clearIfStillOurs(value)
        }
        return "$label copied. Clears in ${clearAfterSeconds}s."
    }

    fun clearIfStillOurs(value: String) {
        val board = clipboard ?: return
        runCatching {
            val current = board.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
            if (current == value) {
                board.setContents(StringSelection(""), null)
                lastCopied = null
            }
        }
    }

    /** Called on lock and at shutdown. */
    fun clearOurs() = lastCopied?.let { clearIfStillOurs(it) }
}

/**
 * Opens an attachment in whatever desktop application handles its type.
 *
 * Same trade as on Android, same honesty: SecureVault has no built-in viewer, and writing one
 * would put a hand-rolled PDF or image parser directly in front of the vault. The file is
 * decrypted to a private directory, handed over, and cleaned up aggressively.
 *
 * **The decrypted copy is real while the viewer holds it**, and the external application may copy,
 * cache or index it somewhere SecureVault cannot reach. That is not a risk this design removes;
 * it is one the UI states before opening anything.
 *
 * Preferred location is `$XDG_RUNTIME_DIR/securevault`, which on a normal session is a tmpfs owned
 * by the user and cleared at logout -- so a copy does not survive a reboot even if cleanup fails.
 * When that is unavailable the fallback is on disk, and [volatileStorage] reports which one is in
 * use so the UI can say so.
 */
class DesktopAttachmentViewer(private val store: AttachmentStore) {

    private val dir: File get() = Paths.secured(File(Paths.runtimeDir, "attachment-view"))

    val volatileStorage: Boolean get() = Paths.runtimeDirIsVolatile

    suspend fun open(session: VaultSession, ref: AttachmentRef): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                purge()
                val target = File(dir, ref.fileName.substringAfterLast('/').ifBlank { "attachment" })
                target.outputStream().use { out -> store.read(session, ref, out) }
                Paths.restrict(target)

                if (!Desktop.isDesktopSupported() ||
                    !Desktop.getDesktop().isSupported(Desktop.Action.OPEN)
                ) {
                    target.delete()
                    error("This desktop environment cannot open files from an application. Save the attachment instead.")
                }
                Desktop.getDesktop().open(target)
            }
        }

    /** Called before each open, on lock, and at startup. */
    fun purge() {
        runCatching { dir.deleteRecursively() }
    }
}

/**
 * Desktop auto-lock, measured from the last genuine user interaction.
 *
 * The rule is **idle time, not elapsed time**: the vault locks after the configured period during
 * which the user did nothing, and any real interaction restarts that period. Unlocking the vault
 * and then using it for an hour must never lock it.
 *
 * Rendering and recomposition are deliberately *not* activity. Compose recomposes for reasons that
 * have nothing to do with a person being present -- a countdown ticking, a flow emitting -- and
 * treating that as interaction would mean the vault never locks while the window is open. Only
 * pointer and key events reach [onInteraction].
 *
 * Three signals:
 *
 *  - **Inactivity**, the setting shared with Android, including "Never" (`Long.MAX_VALUE`).
 *  - **Window focus loss**, the desktop analogue of backgrounding, opt-in as on Android.
 *  - **Suspend and resume**, detected by comparing elapsed wall-clock against elapsed monotonic
 *    time. A machine that was asleep shows a large gap between them. This is a heuristic, not a
 *    system signal: it will also fire on a large clock correction, and it cannot detect a screen
 *    lock that did not involve suspend. Documented as a heuristic rather than dressed up as
 *    suspend detection.
 *
 * The clocks and the unlocked check are injected so the decision logic can be tested with fake
 * time instead of a test that genuinely sleeps for thirty seconds.
 */
class DesktopLockSignals(
    private val scope: CoroutineScope,
    private val lock: () -> Unit,
    private val settings: () -> LockSettings,
    private val isUnlocked: () -> Boolean = { true },
    private val wallClock: () -> Long = System::currentTimeMillis,
    private val monotonicMillis: () -> Long = { System.nanoTime() / 1_000_000 }
) {
    data class LockSettings(
        val autoLockMillis: Long,
        val lockOnFocusLoss: Boolean,
        val lockOnSuspend: Boolean
    )

    @Volatile private var lastInteraction = wallClock()
    @Volatile private var lastWall = wallClock()
    @Volatile private var lastMonotonic = monotonicMillis()
    @Volatile private var running = false

    /**
     * Called for every pointer and key event in the window. Cheap on purpose -- one volatile
     * write -- because it runs on every mouse move.
     */
    fun onInteraction() {
        lastInteraction = wallClock()
    }

    /** Called when the vault is unlocked, so the idle period starts from then rather than launch. */
    fun resetIdle() {
        lastInteraction = wallClock()
        lastWall = wallClock()
        lastMonotonic = monotonicMillis()
    }

    fun onFocusLost() {
        if (settings().lockOnFocusLoss && isUnlocked()) lock()
    }

    /** Milliseconds since the last interaction. Exposed for tests and diagnostics. */
    fun idleMillis(): Long = wallClock() - lastInteraction

    /**
     * One evaluation step. Separated from the loop so tests can drive it with a fake clock.
     *
     * @return true if it locked.
     */
    fun tick(): Boolean {
        val wall = wallClock()
        val monotonic = monotonicMillis()
        val wallDelta = wall - lastWall
        val monotonicDelta = monotonic - lastMonotonic
        lastWall = wall
        lastMonotonic = monotonic

        // Nothing to lock. Still advances the clocks above so a long locked period is not
        // mistaken for a suspend the moment the vault is opened again.
        if (!isUnlocked()) {
            lastInteraction = wall
            return false
        }

        val current = settings()

        // Wall clock ran far ahead of monotonic time: the machine was almost certainly asleep.
        if (current.lockOnSuspend && abs(wallDelta - monotonicDelta) > SUSPEND_GAP_MILLIS) {
            lock()
            return true
        }

        val timeout = current.autoLockMillis
        // "Never" is Long.MAX_VALUE. Compared explicitly rather than by arithmetic, which would
        // overflow.
        if (timeout == Long.MAX_VALUE) return false

        if (wall - lastInteraction >= timeout) {
            lock()
            return true
        }
        return false
    }

    fun start() {
        if (running) return
        running = true
        resetIdle()
        scope.launch {
            while (running) {
                delay(TICK_MILLIS)
                tick()
            }
        }
    }

    fun stop() {
        running = false
    }

    private companion object {
        const val TICK_MILLIS = 1_000L
        const val SUSPEND_GAP_MILLIS = 10_000L
    }
}
