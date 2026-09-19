package app.securevault.platform

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

enum class CopyKind(val label: String) {
    PASSWORD("Password"), USERNAME("Username"), OTP("One-time code"),
    CARD_NUMBER("Card number"), CVV("Security code"), OTHER("Value")
}

/**
 * Copying a secret to the clipboard, with the exposure kept short.
 *
 * Android 13 and later are told the clip is sensitive, which stops the system preview from showing
 * the value on screen and keeps it out of clipboard history. The clip is then cleared after the
 * configured delay.
 *
 * The clipboard is a shared surface; while a secret is on it, any app with focus can read it. That
 * is a property of the platform, not something this app can fix, so the timeout defaults to 30
 * seconds and the UI says what it is doing.
 */
class SecureClipboard(
    private val context: Context,
    private val scope: CoroutineScope
) {
    private val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private var clearJob: Job? = null

    fun copy(value: String, kind: CopyKind, clearAfterSeconds: Int = 30): String {
        val clip = ClipData.newPlainText(kind.label, value).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        manager.setPrimaryClip(clip)
        scheduleClear(value, clearAfterSeconds)
        return if (clearAfterSeconds > 0) {
            "${kind.label} copied. Clipboard clears in ${clearAfterSeconds}s."
        } else {
            "${kind.label} copied."
        }
    }

    private fun scheduleClear(copiedValue: String, seconds: Int) {
        clearJob?.cancel()
        if (seconds <= 0) return
        clearJob = scope.launch {
            delay(seconds * 1000L)
            clearIfStillOurs(copiedValue)
        }
    }

    /** Only clears if our value is still there, so we never wipe something the user copied after. */
    private fun clearIfStillOurs(copiedValue: String) {
        val current = manager.primaryClip?.getItemAt(0)?.text?.toString()
        if (current != copiedValue) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            manager.clearPrimaryClip()
        } else {
            manager.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }

    fun clearNow() {
        clearJob?.cancel()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) manager.clearPrimaryClip()
        else manager.setPrimaryClip(ClipData.newPlainText("", ""))
    }
}
