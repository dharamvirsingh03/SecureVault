package app.securevault.platform

import android.app.Activity
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext

/**
 * Marks a screen as not screenshot-able and not screen-recordable, and keeps it out of the
 * recent-apps thumbnail.
 *
 * Applied by default to every screen that can show a secret. FLAG_SECURE is a strong signal to the
 * platform but not a defence against a compromised OS or a camera pointed at the phone, so the
 * setting is documented as a hardening measure rather than a guarantee.
 */
@Composable
fun SecureScreen(enabled: Boolean = true) {
    val context = LocalContext.current
    DisposableEffect(enabled) {
        val activity = context.findActivity()
        if (enabled && activity != null) {
            activity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }
        onDispose {
            if (enabled) activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

fun android.content.Context.findActivity(): Activity? {
    var context = this
    while (context is android.content.ContextWrapper) {
        if (context is Activity) return context
        context = context.baseContext
    }
    return null
}
