package app.securevault.desktop

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowPosition
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import app.securevault.core.vault.AppTheme
import app.securevault.desktop.ui.AppRoot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

val LocalAppState = staticCompositionLocalOf<AppState> { error("AppState not provided") }
val LocalServices = staticCompositionLocalOf<Services> { error("Services not provided") }

/**
 * SecureVault for Ubuntu.
 *
 * A single resizable window. Global shortcuts are handled here so they work from any screen:
 * Ctrl+L locks immediately, Ctrl+F focuses search, Ctrl+N starts a new item, Escape closes a
 * dialog. Ctrl+L is deliberate -- on a password manager, "lock now" should never be more than one
 * keystroke away, and it is also the reflex most people already have from screen-lock shortcuts.
 */
fun main() = application {
    val scope = remember { CoroutineScope(SupervisorJob() + Dispatchers.Default) }
    val services = remember { Services(scope) }
    val state = remember { AppState(services, scope) }
    val settings by state.settings.collectAsState()

    val windowState = rememberWindowState(
        width = 1180.dp, height = 780.dp, position = WindowPosition(androidx.compose.ui.Alignment.Center)
    )

    Window(
        onCloseRequest = {
            // Locking on exit is not optional: leaving a decrypted session behind because a
            // window closed would defeat every auto-lock setting above it.
            state.lock()
            services.close()
            scope.cancel()
            exitApplication()
        },
        state = windowState,
        title = "SecureVault",
        // Window and taskbar icon. jpackage handles the launcher and .desktop entry separately,
        // from iconFile in desktop/build.gradle.kts -- both point at the same artwork.
        icon = painterResource("icons/securevault-256.png"),
        onKeyEvent = { event ->
            // Key events are the other half of user activity; pointer events are observed at the
            // root of AppRoot.
            state.onInteraction()
            if (event.type == KeyEventType.KeyDown && event.isCtrlPressed && event.key == Key.L) {
                state.lock(); true
            } else false
        }
    ) {
        val dark = when (settings.theme) {
            AppTheme.DARK -> true
            AppTheme.LIGHT -> false
            AppTheme.SYSTEM -> isSystemDark()
        }
        MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                CompositionLocalProvider(
                    LocalAppState provides state,
                    LocalServices provides services
                ) {
                    AppRoot(windowState)
                }
            }
        }
    }
}

/**
 * Best-effort dark-mode detection.
 *
 * There is no portable way to read a desktop environment's colour preference from a plain JVM
 * process, so this reads the GNOME setting via gsettings and falls back to light. Getting it wrong
 * is a cosmetic problem, which is why a heuristic is acceptable here and is not acceptable
 * anywhere in the lock or crypto paths.
 */
private fun isSystemDark(): Boolean = runCatching {
    val process = ProcessBuilder("gsettings", "get", "org.gnome.desktop.interface", "color-scheme")
        .redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().use { it.readText() }
    process.waitFor()
    output.contains("dark", ignoreCase = true)
}.getOrDefault(false)

// Slate and teal, with amber reserved for security warnings -- the same intent as the Android
// theme, adapted to a desktop window rather than copied pixel for pixel.
private val LightScheme = lightColorScheme(
    primary = Color(0xFF1F6F66),
    onPrimary = Color.White,
    secondaryContainer = Color(0xFFD5E8E4),
    onSecondaryContainer = Color(0xFF10302C),
    error = Color(0xFF8C4A00),
    errorContainer = Color(0xFFFFE2C2),
    onErrorContainer = Color(0xFF3B2000),
    background = Color(0xFFF7F9F8),
    surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFE8EDEB)
)

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF6FD3C6),
    onPrimary = Color(0xFF00352F),
    secondaryContainer = Color(0xFF1E4741),
    onSecondaryContainer = Color(0xFFCDEDE7),
    error = Color(0xFFFFB77C),
    errorContainer = Color(0xFF5A3100),
    onErrorContainer = Color(0xFFFFE2C2),
    background = Color(0xFF0F1513),
    surface = Color(0xFF161D1B),
    surfaceVariant = Color(0xFF2A3331)
)
