package app.securevault.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import app.securevault.core.vault.AppTheme

/**
 * Palette notes.
 *
 * A password manager is a tool people open under mild stress -- locked out, mid-checkout, chasing
 * a code that expires in nine seconds. The colour work is therefore load-bearing rather than
 * decorative: a deep slate-teal primary that reads as "secure" without the padlock-grey cliche,
 * and a single warm amber reserved exclusively for security warnings, so amber anywhere in the app
 * always means the same thing.
 */
private val Ink = Color(0xFF10211F)
private val Teal = Color(0xFF186660)
private val TealLight = Color(0xFF6FD3C6)
private val Amber = Color(0xFFB26B00)
private val AmberLight = Color(0xFFFFB95C)
private val Danger = Color(0xFFA5301C)
private val DangerLight = Color(0xFFFF9E8C)
private val Paper = Color(0xFFF7F9F8)

private val LightColors = lightColorScheme(
    primary = Teal,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB9EFE6),
    onPrimaryContainer = Color(0xFF00201C),
    secondary = Color(0xFF4A635F),
    tertiary = Amber,
    onTertiary = Color.White,
    error = Danger,
    background = Paper,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = Color(0xFFDBE5E2),
    outline = Color(0xFF6F7977)
)

private val DarkColors = darkColorScheme(
    primary = TealLight,
    onPrimary = Color(0xFF00352F),
    primaryContainer = Color(0xFF004D46),
    onPrimaryContainer = Color(0xFF8BEFE2),
    secondary = Color(0xFFB1CCC7),
    tertiary = AmberLight,
    onTertiary = Color(0xFF452B00),
    error = DangerLight,
    background = Color(0xFF0D1514),
    onBackground = Color(0xFFDDE4E2),
    surface = Color(0xFF121D1B),
    onSurface = Color(0xFFDDE4E2),
    surfaceVariant = Color(0xFF3F4947),
    outline = Color(0xFF899391)
)

/**
 * Secrets are set in monospace everywhere they appear. Reading a password or a one-time code off a
 * screen is transcription, not prose: fixed advance widths keep 0/O and 1/l apart and keep a code
 * from reflowing as its digits change.
 */
val SecretTextStyle = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontWeight = FontWeight.Medium,
    fontSize = 18.sp,
    letterSpacing = 1.sp
)

val OtpTextStyle = SecretTextStyle.copy(fontSize = 30.sp, letterSpacing = 3.sp)

private val AppTypography = Typography()

@Composable
fun SecureVaultTheme(
    theme: AppTheme = AppTheme.SYSTEM,
    content: @Composable () -> Unit
) {
    val dark = when (theme) {
        AppTheme.SYSTEM -> isSystemInDarkTheme()
        AppTheme.LIGHT -> false
        AppTheme.DARK -> true
    }
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> DarkColors
        else -> LightColors
    }
    MaterialTheme(colorScheme = colors, typography = AppTypography, content = content)
}
