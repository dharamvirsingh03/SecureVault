package app.securevault.desktop.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.WindowState
import app.securevault.desktop.LocalAppState
import app.securevault.desktop.UnlockState

enum class Section(val label: String, val icon: ImageVector) {
    VAULT("Vault", Icons.Filled.Lock),
    GENERATOR("Generator", Icons.Filled.Autorenew),
    SECURITY("Security", Icons.Filled.Shield),
    DATA("Backup & data", Icons.Filled.Storage),
    SETTINGS("Settings", Icons.Filled.Settings)
}

/**
 * The application shell.
 *
 * Desktop layout rather than a stretched phone: a permanent left sidebar for navigation, a wide
 * content pane, and a master-detail split inside the vault. Nothing here is a scaled-up mobile
 * screen -- the information architecture is shared with Android, the layout is not.
 */
@Composable
fun AppRoot(windowState: WindowState) {
    val state = LocalAppState.current
    // Every pointer event in the window resets the idle timer: moves, clicks, drags, scroll.
    // Observed on the Initial pass and never consumed, so nothing below behaves differently --
    // this only watches. Keyboard input is picked up by the window's onKeyEvent in Main.kt.
    //
    // Deliberately NOT tied to recomposition. Compose recomposes for a countdown ticking or a
    // flow emitting, none of which means a person is present, and treating that as activity
    // would stop the vault ever locking while the window is open.
    val activityModifier = Modifier.pointerInput(Unit) {
        awaitPointerEventScope {
            while (true) {
                awaitPointerEvent(PointerEventPass.Initial)
                state.onInteraction()
            }
        }
    }
    val unlockState by state.unlockState.collectAsState()
    val message by state.message.collectAsState()
    val busy by state.busy.collectAsState()
    val recoveryCode by state.recoveryCode.collectAsState()
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(message) {
        message?.let { snackbar.showSnackbar(it); state.consumeMessage() }
    }

    Box(Modifier.fillMaxSize().then(activityModifier)) {
    when (val current = unlockState) {
        UnlockState.NoVault -> SetupScreen()
        is UnlockState.Corrupt -> CorruptScreen(current.message)
        is UnlockState.Locked, UnlockState.Unlocking -> UnlockScreen(
            error = (current as? UnlockState.Locked)?.error,
            lockoutSeconds = (current as? UnlockState.Locked)?.lockoutSeconds ?: 0,
            busy = current is UnlockState.Unlocking
        )
        UnlockState.Unlocked -> UnlockedShell(snackbar, busy)
    }

    recoveryCode?.let { code -> RecoveryCodeDialog(code) { state.consumeRecoveryCode() } }
    }
}

@Composable
private fun UnlockedShell(snackbar: SnackbarHostState, busy: String?) {
    val state = LocalAppState.current
    var section by remember { mutableStateOf(Section.VAULT) }

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { padding ->
        Row(Modifier.fillMaxSize().padding(padding)) {
            Sidebar(section) { section = it }
            VerticalDivider()
            Column(Modifier.weight(1f).fillMaxHeight()) {
                if (busy != null) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(
                        busy,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                    )
                }
                when (section) {
                    Section.VAULT -> VaultScreen()
                    Section.GENERATOR -> GeneratorScreen()
                    Section.SECURITY -> SecurityScreen()
                    Section.DATA -> DataScreen()
                    Section.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}

@Composable
private fun Sidebar(selected: Section, onSelect: (Section) -> Unit) {
    val state = LocalAppState.current
    Column(
        Modifier.width(220.dp).fillMaxHeight()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(vertical = 16.dp)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Image(
                painterResource("icons/securevault-64.png"),
                contentDescription = null,
                modifier = Modifier.size(24.dp)
            )
            Spacer(Modifier.width(10.dp))
            Text("SecureVault", style = MaterialTheme.typography.titleMedium)
        }
        Spacer(Modifier.height(12.dp))

        Section.entries.forEach { item ->
            val active = item == selected
            Row(
                Modifier.fillMaxWidth()
                    .background(
                        if (active) MaterialTheme.colorScheme.secondaryContainer else androidx.compose.ui.graphics.Color.Transparent
                    )
                    .clickable { onSelect(item) }
                    .padding(horizontal = 20.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(item.icon, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(12.dp))
                Text(item.label, style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(Modifier.weight(1f))
        HorizontalDivider()
        Row(
            Modifier.fillMaxWidth().clickable { state.lock() }.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(12.dp))
            Column {
                Text("Lock now", style = MaterialTheme.typography.bodyMedium)
                Text("Ctrl+L", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/**
 * Shown when a vault exists but cannot be read.
 *
 * Offers no way to start over, exactly as on Android. The safe moves from here are a backup or a
 * recovery code, and a button that quietly replaces recoverable data would be the worst thing on
 * the screen.
 */
@Composable
private fun CorruptScreen(message: String) {
    Box(Modifier.fillMaxSize().padding(48.dp), contentAlignment = Alignment.Center) {
        Column(Modifier.widthIn(max = 640.dp)) {
            Text("Vault cannot be opened", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(16.dp))
            Text(message, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(16.dp))
            WarningCard(
                "Do not delete SecureVault's data directory. The encrypted items are still there."
            )
        }
    }
}

@Composable
fun WarningCard(text: String, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.errorContainer,
        shape = MaterialTheme.shapes.medium
    ) {
        Text(
            text,
            Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onErrorContainer
        )
    }
}

@Composable
fun InfoCard(text: String, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium
    ) {
        Text(
            text,
            Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 24.dp, top = 20.dp, bottom = 6.dp)
    )
}

@Composable
fun InfoLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(
            label, Modifier.width(200.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
