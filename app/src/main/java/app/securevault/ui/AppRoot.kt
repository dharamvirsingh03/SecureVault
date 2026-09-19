package app.securevault.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.securevault.platform.SecureScreen
import app.securevault.ui.nav.Route
import app.securevault.ui.nav.rememberNavigator
import app.securevault.ui.screens.BackupScreen
import app.securevault.ui.screens.ChangePasswordScreen
import app.securevault.ui.screens.DestroyVaultScreen
import app.securevault.ui.screens.EmergencyKitScreen
import app.securevault.ui.screens.ExportScreen
import app.securevault.ui.screens.FolderContentsScreen
import app.securevault.ui.screens.FoldersScreen
import app.securevault.ui.screens.GeneratorScreen
import app.securevault.ui.screens.ImportWizardScreen
import app.securevault.ui.screens.ItemDetailScreen
import app.securevault.ui.screens.ItemEditorScreen
import app.securevault.ui.screens.RecoveryCodeDialog
import app.securevault.ui.screens.RecoveryScreen
import app.securevault.ui.screens.RestoreScreen
import app.securevault.ui.screens.SecurityIssuesScreen
import app.securevault.ui.screens.SecurityScreen
import app.securevault.ui.screens.SettingsScreen
import app.securevault.ui.screens.SetupScreen
import app.securevault.ui.screens.TagsScreen
import app.securevault.ui.screens.UnlockScreen
import app.securevault.ui.screens.VaultScreen

/**
 * The root of the app.
 *
 * [SecureScreen] is applied here rather than per screen: every screen in this app can surface
 * something worth hiding, and a per-screen list is a list somebody eventually forgets to update.
 */
@Composable
fun AppRoot(viewModel: VaultViewModel) {
    val unlockState by viewModel.unlockState.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val message by viewModel.message.collectAsState()
    val recoveryCode by viewModel.recoveryCodeToShow.collectAsState()

    val navigator = rememberNavigator()
    val snackbarHost = remember { SnackbarHostState() }

    SecureScreen(enabled = settings.screenshotProtection)

    LaunchedEffect(message) {
        message?.let {
            snackbarHost.showSnackbar(it)
            viewModel.consumeMessage()
        }
    }

    // Locking clears the back stack. Resuming into a detail screen after a lock would briefly
    // render an empty shell where content used to be.
    LaunchedEffect(unlockState) {
        if (unlockState !is UnlockState.Unlocked) navigator.reset()
    }

    // Clean up anything an interrupted restore or a closed attachment viewer left behind. Cheap,
    // and it means a decrypted temporary file cannot outlive a process restart.
    LaunchedEffect(Unit) {
        viewModel.recoverInterruptedRestore()
        viewModel.purgeViewedAttachments()
    }

    when (val state = unlockState) {
        UnlockState.NoVault -> SetupScreen(viewModel)
        // Corrupt is routed away from SetupScreen deliberately: the one thing a user must not be
        // offered here is a fresh vault on top of data that may still be recoverable.
        is UnlockState.Corrupt -> CorruptVaultScreen(state.message)
        is UnlockState.Locked, UnlockState.Unlocking -> UnlockScreen(viewModel)
        UnlockState.Unlocked -> UnlockedApp(viewModel, navigator, snackbarHost)
    }

    recoveryCode?.let { code ->
        RecoveryCodeDialog(code = code, onDismiss = { viewModel.consumeRecoveryCode() })
    }
}

@Composable
private fun UnlockedApp(
    viewModel: VaultViewModel,
    navigator: app.securevault.ui.nav.Navigator,
    snackbarHost: SnackbarHostState
) {
    BackHandler(enabled = navigator.canGoBack) { navigator.pop() }

    val current = navigator.current
    val showBottomBar = current is Route.Tab

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHost) },
        bottomBar = {
            if (showBottomBar) {
                NavigationBar {
                    listOf(
                        Route.Vault to ("Vault" to Icons.Filled.Lock),
                        Route.Generator to ("Generator" to Icons.Filled.Refresh),
                        Route.Security to ("Security" to Icons.Filled.Shield),
                        Route.Settings to ("Settings" to Icons.Filled.Settings)
                    ).forEach { (route, meta) ->
                        val (label, icon) = meta
                        NavigationBarItem(
                            selected = navigator.currentTab == route,
                            onClick = { navigator.selectTab(route) },
                            icon = { Icon(icon, contentDescription = label) },
                            label = { Text(label) }
                        )
                    }
                }
            }
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            Destination(viewModel, navigator)
        }
    }
}

@Composable
private fun Destination(viewModel: VaultViewModel, navigator: app.securevault.ui.nav.Navigator) {
    when (val route = navigator.current) {
        Route.Vault -> VaultScreen(
            viewModel = viewModel,
            onOpenItem = { navigator.push(Route.ItemDetail(it.id)) },
            onOpenFolders = { navigator.push(Route.Folders) },
            onOpenTags = { navigator.push(Route.Tags) },
            onOpenFolder = { navigator.push(Route.FolderContents(it)) },
            onCreate = { type -> navigator.push(Route.ItemEditor(null, type)) }
        )

        Route.Generator -> GeneratorScreen(
            viewModel = viewModel,
            onUseInLogin = {
                // The password travels in ViewModel memory, not in this route.
                navigator.push(Route.ItemEditor(null, app.securevault.core.model.ItemType.LOGIN))
            }
        )

        Route.Security -> SecurityScreen(
            viewModel = viewModel,
            onOpenCategory = { navigator.push(Route.SecurityIssues(it)) }
        )

        Route.Settings -> SettingsScreen(
            viewModel = viewModel,
            onChangePassword = { navigator.push(Route.ChangePassword) },
            onRecovery = { navigator.push(Route.Recovery) },
            onEmergencyKit = { navigator.push(Route.EmergencyKit) },
            onDestroyVault = { navigator.push(Route.DestroyVault) },
            onImport = { navigator.push(Route.Import) },
            onExport = { navigator.push(Route.Export) },
            onBackup = { navigator.push(Route.Backup) },
            onRestore = { navigator.push(Route.Restore) }
        )

        is Route.ItemDetail -> ItemDetailScreen(
            viewModel = viewModel,
            itemId = route.itemId,
            onBack = { navigator.pop() },
            onEdit = { navigator.push(Route.ItemEditor(it.id, it.type)) }
        )

        is Route.ItemEditor -> ItemEditorScreen(
            viewModel = viewModel,
            existingId = route.itemId,
            type = route.type,
            onClose = { navigator.pop() }
        )

        Route.Folders -> FoldersScreen(
            viewModel = viewModel,
            onBack = { navigator.pop() },
            onOpenFolder = { navigator.push(Route.FolderContents(it)) }
        )

        is Route.FolderContents -> FolderContentsScreen(
            viewModel = viewModel,
            folderId = route.folderId,
            onBack = { navigator.pop() },
            onOpenItem = { navigator.push(Route.ItemDetail(it.id)) }
        )

        Route.Tags -> TagsScreen(
            viewModel = viewModel,
            onBack = { navigator.pop() },
            onFilterByTag = { tag ->
                viewModel.setFilter { it.copy(tag = tag, query = "") }
                navigator.selectTab(Route.Vault)
            }
        )

        is Route.SecurityIssues -> SecurityIssuesScreen(
            viewModel = viewModel,
            category = route.category,
            onBack = { navigator.pop() },
            onOpenItem = { navigator.push(Route.ItemDetail(it.id)) }
        )

        Route.Import -> ImportWizardScreen(viewModel) { navigator.pop() }
        Route.Export -> ExportScreen(viewModel) { navigator.pop() }
        Route.Backup -> BackupScreen(viewModel) { navigator.pop() }
        Route.Restore -> RestoreScreen(
            viewModel = viewModel,
            onBack = { navigator.pop() },
            // The restored vault is locked; returning to the root lands on the unlock screen,
            // which is exactly where a just-restored vault should put someone.
            onOpenRestoredVault = { navigator.reset() }
        )
        Route.Recovery -> RecoveryScreen(viewModel) { navigator.pop() }
        Route.EmergencyKit -> EmergencyKitScreen(viewModel) { navigator.pop() }
        Route.ChangePassword -> ChangePasswordScreen(viewModel) { navigator.pop() }
        Route.DestroyVault -> DestroyVaultScreen(
            viewModel = viewModel,
            onBack = { navigator.pop() },
            onDestroyed = { navigator.reset() }
        )
    }
}

/**
 * Shown when a vault exists but cannot be read.
 *
 * Deliberately offers no "start over" button. The safe actions from here are restoring a backup or
 * using a recovery code, and both of those need the vault to be openable first -- so this says so
 * rather than presenting a destructive shortcut as the only thing to tap.
 */
@Composable
private fun CorruptVaultScreen(message: String) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(28.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text("Vault cannot be opened", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(16.dp))
            Text(message, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(16.dp))
            Text(
                "Do not reinstall or clear app data: that would remove the encrypted items that " +
                    "are still on this device.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}
