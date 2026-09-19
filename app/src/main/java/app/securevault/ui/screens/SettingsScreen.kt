package app.securevault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import app.securevault.core.vault.AppTheme
import app.securevault.core.vault.VaultSettings
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.components.WarningCard

/**
 * Settings, grouped the way someone worried about their vault would look for things.
 *
 * Anything destructive or irreversible lives behind its own screen rather than a switch here, so
 * nothing important can be triggered by a mis-tap while scrolling.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    viewModel: VaultViewModel,
    onChangePassword: () -> Unit,
    onRecovery: () -> Unit,
    onEmergencyKit: () -> Unit,
    onDestroyVault: () -> Unit,
    onImport: () -> Unit,
    onExport: () -> Unit,
    onBackup: () -> Unit,
    onRestore: () -> Unit
) {
    val settings by viewModel.settings.collectAsState()
    val context = LocalContext.current

    var confirmNeverClipboard by remember { mutableStateOf(false) }

    fun update(block: (VaultSettings) -> VaultSettings) = viewModel.updateSettings(block(settings))

    Scaffold(topBar = { TopAppBar(title = { Text("Settings") }) }) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
        ) {
            // ---- security ----------------------------------------------------------------
            SectionHeader("Security")

            NavRow("Change master password", "Rewraps your vault key. Instant, and safe to do often.", onChangePassword)
            NavRow(
                "Recovery code",
                if (viewModel.hasRecovery()) "On — a second way into this vault" else "Off",
                onRecovery
            )
            NavRow("Emergency recovery kit", "A printable page with no passwords on it", onEmergencyKit)

            // The setting and reality can disagree: enrolling a new fingerprint or removing the
            // device lock invalidates the Keystore key, and the app only learns that when it next
            // tries to use it. Showing what is actually true beats showing what was last chosen.
            val biometricActuallyWorking = viewModel.isBiometricConfigured()
            SwitchRow(
                "Biometric unlock",
                "Unlocks a key held in secure hardware. Your master password is never stored.",
                settings.biometricUnlockEnabled && biometricActuallyWorking
            ) { enabled ->
                if (!enabled) {
                    viewModel.disableBiometric()
                } else {
                    (context as? FragmentActivity)?.let { activity ->
                        promptBiometricEnrolment(activity, viewModel)
                    }
                }
            }
            if (settings.biometricUnlockEnabled && !biometricActuallyWorking) {
                Column(Modifier.padding(horizontal = 20.dp)) {
                    WarningCard(
                        "Biometric credentials changed on this device. For security, SecureVault " +
                            "requires your master password before biometric unlock can be " +
                            "enabled again.\n\n" +
                            "This is the Keystore working as intended: the key that wrapped your " +
                            "vault key was tied to the biometrics enrolled at the time, and " +
                            "changing them destroyed it. Your vault is untouched and your master " +
                            "password still opens it."
                    )
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = {
                        (context as? FragmentActivity)?.let { promptBiometricEnrolment(it, viewModel) }
                    }) { Text("Set up biometric unlock again") }
                }
            }

            SwitchRow(
                "Screenshot protection",
                "Blocks screenshots, screen recording and the app's preview in recents.",
                settings.screenshotProtection
            ) { update { s -> s.copy(screenshotProtection = it) } }

            SectionHeader("Auto-lock")
            FlowRow(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // The map is label -> millis, not the other way round.
                VaultSettings.AUTO_LOCK_CHOICES.forEach { (label, millis) ->
                    FilterChip(
                        selected = settings.autoLockMillis == millis,
                        onClick = { update { it.copy(autoLockMillis = millis) } },
                        label = { Text(label) }
                    )
                }
            }
            SwitchRow("Lock when the app goes to the background", null, settings.lockOnBackground) {
                update { s -> s.copy(lockOnBackground = it) }
            }
            SwitchRow("Lock when the screen turns off", null, settings.lockOnScreenOff) {
                update { s -> s.copy(lockOnScreenOff = it) }
            }
            SwitchRow(
                "Lock when the device locks",
                "Checked once a second against the system lock state.",
                settings.lockOnDeviceLock
            ) { update { s -> s.copy(lockOnDeviceLock = it) } }

            SectionHeader("Clipboard")
            Column(Modifier.padding(horizontal = 20.dp)) {
                Text(
                    "While a secret is on the clipboard, any app in the foreground can read it. " +
                        "That is the platform, not something SecureVault can fix, and it is why " +
                        "this timeout exists.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Discrete choices rather than a slider: this is a security setting, and a
                    // value someone landed on by dragging is not a decision they made.
                    CLIPBOARD_CHOICES.forEach { (seconds, label) ->
                        FilterChip(
                            selected = settings.clipboardClearSeconds == seconds,
                            onClick = {
                                if (seconds == 0) confirmNeverClipboard = true
                                else update { it.copy(clipboardClearSeconds = seconds) }
                            },
                            label = { Text(label) }
                        )
                    }
                }
                if (settings.clipboardClearSeconds == 0) {
                    Spacer(Modifier.height(8.dp))
                    WarningCard(
                        "Sensitive copied values will remain in the system clipboard until " +
                            "another application replaces them. This is less secure."
                    )
                }
            }
            SwitchRow(
                "Copy one-time codes automatically",
                "Off by default. A code copied without being asked for is a code nobody is watching.",
                settings.autoCopyOtpOnOpen
            ) { update { s -> s.copy(autoCopyOtpOnOpen = it) } }

            SectionHeader("Failed attempts")
            Column(Modifier.padding(horizontal = 20.dp)) {
                Text(
                    if (settings.wipeAfterFailures == 0) {
                        "Delays only. The vault is never wiped automatically."
                    } else {
                        "Vault is destroyed after ${settings.wipeAfterFailures} wrong passwords."
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(0, 10, 20, 50).forEach { count ->
                        FilterChip(
                            selected = settings.wipeAfterFailures == count,
                            onClick = { update { it.copy(wipeAfterFailures = count) } },
                            label = { Text(if (count == 0) "Never wipe" else "$count") }
                        )
                    }
                }
                if (settings.wipeAfterFailures > 0) {
                    Spacer(Modifier.height(8.dp))
                    InfoCard(
                        "Wiping deletes the keys, which makes the data unrecoverable. It does not " +
                            "shred the flash storage, and it does not touch backups you already made."
                    )
                }
            }

            // ---- vault -------------------------------------------------------------------
            SectionHeader("Vault")
            NavRow("Import from CSV", "Bitwarden, 1Password, LastPass, Chrome, KeePass or generic", onImport)
            NavRow("Export to CSV", "Plaintext. Behind a confirmation.", onExport)
            NavRow("Create encrypted backup", "A .securevault file only your password opens", onBackup)
            NavRow("Restore a backup", "Open and verify a backup file", onRestore)

            // ---- generator ---------------------------------------------------------------
            SectionHeader("Generator defaults")
            Column(Modifier.padding(horizontal = 20.dp)) {
                Text("Password length: ${settings.defaultPasswordLength}", style = MaterialTheme.typography.bodyMedium)
                Slider(
                    value = settings.defaultPasswordLength.toFloat(),
                    onValueChange = { update { s -> s.copy(defaultPasswordLength = it.toInt()) } },
                    valueRange = 8f..64f,
                    steps = 55
                )
                Text("Passphrase words: ${settings.defaultPassphraseWords}", style = MaterialTheme.typography.bodyMedium)
                Slider(
                    value = settings.defaultPassphraseWords.toFloat(),
                    onValueChange = { update { s -> s.copy(defaultPassphraseWords = it.toInt()) } },
                    valueRange = 3f..10f,
                    steps = 6
                )
            }

            // ---- appearance ----------------------------------------------------------------
            SectionHeader("Appearance")
            FlowRow(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                AppTheme.entries.forEach { theme ->
                    FilterChip(
                        selected = settings.theme == theme,
                        onClick = { update { it.copy(theme = theme) } },
                        label = { Text(theme.name.lowercase().replaceFirstChar { c -> c.uppercase() }) }
                    )
                }
            }

            // ---- privacy -------------------------------------------------------------------
            SectionHeader("Privacy")
            InfoLine("Analytics", "None")
            InfoLine("Crash reporting", "None")
            InfoLine("Account", "None")
            InfoLine("Server", "None")
            InfoLine("Network use", if (settings.breachCheckEnabled) "Breach check only" else "None")
            Spacer(Modifier.height(8.dp))
            InfoCard(
                "There is no analytics SDK to disable, because none is present. The app makes one " +
                    "kind of outbound request — the breach check on the Security tab — and it is " +
                    "off until you turn it on.",
                Modifier.padding(horizontal = 20.dp)
            )

            SectionHeader("This vault")
            InfoLine("Key derivation", viewModel.kdfDescription())
            viewModel.vaultMetadata()?.let {
                InfoLine("Format version", "${it.formatVersion}")
                InfoLine("Vault created", formatWhen(it.createdAt))
            }

            // ---- danger --------------------------------------------------------------------
            SectionHeader("Danger zone")
            ListItem(
                headlineContent = {
                    Text("Delete vault", color = MaterialTheme.colorScheme.error)
                },
                supportingContent = { Text("Permanently destroys the local encrypted vault") },
                trailingContent = { Icon(Icons.Filled.ChevronRight, contentDescription = null) },
                modifier = Modifier.fillMaxWidth().clickable(onClick = onDestroyVault)
            )

            Spacer(Modifier.height(48.dp))
        }
    }

    if (confirmNeverClipboard) {
        AlertDialog(
            onDismissRequest = { confirmNeverClipboard = false },
            title = { Text("Never clear the clipboard?") },
            text = {
                Text(
                    "Sensitive copied values will remain in the system clipboard until another " +
                        "application replaces them. Any app that comes to the foreground can " +
                        "read them, and some keyboards and clipboard managers keep a history. " +
                        "This is less secure."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.updateSettings(
                        viewModel.settings.value.copy(clipboardClearSeconds = 0)
                    )
                    confirmNeverClipboard = false
                }) { Text("Turn clearing off") }
            },
            dismissButton = {
                TextButton(onClick = { confirmNeverClipboard = false }) { Text("Keep clearing") }
            }
        )
    }
}

@Composable
private fun NavRow(title: String, subtitle: String?, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = subtitle?.let { { Text(it) } },
        trailingContent = { Icon(Icons.Filled.ChevronRight, contentDescription = null) },
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    )
}

@Composable
private fun SwitchRow(
    title: String,
    subtitle: String?,
    checked: Boolean,
    onChange: (Boolean) -> Unit
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            subtitle?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
    HorizontalDivider(Modifier.padding(horizontal = 20.dp))
}

/**
 * Biometric enrolment.
 *
 * BiometricPrompt returns an authenticated Cipher; only then is the vault key wrapped under the
 * Keystore key. The master password is never involved, and enrolling a new fingerprint later
 * invalidates the key and switches this back off — which is correct behaviour, not a bug.
 */
private fun promptBiometricEnrolment(activity: FragmentActivity, viewModel: VaultViewModel) {
    val cipher = runCatching { viewModel.biometricEncryptCipher() }.getOrNull() ?: return
    val prompt = androidx.biometric.BiometricPrompt(
        activity,
        androidx.core.content.ContextCompat.getMainExecutor(activity),
        object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(
                result: androidx.biometric.BiometricPrompt.AuthenticationResult
            ) {
                result.cryptoObject?.cipher?.let { viewModel.enableBiometric(it) }
            }
        }
    )
    prompt.authenticate(
        androidx.biometric.BiometricPrompt.PromptInfo.Builder()
            .setTitle("Turn on biometric unlock")
            .setSubtitle("SecureVault will wrap your vault key with a key held in secure hardware")
            .setNegativeButtonText("Cancel")
            .build(),
        androidx.biometric.BiometricPrompt.CryptoObject(cipher)
    )
}

/** 15 / 30 / 60 seconds, or never. 30 is the default. */
private val CLIPBOARD_CHOICES = listOf(
    15 to "15 seconds",
    30 to "30 seconds",
    60 to "60 seconds",
    0 to "Never"
)
