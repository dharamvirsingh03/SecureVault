package app.securevault.desktop.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.core.vault.AppTheme
import app.securevault.core.vault.VaultSettings
import app.securevault.desktop.*
import app.securevault.desktop.platform.ScreenCapture
import app.securevault.desktop.platform.SecureStorage
import app.securevault.feature.csv.DuplicateAction
import app.securevault.feature.csv.ExportSelection
import app.securevault.feature.generator.PassphraseGenerator
import app.securevault.feature.generator.PassphraseOptions
import app.securevault.feature.generator.PasswordGenerator
import app.securevault.feature.generator.PasswordOptions
import app.securevault.feature.generator.PasswordStrength
import app.securevault.feature.generator.WordLists
import kotlinx.coroutines.launch

@Composable
fun GeneratorScreen() {
    val state = LocalAppState.current
    val services = LocalServices.current
    val settings by state.settings.collectAsState()
    val wordList = remember { services.wordSource.words() }

    var passphraseMode by remember { mutableStateOf(false) }
    var length by remember { mutableStateOf(settings.defaultPasswordLength) }
    var wordCount by remember { mutableStateOf(settings.defaultPassphraseWords) }
    var separator by remember { mutableStateOf("-") }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var value by remember { mutableStateOf("") }

    fun regenerate() {
        value = if (passphraseMode) {
            PassphraseGenerator.generate(
                PassphraseOptions(
                    words = wordCount,
                    separator = separator,
                    capitalise = true,
                    includeNumber = true
                ),
                wordList
            )
        } else {
            PasswordGenerator.generate(
                PasswordOptions(
                    length = length, uppercase = upper, lowercase = lower,
                    numbers = digits, symbols = symbols
                )
            )
        }
    }
    LaunchedEffect(passphraseMode, length, wordCount, separator, upper, lower, digits, symbols) { regenerate() }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Password generator", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        SingleChoiceSegmentedButtonRow {
            SegmentedButton(!passphraseMode, { passphraseMode = false },
                SegmentedButtonDefaults.itemShape(0, 2)) { Text("Password") }
            SegmentedButton(passphraseMode, { passphraseMode = true },
                SegmentedButtonDefaults.itemShape(1, 2)) { Text("Passphrase") }
        }

        Spacer(Modifier.height(20.dp))
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.medium) {
            SelectionContainer {
                Text(
                    value, Modifier.padding(20.dp).fillMaxWidth(),
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        val strength = remember(value) { if (value.isEmpty()) null else PasswordStrength.evaluate(value) }
        strength?.let {
            LinearProgressIndicator({ it.score / 100f }, Modifier.fillMaxWidth())
            Text(
                "${it.label.name.replace('_', ' ').lowercase()} · ${it.entropyBits.toInt()} bits of entropy",
                style = MaterialTheme.typography.bodySmall
            )
        }

        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button({ regenerate() }) { Text("Generate") }
            OutlinedButton({ state.copy(value, "Password") }) { Text("Copy") }
            OutlinedButton({ state.stageGeneratedPassword(value) }) { Text("Use in a new login") }
        }
        Text(
            "\"Use in a new login\" hands the password to the editor in memory — it never travels " +
                "through a file, a setting or the clipboard.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 6.dp)
        )

        Spacer(Modifier.height(24.dp))
        if (passphraseMode) {
            Text("Words: $wordCount", style = MaterialTheme.typography.bodyMedium)
            Slider(wordCount.toFloat(), { wordCount = it.toInt() }, valueRange = 3f..10f, steps = 6)
            OutlinedTextField(separator, { separator = it.take(3) },
                label = { Text("Separator") }, singleLine = true, modifier = Modifier.width(160.dp))
            if (!WordLists.isFullDicewareList(wordList)) {
                Spacer(Modifier.height(10.dp))
                InfoCard(
                    "Using a small built-in word list of ${wordList.size} words, so the entropy above " +
                        "is lower than a full diceware list would give. Bundle the EFF large list " +
                        "for the full strength."
                )
            }
        } else {
            Text("Length: $length", style = MaterialTheme.typography.bodyMedium)
            Slider(length.toFloat(), { length = it.toInt() }, valueRange = 8f..64f, steps = 55)
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                ToggleRow("A-Z", upper) { upper = it }
                ToggleRow("a-z", lower) { lower = it }
                ToggleRow("0-9", digits) { digits = it }
                ToggleRow("!@#", symbols) { symbols = it }
            }
        }
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked, onChange)
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
fun SecurityScreen() {
    val state = LocalAppState.current
    val report by state.health.collectAsState()
    val settings by state.settings.collectAsState()
    val busy by state.busy.collectAsState()

    LaunchedEffect(Unit) { state.refreshHealth() }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Security health", style = MaterialTheme.typography.headlineSmall)
        val current = report
        if (current == null) {
            Spacer(Modifier.height(16.dp))
            Text("Add some items and SecureVault will look for weak, reused and old passwords.")
            return@Column
        }
        Spacer(Modifier.height(16.dp))
        Text("${current.score}", style = MaterialTheme.typography.displaySmall)
        Text(current.label, style = MaterialTheme.typography.titleMedium)
        LinearProgressIndicator({ current.score / 100f }, Modifier.fillMaxWidth().padding(vertical = 8.dp))

        SectionHeader("What to look at")
        IssueLine("Weak passwords", current.weak.size)
        IssueLine("Reused passwords", current.reused.size)
        IssueLine("Old passwords", current.old.size)
        IssueLine("Missing two-factor", current.missingTwoFactor.size)
        if (current.breachCheckRan) IssueLine("Found in a breach", current.breached.size)

        SectionHeader("Breach check")
        InfoCard(
            "The only thing in SecureVault that touches the network, and it is off until you turn " +
                "it on. It sends the first five characters of each password's SHA-1 hash; the " +
                "service returns every match for that prefix and the comparison happens here. It " +
                "never receives a password, a full hash, a username or a site. What it can still " +
                "see: that someone at your IP asked, and when."
        )
        Spacer(Modifier.height(12.dp))
        if (settings.breachCheckEnabled) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button({ state.runBreachCheck() }, enabled = busy == null) { Text("Check now") }
                TextButton({ state.updateSettings(settings.copy(breachCheckEnabled = false)) }) {
                    Text("Turn off")
                }
            }
        } else {
            Button({ state.updateSettings(settings.copy(breachCheckEnabled = true)) }) {
                Text("Turn on breach checking")
            }
        }
    }
}

@Composable
private fun IssueLine(label: String, count: Int) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
        Text(
            "$count", style = MaterialTheme.typography.titleMedium,
            color = if (count == 0) MaterialTheme.colorScheme.onSurfaceVariant
            else MaterialTheme.colorScheme.error
        )
    }
}

// FlowRow (auto-lock, clipboard and theme chips) is still an experimental layout API.
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen() {
    val state = LocalAppState.current
    val settings by state.settings.collectAsState()
    val storageStatus by state.secureStorageStatus.collectAsState()
    var confirmNever by remember { mutableStateOf(false) }
    var changingPassword by remember { mutableStateOf(false) }
    var destroying by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { state.checkSecureStorage() }
    fun update(block: (VaultSettings) -> VaultSettings) = state.updateSettings(block(settings))

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)

        SectionHeader("Auto-lock")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            VaultSettings.AUTO_LOCK_CHOICES.forEach { (label, millis) ->
                FilterChip(settings.autoLockMillis == millis,
                    { update { it.copy(autoLockMillis = millis) } }, { Text(label) })
            }
        }
        SwitchRow("Lock when the window loses focus", null, settings.lockOnBackground) {
            update { s -> s.copy(lockOnBackground = it) }
        }
        SwitchRow(
            "Lock after the machine resumes from sleep",
            "Detected by comparing wall-clock and monotonic time. A heuristic, not a system signal.",
            settings.lockOnScreenOff
        ) { update { s -> s.copy(lockOnScreenOff = it) } }

        SectionHeader("Clipboard")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(15 to "15 seconds", 30 to "30 seconds", 60 to "60 seconds", 0 to "Never")
                .forEach { (seconds, label) ->
                    FilterChip(
                        settings.clipboardClearSeconds == seconds,
                        { if (seconds == 0) confirmNever = true else update { it.copy(clipboardClearSeconds = seconds) } },
                        { Text(label) }
                    )
                }
        }
        Spacer(Modifier.height(8.dp))
        WarningCard(
            "Linux has no equivalent of Android's sensitive-clipboard flag. Clipboard managers " +
                "routinely keep history, SecureVault cannot see them and cannot stop them, and a " +
                "copied password may be retained elsewhere after this timeout."
        )

        SectionHeader("Convenience unlock")
        val storage = LocalServices.current.secureStorage
        when (val status = storageStatus) {
            is SecureStorage.Availability.Available -> InfoCard(
                "${storage.displayName} is available. Convenience unlock would store only your " +
                    "vault key in wrapped form — never your master password, never the raw key.\n\n" +
                    storage.protectionSummary
            )
            is SecureStorage.Availability.Unavailable -> InfoCard(
                "Convenience unlock is unavailable: ${status.reason}\n\n" +
                    "Your master password still opens the vault normally. SecureVault will not " +
                    "fall back to storing anything in a file."
            )
            null -> Text("Checking…", style = MaterialTheme.typography.bodySmall)
        }

        SectionHeader("Screen capture")
        // Reports what this actual session is, rather than a generic disclaimer. There is no
        // switch here because there is nothing to switch on: see ScreenCapture for why no Linux
        // mechanism exists, and why adding a native dependency would not change that.
        val capture = remember { ScreenCapture.detect() }
        WarningCard(capture.summary)
        Spacer(Modifier.height(8.dp))
        InfoCard(capture.detail)

        SectionHeader("Appearance")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            AppTheme.entries.forEach { theme ->
                FilterChip(settings.theme == theme, { update { it.copy(theme = theme) } },
                    { Text(theme.name.lowercase().replaceFirstChar { c -> c.uppercase() }) })
            }
        }

        SectionHeader("Privacy")
        InfoLine("Analytics", "None")
        InfoLine("Crash reporting", "None")
        InfoLine("Account", "None")
        InfoLine("Server", "None")
        InfoLine("Network use", if (settings.breachCheckEnabled) "Breach check only" else "None")

        SectionHeader("This vault")
        InfoLine("Key derivation", state.kdfDescription())
        state.vaultMetadata()?.let {
            InfoLine("Vault format", "version ${it.formatVersion}")
            InfoLine("Created", formatMoment(it.createdAt))
        }
        InfoLine("Platform", app.securevault.desktop.platform.Platform.description)
        InfoLine("Data directory", app.securevault.desktop.platform.Paths.dataDir.absolutePath)

        SectionHeader("Master password")
        Button({ changingPassword = true }) { Text("Change master password") }

        SectionHeader("Danger zone")
        Button(
            { destroying = true },
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
        ) { Text("Delete vault") }
        Spacer(Modifier.height(40.dp))
    }

    if (confirmNever) {
        AlertDialog(
            onDismissRequest = { confirmNever = false },
            title = { Text("Never clear the clipboard?") },
            text = {
                Text(
                    "Copied secrets will stay in the clipboard until something replaces them. Any " +
                        "application can read them, and clipboard managers keep history. This is " +
                        "less secure."
                )
            },
            confirmButton = {
                TextButton({
                    state.updateSettings(settings.copy(clipboardClearSeconds = 0)); confirmNever = false
                }) { Text("Turn clearing off") }
            },
            dismissButton = { TextButton({ confirmNever = false }) { Text("Keep clearing") } }
        )
    }
    if (changingPassword) ChangePasswordDialog { changingPassword = false }
    if (destroying) DestroyVaultDialog { destroying = false }
}

@Composable
private fun SwitchRow(title: String, subtitle: String?, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            subtitle?.let {
                Text(it, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Switch(checked, onChange)
    }
}

@Composable
private fun ChangePasswordDialog(onClose: () -> Unit) {
    val state = LocalAppState.current
    var current by remember { mutableStateOf("") }
    var replacement by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val ready = current.isNotEmpty() && replacement.length >= 12 && replacement == confirm

    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Change master password") },
        text = {
            Column(Modifier.width(460.dp)) {
                InfoCard(
                    "This rewraps your vault key. Items are not re-encrypted, so it is instant " +
                        "however large the vault is, and your recovery code keeps working."
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(current, { current = it }, label = { Text("Current password") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(replacement, { replacement = it }, label = { Text("New password") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    supportingText = { Text("At least 12 characters") },
                    modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(confirm, { confirm = it }, label = { Text("Confirm") },
                    singleLine = true, isError = confirm.isNotEmpty() && confirm != replacement,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton({
                state.changeMasterPassword(current.toCharArray(), replacement.toCharArray()) { onClose() }
            }, enabled = ready) { Text("Change") }
        },
        dismissButton = { TextButton(onClose) { Text("Cancel") } }
    )
}

@Composable
private fun DestroyVaultDialog(onClose: () -> Unit) {
    val state = LocalAppState.current
    var typed by remember { mutableStateOf("") }
    val phrase = "DELETE VAULT"
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Delete vault") },
        text = {
            Column(Modifier.width(460.dp)) {
                WarningCard(
                    "This permanently destroys the local vault: the header, the vault key, the " +
                        "database and every attachment. There is no undo."
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "Your data becomes unreadable because the keys are gone — a stronger guarantee " +
                        "than overwriting files. It does not shred anything: no application can " +
                        "promise that on modern storage. Backups you made earlier are untouched.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(typed, { typed = it }, label = { Text("Type $phrase") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton({ state.destroyVault { onClose() } }, enabled = typed.trim() == phrase) {
                Text("Delete permanently")
            }
        },
        dismissButton = { TextButton(onClose) { Text("Cancel") } }
    )
}
