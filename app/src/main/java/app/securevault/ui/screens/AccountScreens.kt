package app.securevault.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.feature.generator.PasswordStrength
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.components.WarningCard

/**
 * Change the master password.
 *
 * The transactional guarantees are in VaultManager: the current password must unwrap the vault
 * key, that key must match the live session's, and the new header must be shown to work before it
 * replaces the old one. This screen's job is to not lose the user along the way -- in particular,
 * to say what does *not* change, because "will this invalidate my recovery kit?" is the question
 * that stops people changing a password they know they should.
 */
@Composable
fun ChangePasswordScreen(viewModel: VaultViewModel, onBack: () -> Unit) {
    val busy by viewModel.busy.collectAsState()
    var current by remember { mutableStateOf("") }
    var replacement by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    // Same unavoidable String as on the setup screen: Compose TextField state is String-typed.
    // Scoring it adds no further copy. See SECURITY.md, known limitations.
    val strength = remember(replacement) {
        if (replacement.isEmpty()) null else PasswordStrength.evaluate(replacement)
    }
    val tooShort = replacement.isNotEmpty() && replacement.length < 12
    val mismatch = confirm.isNotEmpty() && confirm != replacement
    val ready = current.isNotEmpty() && replacement.length >= 12 && confirm == replacement && busy == null

    ScreenScaffold("Change master password", onBack, busy) {
        InfoCard(
            "Changing your master password rewraps your vault key. Your items are not " +
                "re-encrypted, so this is instant however large your vault is. Biometric unlock " +
                "and your recovery code both keep working, because they wrap the same key."
        )
        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = current,
            onValueChange = { current = it },
            label = { Text("Current master password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = replacement,
            onValueChange = { replacement = it },
            label = { Text("New master password") },
            singleLine = true,
            isError = tooShort,
            visualTransformation = PasswordVisualTransformation(),
            supportingText = {
                Text(
                    when {
                        tooShort -> "At least 12 characters. A passphrase of four or five words is easier to remember and harder to guess."
                        strength != null -> "${strength.label.name.replace('_', ' ').lowercase()
                            .replaceFirstChar { it.uppercase() }} · ${strength.entropyBits.toInt()} bits"
                        else -> "No upper limit. Spaces are fine."
                    }
                )
            },
            modifier = Modifier.fillMaxWidth()
        )
        strength?.suggestions?.take(2)?.forEach {
            Text("• $it", style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = confirm,
            onValueChange = { confirm = it },
            label = { Text("Confirm new password") },
            singleLine = true,
            isError = mismatch,
            visualTransformation = PasswordVisualTransformation(),
            supportingText = { if (mismatch) Text("These do not match") },
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(Modifier.height(20.dp))
        WarningCard(
            "There is no way to recover a forgotten master password unless you have set up a " +
                "recovery code. Write the new one down before you tap the button."
        )
        Spacer(Modifier.height(20.dp))
        Button(
            onClick = {
                viewModel.changeMasterPassword(
                    current.toCharArray(),
                    replacement.toCharArray()
                ) { success ->
                    current = ""; replacement = ""; confirm = ""
                    if (success) onBack()
                }
            },
            enabled = ready
        ) { Text("Change master password") }
    }
}

/**
 * Turn the recovery code on or off.
 *
 * The wording here matters more than the controls. A recovery code is an alternative to the master
 * password, not an addition to it, and a user who does not understand that will store it next to
 * their backup file.
 */
@Composable
fun RecoveryScreen(viewModel: VaultViewModel, onBack: () -> Unit) {
    val busy by viewModel.busy.collectAsState()
    val hasRecovery = remember(busy) { viewModel.hasRecovery() }
    var acknowledged by remember { mutableStateOf(false) }
    var confirmDisable by remember { mutableStateOf(false) }

    ScreenScaffold("Recovery", onBack, busy) {
        SectionHeader("Without recovery")
        Text(
            "If you forget your master password, your vault cannot be opened. Not by you, not by " +
                "us — there is no server, no account and no key held anywhere else. The data stays " +
                "on your device as ciphertext nobody can read.",
            style = MaterialTheme.typography.bodyMedium
        )

        SectionHeader("With recovery")
        Text(
            "SecureVault generates a 32-character code and uses it to wrap a second copy of your " +
                "vault key. That code then opens your vault on its own.",
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(12.dp))
        WarningCard(
            "This means the code is a second master key, not a backup of the first. Anyone " +
                "holding it and a copy of your vault or a backup file gets in. Store it away from " +
                "your backups — a code taped inside the same drawer as the hard drive protects " +
                "nothing."
        )

        Spacer(Modifier.height(20.dp))
        if (hasRecovery) {
            Text("Recovery is on for this vault.", style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = { viewModel.enableRecovery() }) { Text("Generate a new code") }
                TextButton(onClick = { confirmDisable = true }) { Text("Turn recovery off") }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "Generating a new code immediately invalidates the old one. Backup files you " +
                    "already made keep their own copy and still answer to the code that was " +
                    "current when they were written.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = acknowledged, onCheckedChange = { acknowledged = it })
                Text(
                    "  I understand this creates a second way into my vault",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            Spacer(Modifier.height(12.dp))
            Button(onClick = { viewModel.enableRecovery() }, enabled = acknowledged) {
                Text("Set up a recovery code")
            }
        }
    }

    if (confirmDisable) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmDisable = false },
            title = { Text("Turn recovery off?") },
            text = {
                Text(
                    "Your current recovery code will stop working on this vault. If you then " +
                        "forget your master password, the vault cannot be opened. Backup files " +
                        "made earlier are not affected."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.disableRecovery()
                    confirmDisable = false
                }) { Text("Turn off") }
            },
            dismissButton = { TextButton(onClick = { confirmDisable = false }) { Text("Keep it") } }
        )
    }
}

/** Generate the printable emergency recovery kit. */
@Composable
fun EmergencyKitScreen(viewModel: VaultViewModel, onBack: () -> Unit) {
    val busy by viewModel.busy.collectAsState()
    var includePrintedCode by remember { mutableStateOf(false) }
    var typedCode by remember { mutableStateOf("") }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/pdf")
    ) { uri ->
        uri?.let {
            viewModel.writeRecoveryKit(it, typedCode.takeIf { c -> includePrintedCode && c.isNotBlank() })
            typedCode = ""
        }
    }

    ScreenScaffold("Emergency recovery kit", onBack, busy) {
        InfoCard(
            "This document does not contain your passwords. It contains the information needed " +
                "to recover your vault: which algorithm and settings protect it, its salt, its id, " +
                "and step-by-step instructions. The QR code carries the same non-secret details."
        )
        Spacer(Modifier.height(16.dp))
        SectionHeader("What it will contain")
        InfoLine("Key derivation", viewModel.kdfDescription())
        viewModel.vaultMetadata()?.let {
            InfoLine("Vault name", it.name)
            InfoLine("Created", formatWhen(it.createdAt))
            InfoLine("Format version", "${it.formatVersion}")
        }
        Spacer(Modifier.height(12.dp))
        Text(
            "It also prints blank ruled lines for your master password and recovery code, to fill " +
                "in by hand. That is deliberate: the app never writes either of them into a file.",
            style = MaterialTheme.typography.bodyMedium
        )

        Spacer(Modifier.height(20.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = includePrintedCode, onCheckedChange = { includePrintedCode = it })
            Text("  Print my recovery code on it", style = MaterialTheme.typography.bodyMedium)
        }
        if (includePrintedCode) {
            Spacer(Modifier.height(8.dp))
            WarningCard(
                "The printed page then opens your vault by itself. Only do this if you will store " +
                    "it somewhere you would keep a passport."
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = typedCode,
                onValueChange = { typedCode = it.uppercase() },
                label = { Text("Type your recovery code") },
                supportingText = { Text("SecureVault cannot read it back — it was only ever shown once.") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(Modifier.height(20.dp))
        Button(
            onClick = {
                val stamp = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                    .format(java.util.Date())
                launcher.launch("securevault-recovery-kit-$stamp.pdf")
            },
            enabled = busy == null
        ) { Text("Generate and save") }
        Spacer(Modifier.height(8.dp))
        Text(
            "The file goes only where you point the system file picker. Nothing is uploaded, and " +
                "nothing is written to Downloads on its own.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** Destroy the vault. Typed confirmation, and no claims the app cannot back up. */
@Composable
fun DestroyVaultScreen(viewModel: VaultViewModel, onBack: () -> Unit, onDestroyed: () -> Unit) {
    val busy by viewModel.busy.collectAsState()
    var typed by remember { mutableStateOf("") }
    val phrase = "DELETE VAULT"

    ScreenScaffold("Delete vault", onBack, busy) {
        WarningCard(
            "This permanently destroys the local encrypted vault: the header, the vault key, the " +
                "database and every attachment. There is no undo and no copy held anywhere else."
        )
        Spacer(Modifier.height(16.dp))
        Text("What this does and does not do", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            "• Your data becomes unreadable because the keys are gone. That is a stronger " +
                "guarantee than overwriting files.\n\n" +
                "• It does not shred anything. Android's storage layer can leave old blocks on the " +
                "flash chip, and no app can promise otherwise. If that matters to you, use the " +
                "device's own factory reset, which erases the hardware-backed keys.\n\n" +
                "• Backups and CSV exports you made earlier are untouched and still openable with " +
                "the password that was current when you made them.",
            style = MaterialTheme.typography.bodyMedium
        )

        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text("Type $phrase to confirm") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = { viewModel.destroyVault { onDestroyed() } },
            enabled = typed.trim() == phrase && busy == null,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
                contentColor = MaterialTheme.colorScheme.onError
            )
        ) { Text("Delete this vault permanently") }
    }
}
