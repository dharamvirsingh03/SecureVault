package app.securevault.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import app.securevault.feature.backup.RestorePreview
import app.securevault.feature.backup.RestoreSummary
import app.securevault.ui.RestoreState
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.components.WarningCard
import java.text.DateFormat
import java.util.Date

/**
 * Restore a `.securevault` backup into a new vault.
 *
 * Four states, each with its own screen rather than a shared one with conditional text: choose a
 * file, look at what is in it, see it succeed, or see exactly why it did not. The failure states
 * in particular used to be a snackbar, which is the wrong shape for something a user has to act
 * on and may need to read twice.
 */
@Composable
fun RestoreScreen(viewModel: VaultViewModel, onBack: () -> Unit, onOpenRestoredVault: () -> Unit) {
    val state by viewModel.restoreState.collectAsState()
    val busy by viewModel.busy.collectAsState()
    var pendingFile by remember { mutableStateOf<android.net.Uri?>(null) }
    var confirming by remember { mutableStateOf(false) }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> pendingFile = uri }

    ScreenScaffold("Restore a backup", { viewModel.cancelRestore(); onBack() }, busy) {
        when (val current = state) {
            is RestoreState.Idle -> ChooseStep(
                vaultPresent = viewModel.restoreRequiresEmptyDevice(),
                onPick = { picker.launch(arrayOf("*/*")) }
            )

            is RestoreState.Staged -> PreviewStep(
                preview = current.staged.preview,
                onRestore = { confirming = true },
                onCancel = { viewModel.cancelRestore() }
            )

            is RestoreState.Done -> SuccessStep(
                summary = current.summary,
                onOpen = { viewModel.cancelRestore(); onOpenRestoredVault() }
            )

            is RestoreState.Failed -> FailureStep(
                message = current.failure.userMessage,
                onTryAnother = { viewModel.cancelRestore(); picker.launch(arrayOf("*/*")) },
                onBack = { viewModel.cancelRestore(); onBack() }
            )
        }
    }

    pendingFile?.let { uri ->
        PasswordPromptDialog(
            title = "Open this backup",
            body = "Enter the master password that was in use when this backup was made. Nothing " +
                "is written anywhere until you have seen what is inside it.",
            confirmLabel = "Open and check",
            onDismiss = { pendingFile = null },
            onConfirm = { password ->
                pendingFile = null
                viewModel.stageRestore(uri, password)
            }
        )
    }

    if (confirming) {
        PasswordPromptDialog(
            title = "Restore as new vault",
            body = "Confirm your backup password once more. The restored vault will then be " +
                "locked, and you open it the usual way.",
            confirmLabel = "Restore",
            onDismiss = { confirming = false },
            onConfirm = { password ->
                confirming = false
                viewModel.commitRestore(password)
            }
        )
    }
}

@Composable
private fun ChooseStep(vaultPresent: Boolean, onPick: () -> Unit) {
    InfoCard(
        "A backup is restored as a new vault. It keeps its own vault key, key-derivation settings " +
            "and salt, exactly as they were when the backup was written — restoring can never " +
            "move a vault onto weaker settings, because it never picks any."
    )
    Spacer(Modifier.height(16.dp))

    if (vaultPresent) {
        WarningCard(
            "You already have a vault on this device, and SecureVault holds one at a time. " +
                "Restoring will not overwrite it, and there is no button here that would.\n\n" +
                "To move to a restored vault deliberately: create a backup of what you have now, " +
                "delete the current vault from Settings using the typed confirmation, then come " +
                "back here. Those steps are separate on purpose."
        )
        Spacer(Modifier.height(16.dp))
        Text(
            "You can still open a backup here to check it is readable.",
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(12.dp))
    }

    Button(onClick = onPick) { Text("Choose a .securevault file") }
}

@Composable
private fun PreviewStep(preview: RestorePreview, onRestore: () -> Unit, onCancel: () -> Unit) {
    Text("This backup opened and passed every check.", style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(12.dp))
    InfoCard("This backup will create a new vault. Your current vault will not be overwritten.")

    SectionHeader("What is in it")
    InfoLine("Vault name", preview.vaultName)
    InfoLine("Items", "${preview.itemCount}")
    InfoLine("Folders", "${preview.folderCount}")
    InfoLine("Tags", "${preview.tagCount}")
    InfoLine("Attachments", "${preview.attachmentCount}")

    SectionHeader("About the file")
    InfoLine("Backup made", formatMoment(preview.backupCreatedAt))
    InfoLine("Backup format", "version ${preview.backupFormatVersion}")
    InfoLine("Written by", "SecureVault ${preview.appVersion}")
    InfoLine("Key derivation", preview.kdfDescription)
    InfoLine("Vault id", preview.vaultId)
    InfoLine("Recovery code", if (preview.hasRecoveryBlock) "Included" else "Not set up")

    if (preview.legacyPlaintextMetadata) {
        Spacer(Modifier.height(12.dp))
        WarningCard(
            "This is an older format 1 backup. Its vault name and item count were readable " +
                "without a password. Make a fresh backup after restoring; the current format " +
                "encrypts those."
        )
    }

    Spacer(Modifier.height(8.dp))
    Text(
        "No password, one-time code or note from this backup is shown on this screen, and none " +
            "has been written to your device yet.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(Modifier.height(24.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(onClick = onRestore) { Text("Restore as new vault") }
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

@Composable
private fun SuccessStep(summary: RestoreSummary, onOpen: () -> Unit) {
    Text(
        "Vault restored",
        style = MaterialTheme.typography.headlineSmall,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }
    )
    Spacer(Modifier.height(12.dp))
    InfoLine("Vault name", summary.vaultName)
    InfoLine("Items", "${summary.items}")
    InfoLine("Folders", "${summary.folders}")
    InfoLine("Tags", "${summary.tags}")
    InfoLine("Attachments", "${summary.attachments}")
    InfoLine("Restored", formatMoment(summary.restoredAt))
    InfoLine("Destination", "New vault on this device")

    Spacer(Modifier.height(16.dp))
    InfoCard(
        "The restored vault is locked. Open it with the master password that opened the backup — " +
            "restore does not skip that step. Biometric unlock, if you used it before, needs " +
            "setting up again on this device."
    )
    Spacer(Modifier.height(20.dp))
    Button(onClick = onOpen) { Text("Open restored vault") }
}

@Composable
private fun FailureStep(message: String, onTryAnother: () -> Unit, onBack: () -> Unit) {
    Text(
        "Backup could not be restored",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive }
    )
    Spacer(Modifier.height(12.dp))
    WarningCard(
        text = message,
        modifier = Modifier.semantics { contentDescription = "Restore failed. $message" }
    )
    Spacer(Modifier.height(12.dp))
    Text(
        "Nothing was restored and nothing on this device was changed.",
        style = MaterialTheme.typography.bodyMedium
    )
    Spacer(Modifier.height(20.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(onClick = onTryAnother) { Text("Try another backup") }
        TextButton(onClick = onBack) { Text("Back") }
    }
}

internal fun formatMoment(millis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(millis))
