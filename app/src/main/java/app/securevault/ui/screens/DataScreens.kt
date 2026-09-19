package app.securevault.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.feature.csv.ExportSelection
import app.securevault.ui.VaultViewModel
import app.securevault.ui.VerifyState
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.components.WarningCard
import java.text.DateFormat
import java.util.Date

/** Create and verify a `.securevault` backup. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupScreen(viewModel: VaultViewModel, onBack: () -> Unit) {
    val busy by viewModel.busy.collectAsState()
    val items by viewModel.visibleItems.collectAsState()
    val metadata = remember { viewModel.vaultMetadata() }

    var verifyUri by remember { mutableStateOf<android.net.Uri?>(null) }

    val createLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri -> uri?.let { viewModel.createBackup(it) } }

    val verifyLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> verifyUri = uri }

    val verification by viewModel.verifyState.collectAsState()

    ScreenScaffold("Encrypted backup", onBack, busy) {
        when (val outcome = verification) {
            is VerifyState.Failed -> {
                VerificationFailed(
                    message = outcome.failure.userMessage,
                    onTryAnother = {
                        viewModel.dismissVerification()
                        verifyLauncher.launch(arrayOf("*/*"))
                    },
                    onBack = { viewModel.dismissVerification() }
                )
                return@ScreenScaffold
            }
            is VerifyState.Verified -> {
                VerificationPassed(outcome) { viewModel.dismissVerification() }
                return@ScreenScaffold
            }
            VerifyState.Idle -> Unit
        }

        InfoCard(
            "A backup is encrypted with the same vault key your master password protects. " +
                "It is safe to keep on a computer or in cloud storage; without your password it " +
                "is ciphertext. Your master password is not inside it in any form."
        )

        SectionHeader("This vault")
        InfoLine("Items", "${viewModel.totalItems()}")
        InfoLine("Attachments", "${items.sumOf { it.payload.attachments.size }}")
        InfoLine("Key derivation", viewModel.kdfDescription())
        metadata?.let {
            InfoLine("Created", formatWhen(it.createdAt))
            InfoLine("Last changed", formatWhen(it.modifiedAt))
        }

        Spacer(Modifier.height(20.dp))
        Button(
            onClick = {
                val stamp = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                    .format(Date())
                createLauncher.launch("securevault-$stamp.securevault")
            },
            enabled = busy == null
        ) { Text("Create encrypted backup") }

        Spacer(Modifier.height(24.dp))
        SectionHeader("Verify a backup")
        Text(
            "An untested backup is not a backup. Verifying decrypts the whole file and checks " +
                "every chunk, without writing anything.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = { verifyLauncher.launch(arrayOf("*/*")) }) { Text("Choose a backup to verify") }
    }

    verifyUri?.let { uri ->
        PasswordPromptDialog(
            title = "Verify backup",
            body = "Enter the master password that was in use when this backup was made.",
            confirmLabel = "Verify",
            onDismiss = { verifyUri = null },
            onConfirm = { password ->
                viewModel.verifyBackup(uri, password)
                verifyUri = null
            }
        )
    }
}

@Composable
private fun VerificationFailed(message: String, onTryAnother: () -> Unit, onBack: () -> Unit) {
    Text(
        "Backup verification failed",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive }
    )
    Spacer(Modifier.height(12.dp))
    WarningCard(
        text = "This backup cannot be trusted for restoration.\n\n$message",
        modifier = Modifier.semantics {
            contentDescription = "Backup verification failed. This backup cannot be trusted for restoration. $message"
        }
    )
    Spacer(Modifier.height(12.dp))
    // Said explicitly, because the natural fear on reading the message above is that the problem
    // is on this device rather than in the file.
    Text(
        "Your current vault is fine. Nothing on this device was read, changed or deleted, and " +
            "there is no reason to remove anything.",
        style = MaterialTheme.typography.bodyMedium
    )
    Spacer(Modifier.height(20.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(onClick = onTryAnother) { Text("Try another backup") }
        TextButton(onClick = onBack) { Text("Back") }
    }
}

@Composable
private fun VerificationPassed(outcome: VerifyState.Verified, onDone: () -> Unit) {
    Text(
        "Backup verified",
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }
    )
    Spacer(Modifier.height(8.dp))
    Text(
        "Every chunk decrypted and authenticated. Nothing was written.",
        style = MaterialTheme.typography.bodyMedium
    )
    Spacer(Modifier.height(12.dp))
    InfoLine("Made", formatWhen(outcome.createdAt))
    InfoLine("Key derivation", outcome.kdf)
    InfoLine("Backup format", "version ${outcome.formatVersion}")
    InfoLine("Vault id", outcome.vaultId)
    Spacer(Modifier.height(20.dp))
    Button(onClick = onDone) { Text("Done") }
}

/** What an export covers. */
enum class ExportScope(val label: String) {
    ENTIRE_VAULT("Entire vault"),
    CURRENT_FOLDER("Current folder"),
    SELECTED("Selected items")
}

/**
 * CSV export, behind a blocking warning and an explicit scope.
 *
 * The scope used to be implicit -- whatever happened to be filtered into view. That is the sort of
 * default that writes three hundred passwords to a file when someone meant to export four.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportScreen(viewModel: VaultViewModel, onBack: () -> Unit) {
    val busy by viewModel.busy.collectAsState()
    val folders by viewModel.folders.collectAsState()
    val all = remember { viewModel.allItems() }

    var scope by remember { mutableStateOf(ExportScope.ENTIRE_VAULT) }
    var folderId by remember { mutableStateOf(folders.firstOrNull()?.id) }
    val selected = remember { mutableStateListOf<String>() }

    var includeCards by remember { mutableStateOf(false) }
    var includeIdentities by remember { mutableStateOf(false) }
    var includeTotp by remember { mutableStateOf(false) }
    var includeNotes by remember { mutableStateOf(true) }
    var confirming by remember { mutableStateOf(false) }

    val items = when (scope) {
        ExportScope.ENTIRE_VAULT -> all
        ExportScope.CURRENT_FOLDER -> folderId?.let { id -> all.filter { it.folderId == id } }.orEmpty()
        ExportScope.SELECTED -> all.filter { it.id in selected }
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv")
    ) { uri ->
        uri?.let {
            viewModel.exportCsv(
                it,
                ExportSelection(
                    items = items,
                    includeIdentities = includeIdentities,
                    includeCards = includeCards,
                    includeNotes = includeNotes,
                    includeTotpSecrets = includeTotp
                )
            )
        }
    }

    ScreenScaffold("Export to CSV", onBack, busy) {
        WarningCard(
            "CSV is plaintext.\n\n" +
                "• Every password in the file can be read by anyone, and by any app that can " +
                "reach the file.\n" +
                "• There is no password on it and no encryption.\n" +
                "• Once written, it is yours to look after — SecureVault cannot take it back.\n" +
                "• Import it back into SecureVault only when you actually need to, and delete it " +
                "afterwards, including from your downloads folder and any cloud sync."
        )

        SectionHeader("What to export")
        ScopeChoice(
            scope = scope,
            onSelect = { scope = it },
            folderAvailable = folders.isNotEmpty()
        )

        if (scope == ExportScope.CURRENT_FOLDER) {
            FolderPicker(folders = folders, selected = folderId, onSelect = { folderId = it })
        }

        if (scope == ExportScope.SELECTED) {
            SectionHeader("Choose items (${selected.size} selected)")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { selected.clear(); selected.addAll(all.map { it.id }) }) {
                    Text("Select all")
                }
                TextButton(onClick = { selected.clear() }) { Text("Clear") }
            }
            all.forEach { item ->
                val checked = item.id in selected
                Row(
                    Modifier.fillMaxWidth()
                        .clickable { if (checked) selected.remove(item.id) else selected.add(item.id) }
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(checked = checked, onCheckedChange = null)
                    Spacer(Modifier.width(8.dp))
                    Column {
                        Text(item.title.ifBlank { "Untitled" }, style = MaterialTheme.typography.bodyLarge)
                        if (item.username.isNotBlank()) {
                            Text(
                                item.username,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))
        Text(
            "${items.size} ${if (items.size == 1) "item" else "items"} will be written.",
            style = MaterialTheme.typography.bodyLarge
        )

        SectionHeader("Also include")
        CheckRow("Notes", includeNotes) { includeNotes = it }
        CheckRow("Card numbers and security codes", includeCards) { includeCards = it }
        CheckRow("Identity documents", includeIdentities) { includeIdentities = it }
        CheckRow("Two-factor secrets", includeTotp) { includeTotp = it }
        if (includeTotp) {
            Spacer(Modifier.height(8.dp))
            WarningCard(
                "A file holding both the password and the second factor removes the point of " +
                    "having a second factor."
            )
        }

        Spacer(Modifier.height(20.dp))
        Button(onClick = { confirming = true }, enabled = items.isNotEmpty() && busy == null) {
            Text("Export as plaintext CSV")
        }
    }

    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Write passwords in the clear?") },
            text = {
                Text(
                    "You are about to write ${items.size} " +
                        "${if (items.size == 1) "item" else "items"}, including every password, " +
                        "to an unencrypted file. Delete it as soon as you have finished with it."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirming = false
                    val stamp = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(Date())
                    launcher.launch("securevault-export-$stamp.csv")
                }) { Text("I understand, export") }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ScopeChoice(
    scope: ExportScope,
    onSelect: (ExportScope) -> Unit,
    folderAvailable: Boolean
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        ExportScope.entries.forEach { option ->
            val enabled = option != ExportScope.CURRENT_FOLDER || folderAvailable
            FilterChip(
                selected = scope == option,
                onClick = { if (enabled) onSelect(option) },
                enabled = enabled,
                label = { Text(option.label) }
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FolderPicker(
    folders: List<app.securevault.core.model.Folder>,
    selected: String?,
    onSelect: (String) -> Unit
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        folders.forEach { folder ->
            FilterChip(
                selected = selected == folder.id,
                onClick = { onSelect(folder.id) },
                label = { Text(folder.name) }
            )
        }
    }
}

// ---- shared bits ---------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenScaffold(
    title: String,
    onBack: () -> Unit,
    busy: String?,
    content: @Composable () -> Unit
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
        ) {
            if (busy != null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(busy, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
            }
            content()
            Spacer(Modifier.height(40.dp))
        }
    }
}

@Composable
fun InfoLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun CheckRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * Collects a master password for a one-off operation.
 *
 * Hands back a CharArray and clears its own state; the caller is responsible for wiping, which
 * every ViewModel entry point here does.
 */
@Composable
fun PasswordPromptDialog(
    title: String,
    body: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: (CharArray) -> Unit
) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(body, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Master password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val chars = password.toCharArray()
                    password = ""
                    onConfirm(chars)
                },
                enabled = password.isNotEmpty()
            ) { Text(confirmLabel) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

internal fun formatWhen(millis: Long): String =
    DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(millis))
