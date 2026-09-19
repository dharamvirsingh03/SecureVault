package app.securevault.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import app.securevault.core.model.AttachmentRef
import app.securevault.data.attachments.AttachmentViewer
import app.securevault.core.model.FieldKind
import app.securevault.core.model.ItemSchema
import app.securevault.core.model.VaultItem
import app.securevault.feature.totp.TotpEngine
import app.securevault.platform.CopyKind
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.theme.OtpTextStyle
import app.securevault.ui.theme.SecretTextStyle
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date

/**
 * A single item.
 *
 * Secret values are masked until the user asks for them, and revealing one does not reveal the
 * others. Copy actions go through [CopyKind] so the clipboard timeout and the Android 13+
 * sensitive-content flag are applied consistently rather than per call site.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ItemDetailScreen(
    viewModel: VaultViewModel,
    itemId: String,
    onBack: () -> Unit,
    onEdit: (VaultItem) -> Unit
) {
    val item = viewModel.itemById(itemId)
    if (item == null) {
        // The vault locked, or the item was deleted from under us.
        LaunchedEffect(Unit) { onBack() }
        return
    }

    var revealed by remember { mutableStateOf(setOf<String>()) }
    var confirmDelete by remember { mutableStateOf(false) }

    LaunchedEffect(itemId) { viewModel.markUsed(item) }

    val addAttachment = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { viewModel.addAttachment(item, it) } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(item.title.ifBlank { "Untitled" }) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.toggleFavorite(item) }) {
                        Icon(
                            if (item.favorite) Icons.Filled.Star else Icons.Outlined.StarBorder,
                            contentDescription = "Favourite"
                        )
                    }
                    IconButton(onClick = { confirmDelete = true }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Delete")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { onEdit(item) }) {
                Icon(Icons.Filled.Edit, contentDescription = "Edit")
            }
        }
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
        ) {
            Text(
                item.type.displayName,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
            )

            ItemSchema.fieldsFor(item.type).forEach { spec ->
                val value = item.payload.field(spec.key)
                if (value.isBlank()) return@forEach
                DetailField(
                    label = spec.label,
                    value = value,
                    secret = spec.isSecret,
                    revealed = spec.key in revealed,
                    multiline = spec.kind == FieldKind.MULTILINE,
                    onToggleReveal = {
                        revealed = if (spec.key in revealed) revealed - spec.key else revealed + spec.key
                    },
                    onCopy = {
                        viewModel.copy(
                            value,
                            if (spec.isSecret) CopyKind.PASSWORD else CopyKind.OTHER
                        )
                    }
                )
            }

            item.payload.totp?.let { config -> TotpPanel(config, viewModel) }

            if (item.payload.customFields.isNotEmpty()) {
                SectionHeader("Custom fields")
                item.payload.customFields.forEach { field ->
                    DetailField(
                        label = field.name,
                        value = field.value,
                        secret = field.kind == FieldKind.HIDDEN,
                        revealed = "custom:${field.name}" in revealed,
                        multiline = field.kind == FieldKind.MULTILINE,
                        onToggleReveal = {
                            val key = "custom:${field.name}"
                            revealed = if (key in revealed) revealed - key else revealed + key
                        },
                        onCopy = {
                            viewModel.copy(
                                field.value,
                                if (field.kind == FieldKind.HIDDEN) CopyKind.PASSWORD else CopyKind.OTHER
                            )
                        }
                    )
                }
            }

            if (item.payload.recoveryCodes.isNotEmpty()) {
                SectionHeader("Backup codes")
                DetailField(
                    label = "${item.payload.recoveryCodes.size} codes",
                    value = item.payload.recoveryCodes.joinToString("\n"),
                    secret = true,
                    revealed = "backup-codes" in revealed,
                    multiline = true,
                    onToggleReveal = {
                        revealed = if ("backup-codes" in revealed) revealed - "backup-codes"
                        else revealed + "backup-codes"
                    },
                    onCopy = { viewModel.copy(item.payload.recoveryCodes.joinToString("\n"), CopyKind.PASSWORD) }
                )
            }

            if (item.payload.notes.isNotBlank()) {
                SectionHeader("Notes")
                Text(
                    item.payload.notes,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 20.dp)
                )
            }

            // ---- attachments ---------------------------------------------------------------
            SectionHeader("Attachments", action = {
                IconButton(onClick = { addAttachment.launch(arrayOf("*/*")) }) {
                    Icon(Icons.Filled.AttachFile, contentDescription = "Add an attachment")
                }
            })
            if (item.payload.attachments.isEmpty()) {
                Text(
                    "None. Files you attach are encrypted with a key of their own, derived from " +
                        "your vault key.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 20.dp)
                )
            } else {
                item.payload.attachments.forEach { ref ->
                    AttachmentRow(
                        ref = ref,
                        viewModel = viewModel,
                        onExport = { uri -> viewModel.exportAttachment(ref, uri) },
                        onDelete = { viewModel.deleteAttachment(item, ref) }
                    )
                }
            }

            // ---- organisation ----------------------------------------------------------------
            if (item.payload.tags.isNotEmpty()) {
                SectionHeader("Tags")
                FlowRow(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item.payload.tags.forEach { tag -> AssistChip(onClick = {}, label = { Text(tag) }) }
                }
            }

            SectionHeader("Details")
            val folderName = item.folderId?.let { viewModel.folderById(it)?.name } ?: "Unfiled"
            MetaLine("Folder", folderName)
            MetaLine("Created", formatDate(item.createdAt))
            MetaLine("Modified", formatDate(item.updatedAt))
            item.payload.passwordChangedAt?.let { MetaLine("Password last changed", formatDate(it)) }
            item.lastUsedAt?.let { MetaLine("Last used", formatDate(it)) }

            Spacer(Modifier.height(96.dp))
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete this item?") },
            text = {
                Text(
                    "\"${item.title}\" and everything in it will be removed from this device. " +
                        "There is no undo, and backups you already made still contain it."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    viewModel.delete(item)
                    onBack()
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Keep") } }
        )
    }
}

@Composable
private fun DetailField(
    label: String,
    value: String,
    secret: Boolean,
    revealed: Boolean,
    multiline: Boolean,
    onToggleReveal: () -> Unit,
    onCopy: () -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (secret && !revealed) "•".repeat(minOf(value.length, 16)) else value,
                style = if (secret) SecretTextStyle else MaterialTheme.typography.bodyLarge,
                maxLines = if (multiline) 12 else 2,
                modifier = Modifier.weight(1f)
            )
            if (secret) {
                IconButton(onClick = onToggleReveal, modifier = Modifier.size(48.dp)) {
                    Icon(
                        if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (revealed) "Hide $label" else "Show $label"
                    )
                }
            }
            IconButton(onClick = onCopy, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy $label")
            }
        }
    }
    HorizontalDivider(Modifier.padding(horizontal = 20.dp))
}

/**
 * The live one-time code.
 *
 * Recomputed on a one-second tick rather than held, so the value on screen is always the one that
 * is actually valid. Auto-copy is off unless the user turned it on: silently replacing the
 * clipboard when a screen opens is how a code ends up pasted somewhere it should not be.
 */
@Composable
private fun TotpPanel(config: app.securevault.core.model.TotpConfig, viewModel: VaultViewModel) {
    var code by remember { mutableStateOf(TotpEngine.generate(config)) }
    LaunchedEffect(config) {
        while (true) {
            code = TotpEngine.generate(config)
            delay(1_000)
        }
    }
    val settings by viewModel.settings.collectAsState()
    LaunchedEffect(config) {
        // Off by default. A code copied without being asked for is a code on the clipboard that
        // nobody is watching the timeout on.
        if (settings.autoCopyOtpOnOpen) viewModel.copy(code.code, CopyKind.OTP)
    }

    SectionHeader("One-time code")
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(code.formatted, style = OtpTextStyle, modifier = Modifier.weight(1f))
            IconButton(onClick = { viewModel.copy(code.code, CopyKind.OTP) }) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy one-time code")
            }
        }
        LinearProgressIndicator(
            progress = { code.progress },
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
        )
        Text(
            "Expires in ${code.secondsRemaining} ${if (code.secondsRemaining == 1) "second" else "seconds"}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
    Spacer(Modifier.height(8.dp))
    HorizontalDivider(Modifier.padding(horizontal = 20.dp))
}

@Composable
private fun AttachmentRow(
    ref: AttachmentRef,
    viewModel: VaultViewModel,
    onExport: (android.net.Uri) -> Unit,
    onDelete: () -> Unit
) {
    val context = LocalContext.current
    var noViewer by remember { mutableStateOf(false) }
    var confirmOpen by remember { mutableStateOf(false) }

    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(ref.mimeType.ifBlank { "application/octet-stream" })
    ) { uri -> uri?.let(onExport) }

    val canView = AttachmentViewer.looksViewable(ref.mimeType) &&
        ref.sizeBytes <= AttachmentViewer.MAX_INLINE_VIEW_BYTES

    ListItem(
        headlineContent = { Text(ref.fileName) },
        supportingContent = {
            Text("${ref.sizeBytes / 1024} KB · added ${formatDate(ref.addedAt)}")
        },
        trailingContent = {
            Row {
                if (canView) {
                    IconButton(onClick = { confirmOpen = true }) {
                        Icon(
                            Icons.Filled.Visibility,
                            contentDescription = "Open ${ref.fileName} in a viewer"
                        )
                    }
                }
                IconButton(onClick = { saveLauncher.launch(ref.fileName) }) {
                    Icon(
                        Icons.Filled.Download,
                        contentDescription = "Save a decrypted copy of ${ref.fileName}"
                    )
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "Delete ${ref.fileName}")
                }
            }
        },
        modifier = Modifier.fillMaxWidth()
    )

    if (confirmOpen) {
        AlertDialog(
            onDismissRequest = { confirmOpen = false },
            title = { Text("Open in another app?") },
            text = {
                Text(
                    "SecureVault has no built-in viewer, so this file is decrypted to private " +
                        "storage and handed to an app that can display it. While that app has it " +
                        "open, a decrypted copy exists on this device.\n\n" +
                        "The copy is deleted when your vault locks and when SecureVault restarts."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmOpen = false
                    viewModel.openAttachment(
                        ref = ref,
                        onIntent = { context.startActivity(it) },
                        onNoViewer = { noViewer = true }
                    )
                }) { Text("Open") }
            },
            dismissButton = { TextButton(onClick = { confirmOpen = false }) { Text("Cancel") } }
        )
    }

    if (noViewer) {
        AlertDialog(
            onDismissRequest = { noViewer = false },
            title = { Text("No app can open this") },
            text = {
                Text(
                    "Nothing installed on this device handles ${ref.mimeType.ifBlank { "this file type" }}. " +
                        "Save a decrypted copy instead and open it wherever you prefer — and " +
                        "remember to delete it afterwards."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    noViewer = false
                    saveLauncher.launch(ref.fileName)
                }) { Text("Save a copy") }
            },
            dismissButton = { TextButton(onClick = { noViewer = false }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun MetaLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

private fun formatDate(millis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(millis))
