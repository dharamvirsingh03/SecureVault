package app.securevault.desktop.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.core.model.*
import app.securevault.desktop.LocalAppState
import app.securevault.desktop.LocalServices
import app.securevault.feature.generator.PasswordGenerator
import app.securevault.feature.generator.PasswordOptions
import app.securevault.feature.generator.PasswordStrength
import app.securevault.feature.totp.OtpAuthUri
import app.securevault.feature.totp.TotpEngine
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date
import javax.swing.JFileChooser

/**
 * Read-only item view.
 *
 * Secrets are masked until asked for, and revealing one does not reveal the others. Copy actions
 * go through the shared clipboard path so the configured timeout applies everywhere.
 */
@Composable
fun ItemDetail(item: VaultItem, onEdit: () -> Unit, onDeleted: () -> Unit) {
    val state = LocalAppState.current
    var revealed by remember(item.id) { mutableStateOf(setOf<String>()) }
    var confirmDelete by remember { mutableStateOf(false) }

    LaunchedEffect(item.id) { state.markUsed(item) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(iconFor(item.type), null, Modifier.size(28.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.title.ifBlank { "Untitled" }, style = MaterialTheme.typography.headlineSmall)
                Text(item.type.displayName, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            TextButton(onEdit) { Icon(Icons.Filled.Edit, null); Spacer(Modifier.width(6.dp)); Text("Edit") }
            TextButton({ confirmDelete = true }) {
                Icon(Icons.Filled.Delete, null); Spacer(Modifier.width(6.dp)); Text("Delete")
            }
        }
        Spacer(Modifier.height(20.dp))

        ItemSchema.fieldsFor(item.type).forEach { spec ->
            val value = item.payload.field(spec.key)
            if (value.isBlank()) return@forEach
            DetailField(
                label = spec.label, value = value, secret = spec.isSecret,
                revealed = spec.key in revealed,
                onToggle = { revealed = if (spec.key in revealed) revealed - spec.key else revealed + spec.key },
                onCopy = { state.copy(value, spec.label) }
            )
        }

        item.payload.totp?.let { TotpPanel(it) }

        if (item.payload.customFields.isNotEmpty()) {
            SectionHeader("Custom fields")
            item.payload.customFields.forEach { field ->
                val key = "custom:${field.name}"
                DetailField(
                    label = field.name, value = field.value,
                    secret = field.kind == FieldKind.HIDDEN, revealed = key in revealed,
                    onToggle = { revealed = if (key in revealed) revealed - key else revealed + key },
                    onCopy = { state.copy(field.value, field.name) }
                )
            }
        }

        if (item.payload.notes.isNotBlank()) {
            SectionHeader("Notes")
            Text(item.payload.notes, style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 24.dp))
        }

        AttachmentsPanel(item)

        SectionHeader("Details")
        InfoLine("Folder", item.folderId?.let { state.folderById(it)?.name } ?: "Unfiled")
        if (item.payload.tags.isNotEmpty()) InfoLine("Tags", item.payload.tags.joinToString(", "))
        InfoLine("Created", formatMoment(item.createdAt))
        InfoLine("Modified", formatMoment(item.updatedAt))
        item.payload.passwordChangedAt?.let { InfoLine("Password changed", formatMoment(it)) }
        Spacer(Modifier.height(40.dp))
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete this item?") },
            text = {
                Text("\"${item.title}\" will be removed from this device. There is no undo, and " +
                    "backups you already made still contain it.")
            },
            confirmButton = {
                TextButton({ confirmDelete = false; state.delete(item); onDeleted() }) { Text("Delete") }
            },
            dismissButton = { TextButton({ confirmDelete = false }) { Text("Keep") } }
        )
    }
}

@Composable
private fun DetailField(
    label: String, value: String, secret: Boolean, revealed: Boolean,
    onToggle: () -> Unit, onCopy: () -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (secret && !revealed) "•".repeat(minOf(value.length, 18)) else value,
                fontFamily = if (secret) FontFamily.Monospace else FontFamily.Default,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f)
            )
            if (secret) {
                IconButton(onToggle) {
                    Icon(
                        if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (revealed) "Hide $label" else "Show $label"
                    )
                }
            }
            IconButton(onCopy) { Icon(Icons.Filled.ContentCopy, contentDescription = "Copy $label") }
        }
        HorizontalDivider()
    }
}

@Composable
private fun TotpPanel(config: TotpConfig) {
    val state = LocalAppState.current
    var code by remember(config) { mutableStateOf(TotpEngine.generate(config)) }
    LaunchedEffect(config) {
        while (true) { code = TotpEngine.generate(config); delay(1_000) }
    }
    SectionHeader("One-time code")
    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(code.formatted, fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
            IconButton({ state.copy(code.code, "One-time code") }) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy one-time code")
            }
        }
        LinearProgressIndicator({ code.progress }, Modifier.fillMaxWidth())
        Text("Expires in ${code.secondsRemaining}s", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AttachmentsPanel(item: VaultItem) {
    val state = LocalAppState.current
    val services = LocalServices.current
    val scope = rememberCoroutineScope()
    var confirmOpen by remember { mutableStateOf<AttachmentRef?>(null) }

    SectionHeader("Attachments")
    if (item.payload.attachments.isEmpty()) {
        Text(
            "None. Attachments are encrypted with a key derived from your vault key.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 24.dp)
        )
    } else {
        item.payload.attachments.forEach { ref ->
            ListItem(
                headlineContent = { Text(ref.fileName) },
                supportingContent = { Text("${ref.sizeBytes / 1024} KB") },
                trailingContent = {
                    Row {
                        IconButton({ confirmOpen = ref }) {
                            Icon(Icons.Filled.OpenInNew, contentDescription = "Open ${ref.fileName}")
                        }
                        IconButton({
                            chooseSaveFile(ref.fileName)?.let { target ->
                                scope.launch {
                                    val session = services.vaultManager.session.value ?: return@launch
                                    runCatching {
                                        target.outputStream().use { services.attachments.read(session, ref, it) }
                                    }
                                }
                            }
                        }) { Icon(Icons.Filled.Download, contentDescription = "Save ${ref.fileName}") }
                    }
                }
            )
        }
    }

    confirmOpen?.let { ref ->
        AlertDialog(
            onDismissRequest = { confirmOpen = null },
            title = { Text("Open in another application?") },
            text = {
                Text(
                    "SecureVault has no built-in viewer, so this file is decrypted to a private " +
                        "directory and handed to an application that can display it. While that " +
                        "application has it open, a decrypted copy exists on this machine, and it " +
                        "may keep its own copy.\n\n" +
                        if (services.attachmentViewer.volatileStorage)
                            "The copy goes to your session's runtime directory, which is cleared at logout."
                        else
                            "This session has no runtime directory, so the copy is written to disk. " +
                                "It is deleted when the vault locks or SecureVault restarts."
                )
            },
            confirmButton = {
                TextButton({
                    val ref2 = ref; confirmOpen = null
                    scope.launch {
                        val session = services.vaultManager.session.value ?: return@launch
                        services.attachmentViewer.open(session, ref2)
                    }
                }) { Text("Open") }
            },
            dismissButton = { TextButton({ confirmOpen = null }) { Text("Cancel") } }
        )
    }
}

// ---- editor ------------------------------------------------------------------------------------

/**
 * One editor for every item type, driven by the same [ItemSchema] Android uses.
 *
 * A screen per type would mean ten near-identical files and ten chances to forget that a field is
 * secret. The schema says which fields exist and which are masked.
 */
// FlowRow (folder and tag chips) is still an experimental layout API.
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ItemEditorDialog(existingId: String?, type: ItemType, onClose: () -> Unit) {
    val state = LocalAppState.current
    val existing = remember(existingId) { existingId?.let { state.itemById(it) } }
    val folders by state.folders.collectAsState()
    val specs = remember(type) { ItemSchema.fieldsFor(type) }
    val settings by state.settings.collectAsState()

    var title by remember { mutableStateOf(existing?.title.orEmpty()) }
    val values = remember {
        mutableStateMapOf<String, String>().apply {
            specs.forEach { put(it.key, existing?.payload?.field(it.key).orEmpty()) }
            if (existing == null) {
                ItemSchema.generatedFieldFor(type)?.let { field ->
                    state.consumeGeneratedPassword()?.let { put(field, it) }
                }
            }
        }
    }
    var notes by remember { mutableStateOf(existing?.payload?.notes.orEmpty()) }
    var favorite by remember { mutableStateOf(existing?.favorite ?: false) }
    var folderId by remember { mutableStateOf(existing?.folderId) }
    val tags = remember { mutableStateListOf<String>().apply { addAll(existing?.payload?.tags.orEmpty()) } }
    var tagDraft by remember { mutableStateOf("") }
    var totp by remember { mutableStateOf(existing?.payload?.totp) }
    var totpDraft by remember { mutableStateOf("") }
    var revealed by remember { mutableStateOf(setOf<String>()) }

    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(if (existing == null) "New ${type.displayName.lowercase()}" else "Edit item") },
        text = {
            Column(Modifier.width(560.dp).heightIn(max = 560.dp).verticalScroll(rememberScrollState())) {
                OutlinedTextField(title, { title = it }, label = { Text("Name") },
                    placeholder = { Text(ItemSchema.titleHintFor(type)) },
                    singleLine = true, isError = title.isBlank(), modifier = Modifier.fillMaxWidth())

                specs.forEach { spec ->
                    Spacer(Modifier.height(8.dp))
                    val isRevealed = spec.key in revealed
                    OutlinedTextField(
                        values[spec.key].orEmpty(), { values[spec.key] = it },
                        label = { Text(spec.label) },
                        singleLine = spec.kind != FieldKind.MULTILINE,
                        minLines = if (spec.kind == FieldKind.MULTILINE) 3 else 1,
                        visualTransformation = if (spec.isSecret && !isRevealed)
                            PasswordVisualTransformation() else VisualTransformation.None,
                        trailingIcon = {
                            Row {
                                if (spec.isSecret) {
                                    IconButton({
                                        revealed = if (isRevealed) revealed - spec.key else revealed + spec.key
                                    }) {
                                        Icon(
                                            if (isRevealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                            contentDescription = if (isRevealed) "Hide" else "Show"
                                        )
                                    }
                                }
                                if (spec.key == ItemSchema.generatedFieldFor(type)) {
                                    IconButton({
                                        values[spec.key] = PasswordGenerator.generate(
                                            PasswordOptions(length = settings.defaultPasswordLength)
                                        )
                                        revealed = revealed + spec.key
                                    }) { Icon(Icons.Filled.Autorenew, contentDescription = "Generate") }
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                if (ItemSchema.supportsTotp(type)) {
                    SectionHeader("Two-factor code")
                    if (totp != null) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                "${totp!!.algorithm} · ${totp!!.digits} digits · ${totp!!.periodSeconds}s",
                                Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium
                            )
                            TextButton({ totp = null }) { Text("Remove") }
                        }
                    } else {
                        OutlinedTextField(
                            totpDraft, { totpDraft = it },
                            label = { Text("Setup key or otpauth:// link") },
                            singleLine = true,
                            supportingText = {
                                // No QR scanning on the desktop: there is no camera path worth
                                // trusting here, and a fake one would be worse than none.
                                Text("Paste the setup key your account shows for an authenticator app.")
                            },
                            modifier = Modifier.fillMaxWidth()
                        )
                        val parsed = remember(totpDraft) { parseTotp(totpDraft) }
                        TextButton({ totp = parsed; totpDraft = "" }, enabled = parsed != null) {
                            Text(if (parsed == null && totpDraft.isNotBlank()) "Not a valid setup key" else "Add code")
                        }
                    }
                }

                SectionHeader("Notes")
                OutlinedTextField(notes, { notes = it }, minLines = 3, modifier = Modifier.fillMaxWidth())

                SectionHeader("Folder")
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(folderId == null, { folderId = null }, { Text("Unfiled") })
                    folders.forEach { f ->
                        FilterChip(folderId == f.id, { folderId = f.id }, { Text(f.name) })
                    }
                }

                SectionHeader("Tags")
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    tags.forEach { tag ->
                        InputChip(true, { tags.remove(tag) }, { Text(tag) })
                    }
                }
                OutlinedTextField(
                    tagDraft, { tagDraft = it }, label = { Text("Add a tag") }, singleLine = true,
                    trailingIcon = {
                        IconButton({
                            val clean = tagDraft.trim()
                            if (clean.isNotEmpty() && clean !in tags) tags.add(clean)
                            tagDraft = ""
                        }, enabled = tagDraft.isNotBlank()) { Icon(Icons.Filled.Add, "Add tag") }
                    },
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(favorite, { favorite = it })
                    Spacer(Modifier.width(10.dp))
                    Text("Favourite")
                }
            }
        },
        confirmButton = {
            TextButton({
                val payload = ItemPayload(
                    title = title.trim(),
                    fields = values.filterValues { it.isNotBlank() },
                    notes = notes.trim(),
                    tags = tags.toList(),
                    customFields = existing?.payload?.customFields.orEmpty(),
                    totp = totp,
                    recoveryCodes = existing?.payload?.recoveryCodes.orEmpty(),
                    attachments = existing?.payload?.attachments.orEmpty(),
                    passwordChangedAt = if (existing == null) System.currentTimeMillis()
                    else existing.payload.passwordChangedAt,
                    requiresTwoFactor = totp != null
                )
                val item = existing?.copy(
                    payload = payload, favorite = favorite, folderId = folderId,
                    updatedAt = System.currentTimeMillis()
                ) ?: VaultItem(type = type, payload = payload, favorite = favorite, folderId = folderId)
                state.save(item)
                onClose()
            }, enabled = title.isNotBlank()) { Text("Save") }
        },
        dismissButton = { TextButton(onClose) { Text("Cancel") } }
    )
}

private fun parseTotp(raw: String): TotpConfig? {
    val trimmed = raw.trim()
    return when {
        trimmed.isBlank() -> null
        trimmed.startsWith("otpauth://") -> OtpAuthUri.parse(trimmed)
        TotpEngine.isValidSecret(trimmed) ->
            TotpConfig(secretBase32 = trimmed.replace(" ", "").uppercase())
        else -> null
    }
}

internal fun formatMoment(millis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(millis))

/** Swing file dialogs: the only file pickers available to a plain JVM desktop application. */
internal fun chooseSaveFile(suggestedName: String): java.io.File? {
    val chooser = JFileChooser().apply {
        dialogTitle = "Save as"
        selectedFile = java.io.File(System.getProperty("user.home"), suggestedName)
    }
    return if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) chooser.selectedFile else null
}

internal fun chooseOpenFile(title: String): java.io.File? {
    val chooser = JFileChooser().apply {
        dialogTitle = title
        currentDirectory = java.io.File(System.getProperty("user.home"))
    }
    return if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) chooser.selectedFile else null
}
