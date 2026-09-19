package app.securevault.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.core.model.CustomField
import app.securevault.core.model.FieldKind
import app.securevault.core.model.Fields
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemSchema
import app.securevault.core.model.ItemType
import app.securevault.core.model.TotpConfig
import app.securevault.core.model.VaultItem
import app.securevault.feature.generator.PasswordGenerator
import app.securevault.feature.generator.PasswordOptions
import app.securevault.feature.generator.PasswordStrength
import app.securevault.feature.totp.OtpAuthUri
import app.securevault.feature.totp.TotpQrScanner
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.SectionHeader

/**
 * One editor for every item type, driven by [ItemSchema].
 *
 * A screen per type would mean ten near-identical files and ten chances for one of them to forget
 * that a field is secret. The schema says which fields exist and which are masked; this file only
 * knows how to draw a field.
 *
 * Secret values are masked while typing by default and revealed only on request, because the
 * common case for entering a password here is transcribing it somewhere other people can see.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ItemEditorScreen(
    viewModel: VaultViewModel,
    existingId: String?,
    type: ItemType,
    onClose: () -> Unit
) {
    val existing = remember(existingId) { existingId?.let { viewModel.itemById(it) } }
    val folders by viewModel.folders.collectAsState()
    val knownTags = remember { viewModel.allTags() }

    val specs = remember(type) { ItemSchema.fieldsFor(type) }

    var title by remember { mutableStateOf(existing?.title.orEmpty()) }
    val values = remember {
        mutableStateMapOf<String, String>().apply {
            specs.forEach { spec -> put(spec.key, existing?.payload?.field(spec.key).orEmpty()) }
        }
        // A password the generator handed over. Read once and cleared by the ViewModel, so
        // reopening this editor later starts empty.
        .also { map ->
            if (existing == null) {
                ItemSchema.generatedFieldFor(type)?.let { field ->
                    viewModel.consumeGeneratedPassword()?.let { map[field] = it }
                }
            }
        }
    }
    var notes by remember { mutableStateOf(existing?.payload?.notes.orEmpty()) }
    var favorite by remember { mutableStateOf(existing?.favorite ?: false) }
    var folderId by remember { mutableStateOf(existing?.folderId) }
    val tags = remember { mutableStateListOfTags(existing?.payload?.tags.orEmpty()) }
    val customFields = remember { mutableStateListOfCustom(existing?.payload?.customFields.orEmpty()) }
    var totp by remember { mutableStateOf(existing?.payload?.totp) }
    var recoveryCodes by remember {
        mutableStateOf(existing?.payload?.recoveryCodes.orEmpty().joinToString("\n"))
    }

    var revealed by remember { mutableStateOf(setOf<String>()) }
    var showScanner by remember { mutableStateOf(false) }
    var showTotpEntry by remember { mutableStateOf(false) }
    var showDiscard by remember { mutableStateOf(false) }

    if (showScanner) {
        TotpScanFlow(
            existing = totp,
            onConfirmed = { config ->
                totp = config
                showScanner = false
            },
            onCancel = { showScanner = false },
            onEnterByHand = {
                showScanner = false
                showTotpEntry = true
            }
        )
        return
    }

    fun buildItem(): VaultItem {
        val cleanedFields = values.filterValues { it.isNotBlank() }
        val passwordChanged = when {
            existing == null -> System.currentTimeMillis()
            cleanedFields[Fields.PASSWORD] != existing.payload.field(Fields.PASSWORD).ifBlank { null } ->
                System.currentTimeMillis()
            else -> existing.payload.passwordChangedAt
        }
        val payload = ItemPayload(
            title = title.trim(),
            fields = cleanedFields,
            notes = notes.trim(),
            tags = tags.toList(),
            customFields = customFields.filter { it.name.isNotBlank() },
            totp = totp,
            recoveryCodes = recoveryCodes.lines().map { it.trim() }.filter { it.isNotEmpty() },
            attachments = existing?.payload?.attachments.orEmpty(),
            passwordChangedAt = passwordChanged,
            requiresTwoFactor = totp != null || existing?.payload?.requiresTwoFactor == true
        )
        return existing?.copy(payload = payload, favorite = favorite, folderId = folderId,
            updatedAt = System.currentTimeMillis())
            ?: VaultItem(type = type, payload = payload, favorite = favorite, folderId = folderId)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (existing == null) "New ${type.displayName.lowercase()}" else "Edit") },
                navigationIcon = {
                    IconButton(onClick = { showDiscard = true }) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(
                        onClick = {
                            viewModel.save(buildItem())
                            onClose()
                        },
                        enabled = title.isNotBlank()
                    ) { Text("Save") }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(bottom = 40.dp)
        ) {
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Name") },
                placeholder = { Text(ItemSchema.titleHintFor(type)) },
                singleLine = true,
                isError = title.isBlank(),
                supportingText = if (title.isBlank()) {
                    { Text("Every item needs a name so you can find it again") }
                } else null,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)
            )

            specs.forEach { spec ->
                val isRevealed = spec.key in revealed
                OutlinedTextField(
                    value = values[spec.key].orEmpty(),
                    onValueChange = { values[spec.key] = it },
                    label = { Text(spec.label) },
                    placeholder = if (spec.hint.isNotBlank()) {
                        { Text(spec.hint) }
                    } else null,
                    singleLine = spec.kind != FieldKind.MULTILINE,
                    minLines = if (spec.kind == FieldKind.MULTILINE) 3 else 1,
                    visualTransformation =
                        if (spec.isSecret && !isRevealed) PasswordVisualTransformation()
                        else VisualTransformation.None,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = when (spec.kind) {
                            FieldKind.EMAIL -> KeyboardType.Email
                            FieldKind.URL -> KeyboardType.Uri
                            FieldKind.PHONE -> KeyboardType.Phone
                            FieldKind.HIDDEN -> KeyboardType.Password
                            else -> KeyboardType.Text
                        },
                        imeAction = ImeAction.Next
                    ),
                    trailingIcon = {
                        Row {
                            if (spec.isSecret) {
                                IconButton(onClick = {
                                    revealed = if (isRevealed) revealed - spec.key else revealed + spec.key
                                }) {
                                    Icon(
                                        if (isRevealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = if (isRevealed) "Hide" else "Show"
                                    )
                                }
                            }
                            if (spec.key == ItemSchema.generatedFieldFor(type)) {
                                IconButton(onClick = {
                                    values[spec.key] = PasswordGenerator.generate(
                                        PasswordOptions(
                                            length = viewModel.settings.value.defaultPasswordLength
                                        )
                                    )
                                    revealed = revealed + spec.key
                                }) {
                                    Icon(Icons.Filled.Refresh, contentDescription = "Generate")
                                }
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)
                )

                if (spec.key == ItemSchema.generatedFieldFor(type)) {
                    val value = values[spec.key].orEmpty()
                    if (value.isNotEmpty()) {
                        val strength = PasswordStrength.evaluate(value)
                        Text(
                            "${strength.label.name.replace('_', ' ').lowercase()
                                .replaceFirstChar { it.uppercase() }} · ${strength.entropyBits.toInt()} bits",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 24.dp)
                        )
                    }
                }
            }

            // ---- one-time codes ------------------------------------------------------------
            if (ItemSchema.supportsTotp(type)) {
                SectionHeader("Two-factor code")
                if (totp != null) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("Authenticator set up", style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "${totp!!.algorithm} · ${totp!!.digits} digits · ${totp!!.periodSeconds}s",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(onClick = { totp = null }) {
                            Icon(Icons.Filled.Delete, contentDescription = "Remove code")
                        }
                    }
                } else {
                    Row(
                        modifier = Modifier.padding(horizontal = 20.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        AssistChip(
                            onClick = { showScanner = true },
                            label = { Text("Scan QR code") },
                            leadingIcon = { Icon(Icons.Filled.QrCodeScanner, contentDescription = null) }
                        )
                        AssistChip(
                            onClick = { showTotpEntry = true },
                            label = { Text("Enter setup key") }
                        )
                    }
                }
            }

            // ---- recovery codes ------------------------------------------------------------
            if (type == ItemType.LOGIN) {
                SectionHeader("Backup codes")
                OutlinedTextField(
                    value = recoveryCodes,
                    onValueChange = { recoveryCodes = it },
                    label = { Text("One per line") },
                    minLines = 2,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp)
                )
            }

            // ---- notes ----------------------------------------------------------------------
            SectionHeader(if (type == ItemType.SECURE_NOTE) "Note" else "Notes")
            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                minLines = if (type == ItemType.SECURE_NOTE) 8 else 3,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp)
            )

            // ---- organisation ---------------------------------------------------------------
            SectionHeader("Folder")
            FlowRow(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = folderId == null,
                    onClick = { folderId = null },
                    label = { Text("Unfiled") }
                )
                folders.forEach { folder ->
                    FilterChip(
                        selected = folderId == folder.id,
                        onClick = { folderId = folder.id },
                        label = { Text(folder.name) }
                    )
                }
            }

            SectionHeader("Tags")
            TagEditor(tags = tags, suggestions = knownTags)

            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Favourite", Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
                Switch(checked = favorite, onCheckedChange = { favorite = it })
            }

            // ---- custom fields ----------------------------------------------------------------
            SectionHeader("Custom fields", action = {
                IconButton(onClick = { customFields.add(CustomField("", "", FieldKind.TEXT)) }) {
                    Icon(Icons.Filled.Add, contentDescription = "Add a custom field")
                }
            })
            customFields.forEachIndexed { index, field ->
                Column(Modifier.padding(horizontal = 20.dp, vertical = 4.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = field.name,
                            onValueChange = { customFields[index] = field.copy(name = it) },
                            label = { Text("Label") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = { customFields.removeAt(index) }) {
                            Icon(Icons.Filled.Close, contentDescription = "Remove field")
                        }
                    }
                    OutlinedTextField(
                        value = field.value,
                        onValueChange = { customFields[index] = field.copy(value = it) },
                        label = { Text("Value") },
                        visualTransformation =
                            if (field.kind == FieldKind.HIDDEN) PasswordVisualTransformation()
                            else VisualTransformation.None,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Switch(
                            checked = field.kind == FieldKind.HIDDEN,
                            onCheckedChange = {
                                customFields[index] =
                                    field.copy(kind = if (it) FieldKind.HIDDEN else FieldKind.TEXT)
                            }
                        )
                        Text(
                            "  Treat as a secret (masked, and kept out of search)",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            if (existing == null && type == ItemType.DOCUMENT) {
                Spacer(Modifier.height(12.dp))
                InfoCard(
                    "Save this document first, then attach the file from the item screen. " +
                        "Attachments are encrypted separately, each with its own key.",
                    Modifier.padding(horizontal = 20.dp)
                )
            }
        }
    }

    if (showTotpEntry) {
        TotpManualEntryDialog(
            onDismiss = { showTotpEntry = false },
            onConfirm = { config ->
                totp = config
                showTotpEntry = false
            }
        )
    }

    if (showDiscard) {
        AlertDialog(
            onDismissRequest = { showDiscard = false },
            title = { Text("Discard changes?") },
            text = { Text("Anything you typed here will be lost. Nothing has been saved yet.") },
            confirmButton = {
                TextButton(onClick = { showDiscard = false; onClose() }) { Text("Discard") }
            },
            dismissButton = {
                TextButton(onClick = { showDiscard = false }) { Text("Keep editing") }
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TagEditor(tags: MutableList<String>, suggestions: List<String>) {
    var draft by remember { mutableStateOf("") }
    Column(Modifier.padding(horizontal = 20.dp)) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            tags.forEach { tag ->
                InputChip(
                    selected = true,
                    onClick = { tags.remove(tag) },
                    label = { Text(tag) },
                    trailingIcon = { Icon(Icons.Filled.Close, contentDescription = "Remove $tag") }
                )
            }
        }
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            label = { Text("Add a tag") },
            singleLine = true,
            trailingIcon = {
                IconButton(
                    onClick = {
                        val clean = draft.trim()
                        if (clean.isNotEmpty() && clean !in tags) tags.add(clean)
                        draft = ""
                    },
                    enabled = draft.isNotBlank()
                ) { Icon(Icons.Filled.Add, contentDescription = "Add tag") }
            },
            modifier = Modifier.fillMaxWidth()
        )
        val unused = suggestions.filter { it !in tags && it.contains(draft.trim(), ignoreCase = true) }
        if (unused.isNotEmpty()) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                unused.take(8).forEach { tag ->
                    AssistChip(onClick = { tags.add(tag); draft = "" }, label = { Text(tag) })
                }
            }
        }
    }
}

@Composable
private fun TotpManualEntryDialog(onDismiss: () -> Unit, onConfirm: (TotpConfig) -> Unit) {
    var raw by remember { mutableStateOf("") }
    val parsed = remember(raw) {
        val trimmed = raw.trim()
        when {
            trimmed.isBlank() -> null
            trimmed.startsWith("otpauth://") -> OtpAuthUri.parse(trimmed)
            app.securevault.feature.totp.TotpEngine.isValidSecret(trimmed) ->
                TotpConfig(secretBase32 = trimmed.replace(" ", "").uppercase())
            else -> null
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Enter a setup key") },
        text = {
            Column {
                OutlinedTextField(
                    value = raw,
                    onValueChange = { raw = it },
                    label = { Text("Setup key or otpauth:// link") },
                    isError = raw.isNotBlank() && parsed == null,
                    supportingText = {
                        Text(
                            when {
                                raw.isBlank() -> "The site shows this when it offers an authenticator app"
                                parsed == null -> "That is not a valid setup key"
                                else -> "${parsed.algorithm} · ${parsed.digits} digits · ${parsed.periodSeconds}s"
                            }
                        )
                    },
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { parsed?.let(onConfirm) }, enabled = parsed != null) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

private fun mutableStateListOfTags(initial: List<String>) =
    androidx.compose.runtime.mutableStateListOf<String>().also { it.addAll(initial) }

private fun mutableStateListOfCustom(initial: List<CustomField>) =
    androidx.compose.runtime.mutableStateListOf<CustomField>().also { it.addAll(initial) }

/**
 * Scan, parse, preview, confirm.
 *
 * The scanner used to hand a parsed config straight back to the editor, which meant two bad
 * things: an unreadable QR looked like the camera simply was not working, and a readable one was
 * accepted without the user ever seeing which account it belonged to. Both matter -- pointing a
 * camera at the wrong QR code on a page full of them is easy.
 *
 * The secret stays masked in the preview. Everything needed to recognise the code -- issuer,
 * account, algorithm, digits, period -- is shown without it.
 */
@Composable
private fun TotpScanFlow(
    existing: TotpConfig?,
    onConfirmed: (TotpConfig) -> Unit,
    onCancel: () -> Unit,
    onEnterByHand: () -> Unit
) {
    var scanned by remember { mutableStateOf<TotpConfig?>(null) }
    var invalid by remember { mutableStateOf(false) }
    var attempt by remember { mutableStateOf(0) }

    val pending = scanned
    if (pending != null) {
        TotpPreviewDialog(
            config = pending,
            replacingExisting = existing != null,
            onConfirm = { onConfirmed(pending) },
            onScanAgain = { scanned = null; invalid = false; attempt++ },
            onCancel = onCancel
        )
        return
    }

    Column(Modifier.fillMaxSize()) {
        if (invalid) {
            Column(Modifier.padding(20.dp)) {
                Text(
                    "That code is not an authenticator setup code",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive }
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "SecureVault reads otpauth:// codes, which are what a site shows when it " +
                        "offers an authenticator app. Point the camera at that one, or enter the " +
                        "setup key by hand.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(onClick = { invalid = false; attempt++ }) { Text("Scan again") }
                    TextButton(onClick = onEnterByHand) { Text("Enter by hand") }
                    TextButton(onClick = onCancel) { Text("Cancel") }
                }
            }
        }
        key(attempt) {
            TotpQrScanner(
                onScanned = { raw ->
                    if (scanned == null && !invalid) {
                        val parsed = OtpAuthUri.parse(raw)
                        if (parsed != null) scanned = parsed else invalid = true
                    }
                },
                onCancel = onEnterByHand
            )
        }
    }
}

@Composable
private fun TotpPreviewDialog(
    config: TotpConfig,
    replacingExisting: Boolean,
    onConfirm: () -> Unit,
    onScanAgain: () -> Unit,
    onCancel: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Add this two-factor code?") },
        text = {
            Column {
                if (config.issuer.isNotBlank()) PreviewLine("Service", config.issuer)
                if (config.account.isNotBlank()) PreviewLine("Account", config.account)
                PreviewLine("Algorithm", config.algorithm)
                PreviewLine("Digits", "${config.digits}")
                PreviewLine("Refreshes every", "${config.periodSeconds} seconds")
                // Masked deliberately. The length is still a hint, so only a fixed number of dots
                // is shown rather than one per character.
                PreviewLine("Setup key", "••••••••  (hidden)")
                if (replacingExisting) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "This item already has a two-factor code. Confirming replaces it, and the " +
                            "old one cannot be recovered from here.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text("Confirm") } },
        dismissButton = {
            Row {
                TextButton(onClick = onScanAgain) { Text("Scan again") }
                TextButton(onClick = onCancel) { Text("Cancel") }
            }
        }
    )
}

@Composable
private fun PreviewLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
