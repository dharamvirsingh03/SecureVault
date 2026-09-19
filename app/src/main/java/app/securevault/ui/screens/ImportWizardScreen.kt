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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.securevault.core.model.Fields
import app.securevault.feature.csv.CsvFormat
import app.securevault.feature.csv.DuplicateAction
import app.securevault.ui.ImportState
import app.securevault.ui.VaultViewModel
import app.securevault.ui.components.InfoCard
import app.securevault.ui.components.SectionHeader
import app.securevault.ui.components.WarningCard

/**
 * The CSV import wizard: select, detect, map, preview, choose, import, summarise.
 *
 * Every step is visible because a silent import is how people end up with four hundred
 * half-broken entries and no idea which ones failed. The wizard reads the file once through the
 * URI the user picked and never copies it into app storage.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportWizardScreen(viewModel: VaultViewModel, onBack: () -> Unit) {
    val state by viewModel.importState.collectAsState()
    val busy by viewModel.busy.collectAsState()

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { viewModel.beginImport(it) } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Import from CSV") },
                navigationIcon = {
                    IconButton(onClick = { viewModel.cancelImport(); onBack() }) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (busy != null) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(
                    busy!!,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                )
            }

            when (val current = state) {
                is ImportState.Idle -> SelectStep(
                    onPick = { picker.launch(arrayOf("text/csv", "text/comma-separated-values", "text/plain", "*/*")) }
                )

                is ImportState.Failed -> Column(Modifier.padding(20.dp)) {
                    WarningCard(current.reason)
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { viewModel.cancelImport() }) { Text("Try another file") }
                }

                is ImportState.Mapping -> MappingStep(
                    state = current,
                    onChange = viewModel::updateMapping,
                    onContinue = { viewModel.prepareImport() },
                    onCancel = { viewModel.cancelImport() }
                )

                is ImportState.Preview -> PreviewStep(
                    state = current,
                    onImport = { viewModel.commitImport(it) },
                    onBack = { viewModel.cancelImport() }
                )

                is ImportState.Done -> SummaryStep(
                    state = current,
                    onDone = { viewModel.cancelImport(); onBack() }
                )
            }
        }
    }
}

@Composable
private fun SelectStep(onPick: () -> Unit) {
    Column(Modifier.padding(20.dp)) {
        Text("Step 1 of 5 — choose a file", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(12.dp))
        WarningCard(
            "A password export is a plaintext file. Anyone who reads it has every password in it. " +
                "Export it, import it here, then delete the file and empty your downloads."
        )
        Spacer(Modifier.height(16.dp))
        InfoCard(
            "SecureVault recognises exports from Bitwarden, 1Password, LastPass, Chrome and " +
                "KeePass. Anything else is treated as a generic CSV and you map the columns " +
                "yourself in the next step."
        )
        Spacer(Modifier.height(20.dp))
        Button(onClick = onPick) {
            Icon(Icons.Filled.UploadFile, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Choose a CSV file")
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun MappingStep(
    state: ImportState.Mapping,
    onChange: (Int, String?) -> Unit,
    onContinue: () -> Unit,
    onCancel: () -> Unit
) {
    var editingColumn by remember { mutableStateOf<Int?>(null) }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
            Text("Step 2 of 5 — check the columns", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                "Detected format: ${state.parsed.format.label}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                "${state.parsed.rows.size} rows. Tap a column to change what it maps to.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        LazyColumn(Modifier.weight(1f)) {
            items(state.parsed.header.size) { index ->
                val header = state.parsed.header[index]
                val mapped = state.mapping[index]
                val sample = state.parsed.rows.firstOrNull()?.getOrNull(index).orEmpty()
                ListItem(
                    headlineContent = { Text(header.ifBlank { "Column ${index + 1}" }) },
                    supportingContent = {
                        Column {
                            Text(
                                mapped?.let { "→ ${labelFor(it)}" } ?: "→ not imported",
                                color = if (mapped == null) MaterialTheme.colorScheme.onSurfaceVariant
                                else MaterialTheme.colorScheme.primary
                            )
                            if (sample.isNotBlank()) {
                                // First row only, and never rendered as a secret: at this point
                                // the user is looking at their own plaintext export either way.
                                Text(
                                    "e.g. ${sample.take(40)}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    },
                    trailingContent = {
                        TextButton(onClick = { editingColumn = index }) { Text("Change") }
                    }
                )
                if (editingColumn == index) {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterChip(
                            selected = mapped == null,
                            onClick = { onChange(index, null); editingColumn = null },
                            label = { Text("Skip") }
                        )
                        // TARGET_FIELDS pairs the canonical field key with its display label.
                        // The key is what the mapping stores; the label is only for the chip.
                        CsvFormat.TARGET_FIELDS.forEach { (field, label) ->
                            FilterChip(
                                selected = mapped == field,
                                onClick = { onChange(index, field); editingColumn = null },
                                label = { Text(label) }
                            )
                        }
                    }
                }
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(20.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = onContinue,
                enabled = state.mapping.values.any { it == CsvFormat.TITLE || it == Fields.USERNAME || it == Fields.URL }
            ) { Text("Preview") }
            TextButton(onClick = onCancel) { Text("Start over") }
        }
    }
}

@Composable
private fun PreviewStep(
    state: ImportState.Preview,
    onImport: (DuplicateAction) -> Unit,
    onBack: () -> Unit
) {
    var action by remember { mutableStateOf(DuplicateAction.SKIP) }

    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
            Text("Step 3 of 5 — preview", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text("New: ${state.newCount}", style = MaterialTheme.typography.bodyMedium)
            Text("Possible duplicates: ${state.duplicateCount}", style = MaterialTheme.typography.bodyMedium)
            Text("Rows with problems: ${state.invalidCount}", style = MaterialTheme.typography.bodyMedium)
        }

        LazyColumn(Modifier.weight(1f)) {
            item { SectionHeader("First rows") }
            items(state.records.take(25)) { record ->
                ListItem(
                    headlineContent = { Text(record.item.title.ifBlank { "Untitled row" }) },
                    supportingContent = {
                        // Read into a local first. `isDuplicateOf` is a public property of
                        // PreparedRecord, which now lives in :core, and Kotlin will not smart-cast
                        // a public property declared in another module -- it cannot prove the
                        // value has not changed between the null check and the use.
                        val duplicateOf = record.isDuplicateOf
                        Column {
                            if (record.item.username.isNotBlank()) Text(record.item.username)
                            when {
                                duplicateOf != null -> Text(
                                    "Looks like your existing \"${duplicateOf.title}\"",
                                    color = MaterialTheme.colorScheme.tertiary
                                )
                                !record.isValid -> Text(
                                    record.problems.joinToString("; "),
                                    color = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    }
                )
            }
            if (state.records.size > 25) {
                item {
                    Text(
                        "…and ${state.records.size - 25} more",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(20.dp)
                    )
                }
            }
        }

        Column(Modifier.padding(20.dp)) {
            Text("Step 4 of 5 — what to do with duplicates", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            DuplicateAction.entries.forEach { option ->
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    FilterChip(
                        selected = action == option,
                        onClick = { action = option },
                        label = { Text(duplicateLabel(option)) }
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = { onImport(action) }) { Text("Import") }
                TextButton(onClick = onBack) { Text("Start over") }
            }
        }
    }
}

@Composable
private fun SummaryStep(state: ImportState.Done, onDone: () -> Unit) {
    Column(Modifier.padding(20.dp)) {
        Text("Step 5 of 5 — done", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(12.dp))
        Text("Imported: ${state.summary.imported}", style = MaterialTheme.typography.bodyLarge)
        Text("Skipped: ${state.summary.skipped}", style = MaterialTheme.typography.bodyLarge)
        Text("Duplicates found: ${state.summary.duplicates}", style = MaterialTheme.typography.bodyLarge)
        Text("Invalid rows: ${state.summary.invalid}", style = MaterialTheme.typography.bodyLarge)
        if (state.summary.warnings.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            SectionHeader("Warnings")
            state.summary.warnings.take(10).forEach {
                Text("• $it", style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(20.dp))
        WarningCard(
            "Now delete the CSV file you imported from, and empty your downloads folder and " +
                "recycle bin. It still holds every one of those passwords in the clear."
        )
        Spacer(Modifier.height(20.dp))
        Button(onClick = onDone) { Text("Done") }
    }
}

private fun duplicateLabel(action: DuplicateAction) = when (action) {
    DuplicateAction.SKIP -> "Skip duplicates (safest)"
    DuplicateAction.KEEP_BOTH -> "Keep both copies"
    DuplicateAction.REPLACE_EXISTING -> "Replace what I already have"
}

private fun labelFor(field: String): String = when (field) {
    CsvFormat.TITLE -> "Name"
    CsvFormat.NOTES -> "Notes"
    CsvFormat.TOTP -> "Two-factor key"
    CsvFormat.FOLDER -> "Folder"
    CsvFormat.TAGS -> "Tags"
    CsvFormat.FAVORITE -> "Favourite"
    CsvFormat.TYPE -> "Item type"
    Fields.USERNAME -> "Username"
    Fields.EMAIL -> "Email"
    Fields.PASSWORD -> "Password"
    Fields.URL -> "Website"
    else -> field.removePrefix("__").replaceFirstChar { it.uppercase() }
}
