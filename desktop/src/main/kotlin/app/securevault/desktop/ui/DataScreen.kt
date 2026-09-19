package app.securevault.desktop.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.securevault.desktop.*
import app.securevault.feature.csv.DuplicateAction
import app.securevault.feature.csv.ExportSelection
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Backup, verify, restore, CSV and the recovery kit.
 *
 * Every safety property on this screen lives in `:core`: the backup container, the restore
 * journal, staging, extraction bounds, path-traversal guards and existing-vault protection are
 * the same code Android runs. This is file pickers and confirmations around it.
 */
@Composable
fun DataScreen() {
    val state = LocalAppState.current
    val services = LocalServices.current
    val scope = rememberCoroutineScope()
    val restoreState by state.restoreState.collectAsState()
    val verifyState by state.verifyState.collectAsState()
    val importState by state.importState.collectAsState()

    var passwordPrompt by remember { mutableStateOf<Pair<String, (CharArray) -> Unit>?>(null) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp)) {
        Text("Backup & data", style = MaterialTheme.typography.headlineSmall)

        // ---- backup ------------------------------------------------------------------------
        SectionHeader("Encrypted backup")
        InfoCard(
            "A .securevault backup is encrypted with your vault key and is the same format " +
                "Android writes and reads. Your master password is not inside it in any form. " +
                "This is the file that moves a vault between machines."
        )
        Spacer(Modifier.height(12.dp))
        InfoLine("Items", "${state.allItems().size}")
        InfoLine("Key derivation", state.kdfDescription())
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button({
                val stamp = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
                chooseSaveFile("securevault-$stamp.securevault")?.let { target ->
                    state.createBackup(target, services, scope)
                }
            }) { Text("Create backup") }

            OutlinedButton({
                chooseOpenFile("Choose a backup to verify")?.let { file ->
                    passwordPrompt = "Verify backup" to { pw -> state.verifyBackup(file, pw, services, scope) }
                }
            }) { Text("Verify a backup") }
        }

        when (val v = verifyState) {
            is VerifyState.Verified -> {
                Spacer(Modifier.height(12.dp))
                InfoCard(
                    "Backup verified. Every chunk decrypted and authenticated, and nothing was " +
                        "written.\nMade ${formatMoment(v.createdAt)} · ${v.kdf} · format v${v.formatVersion}"
                )
                TextButton({ state.dismissVerification() }) { Text("Dismiss") }
            }
            is VerifyState.Failed -> {
                Spacer(Modifier.height(12.dp))
                WarningCard("This backup cannot be trusted for restoration.\n\n${v.failure.userMessage}")
                Text(
                    "Your current vault is fine. Nothing on this machine was read, changed or deleted.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 8.dp)
                )
                TextButton({ state.dismissVerification() }) { Text("Dismiss") }
            }
            VerifyState.Idle -> {}
        }

        // ---- restore -----------------------------------------------------------------------
        SectionHeader("Restore")
        when (val r = restoreState) {
            RestoreState.Idle -> {
                if (state.restoreRequiresEmptyDevice()) {
                    WarningCard(
                        "You already have a vault, and SecureVault holds one at a time. Restoring " +
                            "will not overwrite it, and there is no button here that would.\n\n" +
                            "To move to a restored vault deliberately: back up what you have, " +
                            "delete the current vault from Settings with the typed confirmation, " +
                            "then come back. Those steps are separate on purpose."
                    )
                    Spacer(Modifier.height(10.dp))
                }
                Button({
                    chooseOpenFile("Choose a .securevault file")?.let { file ->
                        passwordPrompt = "Open backup" to { pw -> state.stageRestore(file, pw, services, scope) }
                    }
                }) { Text("Choose a backup to restore") }
            }
            is RestoreState.Staged -> {
                val p = r.staged.preview
                InfoCard("This backup will create a new vault. Your current vault will not be overwritten.")
                Spacer(Modifier.height(10.dp))
                InfoLine("Vault name", p.vaultName)
                InfoLine("Items", "${p.itemCount}")
                InfoLine("Folders", "${p.folderCount}")
                InfoLine("Tags", "${p.tagCount}")
                InfoLine("Attachments", "${p.attachmentCount}")
                InfoLine("Backup made", formatMoment(p.backupCreatedAt))
                InfoLine("Backup format", "version ${p.backupFormatVersion}")
                InfoLine("Key derivation", p.kdfDescription)
                InfoLine("Recovery code", if (p.hasRecoveryBlock) "Included" else "Not set up")
                Spacer(Modifier.height(8.dp))
                Text(
                    "No password, one-time code or note from this backup is shown here, and none " +
                        "has been written to this machine yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button({
                        passwordPrompt = "Confirm restore" to { pw -> state.commitRestore(pw, services, scope) }
                    }) { Text("Restore as new vault") }
                    TextButton({ state.cancelRestore() }) { Text("Cancel") }
                }
            }
            is RestoreState.Done -> {
                val s = r.summary
                InfoCard(
                    "Vault restored: ${s.items} items, ${s.folders} folders, ${s.attachments} " +
                        "attachments.\n\nThe restored vault is locked. Open it with the master " +
                        "password that opened the backup — restore does not skip that step."
                )
                Spacer(Modifier.height(10.dp))
                Button({ state.cancelRestore(); state.refreshAfterRestore(); state.lock() }) {
                    Text("Open restored vault")
                }
            }
            is RestoreState.Failed -> {
                WarningCard(r.failure.userMessage)
                Text(
                    "Nothing was restored and nothing on this machine was changed.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 8.dp)
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button({ state.cancelRestore() }) { Text("Try another backup") }
                }
            }
        }

        // ---- CSV ---------------------------------------------------------------------------
        SectionHeader("CSV")
        WarningCard(
            "CSV is plaintext. Every password in the file can be read by anyone and by any " +
                "application that can reach it. Export it, use it, then delete it."
        )
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton({
                chooseOpenFile("Choose a CSV to import")?.let { state.beginImport(it, scope) }
            }) { Text("Import from CSV") }
            OutlinedButton({
                val stamp = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
                chooseSaveFile("securevault-export-$stamp.csv")?.let { target ->
                    state.exportCsv(
                        target,
                        ExportSelection(items = state.allItems(), includeNotes = true),
                        scope
                    )
                }
            }) { Text("Export entire vault") }
        }
        ImportPanel(importState, services, scope)

        // ---- recovery ----------------------------------------------------------------------
        SectionHeader("Recovery")
        if (state.hasRecovery()) {
            Text("Recovery is on for this vault.", style = MaterialTheme.typography.bodyMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button({ state.enableRecovery() }) { Text("Generate a new code") }
                TextButton({ state.disableRecovery() }) { Text("Turn recovery off") }
            }
        } else {
            WarningCard(
                "A recovery code is an alternative to your master password, not an addition to " +
                    "it. Anyone holding it and a copy of your vault gets in."
            )
            Spacer(Modifier.height(10.dp))
            Button({ state.enableRecovery() }) { Text("Set up a recovery code") }
        }

        SectionHeader("Emergency recovery kit")
        InfoCard(
            "A printable page with no passwords on it: which algorithm and settings protect your " +
                "vault, its salt and id, restore instructions, and blank ruled lines for your " +
                "master password and recovery code to fill in by hand."
        )
        Spacer(Modifier.height(10.dp))
        Button({
            chooseSaveFile("securevault-recovery-kit.pdf")?.let { state.writeRecoveryKit(it, null) }
        }) { Text("Generate recovery kit PDF") }

        Spacer(Modifier.height(48.dp))
    }

    passwordPrompt?.let { (title, action) ->
        var password by remember(title) { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { passwordPrompt = null },
            title = { Text(title) },
            text = {
                OutlinedTextField(
                    password, { password = it }, label = { Text("Master password") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                TextButton({
                    val chars = password.toCharArray()
                    password = ""
                    passwordPrompt = null
                    action(chars)
                }, enabled = password.isNotEmpty()) { Text("Continue") }
            },
            dismissButton = { TextButton({ passwordPrompt = null }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun ImportPanel(
    importState: ImportState,
    services: Services,
    scope: kotlinx.coroutines.CoroutineScope
) {
    val state = LocalAppState.current
    when (val current = importState) {
        ImportState.Idle -> {}
        is ImportState.Failed -> {
            Spacer(Modifier.height(10.dp))
            WarningCard(current.reason)
            TextButton({ state.cancelImport() }) { Text("Dismiss") }
        }
        is ImportState.Mapping -> {
            Spacer(Modifier.height(10.dp))
            InfoCard(
                "Detected format: ${current.parsed.format.label}\n" +
                    "${current.parsed.rows.size} rows, ${current.mapping.size} columns mapped."
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button({ state.prepareImport(services, scope) }) { Text("Preview") }
                TextButton({ state.cancelImport() }) { Text("Cancel") }
            }
        }
        is ImportState.Preview -> {
            Spacer(Modifier.height(10.dp))
            InfoCard(
                "New: ${current.newCount}   Possible duplicates: ${current.duplicateCount}   " +
                    "Rows with problems: ${current.invalidCount}"
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                DuplicateAction.entries.forEach { action ->
                    OutlinedButton({ state.commitImport(action, services, scope) }) {
                        Text(
                            when (action) {
                                DuplicateAction.SKIP -> "Import, skip duplicates"
                                DuplicateAction.KEEP_BOTH -> "Import, keep both"
                                DuplicateAction.REPLACE_EXISTING -> "Import, replace existing"
                            }
                        )
                    }
                }
            }
            TextButton({ state.cancelImport() }) { Text("Cancel") }
        }
        is ImportState.Done -> {
            Spacer(Modifier.height(10.dp))
            InfoCard(
                "Imported: ${current.summary.imported}   Skipped: ${current.summary.skipped}   " +
                    "Duplicates: ${current.summary.duplicates}   Invalid: ${current.summary.invalid}"
            )
            WarningCard("Now delete the CSV file you imported from. It holds every one of those passwords in the clear.")
            TextButton({ state.cancelImport() }) { Text("Done") }
        }
    }
}
