package app.securevault.desktop

import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.UnsupportedFormatException
import app.securevault.core.crypto.VaultIntegrityException
import app.securevault.core.model.VaultItem
import app.securevault.feature.backup.RestoreFailure
import app.securevault.feature.csv.CsvExporter
import app.securevault.feature.csv.CsvImporter
import app.securevault.feature.csv.DuplicateAction
import app.securevault.feature.csv.ExportSelection
import kotlinx.coroutines.launch
import java.io.File

/**
 * Backup, restore, verification and CSV for the desktop.
 *
 * Separated from [AppState] only to keep one file readable; the important property is that none of
 * these functions contains any format or safety logic. Backup creation, restore staging, journal
 * recovery, extraction bounds and path-traversal guards all happen inside `:core`, in the same
 * code Android runs. These are file pickers and progress messages wrapped around it.
 */

fun AppState.createBackup(target: File, services: Services, scope: kotlinx.coroutines.CoroutineScope) {
    val session = services.vaultManager.session.value ?: return
    val metadata = services.vaultManager.metadata() ?: return
    scope.launch {
        runCatching {
            val items = services.index.items.value
            val folders = services.index.folders.value
            val attachments = services.attachments.allEncryptedFiles()
            val backupKey = session.backupKey()
            target.outputStream().use { out ->
                services.backupCodec.create(metadata, backupKey, items, folders, attachments, out)
            }
            app.securevault.desktop.platform.Paths.restrict(target)
        }.onSuccess { post("Encrypted backup written to ${target.name}") }
            .onFailure { post("The backup could not be written") }
    }
}

/**
 * Verifies a backup without writing anything.
 *
 * Failures are reported as their own state rather than a transient message: "this backup cannot be
 * trusted" is something a user has to act on and may need to read twice.
 */
fun AppState.verifyBackup(file: File, password: CharArray, services: Services, scope: kotlinx.coroutines.CoroutineScope) {
    scope.launch {
        setBusy("Verifying backup")
        val outcome = runCatching {
            file.inputStream().use { input ->
                services.backupCodec.verify(input) { header ->
                    val kek = try {
                        KeyHierarchy.deriveKek(password, header.kdf)
                    } catch (e: KdfUnavailableException) {
                        throw RestoreFailure.KdfUnavailable(e.algorithm.displayName)
                    }
                    try {
                        val vek = try {
                            KeyHierarchy.unwrapVek(kek, header.wrappedVek, header.vaultId)
                        } catch (e: app.securevault.core.crypto.InvalidCredentialsException) {
                            throw RestoreFailure.AuthenticationFailed
                        }
                        try { services.backupCodec.backupKeyFrom(vek) } finally { vek.fill(0) }
                    } finally {
                        kek.fill(0)
                    }
                }
            }
        }
        password.fill('\u0000')
        setBusy(null)
        outcome.onSuccess { header ->
            setVerifyState(
                VerifyState.Verified(header.createdAt, header.kdf.describe(), header.formatVersion)
            )
        }.onFailure { error -> setVerifyState(VerifyState.Failed(error.asRestoreFailure())) }
    }
}

fun AppState.stageRestore(file: File, password: CharArray, services: Services, scope: kotlinx.coroutines.CoroutineScope) {
    scope.launch {
        setBusy("Decrypting and checking backup")
        runCatching { services.restorer.recoverInterruptedRestore() }
        val outcome = runCatching {
            services.restorer.stage({ file.inputStream() }, password)
        }
        password.fill('\u0000')
        setBusy(null)
        outcome.onSuccess { setRestoreState(RestoreState.Staged(it)) }
            .onFailure { setRestoreState(RestoreState.Failed(it.asRestoreFailure())) }
    }
}

fun AppState.commitRestore(password: CharArray, services: Services, scope: kotlinx.coroutines.CoroutineScope) {
    val staged = (restoreState.value as? RestoreState.Staged)?.staged ?: return
    scope.launch {
        setBusy("Restoring vault")
        val outcome = runCatching {
            services.restorer.commit(
                staged = staged,
                password = password,
                currentState = services.vaultManager.state(),
                installHeader = { services.vaultManager.installRestoredHeader(it) }
            )
        }
        password.fill('\u0000')
        setBusy(null)
        outcome.onSuccess { setRestoreState(RestoreState.Done(it)) }
            .onFailure { setRestoreState(RestoreState.Failed(it.asRestoreFailure())) }
    }
}

// ---- CSV -------------------------------------------------------------------------------------

fun AppState.beginImport(file: File, scope: kotlinx.coroutines.CoroutineScope) {
    scope.launch {
        setBusy("Reading file")
        runCatching { CsvImporter().parse(file.readText()) }
            .onSuccess { setImportState(ImportState.Mapping(it, it.mapping)) }
            .onFailure {
                setImportState(ImportState.Failed(it.message ?: "That file could not be read as CSV"))
            }
        setBusy(null)
    }
}

fun AppState.prepareImport(services: Services, scope: kotlinx.coroutines.CoroutineScope) {
    val state = importState.value as? ImportState.Mapping ?: return
    scope.launch {
        setBusy("Checking rows")
        runCatching { CsvImporter().prepare(state.parsed, state.mapping, services.index.items.value) }
            .onSuccess { setImportState(ImportState.Preview(state.parsed, state.mapping, it)) }
            .onFailure { setImportState(ImportState.Failed(it.message ?: "Those rows could not be read")) }
        setBusy(null)
    }
}

fun AppState.commitImport(action: DuplicateAction, services: Services, scope: kotlinx.coroutines.CoroutineScope) {
    val session = services.vaultManager.session.value ?: return
    val state = importState.value as? ImportState.Preview ?: return
    scope.launch {
        setBusy("Encrypting and saving")
        runCatching {
            val (toWrite, summary) = CsvImporter().resolve(state.records, action)
            services.repository.saveAll(session, toWrite)
            services.index.refresh(session, services.repository)
            summary
        }.onSuccess { setImportState(ImportState.Done(it)) }
            .onFailure { setImportState(ImportState.Failed("Import failed. Nothing was saved.")) }
        setBusy(null)
    }
}

/**
 * Plaintext CSV, to a location the user picked.
 *
 * Never written into the SecureVault data directory: an unencrypted copy of every password sitting
 * beside the encrypted vault would undo the point of the vault.
 */
fun AppState.exportCsv(target: File, selection: ExportSelection, scope: kotlinx.coroutines.CoroutineScope) {
    scope.launch {
        val inDataDir = runCatching {
            target.canonicalPath.startsWith(
                app.securevault.desktop.platform.Paths.dataDir.canonicalPath + File.separator
            )
        }.getOrDefault(false)
        if (inDataDir) {
            post("Refusing to write a plaintext CSV inside SecureVault's own data directory.")
            return@launch
        }
        runCatching {
            target.outputStream().use { CsvExporter().export(selection, it) }
            app.securevault.desktop.platform.Paths.restrict(target)
        }.onSuccess {
            post("Exported ${selection.items.size} items in the clear. Delete the file when done.")
        }.onFailure { post("The export could not be written") }
    }
}

private fun Throwable.asRestoreFailure(): RestoreFailure = when (this) {
    is RestoreFailure -> this
    is UnsupportedFormatException ->
        if (message?.contains("not a SecureVault") == true) RestoreFailure.NotABackup
        else RestoreFailure.UnsupportedVersion(message.orEmpty())
    is VaultIntegrityException -> RestoreFailure.AuthenticationFailed
    else -> RestoreFailure.StorageFailed(message ?: "unexpected failure")
}
