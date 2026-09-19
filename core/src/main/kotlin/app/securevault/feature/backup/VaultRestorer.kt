package app.securevault.feature.backup

import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.UnsupportedFormatException
import app.securevault.core.crypto.VaultIntegrityException
import app.securevault.core.model.Folder
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultMetadata
import app.securevault.core.vault.VaultSession
import app.securevault.core.vault.VaultState
import app.securevault.data.repo.ItemRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.UUID

/** Everything the preview screen is allowed to show. All of it non-secret. */
data class RestorePreview(
    val vaultName: String,
    val vaultId: String,
    val backupId: String,
    val backupCreatedAt: Long,
    val backupFormatVersion: Int,
    val appVersion: String,
    val itemCount: Int,
    val folderCount: Int,
    val attachmentCount: Int,
    val tagCount: Int,
    val kdfDescription: String,
    val hasRecoveryBlock: Boolean,
    val legacyPlaintextMetadata: Boolean
)

data class RestoreSummary(
    val vaultName: String,
    val items: Int,
    val folders: Int,
    val attachments: Int,
    val tags: Int,
    val restoredAt: Long,
    val replacedExistingVault: Boolean
)

/**
 * A backup that has been fully decrypted, structurally validated and written to a private staging
 * directory, but not yet committed.
 *
 * Holds no key material. The password is supplied again at commit so the vault key is re-derived
 * rather than kept alive across a user confirmation that might take minutes.
 */
class StagedRestore internal constructor(
    val preview: RestorePreview,
    internal val header: BackupHeader,
    internal val items: List<VaultItem>,
    internal val folders: List<Folder>,
    internal val stagingDir: File
)

/**
 * Restores a `.securevault` backup into a vault.
 *
 * The shape of this class is the security design, so it is worth stating plainly.
 *
 * **Two phases, with the user in between.** [stage] decrypts and verifies the entire backup,
 * rebuilds every item and folder from it, writes attachments into a private staging directory, and
 * checks that what came out is a usable vault. It touches nothing the live app can see. Only
 * [commit] writes into the vault, and only after the user has seen a preview and said yes.
 *
 * **The header is the commit point, and a journal makes the gap recoverable.** Room records and
 * attachment files are written first; `metadata.json` -- the file the whole app keys "does a vault
 * exist" on -- is written last. Room cannot give us a filesystem-atomic transaction across three
 * stores, so instead of pretending, the ordering is chosen so an interruption leaves the app
 * seeing no vault.
 *
 * Ordering alone is not enough, though, and an earlier version of this class got that wrong. It
 * left Room rows and attachment blobs in live storage after a failed commit, and nothing cleared
 * them: a user who gave up and created a fresh vault instead inherited undecryptable ghost records
 * and orphaned attachment files forever. "A retry starts clean" was only true if the retry
 * happened to reach commit again.
 *
 * So a journal file is written *before* the first live write and removed *after* the header lands.
 * It is only ever written once no vault exists, which is what makes the recovery rule safe:
 *
 *   journal present, no header  -> an interrupted restore. Purge live records and attachments.
 *   journal present, header too -> the commit finished; only the marker survived. Delete it.
 *   no journal                  -> nothing to do.
 *
 * [recoverInterruptedRestore] applies that rule at startup and before any restore or vault
 * creation. This is still not atomicity, and SECURITY.md does not call it that.
 *
 * **The vault key is not rewrapped.** A restored vault keeps the backup's own vault id, KDF
 * parameters, salt and wrapped VEK. That is what makes attachments and item records from the
 * backup valid as they stand: the same VEK derives the same item and attachment subkeys. It also
 * means restore cannot quietly move a vault onto weaker KDF settings, because it never chooses
 * any.
 */
class VaultRestorer(
    private val codec: BackupCodec,
    private val repository: ItemRepository,
    private val liveAttachmentsDir: File,
    private val stagingRoot: File,
    private val journalFile: File,
    private val vaultHeaderExists: () -> Boolean
) {

    /**
     * Decrypts, verifies and validates a backup without touching the live vault.
     *
     * @throws RestoreFailure for every expected problem. Nothing else should escape.
     */
    suspend fun stage(
        open: () -> InputStream,
        password: CharArray
    ): StagedRestore = withContext(Dispatchers.IO) {
        val stagingDir = File(stagingRoot, UUID.randomUUID().toString())
        if (!stagingDir.mkdirs()) {
            throw RestoreFailure.StorageFailed("staging directory could not be created")
        }

        try {
            val (header, contents) = try {
                open().use { input ->
                    // BackupCodec authenticates every chunk of the body before the archive is
                    // opened, and applies the entry-name and extraction bounds while unpacking.
                    codec.restore(
                        input = input,
                        backupKeyProvider = { backupHeader -> backupKey(backupHeader, password) },
                        attachmentTarget = File(stagingDir, ATTACHMENTS)
                    )
                }
            } catch (e: RestoreFailure) {
                throw e
            } catch (e: UnsupportedFormatException) {
                throw if (e.message?.contains("not a SecureVault") == true) {
                    RestoreFailure.NotABackup
                } else {
                    RestoreFailure.UnsupportedVersion(e.message.orEmpty())
                }
            } catch (e: VaultIntegrityException) {
                throw RestoreFailure.AuthenticationFailed
            } catch (e: IOException) {
                throw RestoreFailure.StorageFailed(e.message ?: "read failed")
            }

            validateStaged(header, contents, stagingDir)

            val manifest = contents.manifest
            StagedRestore(
                preview = RestorePreview(
                    vaultName = manifest?.vaultName ?: "Restored vault",
                    vaultId = header.vaultId,
                    backupId = header.backupId,
                    backupCreatedAt = header.createdAt,
                    backupFormatVersion = header.formatVersion,
                    appVersion = header.appVersion,
                    itemCount = contents.items.size,
                    folderCount = contents.folders.size,
                    attachmentCount = contents.items.sumOf { it.payload.attachments.size },
                    tagCount = contents.items.flatMap { it.payload.tags }.distinct().size,
                    kdfDescription = header.kdf.describe(),
                    hasRecoveryBlock = header.recovery != null,
                    legacyPlaintextMetadata = header.legacyManifest != null
                ),
                header = header,
                items = contents.items,
                folders = contents.folders,
                stagingDir = stagingDir
            )
        } catch (e: Throwable) {
            // Any failure at all leaves nothing behind.
            stagingDir.deleteRecursively()
            throw e
        }
    }

    /**
     * Derives the backup key, translating crypto failures into restore failures.
     *
     * A missing KDF is separated from a wrong password here, at the one place where the two are
     * genuinely distinguishable without leaking anything: a device that cannot run Argon2 at all
     * learns nothing about whether the password was right, because it never got far enough to try.
     */
    private fun backupKey(header: BackupHeader, password: CharArray): ByteArray {
        val kek = try {
            KeyHierarchy.deriveKek(password, header.kdf)
        } catch (e: KdfUnavailableException) {
            throw RestoreFailure.KdfUnavailable(e.algorithm.displayName)
        }
        return try {
            val vek = KeyHierarchy.unwrapVek(kek, header.wrappedVek, header.vaultId)
            try {
                codec.backupKeyFrom(vek)
            } finally {
                vek.fill(0)
            }
        } catch (e: InvalidCredentialsException) {
            throw RestoreFailure.AuthenticationFailed
        } finally {
            kek.fill(0)
        }
    }

    /**
     * Structural checks on what came out of the backup.
     *
     * A ZIP that extracted is not a vault. Everything here is about whether the reconstructed
     * vault would actually work if committed, checked while it still costs nothing to walk away.
     */
    private fun validateStaged(header: BackupHeader, contents: BackupContents, stagingDir: File) {
        fun fail(reason: String): Nothing = throw RestoreFailure.ValidationFailed(reason)

        if (header.vaultId.isBlank()) fail("the backup has no vault id")
        if (header.wrappedVek.isBlank()) fail("the backup has no vault key")
        if (header.kdf.saltB64.isBlank()) fail("the backup has no key-derivation salt")
        if (header.kdf.outputBytes != app.securevault.core.crypto.Aead.KEY_BYTES) {
            fail("the backup's key length is not one this app uses")
        }
        if (header.formatVersion < BackupCodec.MIN_SUPPORTED_VERSION ||
            header.formatVersion > BackupCodec.FORMAT_VERSION
        ) {
            throw RestoreFailure.UnsupportedVersion("format ${header.formatVersion}")
        }

        if (contents.items.any { it.id.isBlank() }) fail("an item has no identifier")
        val duplicateIds = contents.items.groupingBy { it.id }.eachCount().filterValues { it > 1 }
        if (duplicateIds.isNotEmpty()) fail("${duplicateIds.size} items share an identifier")
        if (contents.folders.any { it.id.isBlank() }) fail("a folder has no identifier")
        val duplicateFolders = contents.folders.groupingBy { it.id }.eachCount().filterValues { it > 1 }
        if (duplicateFolders.isNotEmpty()) fail("${duplicateFolders.size} folders share an identifier")

        // Attachment ids key both the file on disk and the subkey that decrypts it. Two items
        // claiming the same id would mean one of them silently shows the other's file, so this is
        // rejected rather than renamed -- generating replacement ids to make malformed data
        // importable would be inventing data the backup does not contain.
        val attachmentIds = contents.items.flatMap { it.payload.attachments }.map { it.id }
        if (attachmentIds.any { it.isBlank() }) fail("an attachment has no identifier")
        val duplicateAttachments = attachmentIds.groupingBy { it }.eachCount().filterValues { it > 1 }
        if (duplicateAttachments.isNotEmpty()) {
            fail("${duplicateAttachments.size} attachments share an identifier")
        }

        // Every folder an item points at must exist, or the restored vault would show items
        // filed into folders that are not there.
        val folderIds = contents.folders.map { it.id }.toSet()
        val orphaned = contents.items.count { it.folderId != null && it.folderId !in folderIds }
        if (orphaned > 0) fail("$orphaned items reference a folder that is not in the backup")

        // Attachments: every reference must have a file, and every file must be referenced.
        val stagedAttachments = File(stagingDir, ATTACHMENTS)
            .listFiles()?.map { it.name }?.toSet().orEmpty()
        val referenced = contents.items.flatMap { it.payload.attachments }.map { "${it.id}.enc" }.toSet()
        val missing = referenced - stagedAttachments
        if (missing.isNotEmpty()) fail("${missing.size} attachments are missing from the backup")
        val unexpected = stagedAttachments - referenced
        if (unexpected.isNotEmpty()) fail("${unexpected.size} unexpected files were in the backup")

        // Nothing should have landed outside the attachments subdirectory. If anything did, the
        // entry-name guards in BackupCodec did not do their job and this restore stops.
        val strays = stagingDir.listFiles()?.filter { it.name != ATTACHMENTS }.orEmpty()
        if (strays.isNotEmpty()) fail("the backup wrote files where it should not have")

        val escaped = File(stagingDir, ATTACHMENTS).walkTopDown().filter { it.isFile }.any {
            !it.canonicalPath.startsWith(stagingDir.canonicalPath + File.separator)
        }
        if (escaped) fail("an entry in the backup tried to write outside the staging area")
    }

    /**
     * Writes the staged vault into place.
     *
     * Refuses unless no vault currently exists. This app holds one vault, so "restore as a new
     * vault" and "restore on top of the one you have" would be the same operation, and the second
     * is not one this code will perform implicitly.
     *
     * A user who does want to replace their vault is routed through steps that already exist and
     * have already been reviewed: back up the current vault, delete it with the typed
     * confirmation, then restore. That is slower than a single button, and deliberately so -- a
     * second destruction path written for convenience is a second destruction path to get wrong.
     */
    suspend fun commit(
        staged: StagedRestore,
        password: CharArray,
        currentState: VaultState,
        installHeader: (VaultMetadata) -> Unit
    ): RestoreSummary = withContext(Dispatchers.IO) {
        if (currentState !is VaultState.Absent) throw RestoreFailure.VaultAlreadyExists

        // Re-derive rather than having held the key across the confirmation dialog.
        val vek = try {
            val kek = KeyHierarchy.deriveKek(password, staged.header.kdf)
            try {
                KeyHierarchy.unwrapVek(kek, staged.header.wrappedVek, staged.header.vaultId)
            } finally {
                kek.fill(0)
            }
        } catch (e: KdfUnavailableException) {
            throw RestoreFailure.KdfUnavailable(e.algorithm.displayName)
        } catch (e: InvalidCredentialsException) {
            throw RestoreFailure.AuthenticationFailed
        }

        val session = VaultSession(staged.header.vaultId, vek)
        try {
            // 1. Open the journal. From here until it is removed, live storage is known to be
            //    mid-restore and any interruption is recoverable rather than ambiguous.
            openJournal(staged.header.vaultId)

            try {
                // 2. Clear live storage first, not last. The previous order copied attachments in
                //    before wiping, so a retry's wipe never reached the attachments a failed
                //    attempt had already written.
                repository.wipeAll()
                clearLiveAttachments()

                // 3. Attachments, then records.
                liveAttachmentsDir.mkdirs()
                File(staged.stagingDir, ATTACHMENTS).listFiles()?.forEach { file ->
                    val destination = File(liveAttachmentsDir, file.name)
                    if (!file.renameTo(destination)) file.copyTo(destination, overwrite = true)
                }
                if (staged.folders.isNotEmpty()) {
                    staged.folders.forEach { repository.saveFolder(session, it) }
                }
                if (staged.items.isNotEmpty()) {
                    repository.saveAll(session, staged.items)
                }
            } catch (e: IOException) {
                throw RestoreFailure.StorageFailed(e.message ?: "could not write restored data")
            }

            // Re-read what was written, with the restored key, before declaring success. If the
            // records do not decrypt, the header is never written and the app still sees no vault.
            val readBack = repository.loadAll(session)
            if (readBack.size != staged.items.size) {
                throw RestoreFailure.ValidationFailed(
                    "only ${readBack.size} of ${staged.items.size} items could be read back"
                )
            }

            // 4. The commit point.
            installHeader(metadataFor(staged))

            // 5. Journal closed. Everything before this is recoverable; after it, the vault is
            //    simply a vault.
            closeJournal()

            RestoreSummary(
                vaultName = staged.preview.vaultName,
                items = staged.items.size,
                folders = staged.folders.size,
                attachments = staged.preview.attachmentCount,
                tags = staged.preview.tagCount,
                restoredAt = System.currentTimeMillis(),
                replacedExistingVault = false
            )
        } catch (e: Throwable) {
            // Best effort rollback while we are still running. The journal is what covers us if
            // the process dies instead of throwing, so it is deliberately cleared last.
            runCatching { repository.wipeAll() }
            runCatching { clearLiveAttachments() }
            runCatching { closeJournal() }
            throw e
        } finally {
            session.destroy()
            discard(staged)
        }
    }

    // ---- journal -------------------------------------------------------------------------

    private fun openJournal(vaultId: String) {
        // Only ever opened once the caller has established that no vault exists. The recovery rule
        // in [recoverInterruptedRestore] depends on that and would be unsafe without it.
        check(!vaultHeaderExists()) { "refusing to journal a restore over an existing vault" }
        journalFile.parentFile?.mkdirs()
        journalFile.writeText(
            org.json.JSONObject().apply {
                put("vaultId", vaultId)
                put("startedAt", System.currentTimeMillis())
            }.toString()
        )
    }

    private fun closeJournal() {
        journalFile.delete()
    }

    private fun clearLiveAttachments() {
        liveAttachmentsDir.listFiles()?.forEach { it.delete() }
    }

    /** What [recoverInterruptedRestore] did, so the caller can say something truthful about it. */
    enum class RecoveryOutcome { NOTHING_TO_DO, MARKER_CLEARED, INTERRUPTED_RESTORE_PURGED }

    /**
     * Applies the journal rule. Safe to call at any time; called at startup, before staging, and
     * before creating a vault.
     *
     * The purge branch is the one that matters. It runs only when a journal exists and no vault
     * header does, which by construction means a restore began on a device with no vault and did
     * not finish. There is no committed data to lose in that situation -- only the debris of the
     * attempt.
     */
    suspend fun recoverInterruptedRestore(): RecoveryOutcome = withContext(Dispatchers.IO) {
        clearAllStaging()
        if (!journalFile.exists()) return@withContext RecoveryOutcome.NOTHING_TO_DO
        if (vaultHeaderExists()) {
            // The header landed; only the marker survived. Nothing to purge.
            closeJournal()
            return@withContext RecoveryOutcome.MARKER_CLEARED
        }
        runCatching { repository.wipeAll() }
        runCatching { clearLiveAttachments() }
        closeJournal()
        RecoveryOutcome.INTERRUPTED_RESTORE_PURGED
    }

    /**
     * Reconstructs the vault header from the backup.
     *
     * Vault id, KDF parameters, salt, wrapped key and recovery block are carried across exactly as
     * the backup recorded them -- restoring must not choose any of them. The vault's own format
     * version is not in the backup header (that field is the *container* version), so the current
     * one is used; the item payload format has not changed across the versions this build reads.
     */
    private fun metadataFor(staged: StagedRestore) = VaultMetadata(
        vaultId = staged.header.vaultId,
        name = staged.preview.vaultName,
        formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
        createdAt = staged.header.createdAt,
        modifiedAt = System.currentTimeMillis(),
        kdf = staged.header.kdf,
        wrappedVek = staged.header.wrappedVek,
        recovery = staged.header.recovery,
        keyFileRequired = staged.header.keyFileRequired,
        backupId = staged.header.backupId
    )

    /** Removes a staged restore. Safe to call twice; called on cancel and on every failure. */
    fun discard(staged: StagedRestore) {
        staged.stagingDir.deleteRecursively()
    }

    /** Clears anything left by an interrupted restore. Called at startup and before staging. */
    fun clearAllStaging() {
        stagingRoot.deleteRecursively()
    }

    companion object {
        private const val ATTACHMENTS = "attachments"
        const val STAGING_DIR_NAME = "restore-staging"
    }
}

