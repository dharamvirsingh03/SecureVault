package app.securevault.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.model.AttachmentRef
import app.securevault.core.model.Folder
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultLockedOutException
import app.securevault.core.vault.VaultState
import app.securevault.core.vault.VaultSettings
import app.securevault.data.repo.VaultFilter
import app.securevault.di.ServiceLocator
import app.securevault.feature.csv.CsvExporter
import app.securevault.feature.csv.CsvImporter
import app.securevault.feature.csv.DuplicateAction
import app.securevault.feature.csv.ImportSummary
import app.securevault.feature.csv.ParsedCsv
import app.securevault.feature.csv.PreparedRecord
import app.securevault.feature.backup.RestoreFailure
import app.securevault.feature.backup.RestoreSummary
import app.securevault.feature.backup.StagedRestore
import app.securevault.feature.backup.VaultRestorer
import app.securevault.feature.csv.ExportSelection
import app.securevault.feature.health.HealthReport
import app.securevault.feature.health.PasswordHealthAnalyzer
import app.securevault.platform.CopyKind
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.crypto.Cipher

sealed interface UnlockState {
    data object NoVault : UnlockState
    data class Locked(val error: String? = null, val lockoutSeconds: Long = 0) : UnlockState
    data object Unlocking : UnlockState
    data object Unlocked : UnlockState

    /**
     * A vault exists on this device but cannot be read. Distinct from [NoVault] on purpose --
     * offering setup here would let a user bury recoverable data under a fresh vault.
     */
    data class Corrupt(val message: String) : UnlockState
}

/**
 * Where the CSV import wizard has got to.
 *
 * Modelled as state rather than as a chain of screen callbacks so the wizard can be backed out of
 * and resumed, and -- more importantly -- so the parsed plaintext CSV lives in exactly one place
 * that can be dropped on [VaultViewModel.cancelImport] and on lock.
 */
sealed interface ImportState {
    data object Idle : ImportState
    data class Mapping(val parsed: ParsedCsv, val mapping: Map<Int, String>) : ImportState
    data class Preview(
        val parsed: ParsedCsv,
        val mapping: Map<Int, String>,
        val records: List<PreparedRecord>
    ) : ImportState {
        val newCount get() = records.count { it.isValid && it.isDuplicateOf == null }
        val duplicateCount get() = records.count { it.isDuplicateOf != null }
        val invalidCount get() = records.count { !it.isValid }
    }
    data class Done(val summary: ImportSummary) : ImportState
    data class Failed(val reason: String) : ImportState
}

/**
 * Where the restore flow has got to.
 *
 * Staged state holds a fully decrypted, validated backup sitting in a private staging directory.
 * It is dropped on cancel, on failure, and on lock -- a decrypted backup waiting behind a
 * confirmation dialog is exactly the kind of thing that should not outlive the session.
 */
/** Outcome of checking a backup file, shown as its own state rather than a snackbar. */
sealed interface VerifyState {
    data object Idle : VerifyState
    data class Verified(
        val createdAt: Long,
        val kdf: String,
        val formatVersion: Int,
        val vaultId: String
    ) : VerifyState
    data class Failed(val failure: RestoreFailure) : VerifyState
}

sealed interface RestoreState {
    data object Idle : RestoreState
    data class Staged(val staged: StagedRestore) : RestoreState
    data class Done(val summary: RestoreSummary) : RestoreState
    data class Failed(val failure: RestoreFailure) : RestoreState
}

private fun initialState(manager: app.securevault.core.vault.VaultManager): UnlockState =
    when (val state = manager.state()) {
        is VaultState.Absent -> UnlockState.NoVault
        // A header recovered from the crash-window copy surfaces on the unlock screen. Silence
        // here would leave someone who just changed their password staring at "wrong password"
        // with no idea their change had been rolled back.
        is VaultState.Present -> UnlockState.Locked(state.rollbackWarning)
        is VaultState.Corrupt -> UnlockState.Corrupt(state.userMessage)
    }

/**
 * The single view model for the app.
 *
 * It holds no key material of its own: the session lives in VaultManager, decrypted items live in
 * VaultIndex, and both are dropped the moment the vault locks. What is exposed here is display
 * state.
 */
class VaultViewModel(application: Application) : AndroidViewModel(application) {

    private val context = application
    private val vaultManager = ServiceLocator.vaultManager(context)
    private val repository = ServiceLocator.repository(context)
    private val index = ServiceLocator.vaultIndex()
    private val clipboard = ServiceLocator.clipboard(context)

    private val _unlockState = MutableStateFlow(initialState(vaultManager))
    private val _settings = MutableStateFlow(vaultManager.settings())
    private val _filter = MutableStateFlow(VaultFilter())
    private val _visibleItems = MutableStateFlow<List<VaultItem>>(emptyList())
    private val _message = MutableStateFlow<String?>(null)
    private val _health = MutableStateFlow<HealthReport?>(null)
    // CharArray, not String: this value is an alternative to the master password, and a String
    // could not be wiped. See consumeRecoveryCode.
    private val _importState = MutableStateFlow<ImportState>(ImportState.Idle)
    private val _restoreState = MutableStateFlow<RestoreState>(RestoreState.Idle)
    private val _verifyState = MutableStateFlow<VerifyState>(VerifyState.Idle)

    /**
     * A password handed from the generator to a new login editor.
     *
     * Plain in-memory state on the ViewModel, deliberately: not a navigation argument, not
     * SavedStateHandle, not rememberSaveable, not persisted anywhere. It is read exactly once by
     * the editor and wiped on read, on lock, and in onCleared.
     */
    private var pendingGeneratedPassword: CharArray? = null
    private val _busy = MutableStateFlow<String?>(null)
    private val _recoveryCodeToShow = MutableStateFlow<CharArray?>(null)

    val unlockState: StateFlow<UnlockState> = _unlockState.asStateFlow()
    val settings: StateFlow<VaultSettings> = _settings.asStateFlow()
    val filter: StateFlow<VaultFilter> = _filter.asStateFlow()
    val visibleItems: StateFlow<List<VaultItem>> = _visibleItems.asStateFlow()
    val message: StateFlow<String?> = _message.asStateFlow()
    val health: StateFlow<HealthReport?> = _health.asStateFlow()
    val recoveryCodeToShow: StateFlow<CharArray?> = _recoveryCodeToShow.asStateFlow()
    val folders: StateFlow<List<Folder>> = index.folders
    val importState: StateFlow<ImportState> = _importState.asStateFlow()
    val restoreState: StateFlow<RestoreState> = _restoreState.asStateFlow()
    val verifyState: StateFlow<VerifyState> = _verifyState.asStateFlow()
    val busy: StateFlow<String?> = _busy.asStateFlow()

    init {
        viewModelScope.launch {
            vaultManager.session.collect { session ->
                if (session == null) {
                    _visibleItems.value = emptyList()
                    _health.value = null
                    // Neither a recovery code nor a parsed plaintext CSV may outlive the session.
                    consumeRecoveryCode()
                    _importState.value = ImportState.Idle
                    cancelRestore()
                    discardGeneratedPassword()
                    if (_unlockState.value == UnlockState.Unlocked) {
                        _unlockState.value = initialState(vaultManager)
                    }
                } else {
                    index.refresh(session, repository)
                    applyFilter()
                    _unlockState.value = UnlockState.Unlocked
                }
            }
        }
    }

    // ---- unlock and setup -----------------------------------------------------------------

    fun createVault(name: String, password: CharArray, enableRecovery: Boolean) {
        viewModelScope.launch {
            // A vault created right after an interrupted restore must not inherit its records or
            // attachment files. They would be undecryptable under the new key -- invisible, but
            // present, and counted.
            runCatching { restorer.recoverInterruptedRestore() }
            runCatching { vaultManager.createVault(name, password, enableRecovery) }
                .onSuccess { result ->
                    password.fill('\u0000')
                    _recoveryCodeToShow.value = result.recoveryCode
                    // Never silent: if the vault was created under the compatibility KDF because
                    // the Argon2 library would not load, say so now, while the user can still
                    // decide whether to keep it.
                    _message.value = result.kdfFallbackWarning
                    _unlockState.value = UnlockState.Unlocked
                }
                .onFailure { error ->
                    password.fill('\u0000')
                    _unlockState.value = UnlockState.Locked(error.message)
                }
        }
    }

    fun unlock(password: CharArray) {
        _unlockState.value = UnlockState.Unlocking
        viewModelScope.launch {
            runCatching { vaultManager.unlockWithPassword(password) }
                .onSuccess { password.fill('\u0000') }
                .onFailure { error ->
                    password.fill('\u0000')
                    _unlockState.value = when (error) {
                        is VaultLockedOutException ->
                            UnlockState.Locked("Too many attempts", error.remainingMillis / 1000)
                        is InvalidCredentialsException -> UnlockState.Locked("That password did not work")
                        // Not a wrong password, and deliberately not counted as a failed attempt:
                        // the device cannot run this vault's key-derivation function at all. Its
                        // own message already explains that the data is intact.
                        is KdfUnavailableException -> UnlockState.Corrupt(error.message.orEmpty())
                        else -> UnlockState.Locked(error.message ?: "Could not open the vault")
                    }
                }
        }
    }

    fun unlockWithRecoveryCode(code: CharArray) {
        _unlockState.value = UnlockState.Unlocking
        viewModelScope.launch {
            runCatching { vaultManager.unlockWithRecoveryCode(code) }
                .also { code.fill('\u0000') }
                .onFailure { error ->
                    _unlockState.value = when (error) {
                        is VaultLockedOutException ->
                            UnlockState.Locked("Too many attempts", error.remainingMillis / 1000)
                        // Wrong code and malformed code look identical from here, deliberately.
                        else -> UnlockState.Locked("That recovery code did not work")
                    }
                }
        }
    }

    fun biometricDecryptCipher(): Cipher? = vaultManager.biometricDecryptCipher()

    fun completeBiometricUnlock(cipher: Cipher) {
        runCatching { vaultManager.completeBiometricUnlock(cipher) }
            .onFailure { _unlockState.value = UnlockState.Locked("Biometric unlock failed. Use your master password.") }
    }

    fun biometricEncryptCipher(): Cipher = vaultManager.biometricEncryptCipher()

    fun enableBiometric(cipher: Cipher) {
        runCatching { vaultManager.enableBiometricUnlock(cipher) }
            .onSuccess {
                updateSettings(_settings.value.copy(biometricUnlockEnabled = true))
                _message.value = "Biometric unlock is on"
            }
            .onFailure { _message.value = "Could not set up biometric unlock" }
    }

    fun lockNow() = vaultManager.lock()

    fun isBiometricConfigured() = vaultManager.isBiometricConfigured()

    /**
     * Turns biometric unlock off and removes the Keystore key and the wrapped copy of the vault
     * key. Also used to clear up after the key has been invalidated by a biometric enrolment
     * change, so the stored setting stops disagreeing with what the device will actually do.
     */
    fun disableBiometric() {
        vaultManager.disableBiometricUnlock()
        updateSettings(_settings.value.copy(biometricUnlockEnabled = false))
        _message.value = "Biometric unlock turned off"
    }

    fun vaultMetadata() = vaultManager.metadata()

    // ---- items ----------------------------------------------------------------------------

    fun setFilter(update: (VaultFilter) -> VaultFilter) {
        _filter.value = update(_filter.value)
        applyFilter()
    }

    private fun applyFilter() {
        _visibleItems.value = index.query(_filter.value)
    }

    fun save(item: VaultItem) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            repository.save(session, item)
            index.refresh(session, repository)
            applyFilter()
            refreshHealth()
        }
    }

    fun delete(item: VaultItem) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            item.payload.attachments.forEach { ServiceLocator.attachments(context).delete(it) }
            repository.delete(item.id)
            index.refresh(session, repository)
            applyFilter()
        }
    }

    fun markUsed(item: VaultItem) {
        viewModelScope.launch { repository.markUsed(item.id) }
    }

    fun copy(value: String, kind: CopyKind) {
        _message.value = clipboard.copy(value, kind, _settings.value.clipboardClearSeconds)
    }

    fun consumeMessage() {
        _message.value = null
    }

    /**
     * Clears the one-time recovery code.
     *
     * The array is wiped, which removes it from this object. Honest limitation: rendering it in a
     * Compose Text necessarily materialised an immutable String somewhere in the UI layer, and the
     * JVM offers no way to reach that copy. It stays on the heap until garbage collection. This is
     * a real, unavoidable gap and is documented in SECURITY.md rather than papered over.
     */
    fun consumeRecoveryCode() {
        _recoveryCodeToShow.value?.fill('\u0000')
        _recoveryCodeToShow.value = null
    }

    // ---- settings -------------------------------------------------------------------------

    fun updateSettings(settings: VaultSettings) {
        vaultManager.saveSettings(settings)
        _settings.value = settings
    }

    // ---- health ---------------------------------------------------------------------------

    fun refreshHealth() {
        viewModelScope.launch {
            val analyzer = PasswordHealthAnalyzer(
                weakScoreThreshold = _settings.value.weakPasswordThreshold,
                oldPasswordDays = _settings.value.passwordAgeReminderDays
            )
            _health.value = analyzer.analyse(index.items.value)
        }
    }

    /** Only runs when the user has switched breach checking on. */
    fun runBreachCheck() {
        if (!_settings.value.breachCheckEnabled) {
            _message.value = "Turn on breach checking in Settings first"
            return
        }
        viewModelScope.launch {
            _message.value = "Checking password hashes"
            val result = ServiceLocator.breachChecker().check(index.items.value)
            val analyzer = PasswordHealthAnalyzer(
                weakScoreThreshold = _settings.value.weakPasswordThreshold,
                oldPasswordDays = _settings.value.passwordAgeReminderDays
            )
            _health.value = analyzer.analyse(index.items.value, result.breachedItemIds, breachCheckRan = true)
            _message.value = if (result.failed > 0) {
                "Checked ${result.checked - result.failed} of ${result.checked}. Some lookups failed."
            } else {
                "Checked ${result.checked} passwords"
            }
        }
    }

    // ---- import, export, backup -----------------------------------------------------------

    fun exportCsv(uri: Uri, selection: ExportSelection) {
        viewModelScope.launch {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { output ->
                    CsvExporter().export(selection, output)
                } ?: error("Could not write to that location")
            }.onSuccess { _message.value = "Exported. This file is plaintext -- move or delete it when done." }
                .onFailure { _message.value = it.message ?: "Export failed" }
        }
    }

    fun createBackup(uri: Uri) {
        val session = vaultManager.session.value ?: return
        val metadata = vaultManager.metadata() ?: return
        viewModelScope.launch {
            runCatching {
                val backupKey = session.backupKey()
                try {
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        ServiceLocator.backupCodec().create(
                            metadata = metadata,
                            backupKey = backupKey,
                            items = index.items.value,
                            folders = index.folders.value,
                            attachmentFiles = ServiceLocator.attachments(context).allEncryptedFiles(),
                            output = output
                        )
                    } ?: error("Could not write to that location")
                } finally {
                    backupKey.fill(0)
                }
            }.onSuccess { _message.value = "Encrypted backup written" }
                .onFailure { _message.value = it.message ?: "Backup failed" }
        }
    }

    fun writeRecoveryKit(uri: Uri, includeRecoveryCode: String? = null) {
        val metadata = vaultManager.metadata() ?: return
        viewModelScope.launch {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { output ->
                    ServiceLocator.recoveryKit().write(metadata, output, includeRecoveryCode)
                } ?: error("Could not write to that location")
            }.onSuccess { _message.value = "Recovery kit saved. Print it and store it somewhere safe." }
                .onFailure { _message.value = it.message ?: "Could not create the recovery kit" }
        }
    }

    // ---- backup restore ----------------------------------------------------------------------

    private val restorer
        get() = VaultRestorer(
            codec = ServiceLocator.backupCodec(),
            repository = repository,
            liveAttachmentsDir = File(context.filesDir, "attachments"),
            stagingRoot = File(context.filesDir, VaultRestorer.STAGING_DIR_NAME),
            journalFile = File(context.filesDir, "vault/restore.journal"),
            vaultHeaderExists = { vaultManager.state() !is VaultState.Absent }
        )

    /**
     * Phase one: decrypt, verify and validate. Writes only into staging, never into the vault.
     *
     * The URI is opened lazily by the restorer rather than a stream being handed over, so the
     * content resolver is not holding an open descriptor across the whole operation.
     */
    fun stageRestore(uri: Uri, password: CharArray) {
        viewModelScope.launch {
            _busy.value = "Decrypting and checking backup"
            runCatching { restorer.recoverInterruptedRestore() }
            val outcome = runCatching {
                restorer.stage(
                    open = {
                        context.contentResolver.openInputStream(uri)
                            ?: throw RestoreFailure.StorageFailed("that file could not be opened")
                    },
                    password = password
                )
            }
            password.fill('\u0000')
            _busy.value = null
            outcome.onSuccess { _restoreState.value = RestoreState.Staged(it) }
                .onFailure { error ->
                    _restoreState.value = RestoreState.Failed(
                        error as? RestoreFailure
                            ?: RestoreFailure.StorageFailed(error.message ?: "unexpected failure")
                    )
                }
        }
    }

    /**
     * Phase two: commit.
     *
     * The password is asked for again rather than held across the preview. The restored vault is
     * then left locked -- opening it goes through the normal unlock path, because a restore is not
     * a way past authentication.
     */
    fun commitRestore(password: CharArray) {
        val staged = (_restoreState.value as? RestoreState.Staged)?.staged ?: return
        viewModelScope.launch {
            _busy.value = "Restoring vault"
            val outcome = runCatching {
                restorer.commit(
                    staged = staged,
                    password = password,
                    currentState = vaultManager.state(),
                    installHeader = { vaultManager.installRestoredHeader(it) }
                )
            }
            password.fill('\u0000')
            _busy.value = null
            outcome.onSuccess { summary ->
                _restoreState.value = RestoreState.Done(summary)
                // Re-evaluate from disk: the app now has a vault, and it is locked.
                _unlockState.value = initialState(vaultManager)
            }.onFailure { error ->
                _restoreState.value = RestoreState.Failed(
                    error as? RestoreFailure
                        ?: RestoreFailure.StorageFailed(error.message ?: "unexpected failure")
                )
            }
        }
    }

    /** Drops any staged restore and removes its directory. Also called on lock. */
    fun cancelRestore() {
        (_restoreState.value as? RestoreState.Staged)?.let { runCatching { restorer.discard(it.staged) } }
        _restoreState.value = RestoreState.Idle
    }

    /**
     * Applies the restore journal rule and clears staging. Called once at startup and before a
     * vault is created, so an interrupted restore can never leave records or attachment files that
     * a later vault silently inherits.
     */
    fun recoverInterruptedRestore() {
        viewModelScope.launch {
            runCatching { restorer.recoverInterruptedRestore() }
                .onSuccess { outcome ->
                    if (outcome == VaultRestorer.RecoveryOutcome.INTERRUPTED_RESTORE_PURGED) {
                        _message.value =
                            "A restore that did not finish was cleared. Nothing was kept from it."
                    }
                }
        }
    }

    fun restoreRequiresEmptyDevice(): Boolean = vaultManager.state() !is VaultState.Absent


    // ---- generator handoff -------------------------------------------------------------------

    /** Called by the generator when the user chooses "Use in login". */
    fun stageGeneratedPassword(value: String) {
        discardGeneratedPassword()
        pendingGeneratedPassword = value.toCharArray()
    }

    /**
     * Read once by a newly opened login editor. Returns null on any later call, so a generated
     * password cannot leak into a second item by leaving the editor and opening another.
     */
    fun consumeGeneratedPassword(): String? {
        val chars = pendingGeneratedPassword ?: return null
        pendingGeneratedPassword = null
        // The String this produces is the same unavoidable one a Compose text field would hold
        // anyway -- the editor is about to put it in one. The array is wiped either way.
        return String(chars).also { chars.fill('\u0000') }
    }

    fun discardGeneratedPassword() {
        pendingGeneratedPassword?.fill('\u0000')
        pendingGeneratedPassword = null
    }

    // ---- lookups --------------------------------------------------------------------------

    /**
     * Items are looked up from the in-memory index rather than passed through navigation.
     *
     * Returns null once the vault locks, which is the correct answer: the screen holding that id
     * is about to be torn down and must not render stale decrypted content in the meantime.
     */
    fun itemById(id: String): VaultItem? = index.items.value.firstOrNull { it.id == id }

    /** Every item in the vault, ignoring the current filter. Used by export scope selection. */
    fun allItems(): List<VaultItem> = index.items.value.sortedBy { it.title.lowercase() }

    fun folderById(id: String): Folder? = index.folders.value.firstOrNull { it.id == id }

    fun allTags(): List<String> = index.allTags()

    fun favorites(): List<VaultItem> = index.favorites()

    fun recentlyUsed(limit: Int = 6): List<VaultItem> = index.recentlyUsed(limit)

    fun itemsInFolder(folderId: String): List<VaultItem> =
        index.items.value.filter { it.folderId == folderId }.sortedBy { it.title.lowercase() }

    fun countsByType(): Map<ItemType, Int> =
        index.items.value.groupingBy { it.type }.eachCount()

    fun totalItems(): Int = index.items.value.size

    fun toggleFavorite(item: VaultItem) = save(item.copy(favorite = !item.favorite))

    // ---- folders --------------------------------------------------------------------------

    fun saveFolder(folder: Folder) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            runCatching { repository.saveFolder(session, folder) }
                .onSuccess { refresh(session) }
                .onFailure { _message.value = "Could not save that folder" }
        }
    }

    /**
     * Deletes a folder without deleting what was in it.
     *
     * [moveItemsTo] null means the items become unfiled. There is deliberately no "delete the
     * items too" option here: a folder is an organising label, and losing a password because a
     * label was tidied up is not a trade anyone would knowingly make. Items are moved first, so an
     * interruption leaves an empty folder rather than orphaned rows.
     */
    fun deleteFolder(folderId: String, moveItemsTo: String? = null) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            runCatching {
                val affected = index.items.value.filter { it.folderId == folderId }
                if (affected.isNotEmpty()) {
                    repository.saveAll(session, affected.map { it.copy(folderId = moveItemsTo) })
                }
                repository.deleteFolder(folderId)
            }.onSuccess {
                refresh(session)
                _message.value = "Folder removed. Its items were kept."
            }.onFailure { _message.value = "Could not remove that folder" }
        }
    }

    // ---- tags -----------------------------------------------------------------------------

    fun renameTag(from: String, to: String) {
        val session = vaultManager.session.value ?: return
        val clean = to.trim()
        if (clean.isEmpty() || clean == from) return
        viewModelScope.launch {
            runCatching {
                val affected = index.items.value.filter { from in it.payload.tags }
                repository.saveAll(session, affected.map { item ->
                    item.copy(
                        payload = item.payload.copy(
                            tags = item.payload.tags.map { if (it == from) clean else it }.distinct()
                        ),
                        updatedAt = System.currentTimeMillis()
                    )
                })
            }.onSuccess { refresh(session) }
                .onFailure { _message.value = "Could not rename that tag" }
        }
    }

    fun deleteTag(tag: String) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            runCatching {
                val affected = index.items.value.filter { tag in it.payload.tags }
                repository.saveAll(session, affected.map { item ->
                    item.copy(
                        payload = item.payload.copy(tags = item.payload.tags - tag),
                        updatedAt = System.currentTimeMillis()
                    )
                })
            }.onSuccess {
                refresh(session)
                _message.value = "Tag removed from ${'$'}{index.items.value.count { tag in it.payload.tags }} items"
            }.onFailure { _message.value = "Could not remove that tag" }
        }
    }

    // ---- attachments -----------------------------------------------------------------------

    fun addAttachment(item: VaultItem, uri: Uri) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            _busy.value = "Encrypting attachment"
            runCatching {
                val resolver = context.contentResolver
                val name = displayName(uri)
                val size = resolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
                val mime = resolver.getType(uri) ?: "application/octet-stream"
                val ref = resolver.openInputStream(uri)?.use { input ->
                    ServiceLocator.attachments(context).store(session, input, name, mime, size)
                } ?: error("Could not read that file")
                repository.save(
                    session,
                    item.copy(
                        payload = item.payload.copy(attachments = item.payload.attachments + ref),
                        updatedAt = System.currentTimeMillis()
                    )
                )
            }.onSuccess {
                refresh(session)
                _message.value = "Attachment encrypted and added"
            }.onFailure { _message.value = it.message ?: "Could not add that attachment" }
            _busy.value = null
        }
    }

    /** Writes a decrypted copy to a location the user chose. Never to shared storage on its own. */
    fun exportAttachment(ref: AttachmentRef, uri: Uri) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { out ->
                    ServiceLocator.attachments(context).read(session, ref, out)
                } ?: error("Could not write to that location")
            }.onSuccess {
                _message.value = "Saved in the clear where you chose. Delete it when you are done."
            }.onFailure { _message.value = "Could not export that attachment" }
        }
    }

    /**
     * Opens an attachment in an external viewer.
     *
     * Requires an unlocked vault, decrypts to app-private cache, and hands over a read-only
     * grant for that one file. [onNoViewer] fires when nothing on the device can display the
     * type, so the caller can offer an explicit export rather than a dead button.
     */
    fun openAttachment(ref: AttachmentRef, onIntent: (android.content.Intent) -> Unit, onNoViewer: () -> Unit) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            _busy.value = "Decrypting attachment"
            runCatching { ServiceLocator.attachmentViewer(context).open(session, ref) }
                .also { _busy.value = null }
                .onSuccess { intent -> if (intent != null) onIntent(intent) else onNoViewer() }
                .onFailure { _message.value = it.message ?: "That attachment could not be opened" }
        }
    }

    fun purgeViewedAttachments() {
        runCatching { ServiceLocator.attachmentViewer(context).purge() }
    }

    fun deleteAttachment(item: VaultItem, ref: AttachmentRef) {
        val session = vaultManager.session.value ?: return
        viewModelScope.launch {
            runCatching {
                ServiceLocator.attachments(context).delete(ref)
                repository.save(
                    session,
                    item.copy(
                        payload = item.payload.copy(attachments = item.payload.attachments - ref),
                        updatedAt = System.currentTimeMillis()
                    )
                )
            }.onSuccess { refresh(session) }
                .onFailure { _message.value = "Could not remove that attachment" }
        }
    }

    private fun displayName(uri: Uri): String {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            val column = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (column >= 0 && it.moveToFirst()) return it.getString(column)
        }
        return uri.lastPathSegment ?: "attachment"
    }

    // ---- master password, recovery, destruction ---------------------------------------------

    /**
     * Both arrays are wiped here regardless of outcome, so callers never have to remember to.
     * The transactional guarantees live in VaultManager; this only reports.
     */
    fun changeMasterPassword(current: CharArray, replacement: CharArray, onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            _busy.value = "Rewrapping your vault key"
            val outcome = runCatching { vaultManager.changeMasterPassword(current, replacement) }
            current.fill('\u0000')
            replacement.fill('\u0000')
            _busy.value = null
            outcome.onSuccess {
                _message.value = "Master password changed. Biometric unlock and your recovery code still work."
                onDone(true)
            }.onFailure { error ->
                _message.value = when (error) {
                    is VaultLockedOutException ->
                        "Too many attempts. Try again in ${'$'}{error.remainingMillis / 1000} seconds."
                    is InvalidCredentialsException -> "That current password did not work."
                    else -> "Your password was not changed. Nothing was altered."
                }
                onDone(false)
            }
        }
    }

    fun enableRecovery() {
        runCatching { vaultManager.enableRecovery() }
            .onSuccess { _recoveryCodeToShow.value = it }
            .onFailure { _message.value = "Could not set up recovery" }
    }

    fun disableRecovery() {
        vaultManager.disableRecovery()
        _message.value = "Recovery removed. Backups you already made keep their old recovery code."
    }

    fun hasRecovery(): Boolean = vaultManager.metadata()?.recovery != null

    fun kdfDescription(): String = vaultManager.metadata()?.kdf?.describe().orEmpty()

    /**
     * Irreversible. The confirmation lives in the UI; by the time this runs the decision is made.
     */
    fun destroyVault(onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            _busy.value = "Destroying vault"
            val result = runCatching { vaultManager.destroyVault() }
            ServiceLocator.resetAfterDestroy()
            _busy.value = null
            val complete = result.getOrNull()?.complete == true
            _message.value = if (complete) {
                "Vault destroyed. Backup files you made earlier are untouched and still openable."
            } else {
                "Vault keys were destroyed, but some files could not be removed. " +
                    "Uninstalling the app will clear the rest."
            }
            onDone(complete)
        }
    }

    // ---- CSV import wizard -------------------------------------------------------------------

    fun beginImport(uri: Uri) {
        viewModelScope.launch {
            _busy.value = "Reading file"
            runCatching {
                val text = context.contentResolver.openInputStream(uri)
                    ?.bufferedReader()?.use { it.readText() }
                    ?: error("Could not read that file")
                CsvImporter().parse(text)
            }.onSuccess { parsed ->
                _importState.value = ImportState.Mapping(parsed, parsed.mapping)
            }.onFailure {
                _importState.value = ImportState.Failed(it.message ?: "That file could not be read as CSV")
            }
            _busy.value = null
        }
    }

    fun updateMapping(columnIndex: Int, field: String?) {
        val state = _importState.value as? ImportState.Mapping ?: return
        val mapping = state.mapping.toMutableMap()
        if (field == null) mapping.remove(columnIndex) else mapping[columnIndex] = field
        _importState.value = state.copy(mapping = mapping)
    }

    fun prepareImport() {
        val state = _importState.value as? ImportState.Mapping ?: return
        viewModelScope.launch {
            _busy.value = "Checking rows"
            runCatching {
                CsvImporter().prepare(state.parsed, state.mapping, index.items.value)
            }.onSuccess {
                _importState.value = ImportState.Preview(state.parsed, state.mapping, it)
            }.onFailure {
                _importState.value = ImportState.Failed(it.message ?: "Those rows could not be read")
            }
            _busy.value = null
        }
    }

    fun commitImport(duplicateAction: DuplicateAction) {
        val session = vaultManager.session.value ?: return
        val state = _importState.value as? ImportState.Preview ?: return
        viewModelScope.launch {
            _busy.value = "Encrypting and saving"
            runCatching {
                val (toWrite, summary) = CsvImporter().resolve(state.records, duplicateAction)
                repository.saveAll(session, toWrite)
                summary
            }.onSuccess { summary ->
                refresh(session)
                _importState.value = ImportState.Done(summary)
            }.onFailure {
                _importState.value = ImportState.Failed(it.message ?: "Import failed. Nothing was saved.")
            }
            _busy.value = null
        }
    }

    /** Drops the parsed plaintext CSV. Called when the wizard is left, not only when it finishes. */
    fun cancelImport() {
        _importState.value = ImportState.Idle
    }

    // ---- backup verification -----------------------------------------------------------------

    /**
     * Checks a backup file without writing anything.
     *
     * Failures land in [verifyState] as a dedicated screen state rather than a snackbar. A message
     * that says "this backup cannot be trusted" is something a user has to act on and may need to
     * read twice; a toast that vanishes in three seconds is the wrong shape for it.
     */
    fun verifyBackup(uri: Uri, password: CharArray) {
        viewModelScope.launch {
            _busy.value = "Verifying backup"
            val outcome = runCatching {
                val codec = ServiceLocator.backupCodec()
                context.contentResolver.openInputStream(uri)?.use { input ->
                    codec.verify(input) { header ->
                        val kek = try {
                            app.securevault.core.crypto.KeyHierarchy.deriveKek(password, header.kdf)
                        } catch (e: app.securevault.core.crypto.KdfUnavailableException) {
                            throw RestoreFailure.KdfUnavailable(e.algorithm.displayName)
                        }
                        try {
                            val vek = try {
                                app.securevault.core.crypto.KeyHierarchy
                                    .unwrapVek(kek, header.wrappedVek, header.vaultId)
                            } catch (e: InvalidCredentialsException) {
                                throw RestoreFailure.AuthenticationFailed
                            }
                            try { codec.backupKeyFrom(vek) } finally { vek.fill(0) }
                        } finally {
                            kek.fill(0)
                        }
                    }
                } ?: throw RestoreFailure.StorageFailed("that file could not be opened")
            }
            password.fill('\u0000')
            _busy.value = null
            outcome.onSuccess { header ->
                _verifyState.value = VerifyState.Verified(
                    createdAt = header.createdAt,
                    kdf = header.kdf.describe(),
                    formatVersion = header.formatVersion,
                    vaultId = header.vaultId
                )
            }.onFailure { error ->
                _verifyState.value = VerifyState.Failed(
                    when (error) {
                        is RestoreFailure -> error
                        is app.securevault.core.crypto.UnsupportedFormatException ->
                            if (error.message?.contains("not a SecureVault") == true) {
                                RestoreFailure.NotABackup
                            } else {
                                RestoreFailure.UnsupportedVersion(error.message.orEmpty())
                            }
                        is app.securevault.core.crypto.VaultIntegrityException ->
                            RestoreFailure.AuthenticationFailed
                        else -> RestoreFailure.StorageFailed(error.message ?: "verification failed")
                    }
                )
            }
        }
    }

    fun dismissVerification() {
        _verifyState.value = VerifyState.Idle
    }

    private suspend fun refresh(session: app.securevault.core.vault.VaultSession) {
        index.refresh(session, repository)
        applyFilter()
    }

    override fun onCleared() {
        // Last line of defence for the secrets this object holds.
        consumeRecoveryCode()
        discardGeneratedPassword()
        cancelRestore()
        super.onCleared()
    }

    companion object {
        fun factory(application: Application) = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                VaultViewModel(application) as T
        }
    }
}
