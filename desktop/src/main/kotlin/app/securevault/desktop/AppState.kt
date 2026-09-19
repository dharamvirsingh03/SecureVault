package app.securevault.desktop

import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.KdfUnavailableException
import app.securevault.core.model.Folder
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultLockedOutException
import app.securevault.core.vault.VaultSettings
import app.securevault.core.vault.VaultState
import app.securevault.data.repo.VaultFilter
import app.securevault.desktop.platform.DesktopLockSignals
import app.securevault.desktop.platform.Paths
import app.securevault.desktop.platform.RecoveryKitPdf
import app.securevault.desktop.platform.SecureStorage
import app.securevault.feature.backup.RestoreFailure
import app.securevault.feature.backup.RestorePreview
import app.securevault.feature.backup.RestoreSummary
import app.securevault.feature.backup.StagedRestore
import app.securevault.feature.csv.CsvExporter
import app.securevault.feature.csv.CsvImporter
import app.securevault.feature.csv.DuplicateAction
import app.securevault.feature.csv.ExportSelection
import app.securevault.feature.csv.ImportSummary
import app.securevault.feature.csv.ParsedCsv
import app.securevault.feature.csv.PreparedRecord
import app.securevault.feature.health.HealthReport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File

sealed interface UnlockState {
    data object NoVault : UnlockState
    data class Locked(val error: String? = null, val lockoutSeconds: Long = 0) : UnlockState
    data object Unlocking : UnlockState
    data object Unlocked : UnlockState
    data class Corrupt(val message: String) : UnlockState
}

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

sealed interface RestoreState {
    data object Idle : RestoreState
    data class Staged(val staged: StagedRestore) : RestoreState
    data class Done(val summary: RestoreSummary) : RestoreState
    data class Failed(val failure: RestoreFailure) : RestoreState
}

sealed interface VerifyState {
    data object Idle : VerifyState
    data class Verified(val createdAt: Long, val kdf: String, val formatVersion: Int) : VerifyState
    data class Failed(val failure: RestoreFailure) : VerifyState
}

/**
 * Application state for the desktop UI.
 *
 * The same shape as Android's VaultViewModel and, importantly, the same division of labour: this
 * class holds UI state and calls into `:core`; it contains no vault logic, no cryptography and no
 * persistence. Every security decision it appears to make is actually made by VaultManager,
 * VaultRestorer or ItemRepository, all of which are the code the phone runs.
 */
class AppState(private val services: Services, private val scope: CoroutineScope) {

    private val _unlockState = MutableStateFlow(initialState())
    private val _visibleItems = MutableStateFlow<List<VaultItem>>(emptyList())
    private val _filter = MutableStateFlow(VaultFilter())
    private val _settings = MutableStateFlow(services.vaultManager.settings())
    private val _message = MutableStateFlow<String?>(null)
    private val _busy = MutableStateFlow<String?>(null)
    private val _health = MutableStateFlow<HealthReport?>(null)
    private val _importState = MutableStateFlow<ImportState>(ImportState.Idle)
    private val _restoreState = MutableStateFlow<RestoreState>(RestoreState.Idle)
    private val _verifyState = MutableStateFlow<VerifyState>(VerifyState.Idle)
    private val _recoveryCode = MutableStateFlow<CharArray?>(null)
    private val _secureStorageStatus = MutableStateFlow<SecureStorage.Availability?>(null)

    /** Handed from the generator to a new login editor. In memory only, read once, then wiped. */
    private var pendingGeneratedPassword: CharArray? = null

    val unlockState: StateFlow<UnlockState> = _unlockState.asStateFlow()
    val visibleItems: StateFlow<List<VaultItem>> = _visibleItems.asStateFlow()
    val folders: StateFlow<List<Folder>> = services.index.folders
    val filter: StateFlow<VaultFilter> = _filter.asStateFlow()
    val settings: StateFlow<VaultSettings> = _settings.asStateFlow()
    val message: StateFlow<String?> = _message.asStateFlow()
    val busy: StateFlow<String?> = _busy.asStateFlow()
    val health: StateFlow<HealthReport?> = _health.asStateFlow()
    val importState: StateFlow<ImportState> = _importState.asStateFlow()
    val restoreState: StateFlow<RestoreState> = _restoreState.asStateFlow()
    val verifyState: StateFlow<VerifyState> = _verifyState.asStateFlow()
    val recoveryCode: StateFlow<CharArray?> = _recoveryCode.asStateFlow()
    val secureStorageStatus: StateFlow<SecureStorage.Availability?> = _secureStorageStatus.asStateFlow()

    val lockSignals = DesktopLockSignals(
        scope = scope,
        lock = { lock() },
        // Without this the ticker calls lock() once a second on an already-locked vault, and a
        // long time spent at the lock screen counts as idle time against the next session.
        isUnlocked = { services.vaultManager.session.value?.isAlive == true },
        settings = {
            DesktopLockSignals.LockSettings(
                autoLockMillis = _settings.value.autoLockMillis,
                lockOnFocusLoss = _settings.value.lockOnBackground,
                lockOnSuspend = _settings.value.lockOnScreenOff
            )
        }
    )

    init {
        scope.launch {
            services.vaultManager.session.collect { session ->
                if (session == null) {
                    _visibleItems.value = emptyList()
                    _health.value = null
                    services.index.clear()
                    services.clipboard.clearOurs()
                    services.attachmentViewer.purge()
                    consumeRecoveryCode()
                    discardGeneratedPassword()
                    cancelImport()
                    cancelRestore()
                    if (_unlockState.value == UnlockState.Unlocked) _unlockState.value = initialState()
                } else {
                    services.index.refresh(session, services.repository)
                    applyFilter()
                    // The idle period starts now, not when the application launched.
                    lockSignals.resetIdle()
                    _unlockState.value = UnlockState.Unlocked
                }
            }
        }
        scope.launch { runCatching { services.restorer.recoverInterruptedRestore() } }
        services.attachmentViewer.purge()
        lockSignals.start()
    }

    private fun initialState(): UnlockState = when (val state = services.vaultManager.state()) {
        is VaultState.Absent -> UnlockState.NoVault
        is VaultState.Present -> UnlockState.Locked(state.rollbackWarning)
        is VaultState.Corrupt -> UnlockState.Corrupt(state.userMessage)
    }

    // ---- vault lifecycle ---------------------------------------------------------------------

    fun createVault(name: String, password: CharArray, enableRecovery: Boolean) {
        _unlockState.value = UnlockState.Unlocking
        scope.launch {
            runCatching { services.restorer.recoverInterruptedRestore() }
            runCatching { services.vaultManager.createVault(name, password, enableRecovery) }
                .also { password.fill('\u0000') }
                .onSuccess { result ->
                    _recoveryCode.value = result.recoveryCode
                    _message.value = result.kdfFallbackWarning
                    _settings.value = services.vaultManager.settings()
                }
                .onFailure { _unlockState.value = UnlockState.Locked("Could not create the vault") }
        }
    }

    fun unlock(password: CharArray) {
        _unlockState.value = UnlockState.Unlocking
        scope.launch {
            runCatching { services.vaultManager.unlockWithPassword(password) }
                .also { password.fill('\u0000') }
                .onFailure { error -> _unlockState.value = failureState(error) }
        }
    }

    fun unlockWithRecoveryCode(code: CharArray) {
        _unlockState.value = UnlockState.Unlocking
        scope.launch {
            runCatching { services.vaultManager.unlockWithRecoveryCode(code) }
                .also { code.fill('\u0000') }
                .onFailure { error -> _unlockState.value = failureState(error) }
        }
    }

    private fun failureState(error: Throwable): UnlockState = when (error) {
        is VaultLockedOutException ->
            UnlockState.Locked("Too many attempts", error.remainingMillis / 1000)
        is InvalidCredentialsException -> UnlockState.Locked("That did not work")
        // Not a wrong password, and not counted as one.
        is KdfUnavailableException -> UnlockState.Corrupt(error.message.orEmpty())
        else -> UnlockState.Locked(error.message ?: "Could not open the vault")
    }

    fun lock() {
        services.vaultManager.lock()
    }

    fun changeMasterPassword(current: CharArray, replacement: CharArray, onDone: (Boolean) -> Unit) {
        scope.launch {
            _busy.value = "Rewrapping your vault key"
            val outcome = runCatching {
                services.vaultManager.changeMasterPassword(current, replacement)
            }
            current.fill('\u0000'); replacement.fill('\u0000')
            _busy.value = null
            outcome.onSuccess {
                _message.value = "Master password changed. Your recovery code still works."
                onDone(true)
            }.onFailure { error ->
                _message.value = when (error) {
                    is VaultLockedOutException ->
                        "Too many attempts. Try again in ${error.remainingMillis / 1000}s."
                    is InvalidCredentialsException -> "That current password did not work."
                    else -> "Your password was not changed. Nothing was altered."
                }
                onDone(false)
            }
        }
    }

    fun destroyVault(onDone: () -> Unit) {
        scope.launch {
            _busy.value = "Destroying vault"
            val result = runCatching { services.vaultManager.destroyVault() }
            _busy.value = null
            _message.value = if (result.getOrNull()?.complete == true) {
                "Vault destroyed. Backup files you made earlier are untouched."
            } else {
                "Vault keys were destroyed, but some files could not be removed."
            }
            _unlockState.value = UnlockState.NoVault
            onDone()
        }
    }

    // ---- items, folders, tags ------------------------------------------------------------------

    fun itemById(id: String) = services.index.items.value.firstOrNull { it.id == id }
    fun folderById(id: String) = services.index.folders.value.firstOrNull { it.id == id }
    fun allItems() = services.index.items.value.sortedBy { it.title.lowercase() }
    fun allTags() = services.index.allTags()
    fun favorites() = services.index.favorites()
    fun recentlyUsed(limit: Int = 8) = services.index.recentlyUsed(limit)
    fun countsByType() = services.index.items.value.groupingBy { it.type }.eachCount()
    fun itemsInFolder(id: String) =
        services.index.items.value.filter { it.folderId == id }.sortedBy { it.title.lowercase() }

    fun setFilter(update: (VaultFilter) -> VaultFilter) {
        _filter.value = update(_filter.value)
        applyFilter()
    }

    private fun applyFilter() {
        _visibleItems.value = services.index.query(_filter.value)
    }

    fun save(item: VaultItem) = withSession { session ->
        services.repository.save(session, item)
        refresh(session)
    }

    fun delete(item: VaultItem) = withSession { session ->
        services.repository.delete(item.id)
        refresh(session)
    }

    fun toggleFavorite(item: VaultItem) = save(item.copy(favorite = !item.favorite))

    fun markUsed(item: VaultItem) = withSession { services.repository.markUsed(item.id) }

    fun saveFolder(folder: Folder) = withSession { session ->
        services.repository.saveFolder(session, folder)
        refresh(session)
    }

    fun deleteFolder(id: String, moveItemsTo: String?) = withSession { session ->
        val affected = services.index.items.value.filter { it.folderId == id }
        if (affected.isNotEmpty()) {
            services.repository.saveAll(session, affected.map { it.copy(folderId = moveItemsTo) })
        }
        services.repository.deleteFolder(id)
        refresh(session)
        _message.value = "Folder removed. Its items were kept."
    }

    fun renameTag(from: String, to: String) = withSession { session ->
        val clean = to.trim()
        if (clean.isEmpty() || clean == from) return@withSession
        val affected = services.index.items.value.filter { from in it.payload.tags }
        services.repository.saveAll(session, affected.map { item ->
            item.copy(
                payload = item.payload.copy(
                    tags = item.payload.tags.map { if (it == from) clean else it }.distinct()
                ),
                updatedAt = System.currentTimeMillis()
            )
        })
        refresh(session)
    }

    fun deleteTag(tag: String) = withSession { session ->
        val affected = services.index.items.value.filter { tag in it.payload.tags }
        services.repository.saveAll(session, affected.map { item ->
            item.copy(
                payload = item.payload.copy(tags = item.payload.tags - tag),
                updatedAt = System.currentTimeMillis()
            )
        })
        refresh(session)
        _message.value = "Tag removed from ${affected.size} items"
    }

    // ---- generator handoff ----------------------------------------------------------------------

    fun stageGeneratedPassword(value: String) {
        discardGeneratedPassword()
        pendingGeneratedPassword = value.toCharArray()
    }

    fun consumeGeneratedPassword(): String? {
        val chars = pendingGeneratedPassword ?: return null
        pendingGeneratedPassword = null
        return String(chars).also { chars.fill('\u0000') }
    }

    fun discardGeneratedPassword() {
        pendingGeneratedPassword?.fill('\u0000')
        pendingGeneratedPassword = null
    }

    // ---- clipboard, health, recovery --------------------------------------------------------------

    fun copy(value: String, label: String) {
        val result = services.clipboard.copy(value, _settings.value.clipboardClearSeconds, label)
        _message.value = result ?: "This desktop session has no clipboard SecureVault can reach."
    }

    fun refreshHealth() = withSession {
        _health.value = analyzer().analyse(services.index.items.value)
    }

    /**
     * Mirrors Android exactly: the breach lookup runs first and returns the ids it found, then the
     * analyser is told which items were affected. Only a five-character hash prefix ever leaves
     * the machine -- that logic lives in BreachChecker, in :core, shared with the phone.
     */
    fun runBreachCheck() = withSession {
        if (!_settings.value.breachCheckEnabled) {
            _message.value = "Turn on breach checking in Settings first"
            return@withSession
        }
        _busy.value = "Checking password hashes"
        runCatching {
            val result = services.breachChecker.check(services.index.items.value)
            _health.value = analyzer()
                .analyse(services.index.items.value, result.breachedItemIds, breachCheckRan = true)
            result
        }.onSuccess { result ->
            _message.value = if (result.failed > 0) {
                "Checked ${result.checked - result.failed} of ${result.checked}. Some lookups failed."
            } else {
                "Checked ${result.checked} passwords"
            }
        }.onFailure { _message.value = "The breach service could not be reached." }
        _busy.value = null
    }

    private fun analyzer() = services.healthAnalyzer(
        _settings.value.weakPasswordThreshold, _settings.value.passwordAgeReminderDays
    )

    fun enableRecovery() {
        runCatching { services.vaultManager.enableRecovery() }
            .onSuccess { _recoveryCode.value = it }
            .onFailure { _message.value = "Could not set up recovery" }
    }

    fun disableRecovery() {
        services.vaultManager.disableRecovery()
        _message.value = "Recovery removed. Backups you already made keep their old recovery code."
    }

    fun hasRecovery() = services.vaultManager.metadata()?.recovery != null
    fun kdfDescription() = services.vaultManager.metadata()?.kdf?.describe().orEmpty()
    fun vaultMetadata() = services.vaultManager.metadata()

    fun consumeRecoveryCode() {
        _recoveryCode.value?.fill('\u0000')
        _recoveryCode.value = null
    }

    fun writeRecoveryKit(target: File, printedCode: String?) {
        val metadata = vaultMetadata() ?: return
        scope.launch {
            _busy.value = "Writing recovery kit"
            runCatching {
                target.outputStream().use { RecoveryKitPdf.write(metadata, it, printedCode) }
                Paths.restrict(target)
            }.onSuccess { _message.value = "Recovery kit saved to ${target.name}" }
                .onFailure { _message.value = "Could not write the recovery kit" }
            _busy.value = null
        }
    }

    fun checkSecureStorage() {
        scope.launch { _secureStorageStatus.value = services.secureStorage.availability() }
    }

    // ---- settings, messages ------------------------------------------------------------------------

    fun updateSettings(settings: VaultSettings) {
        services.vaultManager.saveSettings(settings)
        _settings.value = settings
    }

    fun consumeMessage() {
        _message.value = null
    }

    // ---- mutators used by DataFlows.kt ---------------------------------------------------------
    // Kept narrow on purpose: the flows file drives state transitions, it does not own state.

    internal fun post(message: String) { _message.value = message }
    internal fun setBusy(label: String?) { _busy.value = label }
    internal fun setImportState(state: ImportState) { _importState.value = state }
    internal fun setRestoreState(state: RestoreState) { _restoreState.value = state }
    internal fun setVerifyState(state: VerifyState) { _verifyState.value = state }

    fun cancelImport() { _importState.value = ImportState.Idle }

    fun cancelRestore() {
        (_restoreState.value as? RestoreState.Staged)?.let {
            runCatching { services.restorer.discard(it.staged) }
        }
        _restoreState.value = RestoreState.Idle
    }

    fun dismissVerification() { _verifyState.value = VerifyState.Idle }

    fun restoreRequiresEmptyDevice(): Boolean =
        services.vaultManager.state() !is VaultState.Absent

    /** Re-reads vault state from disk after a restore commits. */
    fun refreshAfterRestore() { _unlockState.value = initialState() }

    fun onInteraction() = lockSignals.onInteraction()

    private fun withSession(block: suspend (app.securevault.core.vault.VaultSession) -> Unit) {
        val session = services.vaultManager.session.value ?: return
        scope.launch { runCatching { block(session) }.onFailure { _message.value = it.message } }
    }

    private suspend fun refresh(session: app.securevault.core.vault.VaultSession) {
        services.index.refresh(session, services.repository)
        applyFilter()
    }
}
