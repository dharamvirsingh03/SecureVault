package app.securevault.di

import android.content.Context
import app.securevault.core.vault.AutoLockController
import app.securevault.core.vault.VaultManager
import app.securevault.data.attachments.AttachmentStore
import app.securevault.data.attachments.AttachmentViewer
import app.securevault.data.db.RoomFolderStore
import app.securevault.data.db.RoomItemStore
import app.securevault.data.db.VaultDatabase
import app.securevault.platform.androidVaultManager
import java.io.File
import app.securevault.data.repo.ItemRepository
import app.securevault.data.repo.VaultIndex
import app.securevault.feature.backup.BackupCodec
import app.securevault.feature.health.BreachChecker
import app.securevault.feature.health.PasswordHealthAnalyzer
import app.securevault.feature.recovery.RecoveryKitPdf
import app.securevault.platform.SecureClipboard
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Hand-rolled dependency wiring.
 *
 * A DI framework would work here, but this app has one graph, one process and a short list of
 * singletons, and keeping the wiring readable matters more than the ceremony -- anyone auditing
 * the crypto should be able to follow who holds a key and for how long by reading one file.
 */
object ServiceLocator {

    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile private var vaultManager: VaultManager? = null
    @Volatile private var repository: ItemRepository? = null
    @Volatile private var clipboard: SecureClipboard? = null
    @Volatile private var attachments: AttachmentStore? = null
    @Volatile private var autoLock: AutoLockController? = null

    private val index = VaultIndex()

    var appVersion: String = "1.0.0"
        internal set

    fun vaultManager(context: Context): VaultManager = vaultManager ?: synchronized(this) {
        vaultManager ?: androidVaultManager(context.applicationContext).also { manager ->
            vaultManager = manager
            // Whenever the vault locks, drop every decrypted item from memory.
            appScope.launch {
                manager.session.collect { session ->
                    if (session == null) {
                        index.clear()
                        // Any attachment decrypted for an external viewer must not survive a lock.
                        runCatching { AttachmentViewer(context.applicationContext, attachments(context)).purge() }
                    }
                }
            }
        }
    }

    fun repository(context: Context): ItemRepository = repository ?: synchronized(this) {
        repository ?: VaultDatabase.get(context).let { db ->
            // Room is the Android storage backend; the repository itself is platform-neutral.
            ItemRepository(RoomItemStore(db.itemDao()), RoomFolderStore(db.folderDao()))
        }.also { repository = it }
    }

    fun vaultIndex(): VaultIndex = index

    fun attachments(context: Context): AttachmentStore = attachments ?: synchronized(this) {
        attachments ?: AttachmentStore(File(context.applicationContext.filesDir, "attachments")).also { attachments = it }
    }

    fun attachmentViewer(context: Context): AttachmentViewer =
        AttachmentViewer(context.applicationContext, attachments(context))

    fun clipboard(context: Context): SecureClipboard = clipboard ?: synchronized(this) {
        clipboard ?: SecureClipboard(context.applicationContext, appScope).also { clipboard = it }
    }

    fun autoLock(application: android.app.Application): AutoLockController = autoLock ?: synchronized(this) {
        autoLock ?: AutoLockController(application, vaultManager(application), appScope)
            .also { autoLock = it; it.start() }
    }

    /**
     * Drops every cached singleton after the vault is destroyed.
     *
     * Without this the old VaultManager (now permanently closed) and a Room handle pointing at
     * deleted files stay cached for the life of the process, so the app would appear broken until
     * the user force-stopped it. Called by the destroy path, not by ordinary locking.
     */
    fun resetAfterDestroy() {
        synchronized(this) {
            runCatching { vaultManager?.close() }
            vaultManager = null
            repository = null
            attachments = null
            index.clear()
        }
    }

    fun healthAnalyzer(weakThreshold: Int, oldDays: Int) = PasswordHealthAnalyzer(weakThreshold, oldDays)
    fun breachChecker() = BreachChecker()
    fun backupCodec() = BackupCodec(appVersion)
    fun recoveryKit() = RecoveryKitPdf(appVersion = appVersion)
}
