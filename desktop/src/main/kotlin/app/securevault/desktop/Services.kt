package app.securevault.desktop

import app.securevault.core.crypto.Kdf
import app.securevault.core.vault.VaultManager
import app.securevault.data.attachments.AttachmentStore
import app.securevault.data.repo.ItemRepository
import app.securevault.data.repo.VaultIndex
import app.securevault.desktop.platform.BouncyCastleArgon2Backend
import app.securevault.desktop.platform.DesktopAttachmentViewer
import app.securevault.desktop.platform.DesktopClipboard
import app.securevault.desktop.platform.DesktopVaultStore
import app.securevault.desktop.platform.Paths
import app.securevault.desktop.platform.SecretServiceStore
import app.securevault.desktop.platform.SqliteStorage
import app.securevault.feature.backup.BackupCodec
import app.securevault.feature.health.BreachChecker
import app.securevault.feature.backup.VaultRestorer
import app.securevault.feature.generator.WordLists
import app.securevault.feature.generator.WordSource
import app.securevault.feature.health.PasswordHealthAnalyzer
import kotlinx.coroutines.CoroutineScope
import java.io.File

/**
 * The desktop's wiring, and the mirror image of Android's ServiceLocator.
 *
 * Every platform decision this application makes is visible in one place: where files live, what
 * stores ciphertext, what backs optional convenience unlock, what the clipboard is. The vault
 * engine underneath is the same code the phone runs.
 *
 * Note what is passed as `biometricKeyStore`: null. Ubuntu v1 has no mechanism that
 * cryptographically gates a key behind a fingerprint, so there is none offered. Secret Service
 * convenience unlock is a separate thing and is not pretended to be biometric security.
 */
class Services(private val scope: CoroutineScope) : AutoCloseable {

    init {
        // Before anything can open or create a vault. Without it, :core would see no Argon2
        // implementation and behave exactly as a device whose native library failed to load:
        // new vaults on PBKDF2 with a warning, existing Argon2id vaults refusing to open.
        Kdf.installArgon2Backend(BouncyCastleArgon2Backend())
    }

    val appVersion: String = "1.0.0"

    private val storage = SqliteStorage(Paths.databaseFile)

    val repository = ItemRepository(storage.items, storage.folders)
    val index = VaultIndex()
    val attachments = AttachmentStore(Paths.attachmentsDir)
    val clipboard = DesktopClipboard(scope)
    val attachmentViewer = DesktopAttachmentViewer(attachments)
    val secretService = SecretServiceStore()
    val backupCodec = BackupCodec(appVersion)
    val breachChecker = BreachChecker()

    val vaultManager = VaultManager(
        filesDir = Paths.dataDir,
        store = DesktopVaultStore(),
        // No cryptographic biometric gate exists on Ubuntu. See SECURITY.md.
        biometricKeyStore = null,
        databaseCloser = { storage.close() },
        databaseFiles = { Paths.databaseFiles() }
    )

    val restorer = VaultRestorer(
        codec = backupCodec,
        repository = repository,
        liveAttachmentsDir = Paths.attachmentsDir,
        stagingRoot = Paths.stagingDir,
        journalFile = File(Paths.vaultDir, "restore.journal"),
        vaultHeaderExists = {
            vaultManager.state() !is app.securevault.core.vault.VaultState.Absent
        }
    )

    /** The EFF list from the classpath, with the shared fallback when it is not bundled. */
    val wordSource = WordSource {
        runCatching {
            javaClass.getResourceAsStream("/eff_large_wordlist.txt")
                ?.bufferedReader()?.use { WordLists.parse(it.readText()) }
        }.getOrNull()?.takeIf { it.isNotEmpty() } ?: DESKTOP_FALLBACK_WORDS
    }

    fun healthAnalyzer(weakThreshold: Int, oldDays: Int) =
        PasswordHealthAnalyzer(weakThreshold, oldDays)

    override fun close() {
        clipboard.clearOurs()
        attachmentViewer.purge()
        runCatching { vaultManager.close() }
        runCatching { storage.close() }
    }
}

/** Small, honest fallback. The generator reports entropy from the list actually in use. */
private val DESKTOP_FALLBACK_WORDS = listOf(
    "abacus", "anchor", "antique", "autumn", "badge", "bamboo", "banjo", "basket", "beacon",
    "bison", "blanket", "blossom", "bobcat", "bramble", "bridge", "bucket", "bundle", "cabin",
    "cactus", "canyon", "cargo", "carrot", "cedar", "chisel", "cinder", "clover", "cobalt",
    "comet", "compass", "copper", "coral", "cotton", "cradle", "crimson", "crystal", "dagger",
    "dahlia", "denim", "dolphin", "domino", "driftwood", "ember", "emerald", "engine", "fable",
    "falcon", "fennel", "fiddle", "flint", "forest", "fossil", "fountain", "gadget", "gallop",
    "garnet", "gazelle", "ginger", "glacier", "granite", "gravel", "grotto", "hammock", "harbour",
    "harvest", "hazel", "hearth", "helmet", "hollow", "hornet", "icicle", "indigo", "island",
    "ivory", "jasmine", "jigsaw", "jubilee", "juniper", "kettle", "keystone", "lantern", "lattice",
    "lavender", "ledger", "lichen", "lilac", "lobster", "lumber", "magnet", "mallet", "maple",
    "marble", "marigold", "meadow", "mercury", "mineral", "mitten", "monsoon", "mosaic", "nectar",
    "nimbus", "nomad", "nutmeg", "obsidian", "olive", "onyx", "orbit", "orchard", "otter",
    "paddle", "pantry", "papaya", "parsley", "pebble", "pelican", "pepper", "pewter", "pickaxe",
    "pigment", "pillar", "plateau", "pollen", "poplar", "prairie", "pumpkin", "quarry", "quartz",
    "quiver", "radish", "rafter", "rampart", "ravine", "rhubarb", "ribbon", "rivet", "rosemary",
    "rudder", "saffron", "sapling", "satchel", "scallop", "sequoia", "shale", "shovel", "silo",
    "sparrow", "spindle", "sprocket", "starling", "stencil", "sundial", "tamarind", "teapot",
    "thicket", "thimble", "thistle", "timber", "tinder", "toffee", "trellis", "trombone", "trowel",
    "truffle", "tundra", "turnip", "vanilla", "velvet", "vinegar", "violet", "walnut", "whisker",
    "willow", "window", "wombat", "yarrow"
)
