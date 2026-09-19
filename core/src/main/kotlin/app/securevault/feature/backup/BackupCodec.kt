package app.securevault.feature.backup

import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.StreamAead
import app.securevault.core.crypto.UnsupportedFormatException
import app.securevault.core.crypto.VaultIntegrityException
import app.securevault.core.model.Folder
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.RecoveryBlock
import app.securevault.core.vault.VaultMetadata
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.json.JSONArray
import org.json.JSONObject

/**
 * The plaintext part of a backup file.
 *
 * Everything here is load-bearing: without the KDF parameters, salt, wrapped key and vault id, a
 * backup cannot be opened on a new device with only a master password, which is the entire point
 * of the format. Nothing here is secret and nothing here opens anything.
 *
 * Format 2 removed three fields that were in format 1 -- the vault's name and its item and
 * attachment counts. Those were only ever used to describe a file before authenticating, and a
 * vault called "Work — Acme Corp" holding 240 items tells someone who steals the file quite a lot
 * about what is worth attacking. They now live inside the encrypted body ([BackupManifest]) and
 * are readable only after the password is supplied. Format 1 files still open; their values are
 * exposed through [legacyManifest] so the reader can tell they came from plaintext.
 */
data class BackupHeader(
    val formatVersion: Int,
    val vaultId: String,
    val backupId: String,
    val createdAt: Long,
    val appVersion: String,
    val kdf: KdfParams,
    val wrappedVek: String,
    val recovery: RecoveryBlock?,
    val keyFileRequired: Boolean,
    /** Populated only for format 1 files, where these were readable without the password. */
    val legacyManifest: BackupManifest? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("formatVersion", formatVersion)
        put("vaultId", vaultId)
        put("backupId", backupId)
        put("createdAt", createdAt)
        put("appVersion", appVersion)
        put("kdf", kdf.toJson())
        put("wrappedVek", wrappedVek)
        put("keyFileRequired", keyFileRequired)
        recovery?.let { put("recovery", it.toJson()) }
    }

    companion object {
        fun fromJson(json: JSONObject): BackupHeader {
            val version = json.getInt("formatVersion")
            return BackupHeader(
                formatVersion = version,
                vaultId = json.getString("vaultId"),
                backupId = json.getString("backupId"),
                createdAt = json.getLong("createdAt"),
                appVersion = json.optString("appVersion", "unknown"),
                kdf = KdfParams.fromJson(json.getJSONObject("kdf")),
                wrappedVek = json.getString("wrappedVek"),
                recovery = json.optJSONObject("recovery")?.let { RecoveryBlock.fromJson(it) },
                keyFileRequired = json.optBoolean("keyFileRequired", false),
                legacyManifest = if (version >= 2 || !json.has("vaultName")) null else BackupManifest(
                    vaultName = json.optString("vaultName", "Vault"),
                    itemCount = json.optInt("itemCount", 0),
                    attachmentCount = json.optInt("attachmentCount", 0)
                )
            )
        }
    }
}

/** Descriptive detail about a backup. Encrypted from format 2 onwards. */
data class BackupManifest(
    val vaultName: String,
    val itemCount: Int,
    val attachmentCount: Int
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("vaultName", vaultName)
        put("itemCount", itemCount)
        put("attachmentCount", attachmentCount)
    }

    companion object {
        fun fromJson(json: JSONObject) = BackupManifest(
            vaultName = json.optString("vaultName", "Vault"),
            itemCount = json.optInt("itemCount", 0),
            attachmentCount = json.optInt("attachmentCount", 0)
        )
    }
}

data class BackupContents(
    val items: List<VaultItem>,
    val folders: List<Folder>,
    val manifest: BackupManifest? = null
)

/**
 * The .securevault encrypted backup format.
 *
 *   "SVLT" | formatVersion | headerLength | header JSON | chunked AES-256-GCM body
 *
 * The header is plaintext by design: it carries the KDF parameters, salt and the wrapped vault key
 * needed to open the file. None of that is secret, and putting it in the file is what makes a
 * backup restorable on a new device with nothing but the master password. The header is bound to
 * the body as additional authenticated data, so it cannot be edited -- swapping in weaker KDF
 * parameters breaks decryption rather than weakening it.
 *
 * The master password is not in the file, in any form. Without it (or the recovery code, when the
 * user enabled recovery) the file is ciphertext and stays that way.
 */
class BackupCodec(private val appVersion: String) {

    companion object {
        const val EXTENSION = "securevault"
        const val MAGIC = 0x53564C54 // "SVLT"

        /** Written by this build. */
        const val FORMAT_VERSION = 2

        /** Oldest format still readable. Format 1 kept the vault name and counts in plaintext. */
        const val MIN_SUPPORTED_VERSION = 1

        private const val ENTRY_VAULT = "vault.json"
        private const val ENTRY_MANIFEST = "manifest.json"
        private const val ENTRY_ATTACHMENTS = "attachments/"

        /** Sanity bound on the declared header length, to reject absurd or hostile files. */
        private const val MAX_HEADER_BYTES = 1 shl 20

        /**
         * Bounds on what a restore will unpack.
         *
         * A backup that authenticates is not automatically a backup that is safe to expand. These
         * caps stop a decompression bomb -- an archive that is small on disk and enormous once
         * unpacked -- from filling the device while the user watches a progress bar.
         */
        private const val MAX_ENTRIES = 10_000
        private const val MAX_TOTAL_BYTES = 2L * 1024 * 1024 * 1024
    }

    fun create(
        metadata: VaultMetadata,
        backupKey: ByteArray,
        items: List<VaultItem>,
        folders: List<Folder>,
        attachmentFiles: List<File>,
        output: OutputStream
    ) {
        val header = BackupHeader(
            formatVersion = FORMAT_VERSION,
            vaultId = metadata.vaultId,
            backupId = metadata.backupId,
            createdAt = System.currentTimeMillis(),
            appVersion = appVersion,
            // The KDF travels with the backup exactly as the vault recorded it. Restoring must
            // never re-derive under different parameters: the wrapped key here was produced under
            // these, and quietly writing weaker ones would be both broken and dishonest.
            kdf = metadata.kdf,
            wrappedVek = metadata.wrappedVek,
            recovery = metadata.recovery,
            keyFileRequired = metadata.keyFileRequired
        )
        val manifest = BackupManifest(
            vaultName = metadata.name,
            itemCount = items.size,
            attachmentCount = attachmentFiles.size
        )
        val headerBytes = header.toJson().toString().toByteArray(Charsets.UTF_8)

        val out = DataOutputStream(output)
        out.writeInt(MAGIC)
        out.writeInt(FORMAT_VERSION)
        out.writeInt(headerBytes.size)
        out.write(headerBytes)
        out.flush()

        val body = ByteArrayOutputStream()
        ZipOutputStream(body).use { zip ->
            zip.putNextEntry(ZipEntry(ENTRY_MANIFEST))
            zip.write(manifest.toJson().toString().toByteArray(Charsets.UTF_8))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry(ENTRY_VAULT))
            zip.write(serialiseVault(items, folders).toByteArray(Charsets.UTF_8))
            zip.closeEntry()
            attachmentFiles.forEach { file ->
                zip.putNextEntry(ZipEntry(ENTRY_ATTACHMENTS + file.name))
                file.inputStream().use { it.copyTo(zip) }
                zip.closeEntry()
            }
        }
        val bodyBytes = body.toByteArray()
        try {
            StreamAead.encrypt(backupKey, ByteArrayInputStream(bodyBytes), out, aad(headerBytes))
        } finally {
            bodyBytes.fill(0)
        }
        out.flush()
    }

    /**
     * Reads and validates the plaintext header. The single entry point for all three readers --
     * previously restore() and verify() skipped the length bound that readHeader() applied, so a
     * crafted file could ask them to allocate an arbitrary array before anything was checked.
     */
    private fun readHeaderBytes(data: DataInputStream): Pair<BackupHeader, ByteArray> {
        if (data.readInt() != MAGIC) throw UnsupportedFormatException("This is not a SecureVault backup")
        val version = data.readInt()
        if (version > FORMAT_VERSION) {
            throw UnsupportedFormatException("This backup was written by a newer version of the app")
        }
        if (version < MIN_SUPPORTED_VERSION) {
            throw UnsupportedFormatException("This backup uses a format this app no longer reads")
        }
        val length = data.readInt()
        if (length !in 1..MAX_HEADER_BYTES) throw VaultIntegrityException()
        val headerBytes = ByteArray(length)
        data.readFully(headerBytes)
        val header = try {
            BackupHeader.fromJson(JSONObject(String(headerBytes, Charsets.UTF_8)))
        } catch (e: org.json.JSONException) {
            throw VaultIntegrityException(cause = e)
        }
        if (header.formatVersion != version) {
            // The framing and the JSON disagree; something rewrote one of them.
            throw VaultIntegrityException()
        }
        return header to headerBytes
    }

    /**
     * Reads the header only. Used to show what little can honestly be shown about a backup file
     * before a password is supplied: when it was made, which vault id it belongs to, and which KDF
     * will be needed. From format 2 the vault's name and item count are not among those things.
     */
    fun readHeader(input: InputStream): BackupHeader = readHeaderBytes(DataInputStream(input)).first

    /**
     * Restores from an already-open stream. The caller derives the KEK from the password using the
     * KDF parameters in the header, unwraps the vault key and passes the backup subkey in.
     */
    fun restore(
        input: InputStream,
        backupKeyProvider: (BackupHeader) -> ByteArray,
        attachmentTarget: File
    ): Pair<BackupHeader, BackupContents> {
        val data = DataInputStream(input)
        val (header, headerBytes) = readHeaderBytes(data)

        val backupKey = backupKeyProvider(header)
        val body = ByteArrayOutputStream()
        try {
            StreamAead.decrypt(backupKey, data, body, aad(headerBytes))
        } finally {
            backupKey.fill(0)
        }

        // Everything below runs only after StreamAead.decrypt above has authenticated *every*
        // chunk of the body. Nothing from an unverified file is ever unpacked: a single flipped
        // bit anywhere in the archive throws before this point, and no file is written.
        var contents = BackupContents(emptyList(), emptyList())
        var manifest: BackupManifest? = header.legacyManifest
        attachmentTarget.mkdirs()
        val targetRoot = attachmentTarget.canonicalFile
        var entriesSeen = 0
        var bytesWritten = 0L

        ZipInputStream(ByteArrayInputStream(body.toByteArray())).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (++entriesSeen > MAX_ENTRIES) throw VaultIntegrityException()
                when {
                    entry.isDirectory -> Unit
                    entry.name == ENTRY_MANIFEST ->
                        manifest = runCatching {
                            BackupManifest.fromJson(JSONObject(String(zip.readBytes(), Charsets.UTF_8)))
                        }.getOrNull()
                    entry.name == ENTRY_VAULT -> contents = deserialiseVault(zip.readBytes())
                    entry.name.startsWith(ENTRY_ATTACHMENTS) -> {
                        // Three separate guards, because archive entry names are attacker-supplied
                        // even in a file that authenticates: authentication proves the archive was
                        // written by someone holding the key, not that they meant you well.
                        val name = File(entry.name).name
                        if (name.isEmpty() || name.contains("..") || name.contains('/') ||
                            name.contains('\\')
                        ) {
                            zip.closeEntry(); entry = zip.nextEntry; continue
                        }
                        val destination = File(targetRoot, name)
                        // Belt and braces: confirm the resolved path is still inside the staging
                        // directory after the filesystem has had its say about the name.
                        if (!destination.canonicalFile.path.startsWith(targetRoot.path + File.separator)) {
                            zip.closeEntry(); entry = zip.nextEntry; continue
                        }
                        bytesWritten += copyBounded(zip, destination, MAX_TOTAL_BYTES - bytesWritten)
                    }
                }
                zip.closeEntry()
                entry = zip.nextEntry
            }
        }
        return header to contents.copy(manifest = manifest)
    }

    /** Confirms the file parses and the supplied key opens it, without writing anything. */
    fun verify(input: InputStream, backupKeyProvider: (BackupHeader) -> ByteArray): BackupHeader {
        val data = DataInputStream(input)
        val (header, headerBytes) = readHeaderBytes(data)
        val key = backupKeyProvider(header)
        try {
            StreamAead.decrypt(key, data, NullOutputStream(), aad(headerBytes))
        } finally {
            key.fill(0)
        }
        return header
    }

    /** Derives the backup key the way create() expects, given the master password path. */
    fun backupKeyFrom(vek: ByteArray): ByteArray =
        KeyHierarchy.subkey(vek, app.securevault.core.crypto.KeyDomain.BACKUP)

    private fun aad(headerBytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(headerBytes)

    private fun serialiseVault(items: List<VaultItem>, folders: List<Folder>): String =
        JSONObject().apply {
            put("schema", 1)
            put("items", JSONArray(items.map { item ->
                JSONObject().apply {
                    put("id", item.id)
                    put("type", item.type.name)
                    put("favorite", item.favorite)
                    item.folderId?.let { put("folderId", it) }
                    put("createdAt", item.createdAt)
                    put("updatedAt", item.updatedAt)
                    item.lastUsedAt?.let { put("lastUsedAt", it) }
                    put("payload", item.payload.toJson())
                }
            }))
            put("folders", JSONArray(folders.map { folder ->
                JSONObject().apply {
                    put("id", folder.id)
                    put("name", folder.name)
                    folder.parentId?.let { put("parentId", it) }
                    put("createdAt", folder.createdAt)
                }
            }))
        }.toString()

    private fun deserialiseVault(bytes: ByteArray): BackupContents {
        val json = JSONObject(String(bytes, Charsets.UTF_8))
        val itemsJson = json.optJSONArray("items") ?: JSONArray()
        val foldersJson = json.optJSONArray("folders") ?: JSONArray()
        val items = (0 until itemsJson.length()).map { index ->
            val o = itemsJson.getJSONObject(index)
            VaultItem(
                id = o.getString("id"),
                type = ItemType.valueOf(o.getString("type")),
                payload = ItemPayload.fromJson(o.getJSONObject("payload")),
                folderId = o.optString("folderId").ifEmpty { null },
                favorite = o.optBoolean("favorite", false),
                createdAt = o.optLong("createdAt", System.currentTimeMillis()),
                updatedAt = o.optLong("updatedAt", System.currentTimeMillis()),
                lastUsedAt = if (o.has("lastUsedAt")) o.getLong("lastUsedAt") else null
            )
        }
        val folders = (0 until foldersJson.length()).map { index ->
            val o = foldersJson.getJSONObject(index)
            Folder(
                id = o.getString("id"),
                name = o.getString("name"),
                parentId = o.optString("parentId").ifEmpty { null },
                createdAt = o.optLong("createdAt", System.currentTimeMillis())
            )
        }
        return BackupContents(items, folders)
    }

    /** Copies at most [remaining] bytes, failing rather than silently truncating. */
    private fun copyBounded(input: InputStream, destination: File, remaining: Long): Long {
        if (remaining <= 0) throw VaultIntegrityException()
        var written = 0L
        val buffer = ByteArray(64 * 1024)
        destination.outputStream().use { out ->
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                written += read
                if (written > remaining) {
                    out.flush()
                    destination.delete()
                    throw VaultIntegrityException()
                }
                out.write(buffer, 0, read)
            }
        }
        return written
    }

    private class NullOutputStream : OutputStream() {
        override fun write(b: Int) = Unit
        override fun write(b: ByteArray, off: Int, len: Int) = Unit
    }
}
