package app.securevault.data.repo

import app.securevault.core.crypto.Aead
import app.securevault.core.model.Folder
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultSession
import app.securevault.data.store.FolderRecord
import app.securevault.data.store.FolderStore
import app.securevault.data.store.ItemRecord
import app.securevault.data.store.ItemStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * The only place item ciphertext is produced or consumed.
 *
 * Sealing binds each record to its own row id as additional authenticated data, so ciphertext
 * cannot be copied from one row to another -- a swap is detected as tampering rather than
 * silently serving the wrong credential.
 *
 * It talks to [ItemStore] and [FolderStore] rather than to Room. The storage layer only ever sees
 * opaque blobs, which is what allows Android to keep Room and a desktop build to use something
 * else without either of them being anywhere near a key. The record format, the AAD string and the
 * wire layout are unchanged -- a database written by one platform is readable by the other.
 */
class ItemRepository(
    private val itemStore: ItemStore,
    private val folderStore: FolderStore
) {
    private companion object {
        const val RECORD_VERSION = 1
    }

    suspend fun loadAll(session: VaultSession): List<VaultItem> = withContext(Dispatchers.Default) {
        itemStore.getAll().mapNotNull { entity ->
            runCatching { decode(session, entity) }.getOrNull()
        }
    }

    suspend fun get(session: VaultSession, id: String): VaultItem? = withContext(Dispatchers.Default) {
        itemStore.getById(id)?.let { decode(session, it) }
    }

    suspend fun save(session: VaultSession, item: VaultItem): VaultItem = withContext(Dispatchers.Default) {
        val updated = item.copy(updatedAt = System.currentTimeMillis())
        itemStore.upsert(encode(session, updated))
        updated
    }

    suspend fun saveAll(session: VaultSession, items: List<VaultItem>) = withContext(Dispatchers.Default) {
        itemStore.upsertAll(items.map { encode(session, it) })
    }

    suspend fun delete(id: String) = withContext(Dispatchers.Default) { itemStore.delete(id) }

    suspend fun markUsed(id: String) = withContext(Dispatchers.Default) {
        itemStore.markUsed(id, System.currentTimeMillis())
    }

    suspend fun count(): Int = itemStore.count()

    suspend fun loadFolders(session: VaultSession): List<Folder> = withContext(Dispatchers.Default) {
        folderStore.getAll().mapNotNull { entity ->
            runCatching {
                val json = JSONObject(String(Aead.open(session.itemKey, entity.ciphertext, aad(entity.id))))
                Folder(
                    id = entity.id,
                    name = json.getString("name"),
                    parentId = json.optString("parentId").ifEmpty { null },
                    createdAt = entity.createdAt
                )
            }.getOrNull()
        }
    }

    suspend fun saveFolder(session: VaultSession, folder: Folder) = withContext(Dispatchers.Default) {
        val json = JSONObject().apply {
            put("name", folder.name)
            folder.parentId?.let { put("parentId", it) }
        }
        folderStore.upsert(
            FolderRecord(
                id = folder.id,
                createdAt = folder.createdAt,
                ciphertext = Aead.seal(session.itemKey, json.toString().toByteArray(), aad(folder.id))
            )
        )
    }

    suspend fun deleteFolder(id: String) = withContext(Dispatchers.Default) { folderStore.delete(id) }

    suspend fun wipeAll() = withContext(Dispatchers.Default) {
        itemStore.deleteAll()
        folderStore.deleteAll()
    }

    private fun encode(session: VaultSession, item: VaultItem): ItemRecord {
        val record = JSONObject().apply {
            put("v", RECORD_VERSION)
            put("type", item.type.name)
            put("favorite", item.favorite)
            item.folderId?.let { put("folderId", it) }
            put("payload", item.payload.toJson())
        }
        val plaintext = record.toString().toByteArray(Charsets.UTF_8)
        return try {
            ItemRecord(
                id = item.id,
                createdAt = item.createdAt,
                updatedAt = item.updatedAt,
                lastUsedAt = item.lastUsedAt,
                ciphertext = Aead.seal(session.itemKey, plaintext, aad(item.id))
            )
        } finally {
            plaintext.fill(0)
        }
    }

    private fun decode(session: VaultSession, entity: ItemRecord): VaultItem {
        val plaintext = Aead.open(session.itemKey, entity.ciphertext, aad(entity.id))
        return try {
            val record = JSONObject(String(plaintext, Charsets.UTF_8))
            VaultItem(
                id = entity.id,
                type = ItemType.valueOf(record.getString("type")),
                payload = ItemPayload.fromJson(record.getJSONObject("payload")),
                folderId = record.optString("folderId").ifEmpty { null },
                favorite = record.optBoolean("favorite", false),
                createdAt = entity.createdAt,
                updatedAt = entity.updatedAt,
                lastUsedAt = entity.lastUsedAt
            )
        } finally {
            plaintext.fill(0)
        }
    }

    private fun aad(id: String) = "securevault:record:v1:$id".toByteArray(Charsets.UTF_8)
}
