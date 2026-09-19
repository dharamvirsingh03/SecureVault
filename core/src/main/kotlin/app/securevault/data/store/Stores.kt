package app.securevault.data.store

/**
 * A stored item, as it exists on disk: an identifier, three timestamps, and a sealed blob.
 *
 * This is the whole of what persistence sees. Title, username, URL, type, folder, tags and
 * favourite state are all inside [ciphertext] -- someone holding the database learns how many
 * items exist and when they were last touched, and nothing else. That property is the reason this
 * record is shaped the way it is, and any storage backend that adds a searchable column would
 * break it.
 */
data class ItemRecord(
    val id: String,
    val createdAt: Long,
    val updatedAt: Long,
    val lastUsedAt: Long?,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is ItemRecord && id == other.id && ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * id.hashCode() + ciphertext.contentHashCode()
}

/** A stored folder. The name lives inside [ciphertext], not beside it. */
data class FolderRecord(
    val id: String,
    val createdAt: Long,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is FolderRecord && id == other.id && ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * id.hashCode() + ciphertext.contentHashCode()
}

/**
 * Ciphertext storage for items.
 *
 * Deliberately dumb. It moves opaque blobs and never sees a key, a plaintext field or a password;
 * all sealing and opening happens in `ItemRepository`, above this line. That is what lets Android
 * keep Room and a desktop build use something else without either of them touching cryptography.
 *
 * Implementations must not interpret [ItemRecord.ciphertext], must preserve it byte for byte, and
 * must treat `id` as the primary key with replace-on-conflict semantics.
 */
interface ItemStore {
    suspend fun getAll(): List<ItemRecord>
    suspend fun getById(id: String): ItemRecord?
    suspend fun upsert(record: ItemRecord)
    suspend fun upsertAll(records: List<ItemRecord>)
    suspend fun delete(id: String)

    /** Touches only the timestamp. Never rewrites the ciphertext. */
    suspend fun markUsed(id: String, timestamp: Long)

    suspend fun count(): Int
    suspend fun deleteAll()
}

/** Ciphertext storage for folders. Same contract as [ItemStore]. */
interface FolderStore {
    suspend fun getAll(): List<FolderRecord>
    suspend fun upsert(record: FolderRecord)
    suspend fun delete(id: String)
    suspend fun deleteAll()
}
