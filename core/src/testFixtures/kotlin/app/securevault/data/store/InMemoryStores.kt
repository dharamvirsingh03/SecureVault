package app.securevault.data.store

/**
 * In-memory [ItemStore] and [FolderStore], shared by `:core`'s repository tests and `:app`'s
 * restore tests.
 *
 * These store exactly what a real backend stores -- an id, timestamps and an opaque blob -- so the
 * encryption, the per-row AAD binding and the read-back checks in the tests above them are all
 * real. Only SQLite is substituted. That matters: a fake that decrypted or inspected the blob
 * would quietly stop testing the property the storage layer exists to guarantee.
 */
class InMemoryItemStore : ItemStore {

    val rows = linkedMapOf<String, ItemRecord>()

    override suspend fun getAll(): List<ItemRecord> = rows.values.toList()

    override suspend fun getById(id: String): ItemRecord? = rows[id]

    override suspend fun upsert(record: ItemRecord) {
        rows[record.id] = record
    }

    override suspend fun upsertAll(records: List<ItemRecord>) {
        records.forEach { rows[it.id] = it }
    }

    override suspend fun delete(id: String) {
        rows.remove(id)
    }

    override suspend fun markUsed(id: String, timestamp: Long) {
        rows[id] = rows[id]?.copy(lastUsedAt = timestamp) ?: return
    }

    override suspend fun count(): Int = rows.size

    override suspend fun deleteAll() {
        rows.clear()
    }
}

class InMemoryFolderStore : FolderStore {

    val rows = linkedMapOf<String, FolderRecord>()

    override suspend fun getAll(): List<FolderRecord> = rows.values.toList()

    override suspend fun upsert(record: FolderRecord) {
        rows[record.id] = record
    }

    override suspend fun delete(id: String) {
        rows.remove(id)
    }

    override suspend fun deleteAll() {
        rows.clear()
    }
}
