package app.securevault.data.db

import app.securevault.data.store.FolderRecord
import app.securevault.data.store.FolderStore
import app.securevault.data.store.ItemRecord
import app.securevault.data.store.ItemStore

/**
 * Room behind the portable store interfaces.
 *
 * Pure translation: the record types and the entity types hold the same five and three fields, so
 * each method is a field-for-field copy and a delegated call. No query changed, no schema changed,
 * no ciphertext is touched. The Room entities, DAOs, table names and database version are exactly
 * what shipped and was tested on a phone.
 */
class RoomItemStore(private val dao: ItemDao) : ItemStore {

    override suspend fun getAll(): List<ItemRecord> = dao.getAll().map { it.toRecord() }

    override suspend fun getById(id: String): ItemRecord? = dao.getById(id)?.toRecord()

    override suspend fun upsert(record: ItemRecord) = dao.upsert(record.toEntity())

    override suspend fun upsertAll(records: List<ItemRecord>) =
        dao.upsertAll(records.map { it.toEntity() })

    override suspend fun delete(id: String) = dao.delete(id)

    override suspend fun markUsed(id: String, timestamp: Long) = dao.markUsed(id, timestamp)

    override suspend fun count(): Int = dao.count()

    override suspend fun deleteAll() = dao.deleteAll()

    private fun ItemEntity.toRecord() =
        ItemRecord(id = id, createdAt = createdAt, updatedAt = updatedAt,
            lastUsedAt = lastUsedAt, ciphertext = ciphertext)

    private fun ItemRecord.toEntity() =
        ItemEntity(id = id, createdAt = createdAt, updatedAt = updatedAt,
            lastUsedAt = lastUsedAt, ciphertext = ciphertext)
}

/** Room behind [FolderStore]. Same translation, same guarantees. */
class RoomFolderStore(private val dao: FolderDao) : FolderStore {

    override suspend fun getAll(): List<FolderRecord> = dao.getAll().map { it.toRecord() }

    override suspend fun upsert(record: FolderRecord) = dao.upsert(record.toEntity())

    override suspend fun delete(id: String) = dao.delete(id)

    override suspend fun deleteAll() = dao.deleteAll()

    private fun FolderEntity.toRecord() =
        FolderRecord(id = id, createdAt = createdAt, ciphertext = ciphertext)

    private fun FolderRecord.toEntity() =
        FolderEntity(id = id, createdAt = createdAt, ciphertext = ciphertext)
}
