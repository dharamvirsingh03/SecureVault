package app.securevault.data.db

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

/**
 * Storage layout.
 *
 * Room holds ciphertext and nothing else. The only plaintext columns are a random UUID and three
 * timestamps, kept outside the blob so the list can be sorted and backups merged without
 * decrypting every row first. Everything a person would recognise -- title, username, URL, tags,
 * folder, item type -- lives inside [ItemEntity.ciphertext].
 *
 * An encrypted SQLite build (SQLCipher) can be layered underneath this with a key from
 * VaultSession.databaseKey, and that is worth doing as defence in depth. It is not the security
 * boundary: whole-database encryption alone leaves plaintext in journals, temp files and process
 * memory, and it puts every secret under one key with a lifetime as long as the open connection.
 * Per-record authenticated encryption is what actually protects the data here.
 */
@Entity(tableName = "items")
data class ItemEntity(
    @PrimaryKey val id: String,
    val createdAt: Long,
    val updatedAt: Long,
    val lastUsedAt: Long?,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is ItemEntity && id == other.id && ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * id.hashCode() + ciphertext.contentHashCode()
}

@Entity(tableName = "folders")
data class FolderEntity(
    @PrimaryKey val id: String,
    val createdAt: Long,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is FolderEntity && id == other.id && ciphertext.contentEquals(other.ciphertext)

    override fun hashCode(): Int = 31 * id.hashCode() + ciphertext.contentHashCode()
}

@Dao
interface ItemDao {
    @Query("SELECT * FROM items ORDER BY updatedAt DESC")
    fun observeAll(): Flow<List<ItemEntity>>

    @Query("SELECT * FROM items")
    suspend fun getAll(): List<ItemEntity>

    @Query("SELECT * FROM items WHERE id = :id")
    suspend fun getById(id: String): ItemEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: ItemEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(items: List<ItemEntity>)

    @Query("DELETE FROM items WHERE id = :id")
    suspend fun delete(id: String)

    @Query("UPDATE items SET lastUsedAt = :timestamp WHERE id = :id")
    suspend fun markUsed(id: String, timestamp: Long)

    @Query("SELECT COUNT(*) FROM items")
    suspend fun count(): Int

    @Query("DELETE FROM items")
    suspend fun deleteAll()
}

@Dao
interface FolderDao {
    @Query("SELECT * FROM folders ORDER BY createdAt ASC")
    fun observeAll(): Flow<List<FolderEntity>>

    @Query("SELECT * FROM folders")
    suspend fun getAll(): List<FolderEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(folder: FolderEntity)

    @Query("DELETE FROM folders WHERE id = :id")
    suspend fun delete(id: String)

    @Query("DELETE FROM folders")
    suspend fun deleteAll()
}

@Database(entities = [ItemEntity::class, FolderEntity::class], version = 1, exportSchema = true)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun itemDao(): ItemDao
    abstract fun folderDao(): FolderDao

    companion object {
        const val NAME = "securevault.db"

        @Volatile
        private var instance: VaultDatabase? = null

        fun get(context: Context): VaultDatabase = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(context.applicationContext, VaultDatabase::class.java, NAME)
                .build()
                .also { instance = it }
        }

        /**
         * Closes the database and forgets the singleton.
         *
         * Required before deleting the database files. SQLite keeps a write-ahead log and a
         * journal alongside the main file; deleting the main file while a connection is open can
         * leave those behind, which would mean a "destroyed" vault that still has ciphertext on
         * disk. Callers must not hold a reference to the old instance afterwards -- [get] builds
         * a fresh one on the next call.
         */
        fun closeAndClear() {
            synchronized(this) {
                instance?.let { db -> runCatching { db.close() } }
                instance = null
            }
        }
    }
}
