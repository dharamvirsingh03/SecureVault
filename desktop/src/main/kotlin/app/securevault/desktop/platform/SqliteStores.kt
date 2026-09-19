package app.securevault.desktop.platform

import app.securevault.data.store.FolderRecord
import app.securevault.data.store.FolderStore
import app.securevault.data.store.ItemRecord
import app.securevault.data.store.ItemStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.sql.Connection
import java.sql.DriverManager

/**
 * SQLite persistence for the desktop, behind the same [ItemStore]/[FolderStore] contract Android's
 * Room adapters satisfy.
 *
 * The schema is deliberately identical in shape to the Room one: an id, timestamps, and an opaque
 * blob. Nothing here decrypts, inspects or indexes the ciphertext, and there is no searchable
 * column -- adding one would recreate on disk exactly the data the encryption exists to hide.
 *
 * Note what this class does **not** do: it never sees a key, a password or a plaintext field. That
 * boundary is why a desktop backend could be swapped for another without touching cryptography.
 *
 * SQLCipher is not used, for the same reason it is not used on Android: whole-database encryption
 * would leave plaintext in journals and temp files and put every secret under one long-lived key.
 * Per-record authenticated encryption above this layer is what protects the data.
 */
class SqliteStorage(databaseFile: File) : AutoCloseable {

    private val url = "jdbc:sqlite:${databaseFile.absolutePath}"

    // SQLite tolerates concurrent readers but one writer; the vault is small and this serialises
    // everything rather than depending on busy-timeout behaviour.
    private val lock = Mutex()

    private val connection: Connection by lazy {
        Paths.secured(databaseFile.parentFile)
        DriverManager.getConnection(url).also { conn ->
            conn.createStatement().use { st ->
                st.executeUpdate("PRAGMA journal_mode=WAL")
                st.executeUpdate("PRAGMA synchronous=FULL")
                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS items (
                        id TEXT PRIMARY KEY NOT NULL,
                        createdAt INTEGER NOT NULL,
                        updatedAt INTEGER NOT NULL,
                        lastUsedAt INTEGER,
                        ciphertext BLOB NOT NULL
                    )
                    """.trimIndent()
                )
                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS folders (
                        id TEXT PRIMARY KEY NOT NULL,
                        createdAt INTEGER NOT NULL,
                        ciphertext BLOB NOT NULL
                    )
                    """.trimIndent()
                )
            }
            Paths.restrict(databaseFile)
        }
    }

    internal suspend fun <T> withConnection(block: (Connection) -> T): T =
        withContext(Dispatchers.IO) { lock.withLock { block(connection) } }

    val items: ItemStore = SqliteItemStore(this)
    val folders: FolderStore = SqliteFolderStore(this)

    override fun close() {
        runCatching { connection.close() }
    }
}

private class SqliteItemStore(private val storage: SqliteStorage) : ItemStore {

    override suspend fun getAll(): List<ItemRecord> = storage.withConnection { conn ->
        conn.prepareStatement("SELECT id, createdAt, updatedAt, lastUsedAt, ciphertext FROM items")
            .use { st ->
                st.executeQuery().use { rs ->
                    buildList {
                        while (rs.next()) add(rs.toItemRecord())
                    }
                }
            }
    }

    override suspend fun getById(id: String): ItemRecord? = storage.withConnection { conn ->
        conn.prepareStatement(
            "SELECT id, createdAt, updatedAt, lastUsedAt, ciphertext FROM items WHERE id = ?"
        ).use { st ->
            st.setString(1, id)
            st.executeQuery().use { rs -> if (rs.next()) rs.toItemRecord() else null }
        }
    }

    override suspend fun upsert(record: ItemRecord) = storage.withConnection { conn ->
        conn.upsertItem(record)
    }

    override suspend fun upsertAll(records: List<ItemRecord>) = storage.withConnection { conn ->
        // One transaction: a partial import is a vault in a state nobody asked for.
        val previous = conn.autoCommit
        conn.autoCommit = false
        try {
            records.forEach { conn.upsertItem(it) }
            conn.commit()
        } catch (e: Throwable) {
            runCatching { conn.rollback() }
            throw e
        } finally {
            conn.autoCommit = previous
        }
    }

    override suspend fun delete(id: String) = storage.withConnection { conn ->
        conn.prepareStatement("DELETE FROM items WHERE id = ?").use { st ->
            st.setString(1, id)
            st.executeUpdate()
        }
        Unit
    }

    override suspend fun markUsed(id: String, timestamp: Long) = storage.withConnection { conn ->
        // Touches the timestamp only; the ciphertext is never rewritten.
        conn.prepareStatement("UPDATE items SET lastUsedAt = ? WHERE id = ?").use { st ->
            st.setLong(1, timestamp)
            st.setString(2, id)
            st.executeUpdate()
        }
        Unit
    }

    override suspend fun count(): Int = storage.withConnection { conn ->
        conn.createStatement().use { st ->
            st.executeQuery("SELECT COUNT(*) FROM items").use { rs -> if (rs.next()) rs.getInt(1) else 0 }
        }
    }

    override suspend fun deleteAll() = storage.withConnection { conn ->
        conn.createStatement().use { it.executeUpdate("DELETE FROM items") }
        Unit
    }
}

private class SqliteFolderStore(private val storage: SqliteStorage) : FolderStore {

    override suspend fun getAll(): List<FolderRecord> = storage.withConnection { conn ->
        conn.prepareStatement("SELECT id, createdAt, ciphertext FROM folders ORDER BY createdAt ASC")
            .use { st ->
                st.executeQuery().use { rs ->
                    buildList {
                        while (rs.next()) {
                            add(
                                FolderRecord(
                                    id = rs.getString("id"),
                                    createdAt = rs.getLong("createdAt"),
                                    ciphertext = rs.getBytes("ciphertext")
                                )
                            )
                        }
                    }
                }
            }
    }

    override suspend fun upsert(record: FolderRecord) = storage.withConnection { conn ->
        conn.prepareStatement(
            "INSERT INTO folders(id, createdAt, ciphertext) VALUES(?,?,?) " +
                "ON CONFLICT(id) DO UPDATE SET createdAt=excluded.createdAt, ciphertext=excluded.ciphertext"
        ).use { st ->
            st.setString(1, record.id)
            st.setLong(2, record.createdAt)
            st.setBytes(3, record.ciphertext)
            st.executeUpdate()
        }
        Unit
    }

    override suspend fun delete(id: String) = storage.withConnection { conn ->
        conn.prepareStatement("DELETE FROM folders WHERE id = ?").use { st ->
            st.setString(1, id)
            st.executeUpdate()
        }
        Unit
    }

    override suspend fun deleteAll() = storage.withConnection { conn ->
        conn.createStatement().use { it.executeUpdate("DELETE FROM folders") }
        Unit
    }
}

private fun Connection.upsertItem(record: ItemRecord) {
    prepareStatement(
        "INSERT INTO items(id, createdAt, updatedAt, lastUsedAt, ciphertext) VALUES(?,?,?,?,?) " +
            "ON CONFLICT(id) DO UPDATE SET createdAt=excluded.createdAt, " +
            "updatedAt=excluded.updatedAt, lastUsedAt=excluded.lastUsedAt, " +
            "ciphertext=excluded.ciphertext"
    ).use { st ->
        st.setString(1, record.id)
        st.setLong(2, record.createdAt)
        st.setLong(3, record.updatedAt)
        if (record.lastUsedAt == null) st.setNull(4, java.sql.Types.INTEGER)
        else st.setLong(4, record.lastUsedAt!!)
        st.setBytes(5, record.ciphertext)
        st.executeUpdate()
    }
}

private fun java.sql.ResultSet.toItemRecord(): ItemRecord {
    // wasNull() describes the column read *most recently*, not the one named above it. Reading
    // lastUsedAt and then evaluating wasNull() inside the constructor call meant three more
    // columns were read in between, so wasNull() was answering about updatedAt -- which is never
    // null -- and a never-used item came back as 0L instead of null. Capture it immediately.
    val lastUsedRaw = getLong("lastUsedAt")
    val lastUsedWasNull = wasNull()
    return ItemRecord(
        id = getString("id"),
        createdAt = getLong("createdAt"),
        updatedAt = getLong("updatedAt"),
        lastUsedAt = if (lastUsedWasNull) null else lastUsedRaw,
        ciphertext = getBytes("ciphertext")
    )
}
