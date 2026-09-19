package app.securevault

import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.StreamAead
import app.securevault.core.crypto.VaultIntegrityException
import app.securevault.core.model.Fields
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultMetadata
import app.securevault.feature.backup.BackupCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * The boundary between "a file someone handed me" and "my vault".
 *
 * The premise these tests encode: a backup that authenticates is a backup written by someone who
 * held the key. It is not a backup written by someone who meant you well. Authentication tells you
 * the bytes are unaltered; it says nothing about whether the archive inside is sane. So the
 * unpacking step keeps its own guards.
 */
class RestoreBoundaryTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val codec = BackupCodec("1.0.0-test")
    private val vek = KeyHierarchy.generateVek()
    private val vaultId = "vault-restore-test"

    private val kdf = KdfParams(
        algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
        saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
        pbkdf2Rounds = 1_000
    )

    private val metadata = VaultMetadata(
        vaultId = vaultId,
        name = "Restore test",
        formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
        createdAt = 1_700_000_000_000,
        modifiedAt = 1_700_000_000_000,
        kdf = kdf,
        wrappedVek = KeyHierarchy.wrapVek(
            KeyHierarchy.deriveKek("a passphrase".toCharArray(), kdf), vek, vaultId
        ),
        recovery = null,
        keyFileRequired = false,
        backupId = "backup-1"
    )

    private val items = listOf(
        VaultItem(
            type = ItemType.LOGIN,
            payload = ItemPayload(
                title = "Example",
                fields = mapOf(Fields.USERNAME to "someone", Fields.PASSWORD to "a-password")
            )
        )
    )

    private fun backupKey() = codec.backupKeyFrom(vek)

    private fun goodBackup(attachments: List<File> = emptyList()): ByteArray {
        val out = ByteArrayOutputStream()
        codec.create(metadata, backupKey(), items, emptyList(), attachments, out)
        return out.toByteArray()
    }

    // ---- verification is separate from restoration -------------------------------------------

    @Test
    fun `verify writes nothing anywhere`() {
        val attachment = temp.newFile("verified.enc").apply { writeBytes(RandomSource.bytes(2048)) }
        val bytes = goodBackup(listOf(attachment))
        val before = temp.root.walkTopDown().filter { it.isFile }.map { it.path }.toSet()

        codec.verify(ByteArrayInputStream(bytes), { backupKey() })

        val after = temp.root.walkTopDown().filter { it.isFile }.map { it.path }.toSet()
        assertEquals("verify must not create a single file", before, after)
    }

    @Test
    fun `verify does not need a destination at all`() {
        // Its signature takes no target directory, which is the structural reason it cannot write
        // into a vault by accident.
        val header = codec.verify(ByteArrayInputStream(goodBackup()), { backupKey() })
        assertEquals(vaultId, header.vaultId)
    }

    // ---- nothing is unpacked before the whole body authenticates ------------------------------

    @Test
    fun `a tampered backup unpacks nothing`() {
        val attachment = temp.newFile("payload.enc").apply { writeBytes(RandomSource.bytes(4096)) }
        val bytes = goodBackup(listOf(attachment))
        bytes[bytes.size - 20] = (bytes[bytes.size - 20] + 1).toByte()

        val staging = temp.newFolder("staging-tampered")
        assertThrows(VaultIntegrityException::class.java) {
            codec.restore(ByteArrayInputStream(bytes), { backupKey() }, staging)
        }
        assertEquals("a failed restore must leave nothing behind", 0, staging.listFiles()!!.size)
    }

    @Test
    fun `the wrong key unpacks nothing`() {
        val attachment = temp.newFile("payload2.enc").apply { writeBytes(RandomSource.bytes(2048)) }
        val staging = temp.newFolder("staging-wrongkey")
        assertThrows(VaultIntegrityException::class.java) {
            codec.restore(
                ByteArrayInputStream(goodBackup(listOf(attachment))),
                { RandomSource.bytes(32) },
                staging
            )
        }
        assertEquals(0, staging.listFiles()!!.size)
    }

    // ---- attachments land in the directory the caller named -----------------------------------

    @Test
    fun `attachments go only to the staging directory given`() {
        val attachment = temp.newFile("real.enc").apply { writeBytes(RandomSource.bytes(1024)) }
        val staging = temp.newFolder("staging-ok")

        val (_, contents) = codec.restore(
            ByteArrayInputStream(goodBackup(listOf(attachment))), { backupKey() }, staging
        )
        assertEquals(1, contents.items.size)
        assertEquals(listOf("real.enc"), staging.listFiles()!!.map { it.name })
    }

    // ---- path traversal -----------------------------------------------------------------------

    @Test
    fun `traversal entry names are refused`() {
        val staging = temp.newFolder("staging-traversal")
        val sibling = File(staging.parentFile, "escaped.txt")
        sibling.delete()

        val hostile = craftBackup(
            entries = listOf(
                "attachments/../../escaped.txt" to "owned".toByteArray(),
                "attachments/../escaped.txt" to "owned".toByteArray(),
                "attachments//..//escaped.txt" to "owned".toByteArray()
            )
        )

        codec.restore(ByteArrayInputStream(hostile), { backupKey() }, staging)

        assertFalse("a crafted archive must not write outside staging", sibling.exists())
        // The basename-only rule may legitimately land "escaped.txt" *inside* staging; what must
        // never happen is a write above it.
        staging.listFiles()!!.forEach {
            assertTrue(it.canonicalPath.startsWith(staging.canonicalPath))
        }
    }

    @Test
    fun `absolute entry names are refused`() {
        val staging = temp.newFolder("staging-absolute")
        val hostile = craftBackup(
            entries = listOf("attachments//etc/passwd" to "owned".toByteArray())
        )
        codec.restore(ByteArrayInputStream(hostile), { backupKey() }, staging)
        staging.listFiles()!!.forEach {
            assertTrue(it.canonicalPath.startsWith(staging.canonicalPath))
        }
    }

    // ---- decompression bounds ------------------------------------------------------------------

    @Test
    fun `an archive with too many entries is refused`() {
        val staging = temp.newFolder("staging-many")
        val many = (0..10_050).map { "attachments/file$it.enc" to ByteArray(1) }
        val hostile = craftBackup(entries = many)

        assertThrows(VaultIntegrityException::class.java) {
            codec.restore(ByteArrayInputStream(hostile), { backupKey() }, staging)
        }
    }

    // ---- the KDF travels with the file ----------------------------------------------------------

    @Test
    fun `restore derives using the backup's own KDF, not the current device's`() {
        var seenAlgorithm: KdfAlgorithm? = null
        var seenSalt: String? = null

        codec.restore(ByteArrayInputStream(goodBackup()), { header ->
            seenAlgorithm = header.kdf.algorithm
            seenSalt = header.kdf.saltB64
            // Exactly what the production path does: derive from the header, not from anything
            // local. A backup made under different parameters must still open.
            val kek = KeyHierarchy.deriveKek("a passphrase".toCharArray(), header.kdf)
            try {
                val unwrapped = KeyHierarchy.unwrapVek(kek, header.wrappedVek, header.vaultId)
                try { codec.backupKeyFrom(unwrapped) } finally { unwrapped.fill(0) }
            } finally {
                kek.fill(0)
            }
        }, temp.newFolder("staging-kdf"))

        assertEquals(kdf.algorithm, seenAlgorithm)
        assertEquals(kdf.saltB64, seenSalt)
    }

    /**
     * Builds a well-formed, correctly authenticated backup with an attacker-chosen archive inside.
     *
     * This is the case that matters: everything the crypto can check passes, and the guards being
     * tested are the ones that run afterwards.
     */
    private fun craftBackup(entries: List<Pair<String, ByteArray>>): ByteArray {
        val headerJson = org.json.JSONObject().apply {
            put("formatVersion", BackupCodec.FORMAT_VERSION)
            put("vaultId", vaultId)
            put("backupId", "crafted")
            put("createdAt", System.currentTimeMillis())
            put("appVersion", "1.0.0-test")
            put("kdf", kdf.toJson())
            put("wrappedVek", metadata.wrappedVek)
            put("keyFileRequired", false)
        }
        val headerBytes = headerJson.toString().toByteArray(Charsets.UTF_8)

        val body = ByteArrayOutputStream()
        ZipOutputStream(body).use { zip ->
            zip.putNextEntry(ZipEntry("vault.json"))
            zip.write("""{"schema":1,"items":[],"folders":[]}""".toByteArray())
            zip.closeEntry()
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }

        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.writeInt(BackupCodec.MAGIC)
        data.writeInt(BackupCodec.FORMAT_VERSION)
        data.writeInt(headerBytes.size)
        data.write(headerBytes)
        data.flush()
        StreamAead.encrypt(
            backupKey(),
            ByteArrayInputStream(body.toByteArray()),
            data,
            MessageDigest.getInstance("SHA-256").digest(headerBytes)
        )
        data.flush()
        return out.toByteArray()
    }
}
