package app.securevault

import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.UnsupportedFormatException
import app.securevault.core.crypto.VaultIntegrityException
import app.securevault.core.model.Fields
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.TotpConfig
import app.securevault.core.model.VaultItem
import app.securevault.core.model.Folder
import app.securevault.core.vault.VaultMetadata
import app.securevault.feature.backup.BackupCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * What a stolen `.securevault` file gives away, and what it must not.
 *
 * The interesting assertion is `plaintext header leaks nothing descriptive`: the file is scanned
 * for every string a thief would want, including ones that used to be readable without a password.
 */
class BackupFormatTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val codec = BackupCodec("1.0.0-test")
    private val vek = KeyHierarchy.generateVek()
    private val vaultId = "vault-under-test"

    private val kdf = KdfParams(
        algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
        saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
        pbkdf2Rounds = 1_000
    )

    private val metadata = VaultMetadata(
        vaultId = vaultId,
        name = "Acme Corporation credentials",
        formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
        createdAt = 1_700_000_000_000,
        modifiedAt = 1_700_000_000_000,
        kdf = kdf,
        wrappedVek = KeyHierarchy.wrapVek(
            KeyHierarchy.deriveKek("a passphrase".toCharArray(), kdf), vek, vaultId
        ),
        recovery = null,
        keyFileRequired = false,
        backupId = "backup-id-1"
    )

    private val items = listOf(
        VaultItem(
            type = ItemType.LOGIN,
            payload = ItemPayload(
                title = "First National Bank",
                fields = mapOf(
                    Fields.USERNAME to "jane.doe@example.com",
                    Fields.PASSWORD to "hunter2-but-longer",
                    Fields.URL to "https://firstnational.example"
                ),
                notes = "the joint account",
                tags = listOf("finance", "critical"),
                totp = TotpConfig(secretBase32 = "GEZDGNBVGY3TQOJQ")
            ),
            folderId = "folder-1"
        )
    )

    private val folders = listOf(Folder(id = "folder-1", name = "Money"))

    private fun backupKey() = codec.backupKeyFrom(vek)

    private fun write(): ByteArray {
        val out = ByteArrayOutputStream()
        codec.create(metadata, backupKey(), items, folders, emptyList(), out)
        return out.toByteArray()
    }

    // ---- confidentiality ---------------------------------------------------------------------

    @Test
    fun `plaintext header leaks nothing descriptive`() {
        val bytes = write()
        val asText = String(bytes, Charsets.ISO_8859_1)

        listOf(
            "Acme Corporation credentials",   // vault name: plaintext in format 1
            "First National Bank",            // title
            "jane.doe@example.com",           // username
            "hunter2-but-longer",             // password
            "firstnational.example",          // URL
            "finance",                        // tag
            "Money",                          // folder name
            "GEZDGNBVGY3TQOJQ",               // TOTP secret
            "the joint account"               // notes
        ).forEach { secret ->
            assertFalse("'$secret' is readable in the backup file", asText.contains(secret))
        }
    }

    @Test
    fun `the header exposes only what opening the file requires`() {
        val header = codec.readHeader(ByteArrayInputStream(write()))

        assertEquals(BackupCodec.FORMAT_VERSION, header.formatVersion)
        assertEquals(vaultId, header.vaultId)
        assertEquals("backup-id-1", header.backupId)
        assertEquals(KdfAlgorithm.PBKDF2_HMAC_SHA256, header.kdf.algorithm)
        // Descriptive detail moved inside the encryption in format 2.
        assertEquals(null, header.legacyManifest)
    }

    @Test
    fun `the vault name is readable only after authenticating`() {
        val (_, contents) = codec.restore(
            ByteArrayInputStream(write()), { backupKey() }, temp.newFolder("attach")
        )
        assertEquals("Acme Corporation credentials", contents.manifest?.vaultName)
        assertEquals(1, contents.manifest?.itemCount)
    }

    // ---- round trip -------------------------------------------------------------------------

    @Test
    fun `contents survive a round trip`() {
        val (_, contents) = codec.restore(
            ByteArrayInputStream(write()), { backupKey() }, temp.newFolder("attach")
        )
        assertEquals(1, contents.items.size)
        val item = contents.items.first()
        assertEquals("First National Bank", item.title)
        assertEquals("hunter2-but-longer", item.password)
        assertEquals("GEZDGNBVGY3TQOJQ", item.payload.totp?.secretBase32)
        assertEquals(listOf("finance", "critical"), item.payload.tags)
        assertEquals("Money", contents.folders.first().name)
    }

    @Test
    fun `verify accepts a good file without writing anything`() {
        assertNotNull(codec.verify(ByteArrayInputStream(write()), { backupKey() }))
    }

    // ---- KDF preservation ---------------------------------------------------------------------

    @Test
    fun `the backup carries the vault's own KDF, unchanged`() {
        val header = codec.readHeader(ByteArrayInputStream(write()))
        assertEquals(kdf.algorithm, header.kdf.algorithm)
        assertEquals(kdf.saltB64, header.kdf.saltB64)
        assertEquals(kdf.pbkdf2Rounds, header.kdf.pbkdf2Rounds)
        assertEquals(kdf.outputBytes, header.kdf.outputBytes)
    }

    @Test
    fun `weakening the KDF in the header breaks the file rather than the encryption`() {
        val bytes = write()
        val text = String(bytes, Charsets.ISO_8859_1)
        val weakened = text.replace("\"pbkdf2Rounds\":1000", "\"pbkdf2Rounds\":1...")
            .toByteArray(Charsets.ISO_8859_1)
        // Header is bound to the body as AAD, so any edit at all fails authentication.
        assertThrows(Exception::class.java) {
            codec.verify(ByteArrayInputStream(weakened), { backupKey() })
        }
    }

    // ---- integrity ----------------------------------------------------------------------------

    @Test
    fun `a tampered body fails cleanly`() {
        val bytes = write()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()
        assertThrows(VaultIntegrityException::class.java) {
            codec.verify(ByteArrayInputStream(bytes), { backupKey() })
        }
    }

    @Test
    fun `a tampered header fails cleanly`() {
        val bytes = write()
        // "backup-id-1" sits in the plaintext header; changing it must invalidate the body.
        val edited = String(bytes, Charsets.ISO_8859_1)
            .replace("backup-id-1", "backup-id-2")
            .toByteArray(Charsets.ISO_8859_1)
        assertThrows(VaultIntegrityException::class.java) {
            codec.verify(ByteArrayInputStream(edited), { backupKey() })
        }
    }

    @Test
    fun `the wrong key never opens the file`() {
        assertThrows(VaultIntegrityException::class.java) {
            codec.verify(ByteArrayInputStream(write()), { RandomSource.bytes(32) })
        }
    }

    @Test
    fun `a truncated file fails cleanly`() {
        val bytes = write()
        assertThrows(Exception::class.java) {
            codec.verify(ByteArrayInputStream(bytes.copyOf(bytes.size / 2)), { backupKey() })
        }
    }

    // ---- versioning ---------------------------------------------------------------------------

    @Test
    fun `a foreign file is rejected by magic number`() {
        assertThrows(UnsupportedFormatException::class.java) {
            codec.readHeader(ByteArrayInputStream(ByteArray(64) { 0x7F }))
        }
    }

    @Test
    fun `a newer format version is refused rather than guessed at`() {
        val bytes = write()
        // Bump the framing version past what this build writes.
        bytes[7] = (BackupCodec.FORMAT_VERSION + 1).toByte()
        assertThrows(UnsupportedFormatException::class.java) {
            codec.readHeader(ByteArrayInputStream(bytes))
        }
    }

    @Test
    fun `an implausible header length is rejected before allocating`() {
        val bytes = write()
        // Header length field sits at offset 8.
        bytes[8] = 0x7F; bytes[9] = 0x7F; bytes[10] = 0x7F; bytes[11] = 0x7F
        assertThrows(VaultIntegrityException::class.java) {
            codec.readHeader(ByteArrayInputStream(bytes))
        }
        // restore and verify must apply the same bound, not just readHeader.
        assertThrows(VaultIntegrityException::class.java) {
            codec.verify(ByteArrayInputStream(bytes), { backupKey() })
        }
        assertThrows(VaultIntegrityException::class.java) {
            codec.restore(ByteArrayInputStream(bytes), { backupKey() }, temp.newFolder("a2"))
        }
    }

    @Test
    fun `format version in the framing must agree with the header json`() {
        val bytes = write()
        val edited = String(bytes, Charsets.ISO_8859_1)
            .replace("\"formatVersion\":2", "\"formatVersion\":1")
            .toByteArray(Charsets.ISO_8859_1)
        assertThrows(VaultIntegrityException::class.java) {
            codec.readHeader(ByteArrayInputStream(edited))
        }
    }
}
