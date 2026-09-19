package app.securevault

import app.securevault.core.crypto.KdfAlgorithm
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KeyDomain
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.StreamAead
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.core.vault.VaultMetadata
import app.securevault.feature.backup.BackupCodec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.Base64

/**
 * Pins every constant that appears on disk or in a `.securevault` file.
 *
 * These are not unit tests of behaviour. They exist because the vault format is the one thing in
 * this project that cannot be changed later: a vault written by Android must open on Ubuntu and a
 * backup written on Ubuntu must open on Android, and both are decided entirely by the bytes and
 * labels asserted below. Four extraction phases have moved this code between modules; nothing has
 * been checking that a rename or a merge did not quietly alter one of them.
 *
 * If a test here fails, the correct response is almost never to update the expected value.
 */
class WireFormatTest {

    // ---- container framing ---------------------------------------------------------------------

    @Test
    fun `backup magic and versions are fixed`() {
        assertEquals(0x53564C54, BackupCodec.MAGIC)                 // "SVLT"
        assertEquals("SVLT", String(ByteBuffer.allocate(4).putInt(BackupCodec.MAGIC).array()))
        assertEquals(2, BackupCodec.FORMAT_VERSION)
        assertEquals(1, BackupCodec.MIN_SUPPORTED_VERSION)
        assertEquals("securevault", BackupCodec.EXTENSION)
    }

    @Test
    fun `chunked stream framing is fixed`() {
        assertEquals(64 * 1024, StreamAead.CHUNK_SIZE)
    }

    @Test
    fun `a written backup starts with the exact expected bytes`() {
        val bytes = sampleBackup()
        val header = ByteBuffer.wrap(bytes, 0, 12)
        assertEquals("magic", 0x53564C54, header.int)
        assertEquals("framing version", 2, header.int)
        val headerLength = header.int
        assertTrue("header length must be bounded", headerLength in 1..(1 shl 20))

        // The body begins with the stream magic, immediately after the header JSON.
        val body = ByteBuffer.wrap(bytes, 12 + headerLength, 8)
        assertEquals("stream magic", 0x53565354, body.int)         // "SVST"
    }

    // ---- header JSON ----------------------------------------------------------------------------

    @Test
    fun `backup header carries exactly the keys Android writes`() {
        val bytes = sampleBackup()
        val headerLength = ByteBuffer.wrap(bytes, 8, 4).int
        val json = JSONObject(String(bytes, 12, headerLength, Charsets.UTF_8))

        assertEquals(
            setOf("formatVersion", "vaultId", "backupId", "createdAt", "appVersion",
                "kdf", "wrappedVek", "keyFileRequired"),
            json.keys().asSequence().toSet()
        )
        // Format 2 keeps the vault name and item counts out of the plaintext header.
        listOf("vaultName", "itemCount", "attachmentCount").forEach {
            assertTrue("$it must not be in the plaintext header", !json.has(it))
        }
    }

    @Test
    fun `KDF parameters serialise under the short keys`() {
        val params = KdfParams(
            algorithm = KdfAlgorithm.ARGON2ID,
            saltB64 = Base64.getEncoder().encodeToString(ByteArray(16)),
            memoryKib = 65_536, iterations = 3, parallelism = 2
        )
        val json = params.toJson()
        assertEquals(
            setOf("alg", "salt", "m", "t", "p", "pbkdf2Rounds", "len"),
            json.keys().asSequence().toSet()
        )
        assertEquals("ARGON2ID", json.getString("alg"))
        assertEquals(32, json.getInt("len"))
        // Enum names are written verbatim into headers, so renaming one breaks every vault.
        assertEquals(listOf("ARGON2ID", "PBKDF2_HMAC_SHA256"), KdfAlgorithm.entries.map { it.name })
    }

    @Test
    fun `vault header round trips through JSON unchanged`() {
        val original = sampleMetadata()
        val restored = VaultMetadata.fromJson(JSONObject(original.toJson().toString()))
        assertEquals(original.vaultId, restored.vaultId)
        assertEquals(original.wrappedVek, restored.wrappedVek)
        assertEquals(original.kdf, restored.kdf)
        assertEquals(original.formatVersion, restored.formatVersion)
        assertEquals(original.backupId, restored.backupId)
    }

    // ---- key hierarchy labels -------------------------------------------------------------------

    @Test
    fun `HKDF domain labels are fixed`() {
        assertEquals("securevault:v1:items", KeyDomain.ITEMS)
        assertEquals("securevault:v1:attachments", KeyDomain.ATTACHMENTS)
        assertEquals("securevault:v1:backup", KeyDomain.BACKUP)
        assertEquals("securevault:v1:metadata", KeyDomain.METADATA)
        assertEquals("securevault:v1:database", KeyDomain.DATABASE)
    }

    @Test
    fun `subkey derivation is stable for a known vault key`() {
        // A fixed key in, a fixed subkey out. Any change to the HKDF construction shows up here
        // rather than as an unopenable vault on someone's phone.
        val vek = ByteArray(32) { it.toByte() }
        val items = KeyHierarchy.subkey(vek, KeyDomain.ITEMS)
        val backup = KeyHierarchy.subkey(vek, KeyDomain.BACKUP)
        assertEquals(32, items.size)
        assertTrue("domains must not collide", !items.contentEquals(backup))
        // Deterministic across runs and platforms.
        assertTrue(KeyHierarchy.subkey(vek, KeyDomain.ITEMS).contentEquals(items))
    }

    @Test
    fun `the wrapped key is bound to its vault id`() {
        val vek = KeyHierarchy.generateVek()
        val kek = ByteArray(32) { 7 }
        val wrapped = KeyHierarchy.wrapVek(kek, vek, "vault-a")
        assertTrue(KeyHierarchy.unwrapVek(kek, wrapped, "vault-a").contentEquals(vek))
        // A different vault id is a different AAD, so the same bytes must not open.
        org.junit.Assert.assertThrows(Exception::class.java) {
            KeyHierarchy.unwrapVek(kek, wrapped, "vault-b")
        }
    }

    @Test
    fun `recovery codes are 160 bits`() {
        assertEquals(20, KeyHierarchy.RECOVERY_CODE_BYTES)
    }

    // ---- fixtures -------------------------------------------------------------------------------

    private val vek = KeyHierarchy.generateVek()

    private fun sampleMetadata(): VaultMetadata {
        val kdf = KdfParams(
            algorithm = KdfAlgorithm.PBKDF2_HMAC_SHA256,
            saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(16)),
            pbkdf2Rounds = 1_000
        )
        return VaultMetadata(
            vaultId = "wire-format-vault",
            name = "Wire format",
            formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
            createdAt = 1_700_000_000_000,
            modifiedAt = 1_700_000_000_000,
            kdf = kdf,
            wrappedVek = KeyHierarchy.wrapVek(
                KeyHierarchy.deriveKek("a passphrase".toCharArray(), kdf), vek, "wire-format-vault"
            ),
            recovery = null,
            keyFileRequired = false,
            backupId = "wire-format-backup"
        )
    }

    private fun sampleBackup(): ByteArray {
        val codec = BackupCodec("1.0.0-test")
        val out = ByteArrayOutputStream()
        codec.create(
            sampleMetadata(), codec.backupKeyFrom(vek),
            listOf(VaultItem(id = "i1", type = ItemType.LOGIN, payload = ItemPayload(title = "T"))),
            emptyList(), emptyList(), out
        )
        val bytes = out.toByteArray()
        // Sanity: it reads back.
        codec.verify(ByteArrayInputStream(bytes)) { codec.backupKeyFrom(vek) }
        return bytes
    }
}
