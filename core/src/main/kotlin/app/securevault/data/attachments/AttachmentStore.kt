package app.securevault.data.attachments

import app.securevault.core.crypto.StreamAead
import app.securevault.core.model.AttachmentRef
import app.securevault.core.vault.VaultSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

/**
 * Encrypted file attachments.
 *
 * Files are encrypted with a key derived from the vault key and specific to the attachment id,
 * then written as ciphertext into app-private storage. App-private storage on its own is not
 * protection -- it is readable on a rooted device, from a backup, or from an offline image of the
 * flash -- so the file never touches disk in the clear.
 *
 * Decryption streams to a caller-supplied OutputStream. No plaintext temp file is created; a
 * viewer that needs a file path should receive it through a FileProvider backed by a cache file
 * the caller deletes, and the UI warns before doing that.
 */
class AttachmentStore(root: File) {

    companion object {
        const val MAX_ATTACHMENT_BYTES = 25L * 1024 * 1024
    }

    private val dir = root.apply { mkdirs() }

    suspend fun store(
        session: VaultSession,
        input: InputStream,
        fileName: String,
        mimeType: String,
        sizeBytes: Long
    ): AttachmentRef = withContext(Dispatchers.IO) {
        require(sizeBytes <= MAX_ATTACHMENT_BYTES) {
            "Attachments are limited to ${MAX_ATTACHMENT_BYTES / (1024 * 1024)} MB"
        }
        val id = UUID.randomUUID().toString()
        val key = session.attachmentKeyFor(id)
        try {
            File(dir, "$id.enc").outputStream().use { out ->
                StreamAead.encrypt(key, input, out, aad(id))
            }
        } finally {
            key.fill(0)
        }
        AttachmentRef(
            id = id,
            fileName = fileName,
            mimeType = mimeType,
            sizeBytes = sizeBytes,
            addedAt = System.currentTimeMillis()
        )
    }

    suspend fun read(session: VaultSession, ref: AttachmentRef, output: OutputStream) =
        withContext(Dispatchers.IO) {
            val file = File(dir, "${ref.id}.enc")
            check(file.exists()) { "Attachment file is missing" }
            val key = session.attachmentKeyFor(ref.id)
            try {
                file.inputStream().use { input -> StreamAead.decrypt(key, input, output, aad(ref.id)) }
            } finally {
                key.fill(0)
            }
        }

    fun delete(ref: AttachmentRef) {
        File(dir, "${ref.id}.enc").delete()
    }

    fun allEncryptedFiles(): List<File> = dir.listFiles()?.toList().orEmpty()

    private fun aad(id: String) = "securevault:attachment:v1:$id".toByteArray(Charsets.UTF_8)
}
