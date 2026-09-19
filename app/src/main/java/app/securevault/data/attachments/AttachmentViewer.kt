package app.securevault.data.attachments

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import app.securevault.core.model.AttachmentRef
import app.securevault.core.vault.VaultSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Opens an attachment in whatever app on the device can display it.
 *
 * There is no way to render arbitrary file types inside this app, and writing half a viewer would
 * be worse than not having one: a bad PDF or image parser is a large attack surface pointed
 * directly at the thing the vault was protecting. So the file is decrypted to a private cache
 * directory, handed to an external viewer through a scoped FileProvider grant, and the directory
 * is purged aggressively.
 *
 * **The honest limitation**, and it is a real one: while the viewer has the file open, a decrypted
 * copy exists on disk. It is in app-private cache, not shared storage, and the URI grant is
 * read-only and for that one file — but a decrypted copy is a decrypted copy, and no amount of
 * cleanup makes that window zero. [purge] runs when the vault locks and when the app starts, so
 * the copy does not survive a lock or a restart, and the UI says so before opening anything.
 */
class AttachmentViewer(private val context: Context, private val store: AttachmentStore) {

    companion object {
        private const val DIR = "attachment-view"

        /** Above this, hand off to Save instead: nothing good comes of a 25 MB cache copy. */
        const val MAX_INLINE_VIEW_BYTES = 8L * 1024 * 1024

        private val VIEWABLE_PREFIXES = listOf("image/", "text/", "audio/", "video/")
        private val VIEWABLE_EXACT = setOf("application/pdf")

        /** Whether an external viewer is likely to exist. Advisory, checked again before launch. */
        fun looksViewable(mimeType: String): Boolean {
            val mime = mimeType.lowercase()
            return VIEWABLE_PREFIXES.any { mime.startsWith(it) } || mime in VIEWABLE_EXACT
        }
    }

    private val dir get() = File(context.cacheDir, DIR)

    /**
     * Decrypts [ref] to cache and returns an intent that opens it, or null when nothing on the
     * device can display it — in which case the caller should offer an explicit export instead of
     * pretending a viewer exists.
     */
    suspend fun open(session: VaultSession, ref: AttachmentRef): Intent? = withContext(Dispatchers.IO) {
        require(ref.sizeBytes <= MAX_INLINE_VIEW_BYTES) {
            "This attachment is too large to open here. Save it instead."
        }
        purge()
        if (!dir.exists() && !dir.mkdirs()) return@withContext null

        val mime = ref.mimeType.ifBlank { "application/octet-stream" }
        val target = File(dir, ref.fileName.substringAfterLast('/').ifBlank { "attachment" })
        target.outputStream().use { out -> store.read(session, ref, out) }

        val uri = FileProvider.getUriForFile(
            context, "${context.packageName}.attachments", target
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (intent.resolveActivity(context.packageManager) == null) {
            target.delete()
            return@withContext null
        }
        intent
    }

    /** Deletes every temporarily decrypted copy. Called on lock, on startup, and before each open. */
    fun purge() {
        runCatching { dir.deleteRecursively() }
    }
}
