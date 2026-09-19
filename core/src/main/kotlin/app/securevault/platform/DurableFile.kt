package app.securevault.platform

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Crash-safe replacement of a small file, plus a previous-good copy to fall back on.
 *
 * The naive sequence -- write temp, rename over the target -- looks atomic and mostly is, but the
 * rename can reach the disk before the temp file's *contents* do. Lose power in that window and
 * the target exists, is named correctly, and is empty. For the vault header that means an
 * unopenable vault, which is the worst outcome this app has.
 *
 * So: write, flush, fsync the file, keep the previous version aside, rename, then try to fsync the
 * directory.
 *
 * Honest limits. The JDK exposes no portable directory fsync, so the directory step is attempted
 * and its failure ignored -- on some Android filesystems it will not happen at all. Devices also
 * lie about sync: an fsync that returns does not prove the flash controller has committed. This
 * makes the dangerous window much smaller; it does not make it zero. The [previous] copy exists
 * because of that residual risk, not as decoration.
 *
 * **The previous copy is crash-window scaffolding, not an archive.** Callers must read the target
 * back, confirm it is valid, and call [confirm] -- which deletes it. Leaving old copies lying
 * around would turn every write into a rollback point, and for the vault header that means an old
 * wrapped key under an old password staying openable forever. See VaultManager.writeMetadata.
 */
object DurableFile {

    private const val TEMP_SUFFIX = ".tmp"
    private const val PREVIOUS_SUFFIX = ".prev"

    fun temp(target: File) = File(target.parentFile, target.name + TEMP_SUFFIX)

    /** The last known-good copy of [target], kept across writes. */
    fun previous(target: File) = File(target.parentFile, target.name + PREVIOUS_SUFFIX)

    /**
     * Writes [bytes] to [target] durably. On return, either [target] holds the new content or the
     * call threw and [target] still holds whatever it held before.
     */
    @Throws(IOException::class)
    fun write(target: File, bytes: ByteArray) {
        val dir = target.parentFile ?: throw IOException("Target has no parent directory")
        if (!dir.exists() && !dir.mkdirs()) throw IOException("Cannot create ${dir.path}")

        val temp = temp(target)
        FileOutputStream(temp).use { out ->
            out.write(bytes)
            out.flush()
            // The step the naive version skips. Without it the rename below can be durable while
            // the bytes are not.
            out.fd.sync()
        }

        // Keep the outgoing version. If the rename tears, or if the new content turns out to be
        // unreadable later, there is still something valid on disk to fall back to.
        if (target.exists()) {
            val prev = previous(target)
            prev.delete()
            if (!target.renameTo(prev)) {
                // Could not preserve the old copy; copy it instead rather than pressing on blind.
                target.copyTo(prev, overwrite = true)
            }
        }

        if (!temp.renameTo(target)) {
            temp.delete()
            throw IOException("Could not commit ${target.name}")
        }

        syncDirectory(dir)
    }

    /**
     * Marks a write as confirmed by deleting the preserved previous copy.
     *
     * Call only after reading the target back and checking it is valid. Until this is called the
     * previous copy is still on disk and will be used as a fallback, which is correct during the
     * crash window and wrong afterwards.
     */
    fun confirm(target: File) {
        previous(target).delete()
    }

    /** Deletes the target and both of its shadow files. */
    fun deleteAll(target: File) {
        target.delete()
        temp(target).delete()
        previous(target).delete()
    }

    /**
     * Best-effort directory fsync so the rename itself is durable.
     *
     * Opening a directory as a stream is not portable and throws on some runtimes; when it does,
     * there is nothing further we can do from the JDK, so the failure is swallowed rather than
     * failing a write that otherwise succeeded.
     */
    private fun syncDirectory(dir: File) {
        runCatching { FileInputStream(dir).use { it.fd.sync() } }
    }
}
