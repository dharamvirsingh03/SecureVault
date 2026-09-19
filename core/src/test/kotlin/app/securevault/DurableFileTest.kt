package app.securevault

import app.securevault.platform.DurableFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/** S2: crash-safe replacement of the vault header. */
class DurableFileTest {

    @get:Rule
    val temp = TemporaryFolder()

    @Test
    fun `writes a new file`() {
        val target = File(temp.root, "meta.json")
        DurableFile.write(target, "first".toByteArray())
        assertEquals("first", target.readText())
        // Nothing left behind for a first write.
        assertFalse(DurableFile.temp(target).exists())
        assertFalse(DurableFile.previous(target).exists())
    }

    @Test
    fun `replaces content and preserves the previous version`() {
        val target = File(temp.root, "meta.json")
        DurableFile.write(target, "first".toByteArray())
        DurableFile.write(target, "second".toByteArray())

        assertEquals("second", target.readText())
        assertEquals("first", DurableFile.previous(target).readText())
        assertFalse("temp file must not survive a commit", DurableFile.temp(target).exists())
    }

    @Test
    fun `previous copy rolls forward across several writes`() {
        val target = File(temp.root, "meta.json")
        DurableFile.write(target, "one".toByteArray())
        DurableFile.write(target, "two".toByteArray())
        DurableFile.write(target, "three".toByteArray())

        assertEquals("three", target.readText())
        assertEquals("two", DurableFile.previous(target).readText())
    }

    @Test
    fun `a torn write leaves the old content in place`() {
        val target = File(temp.root, "meta.json")
        DurableFile.write(target, "committed".toByteArray())

        // Simulate the dangerous window: a temp file exists with partial content but was never
        // renamed. Nothing should have consumed it.
        DurableFile.temp(target).writeText("half-writ")

        assertEquals("committed", target.readText())
    }

    @Test
    fun `creates the parent directory when missing`() {
        val target = File(File(temp.root, "nested/deeper"), "meta.json")
        DurableFile.write(target, "value".toByteArray())
        assertEquals("value", target.readText())
    }

    @Test
    fun `fails loudly when the target cannot be written`() {
        // The parent path is a regular file, so anything beneath it is ENOTDIR. The kernel
        // enforces that for every user including root, on every POSIX filesystem.
        //
        // The earlier version of this test put a directory at the target path and expected the
        // write to fail. It does not: Linux renames the directory out of the way to the .prev
        // name and the write commits normally, so the test was asserting a failure that never
        // happened. A permission bit would have been no better -- root ignores those, and CI
        // often runs as root.
        val blockingFile = File(temp.root, "not-a-directory").apply { writeText("in the way") }
        val target = File(blockingFile, "meta.json")

        assertThrows(IOException::class.java) {
            DurableFile.write(target, "value".toByteArray())
        }

        // The invariant this test exists for: a write that cannot complete commits nothing and
        // leaves no debris behind for the next attempt to trip over.
        assertEquals("in the way", blockingFile.readText())
        assertFalse(target.exists())
        assertFalse(DurableFile.temp(target).exists())
        assertFalse(DurableFile.previous(target).exists())
    }

    @Test
    fun `deleteAll removes every shadow file`() {
        val target = File(temp.root, "meta.json")
        DurableFile.write(target, "one".toByteArray())
        DurableFile.write(target, "two".toByteArray())
        DurableFile.temp(target).writeText("stale")

        DurableFile.deleteAll(target)

        assertFalse(target.exists())
        assertFalse(DurableFile.previous(target).exists())
        assertFalse(DurableFile.temp(target).exists())
    }

    @Test
    fun `empty content is written faithfully`() {
        val target = File(temp.root, "meta.json")
        DurableFile.write(target, ByteArray(0))
        assertTrue(target.exists())
        assertEquals(0, target.length())
    }
}
