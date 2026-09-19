package app.securevault.desktop.platform

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFilePermission

/**
 * Where SecureVault keeps things, per platform.
 *
 * Never the installation directory on either. `/opt/securevault` and `C:\Program Files\SecureVault`
 * hold the application; a vault belongs to the user, survives reinstalls and package removal, and
 * must not need administrator rights to write.
 *
 * | | Linux | Windows |
 * |---|---|---|
 * | Vault, database, attachments | `$XDG_DATA_HOME/securevault` or `~/.local/share/securevault` | `%LOCALAPPDATA%\SecureVault` |
 * | Settings | `$XDG_CONFIG_HOME/securevault` | `%LOCALAPPDATA%\SecureVault\config` |
 * | Temporarily decrypted attachments | `$XDG_RUNTIME_DIR/securevault` (tmpfs) | `%LOCALAPPDATA%\SecureVault\cache` (on disk) |
 *
 * `%LOCALAPPDATA%` rather than `%APPDATA%` on purpose: roaming profiles would copy the encrypted
 * vault to a domain server on every logon, which is a decision for the user to make deliberately
 * with a backup file, not one an application should make silently.
 */
interface PlatformPaths {
    val dataDir: File
    val configDir: File
    /** Where temporarily decrypted attachments go. */
    val runtimeDir: File
    /** True when [runtimeDir] is cleared by the OS at logout. Linux tmpfs; never on Windows. */
    val runtimeDirIsVolatile: Boolean
}

private class LinuxPaths : PlatformPaths {
    override val dataDir: File get() = Paths.secured(File(xdg("XDG_DATA_HOME", ".local/share"), "securevault"))
    override val configDir: File get() = Paths.secured(File(xdg("XDG_CONFIG_HOME", ".config"), "securevault"))
    override val runtimeDir: File
        get() {
            val runtime = System.getenv("XDG_RUNTIME_DIR")
            val base = if (!runtime.isNullOrBlank()) File(runtime) else dataDir
            return Paths.secured(File(base, "securevault"))
        }
    override val runtimeDirIsVolatile: Boolean
        get() = !System.getenv("XDG_RUNTIME_DIR").isNullOrBlank()

    private fun xdg(variable: String, fallback: String): File {
        val value = System.getenv(variable)
        return if (!value.isNullOrBlank()) File(value) else File(System.getProperty("user.home"), fallback)
    }
}

private class WindowsPaths : PlatformPaths {
    private val base: File
        get() {
            val local = System.getenv("LOCALAPPDATA")
            return if (!local.isNullOrBlank()) File(local, "SecureVault")
            else File(System.getProperty("user.home"), "AppData\\Local\\SecureVault")
        }

    override val dataDir: File get() = Paths.secured(base)
    override val configDir: File get() = Paths.secured(File(base, "config"))

    // Windows has no tmpfs equivalent, so a decrypted attachment handed to an external viewer is
    // written to disk. Stated rather than glossed: see DesktopAttachmentViewer.
    override val runtimeDir: File get() = Paths.secured(File(base, "cache"))
    override val runtimeDirIsVolatile: Boolean get() = false
}

object Paths {

    private val impl: PlatformPaths = if (Platform.isWindows) WindowsPaths() else LinuxPaths()

    val dataDir: File get() = impl.dataDir
    val configDir: File get() = impl.configDir
    val runtimeDir: File get() = impl.runtimeDir
    val runtimeDirIsVolatile: Boolean get() = impl.runtimeDirIsVolatile

    val vaultDir: File get() = secured(File(dataDir, "vault"))
    val attachmentsDir: File get() = secured(File(dataDir, "attachments"))
    val stagingDir: File get() = secured(File(dataDir, "restore-staging"))
    val stateDir: File get() = secured(File(dataDir, "state"))
    val databaseFile: File get() = File(dataDir, "securevault.db")

    fun databaseFiles(): List<File> =
        dataDir.listFiles { f -> f.name.startsWith("securevault.db") }?.toList().orEmpty()

    /**
     * Creates the directory and restricts it to the owner.
     *
     * POSIX 0700 on Linux. On Windows, POSIX permissions do not exist, so the ACL is rewritten to
     * grant the owner alone -- `%LOCALAPPDATA%` already inherits per-user ACLs, and this removes
     * any inherited group or Administrators entry rather than trusting the default. Both attempts
     * are best effort: a filesystem that supports neither view (a FAT volume, a network share)
     * leaves the directory with whatever it inherits, and the encryption remains what actually
     * protects the vault.
     */
    fun secured(dir: File): File {
        if (!dir.exists()) dir.mkdirs()
        if (Platform.isWindows) restrictWindowsAcl(dir) else runCatching {
            Files.setPosixFilePermissions(
                dir.toPath(),
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE
                )
            )
        }
        return dir
    }

    /** Restricts a file to the owner. Called after every write that could create one. */
    fun restrict(file: File) {
        if (!file.exists()) return
        if (Platform.isWindows) restrictWindowsAcl(file) else runCatching {
            Files.setPosixFilePermissions(
                file.toPath(),
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            )
        }
    }

    private fun restrictWindowsAcl(target: File) {
        runCatching {
            val view = Files.getFileAttributeView(target.toPath(), AclFileAttributeView::class.java)
                ?: return@runCatching
            val owner = view.owner
            val entry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(AclEntryPermission.entries.toSet())
                .build()
            view.acl = listOf(entry)
        }
    }
}
