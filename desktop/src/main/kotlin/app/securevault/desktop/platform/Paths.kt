package app.securevault.desktop.platform

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * Where SecureVault keeps things on Linux, following the XDG base directory specification.
 *
 * Never the installation directory. `/opt/securevault` holds the application; a user's vault
 * belongs to the user, survives reinstalls and package removal, and must not need root to write.
 *
 * Every directory created here is 0700 and every file 0600. That is not a substitute for
 * encryption -- it is the encryption that protects the vault -- but it keeps the database out of
 * reach of other accounts on a shared machine, which costs nothing to get right.
 */
object Paths {

    private const val APP = "securevault"

    /** `$XDG_DATA_HOME/securevault`, or `~/.local/share/securevault`. Vault, database, attachments. */
    val dataDir: File by lazy {
        secured(File(xdg("XDG_DATA_HOME", ".local/share"), APP))
    }

    /** `$XDG_CONFIG_HOME/securevault`, or `~/.config/securevault`. Settings only. */
    val configDir: File by lazy {
        secured(File(xdg("XDG_CONFIG_HOME", ".config"), APP))
    }

    /**
     * `$XDG_RUNTIME_DIR/securevault`, falling back to the data directory.
     *
     * Preferred for temporarily decrypted attachments because on a normal Ubuntu session it is a
     * tmpfs owned by the user and cleared at logout -- so a decrypted copy does not survive a
     * reboot even if cleanup fails. The fallback is on disk, which is worse; the attachment viewer
     * says so.
     */
    val runtimeDir: File by lazy {
        val xdgRuntime = System.getenv("XDG_RUNTIME_DIR")
        val base = if (!xdgRuntime.isNullOrBlank()) File(xdgRuntime) else dataDir
        secured(File(base, APP))
    }

    /** True when [runtimeDir] is a real XDG runtime directory rather than the on-disk fallback. */
    val runtimeDirIsVolatile: Boolean
        get() = !System.getenv("XDG_RUNTIME_DIR").isNullOrBlank()

    val vaultDir: File get() = secured(File(dataDir, "vault"))
    val attachmentsDir: File get() = secured(File(dataDir, "attachments"))
    val stagingDir: File get() = secured(File(dataDir, "restore-staging"))
    val stateDir: File get() = secured(File(dataDir, "state"))
    val databaseFile: File get() = File(dataDir, "securevault.db")

    fun databaseFiles(): List<File> =
        dataDir.listFiles { f -> f.name.startsWith("securevault.db") }?.toList().orEmpty()

    private fun xdg(variable: String, fallback: String): File {
        val value = System.getenv(variable)
        return if (!value.isNullOrBlank()) File(value)
        else File(System.getProperty("user.home"), fallback)
    }

    /** Creates the directory if needed and forces owner-only permissions. */
    fun secured(dir: File): File {
        if (!dir.exists()) dir.mkdirs()
        runCatching {
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

    /** Forces 0600 on a file. Called after every write that could create one. */
    fun restrict(file: File) {
        runCatching {
            Files.setPosixFilePermissions(
                file.toPath(),
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            )
        }
    }
}
