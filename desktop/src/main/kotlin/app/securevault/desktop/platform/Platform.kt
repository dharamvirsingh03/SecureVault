package app.securevault.desktop.platform

/**
 * Which desktop this is running on.
 *
 * `:desktop` is one module serving Linux and Windows rather than two modules serving one each.
 * That is a deliberate choice made by measuring: of seventeen files, only three contain anything
 * operating-system specific. Splitting would have duplicated the entire Compose UI, the SQLite
 * backend, the Argon2 backend, the PDF renderer, auto-lock and the clipboard -- roughly 2,400
 * lines -- to isolate about 300. Every copy is a place the two platforms can quietly drift apart,
 * which for a password manager means two subtly different security models wearing one name.
 *
 * The rule is the same as for `:core`: platform differences live behind an interface, chosen once
 * here, and nothing else in the module asks what it is running on.
 */
enum class Os { LINUX, WINDOWS, MAC, OTHER }

object Platform {

    val os: Os by lazy {
        val name = System.getProperty("os.name").orEmpty().lowercase()
        when {
            name.startsWith("windows") -> Os.WINDOWS
            name.startsWith("linux") -> Os.LINUX
            name.startsWith("mac") || name.contains("darwin") -> Os.MAC
            else -> Os.OTHER
        }
    }

    val isWindows: Boolean get() = os == Os.WINDOWS
    val isLinux: Boolean get() = os == Os.LINUX

    /** For the About screen and diagnostics. Carries no secret. */
    val description: String
        get() = "${System.getProperty("os.name")} ${System.getProperty("os.version")} " +
            "(${System.getProperty("os.arch")})"
}
