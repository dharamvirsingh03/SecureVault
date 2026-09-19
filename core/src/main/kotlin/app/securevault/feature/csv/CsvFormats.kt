package app.securevault.feature.csv

import app.securevault.core.model.Fields

/**
 * Column mappings for the exports people actually arrive with.
 *
 * Detection is a best-effort match on the header row; every format falls back to the manual
 * mapping step in the wizard, so an unrecognised or customised export is still importable rather
 * than rejected.
 */
enum class CsvFormat(val label: String) {
    SECUREVAULT("SecureVault"),
    BITWARDEN("Bitwarden"),
    ONE_PASSWORD("1Password"),
    LASTPASS("LastPass"),
    CHROME("Chrome / Google Password Manager"),
    KEEPASS("KeePass"),
    GENERIC("Generic CSV");

    companion object {
        /** Header name (lowercased) -> canonical field, per format. */
        fun mappingFor(format: CsvFormat): Map<String, String> = when (format) {
            BITWARDEN -> mapOf(
                "name" to TITLE, "login_username" to Fields.USERNAME, "login_password" to Fields.PASSWORD,
                "login_uri" to Fields.URL, "login_totp" to TOTP, "notes" to NOTES, "folder" to FOLDER,
                "favorite" to FAVORITE
            )
            ONE_PASSWORD -> mapOf(
                "title" to TITLE, "username" to Fields.USERNAME, "password" to Fields.PASSWORD,
                "url" to Fields.URL, "otpauth" to TOTP, "notes" to NOTES, "tags" to TAGS,
                "favorite" to FAVORITE, "type" to TYPE
            )
            LASTPASS -> mapOf(
                "name" to TITLE, "username" to Fields.USERNAME, "password" to Fields.PASSWORD,
                "url" to Fields.URL, "totp" to TOTP, "extra" to NOTES, "grouping" to FOLDER,
                "fav" to FAVORITE
            )
            CHROME -> mapOf(
                "name" to TITLE, "username" to Fields.USERNAME, "password" to Fields.PASSWORD,
                "url" to Fields.URL, "note" to NOTES
            )
            KEEPASS -> mapOf(
                "account" to TITLE, "title" to TITLE, "login name" to Fields.USERNAME,
                "user name" to Fields.USERNAME, "password" to Fields.PASSWORD,
                "web site" to Fields.URL, "url" to Fields.URL, "comments" to NOTES, "notes" to NOTES
            )
            SECUREVAULT, GENERIC -> mapOf(
                "title" to TITLE, "username" to Fields.USERNAME, "email" to Fields.EMAIL,
                "password" to Fields.PASSWORD, "url" to Fields.URL, "website" to Fields.URL,
                "totp" to TOTP, "notes" to NOTES, "folder" to FOLDER, "tags" to TAGS,
                "favorite" to FAVORITE, "type" to TYPE
            )
        }

        fun detect(header: List<String>): CsvFormat {
            val normalised = header.map { it.trim().lowercase() }.toSet()
            return when {
                normalised.containsAll(listOf("login_username", "login_password")) -> BITWARDEN
                normalised.contains("otpauth") && normalised.contains("title") -> ONE_PASSWORD
                normalised.containsAll(listOf("grouping", "extra")) -> LASTPASS
                normalised.containsAll(listOf("name", "url", "username", "password")) &&
                    normalised.size <= 5 -> CHROME
                normalised.contains("login name") || normalised.contains("web site") -> KEEPASS
                normalised.containsAll(listOf("title", "username", "password")) -> SECUREVAULT
                else -> GENERIC
            }
        }

        const val TITLE = "__title"
        const val NOTES = "__notes"
        const val TOTP = "__totp"
        const val FOLDER = "__folder"
        const val TAGS = "__tags"
        const val FAVORITE = "__favorite"
        const val TYPE = "__type"

        val TARGET_FIELDS = listOf(
            TITLE to "Title",
            Fields.USERNAME to "Username",
            Fields.EMAIL to "Email",
            Fields.PASSWORD to "Password",
            Fields.URL to "Website",
            TOTP to "TOTP secret",
            NOTES to "Notes",
            FOLDER to "Folder",
            TAGS to "Tags",
            FAVORITE to "Favourite"
        )
    }
}
