package app.securevault.feature.csv

import app.securevault.core.model.Fields
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.feature.totp.OtpAuthUri
import java.io.OutputStream

data class ExportSelection(
    val items: List<VaultItem>,
    val includeIdentities: Boolean = false,
    val includeCards: Boolean = false,
    val includeNotes: Boolean = true,
    val includeTotpSecrets: Boolean = false
)

/**
 * CSV export.
 *
 * This writes every selected password in the clear. The UI puts that in front of the user as a
 * blocking confirmation before this code runs, and the file goes only where the user pointed the
 * system file picker.
 *
 * Identity records and card records are excluded unless explicitly selected, and TOTP secrets are
 * excluded by default: a CSV containing both the password and the second factor removes the point
 * of having a second factor.
 */
class CsvExporter {

    companion object {
        val HEADER = listOf(
            "type", "title", "username", "email", "password", "url", "totp", "notes", "tags", "favorite"
        )

        const val WARNING =
            "CSV exports are not encrypted and contain your passwords in plaintext. " +
                "Anyone who obtains this file may access your accounts."

        val AFTER_EXPORT_GUIDANCE = listOf(
            "Move the file to encrypted storage or delete it once you have finished with it.",
            "Do not leave it in Downloads, and do not let it sync to a cloud folder.",
            "Use an encrypted .securevault backup for anything you intend to keep."
        )
    }

    fun export(selection: ExportSelection, output: OutputStream) {
        val filtered = selection.items.filter { item ->
            when (item.type) {
                ItemType.IDENTITY -> selection.includeIdentities
                ItemType.CARD, ItemType.BANK_ACCOUNT -> selection.includeCards
                ItemType.SECURE_NOTE -> selection.includeNotes
                else -> true
            }
        }

        output.bufferedWriter().use { writer ->
            writer.appendLine(Csv.writeRow(HEADER))
            for (item in filtered) {
                writer.appendLine(
                    Csv.writeRow(
                        listOf(
                            item.type.name.lowercase(),
                            item.title,
                            item.payload.field(Fields.USERNAME),
                            item.payload.field(Fields.EMAIL),
                            item.payload.field(Fields.PASSWORD),
                            item.payload.field(Fields.URL),
                            if (selection.includeTotpSecrets) {
                                item.payload.totp?.let { OtpAuthUri.build(it) }.orEmpty()
                            } else "",
                            item.payload.notes,
                            item.payload.tags.joinToString(";"),
                            if (item.favorite) "true" else "false"
                        )
                    )
                )
            }
            writer.flush()
        }
    }
}
