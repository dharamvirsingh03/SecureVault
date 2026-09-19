package app.securevault.feature.csv

import app.securevault.core.model.Fields
import app.securevault.core.model.ItemPayload
import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.feature.totp.OtpAuthUri
import app.securevault.feature.totp.TotpEngine
import app.securevault.core.model.TotpConfig

enum class DuplicateAction { KEEP_BOTH, REPLACE_EXISTING, SKIP }

data class ParsedCsv(
    val format: CsvFormat,
    val header: List<String>,
    val rows: List<List<String>>,
    val mapping: Map<Int, String>
)

data class PreparedRecord(
    val item: VaultItem,
    val isDuplicateOf: VaultItem?,
    val problems: List<String>
) {
    val isValid: Boolean get() = problems.isEmpty()
}

data class ImportSummary(
    val imported: Int,
    val skipped: Int,
    val duplicates: Int,
    val invalid: Int,
    val warnings: List<String>
)

/**
 * CSV import.
 *
 * The wizard steps -- select, detect, map, preview, dedupe, validate, import, summarise -- exist
 * because a silent import is how people end up with 400 half-broken entries and no idea which ones
 * failed. Every record reaches the summary as imported, skipped, duplicate or invalid.
 *
 * A CSV of passwords is plaintext. Nothing is copied into app storage, the file is read once
 * through the content URI the user picked, and the UI tells the user to delete the source
 * afterwards.
 */
class CsvImporter {

    fun parse(text: String): ParsedCsv {
        val rows = Csv.parse(text)
        require(rows.isNotEmpty()) { "That file has no rows" }
        val header = rows.first().map { it.trim() }
        val format = CsvFormat.detect(header)
        val mapping = autoMap(header, format)
        return ParsedCsv(format, header, rows.drop(1), mapping)
    }

    fun autoMap(header: List<String>, format: CsvFormat): Map<Int, String> {
        val table = CsvFormat.mappingFor(format)
        return header.mapIndexedNotNull { index, name ->
            table[name.trim().lowercase()]?.let { index to it }
        }.toMap()
    }

    fun prepare(
        parsed: ParsedCsv,
        mapping: Map<Int, String> = parsed.mapping,
        existing: List<VaultItem>
    ): List<PreparedRecord> = parsed.rows.map { row ->
        val values = mapping.entries.associate { (index, field) ->
            field to (row.getOrNull(index)?.trim().orEmpty())
        }

        val problems = mutableListOf<String>()
        val title = values[CsvFormat.TITLE]?.ifBlank { null }
            ?: values[Fields.URL]?.ifBlank { null }
            ?: values[Fields.USERNAME]?.ifBlank { null }
        if (title == null) problems += "No title, website or username in this row"

        val totp = values[CsvFormat.TOTP]?.ifBlank { null }?.let { raw ->
            OtpAuthUri.parse(raw) ?: if (TotpEngine.isValidSecret(raw)) {
                TotpConfig(secretBase32 = raw.replace(" ", "").uppercase())
            } else {
                problems += "TOTP value could not be read and was dropped"
                null
            }
        }

        val fields = buildMap {
            values[Fields.USERNAME]?.takeIf { it.isNotBlank() }?.let { put(Fields.USERNAME, it) }
            values[Fields.EMAIL]?.takeIf { it.isNotBlank() }?.let { put(Fields.EMAIL, it) }
            values[Fields.PASSWORD]?.takeIf { it.isNotBlank() }?.let { put(Fields.PASSWORD, it) }
            values[Fields.URL]?.takeIf { it.isNotBlank() }?.let { put(Fields.URL, it) }
        }

        val item = VaultItem(
            type = ItemType.LOGIN,
            favorite = values[CsvFormat.FAVORITE]?.lowercase() in setOf("1", "true", "yes"),
            payload = ItemPayload(
                title = title.orEmpty(),
                fields = fields,
                notes = values[CsvFormat.NOTES].orEmpty(),
                tags = values[CsvFormat.TAGS]?.split(',', ';')?.map { it.trim() }?.filter { it.isNotEmpty() }
                    ?: emptyList(),
                totp = totp
            )
        )

        PreparedRecord(item, findDuplicate(item, existing), problems)
    }

    /** Same username on the same host, or an identical title and username. */
    fun findDuplicate(candidate: VaultItem, existing: List<VaultItem>): VaultItem? {
        val host = host(candidate.url)
        val username = candidate.username.lowercase()
        return existing.firstOrNull { other ->
            val sameLogin = username.isNotEmpty() && other.username.lowercase() == username
            val sameHost = host.isNotEmpty() && host(other.url) == host
            val sameTitle = other.title.equals(candidate.title, ignoreCase = true)
            (sameLogin && sameHost) || (sameLogin && sameTitle)
        }
    }

    fun resolve(
        records: List<PreparedRecord>,
        duplicateAction: DuplicateAction
    ): Pair<List<VaultItem>, ImportSummary> {
        val toWrite = mutableListOf<VaultItem>()
        var skipped = 0
        var duplicates = 0
        var invalid = 0

        for (record in records) {
            when {
                !record.isValid && record.item.title.isBlank() -> invalid++
                record.isDuplicateOf != null -> {
                    duplicates++
                    when (duplicateAction) {
                        DuplicateAction.SKIP -> skipped++
                        DuplicateAction.KEEP_BOTH -> toWrite += record.item
                        DuplicateAction.REPLACE_EXISTING ->
                            toWrite += record.item.copy(id = record.isDuplicateOf.id)
                    }
                }
                else -> {
                    if (!record.isValid) invalid++
                    toWrite += record.item
                }
            }
        }

        val warnings = buildList {
            add("The file you imported is plaintext. Delete it from your device and from any cloud folder it synced to.")
            if (records.any { it.problems.isNotEmpty() }) add("Some rows had problems. Check them in the vault.")
        }
        return toWrite to ImportSummary(toWrite.size, skipped, duplicates, invalid, warnings)
    }

    private fun host(url: String): String =
        url.lowercase().substringAfter("://").substringBefore('/').removePrefix("www.")
}
