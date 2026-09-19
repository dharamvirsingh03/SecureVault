package app.securevault.feature.csv

/**
 * RFC 4180 CSV reader and writer.
 *
 * Handles quoted fields, escaped quotes and embedded newlines, which the exports from real
 * password managers contain constantly -- notes fields are full of line breaks and commas, and a
 * naive split(",") silently corrupts them.
 */
object Csv {

    fun parse(text: String): List<List<String>> {
        val rows = mutableListOf<List<String>>()
        val row = mutableListOf<String>()
        val field = StringBuilder()
        var inQuotes = false
        var index = 0
        val input = text.removePrefix("\uFEFF")

        while (index < input.length) {
            val c = input[index]
            when {
                inQuotes && c == '"' && index + 1 < input.length && input[index + 1] == '"' -> {
                    field.append('"'); index++
                }
                c == '"' -> inQuotes = !inQuotes
                !inQuotes && c == ',' -> { row += field.toString(); field.setLength(0) }
                !inQuotes && (c == '\n' || c == '\r') -> {
                    if (c == '\r' && index + 1 < input.length && input[index + 1] == '\n') index++
                    row += field.toString(); field.setLength(0)
                    rows += row.toList(); row.clear()
                }
                else -> field.append(c)
            }
            index++
        }
        if (field.isNotEmpty() || row.isNotEmpty()) {
            row += field.toString()
            rows += row.toList()
        }
        return rows.filter { line -> line.any { it.isNotBlank() } }
    }

    fun writeRow(values: List<String>): String = values.joinToString(",") { escape(it) }

    private fun escape(value: String): String =
        if (value.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            "\"" + value.replace("\"", "\"\"") + "\""
        } else value
}
