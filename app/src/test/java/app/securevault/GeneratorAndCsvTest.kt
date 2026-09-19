package app.securevault

import app.securevault.feature.csv.Csv
import app.securevault.feature.csv.CsvFormat
import app.securevault.feature.generator.PasswordGenerator
import app.securevault.feature.generator.PasswordOptions
import app.securevault.feature.generator.PasswordStrength
import app.securevault.feature.generator.StrengthLabel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GeneratorAndCsvTest {

    @Test
    fun `generated passwords honour length and required classes`() {
        repeat(200) {
            val password = PasswordGenerator.generate(
                PasswordOptions(length = 16, minNumbers = 2, minSymbols = 2)
            )
            assertEquals(16, password.length)
            assertTrue(password.count { it.isDigit() } >= 2)
            assertTrue(password.count { !it.isLetterOrDigit() } >= 2)
        }
    }

    @Test
    fun `generated passwords are not repeated`() {
        val seen = (1..500).map { PasswordGenerator.generate(PasswordOptions(length = 20)) }.toSet()
        assertEquals(500, seen.size)
    }

    @Test
    fun `strength estimator punishes predictable shapes`() {
        assertTrue(PasswordStrength.evaluate("Password1!").label <= StrengthLabel.WEAK)
        assertTrue(PasswordStrength.evaluate("qwerty123").label <= StrengthLabel.WEAK)
        assertTrue(PasswordStrength.evaluate("correct horse battery staple xylo").label >= StrengthLabel.STRONG)
    }

    @Test
    fun `csv parser handles quotes and embedded newlines`() {
        val text = "name,notes\n\"Bank\",\"line one\nline two, with comma\"\n\"He said \"\"hi\"\"\",plain"
        val rows = Csv.parse(text)
        assertEquals(3, rows.size)
        assertEquals("line one\nline two, with comma", rows[1][1])
        assertEquals("He said \"hi\"", rows[2][0])
    }

    @Test
    fun `format detection recognises common exports`() {
        assertEquals(
            CsvFormat.BITWARDEN,
            CsvFormat.detect(listOf("folder", "favorite", "type", "name", "notes", "login_username", "login_password"))
        )
        assertEquals(
            CsvFormat.LASTPASS,
            CsvFormat.detect(listOf("url", "username", "password", "extra", "name", "grouping", "fav"))
        )
        assertEquals(
            CsvFormat.CHROME,
            CsvFormat.detect(listOf("name", "url", "username", "password", "note"))
        )
    }
}
