package app.securevault

import app.securevault.feature.generator.CharArrayView
import app.securevault.feature.generator.PasswordStrength
import app.securevault.feature.generator.StrengthLabel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the removal of the master-password String copy.
 *
 * Two things are being pinned here. First, that scoring a CharArray produces exactly the same
 * result as scoring the equivalent String -- the refactor must not have quietly weakened the
 * algorithm. Second, that nothing on the scoring path calls toString() on the view: if it did,
 * every rule below that depends on the actual characters would score the redacted marker instead
 * and these comparisons would diverge.
 */
class PasswordStrengthTest {

    /** Chosen to exercise every rule: common words, keyboard runs, repeats, years, shapes. */
    private val samples = listOf(
        "",
        "a",
        "short",
        "Password1!",
        "qwerty123",
        "aaaabbbb1111",
        "summer2024",
        "Tr0ub4dor&3",
        "correct horse battery staple",
        "correct horse battery staple xylo",
        "QWERTYuiop!2345",
        "ZXCVBNM,./asdf",
        "PASSWORD",
        "PaSsWoRd2019!!",
        "\u00e9\u00e8\u00ea-passphrase-with-accents-and-length"
    )

    @Test
    fun `CharArray scoring matches String scoring exactly`() {
        samples.forEach { sample ->
            val fromString = PasswordStrength.evaluate(sample)
            val fromArray = PasswordStrength.evaluate(sample.toCharArray())
            assertEquals("score differs for '$sample'", fromString.score, fromArray.score)
            assertEquals("bits differ for '$sample'", fromString.entropyBits, fromArray.entropyBits, 1e-9)
            assertEquals("label differs for '$sample'", fromString.label, fromArray.label)
            assertEquals("advice differs for '$sample'", fromString.suggestions, fromArray.suggestions)
        }
    }

    @Test
    fun `the case-insensitive rules still fire on a CharArray`() {
        // If toString() were on the scoring path, none of these would be detected.
        val shouting = PasswordStrength.evaluate("PASSWORD".toCharArray())
        assertTrue(shouting.suggestions.any { it.contains("common password") })

        val mixed = PasswordStrength.evaluate("QwErTyUiOp".toCharArray())
        assertTrue(mixed.suggestions.any { it.contains("keyboard runs") })
    }

    @Test
    fun `the regex rules still fire on a CharArray`() {
        assertTrue(
            PasswordStrength.evaluate("Summer2024".toCharArray())
                .suggestions.any { it.contains("years and dates") }
        )
        assertTrue(
            PasswordStrength.evaluate("abbbbc!!".toCharArray())
                .suggestions.any { it.contains("repeated characters") }
        )
        assertTrue(
            PasswordStrength.evaluate("Hunter22!".toCharArray())
                .suggestions.any { it.contains("predictable") }
        )
    }

    @Test
    fun `the analysis does not modify the array it was given`() {
        val original = "correct horse battery staple".toCharArray()
        val copy = original.copyOf()
        PasswordStrength.evaluate(original)
        PasswordStrength.masterPasswordIssues(original)
        assertTrue("scoring must leave the caller's array intact", original.contentEquals(copy))
    }

    @Test
    fun `the caller can still wipe the array afterwards`() {
        val password = "a long enough passphrase".toCharArray()
        PasswordStrength.masterPasswordIssues(password)
        password.fill('\u0000')
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun `master password policy is unchanged`() {
        assertTrue(
            PasswordStrength.masterPasswordIssues("short".toCharArray())
                .any { it.contains("at least 12") }
        )
        assertTrue(
            PasswordStrength.masterPasswordIssues("passwordpassword".toCharArray())
                .any { it.contains("guessable") }
        )
        assertTrue(
            PasswordStrength.masterPasswordIssues(
                "vinegar trombone lantern pickaxe".toCharArray()
            ).isEmpty()
        )
    }

    @Test
    fun `the view never renders its contents`() {
        val view = CharArrayView("the-secret-value".toCharArray())
        val rendered = view.toString()
        assertFalse("toString must not leak the password", rendered.contains("secret"))
        assertTrue(rendered.contains("redacted"))
        // Indexing still works, which is all the scoring path needs.
        assertEquals('t', view[0])
        assertEquals(16, view.length)
    }

    @Test
    fun `the view slices without copying semantics changing`() {
        val view = CharArrayView("abcdefgh".toCharArray())
        val slice = view.subSequence(2, 5)
        assertEquals(3, slice.length)
        assertEquals('c', slice[0])
        assertEquals('e', slice[2])
    }

    @Test
    fun `empty input is handled`() {
        val result = PasswordStrength.evaluate(CharArray(0))
        assertEquals(StrengthLabel.VERY_WEAK, result.label)
        assertEquals(0.0, result.entropyBits, 1e-9)
    }
}
