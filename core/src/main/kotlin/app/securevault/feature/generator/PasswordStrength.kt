package app.securevault.feature.generator

import kotlin.math.ln
import kotlin.math.min

enum class StrengthLabel { VERY_WEAK, WEAK, FAIR, STRONG, VERY_STRONG }

data class StrengthResult(
    val score: Int,             // 0-100
    val entropyBits: Double,
    val label: StrengthLabel,
    val suggestions: List<String>
)

/**
 * A read-only [CharSequence] view over a [CharArray], with no copy.
 *
 * This exists so the master password can be scored without ever becoming a `String`. A String is
 * immutable, so it cannot be wiped; once the master password has been materialised as one it sits
 * on the heap until garbage collection, and possibly on disk if that memory is ever paged. The
 * array this wraps stays the caller's to zero.
 *
 * [toString] deliberately returns a redacted marker rather than the contents. Nothing in the
 * scoring path calls it -- `java.util.regex.Matcher` indexes a CharSequence with `charAt` and does
 * not copy it -- and if some future code does reach for it, a redacted marker is a far better
 * failure than a silent leak. The regression tests compare String and CharArray scoring for
 * exactly the regex-driven rules, so an accidental `toString()` on that path shows up as a
 * mismatch rather than as nothing at all.
 */
class CharArrayView private constructor(
    private val chars: CharArray,
    private val offset: Int,
    override val length: Int
) : CharSequence {

    constructor(chars: CharArray) : this(chars, 0, chars.size)

    override fun get(index: Int): Char {
        if (index < 0 || index >= length) throw IndexOutOfBoundsException("index $index")
        return chars[offset + index]
    }

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence {
        require(startIndex in 0..endIndex && endIndex <= length) { "bad range" }
        return CharArrayView(chars, offset + startIndex, endIndex - startIndex)
    }

    /** Redacted on purpose. See the class comment. */
    override fun toString(): String = "CharArrayView(length=$length, contents redacted)"
}

/**
 * A deliberately conservative strength estimate.
 *
 * It starts from character-pool entropy, then penalises the patterns that make a password far
 * weaker than its length suggests: dictionary words, keyboard runs, repeats, dates, and the
 * "Password1!" shape that satisfies a naive complexity rule while being trivially guessable.
 *
 * It runs entirely offline, the password is never sent anywhere to be scored, and -- since this
 * revision -- scoring a [CharArray] never produces an intermediate `String`. Every step works on
 * the [CharSequence] the caller supplied: case-insensitive matching is done character by character
 * rather than through `lowercase()`, and the regular expressions run against the sequence directly.
 */
object PasswordStrength {

    private val COMMON = setOf(
        "password", "123456", "123456789", "qwerty", "abc123", "letmein", "welcome", "admin",
        "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "charlie", "login",
        "master", "hello", "freedom", "whatever", "trustno1", "passw0rd", "qwertyuiop", "starwars"
    )
    private val KEYBOARD_RUNS = listOf(
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"
    )

    private val REPEATED = Regex("(.)\\1{2,}")
    private val YEAR = Regex("(19|20)\\d{2}")
    private val PREDICTABLE_SHAPE = Regex("^[A-Z][a-z]+\\d{1,4}[!@#$]?$")

    /**
     * Scores a password.
     *
     * Takes a [CharSequence] rather than a String so a [CharArrayView] can be passed straight in.
     * `String` is a `CharSequence`, so every existing caller keeps working unchanged and the
     * result is identical either way -- which the regression tests assert.
     */
    fun evaluate(password: CharSequence): StrengthResult {
        if (password.isEmpty()) {
            return StrengthResult(0, 0.0, StrengthLabel.VERY_WEAK, listOf("Enter a password"))
        }

        var pool = 0
        if (password.any { it.isLowerCase() }) pool += 26
        if (password.any { it.isUpperCase() }) pool += 26
        if (password.any { it.isDigit() }) pool += 10
        if (password.any { !it.isLetterOrDigit() }) pool += 32
        var entropy = password.length * (ln(pool.coerceAtLeast(2).toDouble()) / ln(2.0))

        val suggestions = mutableListOf<String>()

        // Previously: password.lowercase(), which allocated a String copy of the secret. The
        // comparison below folds case per character instead, so nothing is copied.
        if (COMMON.any { containsIgnoringCase(password, it) }) {
            entropy -= 30
            suggestions += "Contains a very common password"
        }
        if (KEYBOARD_RUNS.any { run -> run.windowed(4).any { containsIgnoringCase(password, it) } }) {
            entropy -= 12
            suggestions += "Avoid keyboard runs like qwerty or 1234"
        }
        if (REPEATED.containsMatchIn(password)) {
            entropy -= 8
            suggestions += "Avoid repeated characters"
        }
        if (YEAR.containsMatchIn(password)) {
            entropy -= 6
            suggestions += "Avoid years and dates"
        }
        if (PREDICTABLE_SHAPE.matches(password)) {
            entropy -= 10
            suggestions += "This shape is predictable, even though it meets complexity rules"
        }
        if (password.length < 12) {
            suggestions += "Use at least 12 characters, 16 or more is better"
        }
        if (password.length >= 20 && suggestions.isEmpty()) {
            suggestions += "Strong. A passphrase of this length is easy to keep."
        }

        entropy = entropy.coerceAtLeast(0.0)
        val score = min(100, (entropy / 100.0 * 100).toInt())
        return StrengthResult(
            score = score,
            entropyBits = entropy,
            label = when {
                entropy < 28 -> StrengthLabel.VERY_WEAK
                entropy < 45 -> StrengthLabel.WEAK
                entropy < 65 -> StrengthLabel.FAIR
                entropy < 90 -> StrengthLabel.STRONG
                else -> StrengthLabel.VERY_STRONG
            },
            suggestions = suggestions.distinct()
        )
    }

    /** Scores a wipeable array without copying it. The array is not modified. */
    fun evaluate(password: CharArray): StrengthResult = evaluate(CharArrayView(password))

    /**
     * Master password policy: long, no artificial ceiling, spaces welcome.
     *
     * This used to do `String(password)` before scoring, which left an unwipeable copy of the
     * master password on the heap every time the setup or change-password screen recalculated.
     * It now scores the array in place.
     */
    fun masterPasswordIssues(password: CharArray): List<String> {
        val issues = mutableListOf<String>()
        if (password.size < 12) issues += "Use at least 12 characters"
        val strength = evaluate(CharArrayView(password))
        if (strength.entropyBits < 60) {
            issues += "This master password is guessable. Aim for a long passphrase."
        }
        return issues
    }

    /**
     * Case-insensitive substring search that allocates nothing.
     *
     * [needle] is expected to already be lowercase; every caller in this file supplies a constant
     * that is. Folding only the haystack side avoids a second allocation per comparison.
     */
    private fun containsIgnoringCase(haystack: CharSequence, needle: String): Boolean {
        if (needle.isEmpty()) return true
        if (haystack.length < needle.length) return false
        outer@ for (start in 0..haystack.length - needle.length) {
            for (offset in needle.indices) {
                if (haystack[start + offset].lowercaseChar() != needle[offset]) continue@outer
            }
            return true
        }
        return false
    }
}
