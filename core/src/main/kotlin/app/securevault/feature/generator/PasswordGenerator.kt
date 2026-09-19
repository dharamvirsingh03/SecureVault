package app.securevault.feature.generator

import app.securevault.core.crypto.RandomSource
import kotlin.math.ln

data class PasswordOptions(
    val length: Int = 20,
    val uppercase: Boolean = true,
    val lowercase: Boolean = true,
    val numbers: Boolean = true,
    val symbols: Boolean = true,
    val minNumbers: Int = 1,
    val minSymbols: Int = 1,
    val avoidAmbiguous: Boolean = false
)

data class PassphraseOptions(
    val words: Int = 4,
    val separator: String = "-",
    val capitalise: Boolean = false,
    val includeNumber: Boolean = true
)

/**
 * Password and passphrase generation.
 *
 * Every character comes from SecureRandom via RandomSource. Required character classes are placed
 * first and the result is shuffled with a CSPRNG-driven Fisher-Yates, so guaranteeing "at least
 * one digit" does not put the digit in a predictable position.
 */
object PasswordGenerator {

    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
    private const val AMBIGUOUS = "Il1O0o"

    fun generate(options: PasswordOptions): String {
        val pools = buildList {
            if (options.uppercase) add(filter(UPPER, options))
            if (options.lowercase) add(filter(LOWER, options))
            if (options.numbers) add(filter(DIGITS, options))
            if (options.symbols) add(filter(SYMBOLS, options))
        }
        require(pools.isNotEmpty()) { "Choose at least one character type" }
        val minimums = options.minNumbers.coerceAtLeast(0) + options.minSymbols.coerceAtLeast(0)
        require(options.length >= maxOf(pools.size, minimums)) {
            "Length is too short for the selected requirements"
        }

        val chars = mutableListOf<Char>()
        if (options.numbers) repeat(options.minNumbers) { chars += randomChar(filter(DIGITS, options)) }
        if (options.symbols) repeat(options.minSymbols) { chars += randomChar(filter(SYMBOLS, options)) }
        pools.forEach { pool -> if (chars.size < options.length) chars += randomChar(pool) }

        val combined = pools.joinToString("")
        while (chars.size < options.length) chars += randomChar(combined)
        RandomSource.shuffle(chars)
        return chars.take(options.length).joinToString("")
    }

    /** Bits of entropy for a uniformly random password of this shape. */
    fun entropyBits(options: PasswordOptions): Double {
        var pool = 0
        if (options.uppercase) pool += filter(UPPER, options).length
        if (options.lowercase) pool += filter(LOWER, options).length
        if (options.numbers) pool += filter(DIGITS, options).length
        if (options.symbols) pool += filter(SYMBOLS, options).length
        if (pool <= 1) return 0.0
        return options.length * (ln(pool.toDouble()) / ln(2.0))
    }

    private fun filter(source: String, options: PasswordOptions): String =
        if (options.avoidAmbiguous) source.filterNot { it in AMBIGUOUS } else source

    private fun randomChar(pool: String): Char = pool[RandomSource.int(pool.length)]
}

object PassphraseGenerator {

    fun generate(options: PassphraseOptions, wordList: List<String>): String {
        require(wordList.size >= 16) { "Word list is too small to generate a safe passphrase" }
        val words = (1..options.words.coerceAtLeast(2)).map {
            val word = RandomSource.pick(wordList)
            if (options.capitalise) word.replaceFirstChar { c -> c.uppercaseChar() } else word
        }.toMutableList()
        if (options.includeNumber) words += RandomSource.int(100).toString().padStart(2, '0')
        return words.joinToString(options.separator)
    }

    /** Entropy depends on the real list size, so a small bundled list reports a small number. */
    fun entropyBits(options: PassphraseOptions, wordListSize: Int): Double {
        val perWord = ln(wordListSize.toDouble()) / ln(2.0)
        val numberBits = if (options.includeNumber) ln(100.0) / ln(2.0) else 0.0
        return options.words * perWord + numberBits
    }
}
