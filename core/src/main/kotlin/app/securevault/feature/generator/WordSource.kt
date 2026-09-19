package app.securevault.feature.generator

/**
 * Where the passphrase word list comes from.
 *
 * The list itself is portable; *finding* it is not -- Android reads an asset through a Context,
 * a desktop build reads a classpath resource. That single difference is the whole interface.
 *
 * [FallbackWordSource] exists so the generator always works. It is small, and the generator
 * reports entropy from the list actually in use, so a short list under-promises rather than
 * over-promises. Ship the EFF large list on both platforms.
 */
fun interface WordSource {
    fun words(): List<String>
}

object WordLists {
    /** 7776 words is the EFF large list; below 1024 the entropy per word is materially lower. */
    fun isFullDicewareList(list: List<String>): Boolean = list.size >= 1024

    /**
     * Parses the EFF list format: either one word per line, or "12345<tab>word".
     * Shared by every platform so a list that works on one works on all.
     */
    fun parse(text: String): List<String> = text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { line -> line.substringAfterLast('\t').substringAfterLast(' ').trim() }
        .filter { it.length in 3..12 && it.all { c -> c.isLetter() } }
        .distinct()
        .toList()
}
