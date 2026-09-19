package app.securevault.feature.autofill

/**
 * Decides whether a stored item belongs to a requesting page or app.
 *
 * Pure, and deliberately strict. A loose `contains` match would offer a bank login to
 * `bank.evil.com`, which is the classic autofill phishing hole. Matching is on registrable host
 * boundaries only: exact host, or a subdomain relationship in either direction.
 */
object AutofillDomainMatcher {

    fun hostOf(urlOrHost: String): String =
        urlOrHost.trim().lowercase()
            .substringAfter("://")
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore(':')
            .removePrefix("www.")

    fun matches(storedUrl: String, requested: String): Boolean {
        val stored = hostOf(storedUrl)
        val target = hostOf(requested)
        if (stored.isEmpty() || target.isEmpty()) return false
        if (stored == target) return true
        // Subdomain relationship, anchored on a dot so "evilbank.com" never matches "bank.com".
        return stored.endsWith(".$target") || target.endsWith(".$stored")
    }
}
