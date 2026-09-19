package app.securevault.feature.health

import app.securevault.core.model.VaultItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

data class BreachResult(val breachedItemIds: Set<String>, val checked: Int, val failed: Int)

/**
 * Optional breach check using the k-anonymity range API.
 *
 * How it works, and what leaves the device: the password is hashed with SHA-1 locally, and only
 * the first five hex characters of that hash are sent. The service replies with every suffix
 * sharing that prefix -- typically several hundred -- and the comparison happens here. The service
 * never receives the password, the full hash, the site, the username, or anything identifying the
 * vault.
 *
 * What it still reveals: that someone at this IP address asked about a 5-character hash prefix, at
 * this time. That is why the feature is off by default and must be switched on deliberately.
 *
 * SHA-1 is used because the API is built on it. It is a hash-prefix lookup, not a security
 * boundary, and no part of the vault depends on SHA-1.
 */
class BreachChecker(
    private val endpoint: String = "https://api.pwnedpasswords.com/range/"
) {
    suspend fun check(items: List<VaultItem>): BreachResult = withContext(Dispatchers.IO) {
        val withPasswords = items.filter { it.password.isNotEmpty() }
        val byPrefix = withPasswords.groupBy { sha1(it.password).take(5) }

        val breached = mutableSetOf<String>()
        var failed = 0

        for ((prefix, group) in byPrefix) {
            val suffixes = runCatching { fetchSuffixes(prefix) }.getOrElse {
                failed += group.size
                continue
            }
            for (item in group) {
                val suffix = sha1(item.password).drop(5)
                if (suffixes.contains(suffix)) breached += item.id
            }
        }
        BreachResult(breached, withPasswords.size, failed)
    }

    private fun fetchSuffixes(prefix: String): Set<String> {
        val connection = (URL("$endpoint$prefix").openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 10_000
            // Pads the response so its size cannot hint at the prefix being queried.
            setRequestProperty("Add-Padding", "true")
            setRequestProperty("User-Agent", "SecureVault-Android")
        }
        return try {
            if (connection.responseCode != 200) throw IllegalStateException("HTTP ${connection.responseCode}")
            connection.inputStream.bufferedReader().useLines { lines ->
                lines.mapNotNull { line ->
                    val parts = line.split(':')
                    if (parts.size == 2 && parts[1].trim() != "0") parts[0].trim().uppercase() else null
                }.toSet()
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun sha1(value: String): String =
        MessageDigest.getInstance("SHA-1").digest(value.toByteArray())
            .joinToString("") { "%02X".format(it) }
}
