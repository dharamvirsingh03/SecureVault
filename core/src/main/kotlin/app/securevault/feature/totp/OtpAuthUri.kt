package app.securevault.feature.totp

import app.securevault.core.model.TotpConfig
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * Parses and builds otpauth:// URIs, the format every authenticator QR code uses.
 *
 * Parsing happens entirely on device. A scanned QR code is decoded locally and never sent
 * anywhere -- there is no image upload, no lookup, no network call in this path at all.
 *
 * Deliberately implemented without `android.net.Uri`. This is pure string work that decides
 * whether a scanned code is trustworthy enough to enrol, and a decision like that is worth being
 * able to test directly rather than only on a device. It also means a malformed code produces a
 * clean null on every platform rather than depending on how one particular URI parser copes.
 */
object OtpAuthUri {

    /** @return null for anything that is not a usable TOTP enrolment. Callers must say so. */
    fun parse(uri: String): TotpConfig? {
        val trimmed = uri.trim()
        if (!trimmed.startsWith("otpauth://", ignoreCase = true)) return null

        val rest = trimmed.substring("otpauth://".length)
        val beforeQuery = rest.substringBefore('?')
        val queryString = rest.substringAfter('?', "")

        // Only time-based codes. Counter-based (hotp) enrolment would need counter state this app
        // does not keep, and silently treating one as the other would produce codes that never work.
        val type = beforeQuery.substringBefore('/')
        if (!type.equals("totp", ignoreCase = true)) return null

        val query = parseQuery(queryString)

        val secret = query["secret"]?.replace(" ", "")?.uppercase() ?: return null
        if (!TotpEngine.isValidSecret(secret)) return null

        val label = decode(beforeQuery.substringAfter('/', ""))
        val labelIssuer = label.substringBefore(':', "").trim()
        val account = label.substringAfter(':', label).trim()

        return TotpConfig(
            secretBase32 = secret,
            algorithm = query["algorithm"]?.uppercase() ?: "SHA1",
            digits = query["digits"]?.toIntOrNull() ?: 6,
            periodSeconds = query["period"]?.toIntOrNull() ?: 30,
            issuer = query["issuer"]?.ifBlank { null } ?: labelIssuer,
            account = account
        ).takeIf {
            it.algorithm in TotpEngine.SUPPORTED_ALGORITHMS &&
                it.digits in 6..10 &&
                it.periodSeconds in 1..300
        }
    }

    fun build(config: TotpConfig): String {
        val label = listOfNotNull(config.issuer.ifBlank { null }, config.account.ifBlank { null })
            .joinToString(":")
        val query = buildString {
            append("secret=").append(config.secretBase32)
            if (config.issuer.isNotBlank()) append("&issuer=").append(encode(config.issuer))
            append("&algorithm=").append(config.algorithm)
            append("&digits=").append(config.digits)
            append("&period=").append(config.periodSeconds)
        }
        return "otpauth://totp/${encode(label)}?$query"
    }

    private fun parseQuery(query: String): Map<String, String> =
        query.split('&')
            .filter { it.isNotBlank() }
            .mapNotNull { pair ->
                val name = pair.substringBefore('=', "")
                if (name.isBlank()) null
                else decode(name).lowercase() to decode(pair.substringAfter('=', ""))
            }
            .toMap()

    private fun encode(value: String) = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    private fun decode(value: String) =
        runCatching { URLDecoder.decode(value, "UTF-8") }.getOrDefault(value)
}
