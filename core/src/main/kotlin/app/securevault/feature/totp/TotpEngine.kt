package app.securevault.feature.totp

import app.securevault.core.crypto.Base32
import app.securevault.core.model.TotpConfig
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

data class OtpCode(
    val code: String,
    val secondsRemaining: Int,
    val periodSeconds: Int
) {
    /** "482 193" -- grouped for reading off a screen, ungrouped when copied. */
    val formatted: String
        get() = if (code.length % 2 == 0) {
            code.chunked(code.length / 2).joinToString(" ")
        } else code

    val progress: Float get() = secondsRemaining.toFloat() / periodSeconds.toFloat()
}

/**
 * RFC 6238 TOTP / RFC 4226 HOTP.
 *
 * Generated codes are never logged and never written to disk. The secret only exists inside the
 * encrypted item payload, and is decrypted for the moment a code is generated.
 */
object TotpEngine {

    fun generate(config: TotpConfig, nowMillis: Long = System.currentTimeMillis()): OtpCode {
        val period = config.periodSeconds.coerceAtLeast(1)
        val seconds = nowMillis / 1000
        val counter = seconds / period
        val code = hotp(
            secret = Base32.decode(config.secretBase32),
            counter = counter,
            digits = config.digits,
            algorithm = macAlgorithm(config.algorithm)
        )
        return OtpCode(
            code = code,
            secondsRemaining = (period - (seconds % period)).toInt(),
            periodSeconds = period
        )
    }

    fun hotp(secret: ByteArray, counter: Long, digits: Int, algorithm: String): String {
        require(digits in 6..10) { "Unsupported digit count: $digits" }
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(secret, algorithm))
        val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        secret.fill(0)

        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        hash.fill(0)

        val modulus = 10.0.pow(digits).toInt()
        return (binary % modulus).toString().padStart(digits, '0')
    }

    fun isValidSecret(base32: String): Boolean = runCatching {
        Base32.decode(base32).also { it.fill(0) }.isNotEmpty()
    }.getOrDefault(false)

    private fun macAlgorithm(name: String): String = when (name.uppercase().replace("-", "")) {
        "SHA1" -> "HmacSHA1"
        "SHA256" -> "HmacSHA256"
        "SHA512" -> "HmacSHA512"
        else -> throw IllegalArgumentException("Unsupported TOTP algorithm: $name")
    }

    val SUPPORTED_ALGORITHMS = listOf("SHA1", "SHA256", "SHA512")
    val SUPPORTED_DIGITS = listOf(6, 8)
}
