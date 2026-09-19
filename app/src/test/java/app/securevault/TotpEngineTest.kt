package app.securevault

import app.securevault.core.crypto.Base32
import app.securevault.feature.totp.TotpEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RFC 6238 Appendix B reference vectors. If these ever fail, every stored TOTP secret in the app
 * is producing wrong codes, so they run on every build.
 */
class TotpEngineTest {

    private val sha1Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    private val sha256Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
    private val sha512Secret =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"

    private fun code(secret: String, seconds: Long, algorithm: String) =
        TotpEngine.hotp(Base32.decode(secret), seconds / 30, 8, algorithm)

    @Test
    fun `sha1 reference vectors`() {
        assertEquals("94287082", code(sha1Secret, 59, "HmacSHA1"))
        assertEquals("07081804", code(sha1Secret, 1111111109, "HmacSHA1"))
        assertEquals("89005924", code(sha1Secret, 1234567890, "HmacSHA1"))
        assertEquals("69279037", code(sha1Secret, 2000000000, "HmacSHA1"))
    }

    @Test
    fun `sha256 reference vectors`() {
        assertEquals("46119246", code(sha256Secret, 59, "HmacSHA256"))
        assertEquals("68084774", code(sha256Secret, 1111111109, "HmacSHA256"))
        assertEquals("91819424", code(sha256Secret, 1234567890, "HmacSHA256"))
    }

    @Test
    fun `sha512 reference vectors`() {
        assertEquals("90693936", code(sha512Secret, 59, "HmacSHA512"))
        assertEquals("25091201", code(sha512Secret, 1111111109, "HmacSHA512"))
        assertEquals("93441116", code(sha512Secret, 1234567890, "HmacSHA512"))
    }

    @Test
    fun `base32 round trips`() {
        val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        assertTrue(Base32.decode(Base32.encode(data)).contentEquals(data))
    }
}
