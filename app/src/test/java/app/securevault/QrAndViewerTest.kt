package app.securevault

import app.securevault.data.attachments.AttachmentViewer
import app.securevault.feature.totp.OtpAuthUri
import app.securevault.feature.totp.TotpEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The decision logic behind two flows that otherwise need a device.
 *
 * The camera and the external viewer cannot be exercised here. What can be is the part that
 * decides what happens: whether a scanned code is usable, and whether an attachment should be
 * offered an in-app open at all. Both used to fail silently -- an unreadable QR looked like a
 * broken camera, and an unopenable file would have been a dead button.
 */
class QrAndViewerTest {

    // ---- QR parsing, which drives the preview/confirm step -------------------------------------

    @Test
    fun `a well formed otpauth uri parses into a previewable config`() {
        val config = OtpAuthUri.parse(
            "otpauth://totp/Example:jane@example.com" +
                "?secret=GEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60"
        )
        assertNotNull(config)
        assertEquals("GEZDGNBVGY3TQOJQ", config!!.secretBase32)
        assertEquals("SHA256", config.algorithm)
        assertEquals(8, config.digits)
        assertEquals(60, config.periodSeconds)
        assertEquals("Example", config.issuer)
        // These four are exactly what the preview dialog shows; the secret is not among them.
        assertTrue(config.account.contains("jane"))
    }

    @Test
    fun `defaults are applied when the uri omits them`() {
        val config = OtpAuthUri.parse("otpauth://totp/Acme?secret=GEZDGNBVGY3TQOJQ")
        assertNotNull(config)
        assertEquals("SHA1", config!!.algorithm)
        assertEquals(6, config.digits)
        assertEquals(30, config.periodSeconds)
    }

    @Test
    fun `codes that are not otpauth are rejected rather than ignored`() {
        // Each of these previously produced silence from the scanner. Now they must come back
        // null so the flow can say why.
        listOf(
            "https://example.com",
            "otpauth://totp/Acme",                       // no secret
            "otpauth://hotp/Acme?secret=GEZDGNBVGY3TQOJQ", // counter-based, not supported
            "otpauth://totp/Acme?secret=not-base32!!",
            "",
            "WIFI:S:MyNetwork;T:WPA;P:hunter2;;"
        ).forEach { raw ->
            assertNull("'$raw' should not parse", OtpAuthUri.parse(raw))
        }
    }

    @Test
    fun `a parsed config actually generates codes`() {
        // Confirming in the preview must not enrol something that then produces nothing.
        val config = OtpAuthUri.parse("otpauth://totp/Acme?secret=GEZDGNBVGY3TQOJQ")!!
        val code = TotpEngine.generate(config, nowMillis = 59_000)
        assertEquals(6, code.code.length)
        assertTrue(code.code.all { it.isDigit() })
    }

    // ---- attachment viewing gate ------------------------------------------------------------------

    @Test
    fun `common displayable types are offered an in-app open`() {
        listOf(
            "image/png", "image/jpeg", "application/pdf", "text/plain", "video/mp4", "audio/mpeg"
        ).forEach { assertTrue("$it should be viewable", AttachmentViewer.looksViewable(it)) }
    }

    @Test
    fun `types nothing can render are not offered a dead button`() {
        listOf(
            "application/octet-stream", "application/x-sqlite3", "", "application/zip"
        ).forEach { assertFalse("$it should not be viewable", AttachmentViewer.looksViewable(it)) }
    }

    @Test
    fun `the inline view limit is well below the attachment limit`() {
        // Decrypting a 25 MB attachment into cache to hand to a viewer is not a trade worth making.
        assertTrue(
            AttachmentViewer.MAX_INLINE_VIEW_BYTES <
                app.securevault.data.attachments.AttachmentStore.MAX_ATTACHMENT_BYTES
        )
    }
}
