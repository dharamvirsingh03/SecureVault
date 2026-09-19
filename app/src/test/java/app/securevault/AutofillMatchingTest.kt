package app.securevault

import app.securevault.feature.autofill.AutofillDomainMatcher
import app.securevault.feature.autofill.FieldClassifier
import app.securevault.feature.autofill.FieldRole
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * S6: the parts of the autofill flow that can be tested without a device.
 *
 * The PendingIntent mutability fix and the EXTRA_AUTHENTICATION_RESULT round trip cannot be unit
 * tested -- they need the platform's autofill framework. Those remain untested and are listed as
 * such in README.md.
 */
class AutofillMatchingTest {

    @Test
    fun `exact host matches`() {
        assertTrue(AutofillDomainMatcher.matches("https://example.com/login", "example.com"))
        assertTrue(AutofillDomainMatcher.matches("example.com", "https://example.com/"))
    }

    @Test
    fun `www is ignored`() {
        assertTrue(AutofillDomainMatcher.matches("https://www.example.com", "example.com"))
        assertTrue(AutofillDomainMatcher.matches("example.com", "www.example.com"))
    }

    @Test
    fun `subdomains match in both directions`() {
        assertTrue(AutofillDomainMatcher.matches("https://accounts.example.com", "example.com"))
        assertTrue(AutofillDomainMatcher.matches("https://example.com", "login.example.com"))
    }

    @Test
    fun `lookalike domains do not match`() {
        // The reason matching is anchored on a dot rather than using contains or endsWith alone.
        assertFalse(AutofillDomainMatcher.matches("https://mybank.com", "notmybank.com"))
        assertFalse(AutofillDomainMatcher.matches("https://mybank.com", "mybank.com.evil.net"))
        assertFalse(AutofillDomainMatcher.matches("https://mybank.com", "mybank.co"))
        assertFalse(AutofillDomainMatcher.matches("https://bank.com", "evilbank.com"))
    }

    @Test
    fun `empty inputs never match`() {
        assertFalse(AutofillDomainMatcher.matches("", "example.com"))
        assertFalse(AutofillDomainMatcher.matches("https://example.com", ""))
        assertFalse(AutofillDomainMatcher.matches("", ""))
    }

    @Test
    fun `ports and paths are stripped`() {
        assertTrue(AutofillDomainMatcher.matches("https://example.com:8443/a/b?c=d", "example.com"))
    }

    @Test
    fun `password fields win over username lookalikes`() {
        // "user password" contains "user"; classifying it as a username would type the account
        // name into a password box, or worse, the reverse.
        assertEquals(FieldRole.PASSWORD, FieldClassifier.classify(emptyList(), "user_password", null))
        assertEquals(FieldRole.PASSWORD, FieldClassifier.classify(listOf("current-password"), "field1", null))
        assertEquals(FieldRole.PASSWORD, FieldClassifier.classify(emptyList(), null, "Password"))
    }

    @Test
    fun `username and email fields`() {
        assertEquals(FieldRole.USERNAME, FieldClassifier.classify(listOf("username"), null, null))
        assertEquals(FieldRole.USERNAME, FieldClassifier.classify(listOf("emailAddress"), null, null))
        assertEquals(FieldRole.USERNAME, FieldClassifier.classify(emptyList(), "login_user", null))
    }

    @Test
    fun `one time code fields`() {
        assertEquals(FieldRole.OTP, FieldClassifier.classify(listOf("smsOTPCode"), null, null))
        assertEquals(FieldRole.OTP, FieldClassifier.classify(emptyList(), "otp_input", null))
    }

    @Test
    fun `unrecognised fields are left alone`() {
        assertEquals(FieldRole.UNKNOWN, FieldClassifier.classify(emptyList(), "street_address", null))
        assertEquals(FieldRole.UNKNOWN, FieldClassifier.classify(emptyList(), null, null))
        assertEquals(FieldRole.UNKNOWN, FieldClassifier.classify(listOf("postalCode"), "zip", null))
    }
}
