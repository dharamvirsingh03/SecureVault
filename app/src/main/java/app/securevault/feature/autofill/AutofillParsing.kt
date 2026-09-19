package app.securevault.feature.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.view.View
import android.view.autofill.AutofillId
import androidx.annotation.RequiresApi

/** Which credential field a form input appears to be. */
enum class FieldRole { USERNAME, PASSWORD, OTP, UNKNOWN }

/**
 * Field classification, extracted from the AssistStructure walk so it can be unit tested.
 *
 * Order matters: password is checked first because "user password" contains "user", and an input
 * misfiled as a username would receive the username in plaintext where a password was expected.
 * When in doubt this returns UNKNOWN and the field is left alone -- guessing wrong is worse than
 * not filling.
 */
object FieldClassifier {

    private val PASSWORD_HINTS = setOf("password", "new-password", "current-password")
    private val USERNAME_HINTS = setOf("username", "email", "emailaddress", "new-username")
    private val OTP_HINTS = setOf("otp", "smsotpcode", "smscode", "one-time-code", "onetimecode")

    fun classify(autofillHints: List<String>, idEntry: String?, hintText: String?): FieldRole {
        val hints = autofillHints.map { it.lowercase().trim() }
        val id = idEntry?.lowercase().orEmpty()
        val text = hintText?.lowercase().orEmpty()

        if (hints.any { h -> PASSWORD_HINTS.any { h.contains(it) } } ||
            id.contains("password") || id.contains("passwd") || text.contains("password")
        ) return FieldRole.PASSWORD

        if (hints.any { h -> OTP_HINTS.any { h.contains(it) } } ||
            id.contains("otp") || id.contains("totp") || id.contains("onetime")
        ) return FieldRole.OTP

        if (hints.any { h -> USERNAME_HINTS.any { h.contains(it) } } ||
            id.contains("user") || id.contains("email") || id.contains("login") ||
            text.contains("username") || text.contains("e-mail")
        ) return FieldRole.USERNAME

        return FieldRole.UNKNOWN
    }
}

/** The fields a fill or save request is about. */
data class ParsedFields(
    val usernameId: AutofillId? = null,
    val passwordId: AutofillId? = null,
    val otpId: AutofillId? = null,
    val domain: String? = null,
    val packageName: String? = null,
    val usernameValue: String? = null,
    val passwordValue: String? = null
) {
    val autofillIds: Array<AutofillId>
        get() = listOfNotNull(usernameId, passwordId, otpId).toTypedArray()

    val hasCredentialFields: Boolean get() = usernameId != null || passwordId != null

    /** What to match vault items against: the web domain when the browser gives one. */
    val matchTarget: String? get() = domain?.takeIf { it.isNotBlank() } ?: packageName
}

@RequiresApi(Build.VERSION_CODES.O)
object AutofillStructureParser {

    /**
     * @param captureValues true for save requests, where the point is the text the user typed.
     * Fill requests pass false: there is no reason to read form contents just to offer a dataset.
     */
    fun parse(structure: AssistStructure, captureValues: Boolean = false): ParsedFields {
        var username: AutofillId? = null
        var password: AutofillId? = null
        var otp: AutofillId? = null
        var domain: String? = null
        var usernameValue: String? = null
        var passwordValue: String? = null

        fun textOf(node: AssistStructure.ViewNode): String? {
            if (!captureValues) return null
            node.autofillValue?.takeIf { it.isText }?.let { return it.textValue.toString() }
            return node.text?.toString()
        }

        fun visit(node: AssistStructure.ViewNode) {
            node.webDomain?.takeIf { it.isNotBlank() }?.let { domain = it }

            val autofillId = node.autofillId
            if (autofillId != null && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                val role = FieldClassifier.classify(
                    autofillHints = node.autofillHints?.toList().orEmpty(),
                    idEntry = node.idEntry,
                    hintText = node.hint
                )
                when (role) {
                    FieldRole.PASSWORD -> if (password == null) {
                        password = autofillId
                        passwordValue = textOf(node)
                    }
                    FieldRole.USERNAME -> if (username == null) {
                        username = autofillId
                        usernameValue = textOf(node)
                    }
                    FieldRole.OTP -> if (otp == null) otp = autofillId
                    FieldRole.UNKNOWN -> Unit
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }

        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)

        return ParsedFields(
            usernameId = username,
            passwordId = password,
            otpId = otp,
            domain = domain,
            packageName = structure.activityComponent?.packageName,
            usernameValue = usernameValue,
            passwordValue = passwordValue
        )
    }
}
