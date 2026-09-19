package app.securevault.core.model

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

enum class ItemType {
    LOGIN, CARD, IDENTITY, SECURE_NOTE, WIFI, API_KEY, SSH_KEY,
    BANK_ACCOUNT, SOFTWARE_LICENSE, DOCUMENT, PASSKEY;

    val displayName: String
        get() = when (this) {
            LOGIN -> "Login"
            CARD -> "Card"
            IDENTITY -> "Identity"
            SECURE_NOTE -> "Secure note"
            WIFI -> "Wi-Fi"
            API_KEY -> "API key"
            SSH_KEY -> "SSH key"
            BANK_ACCOUNT -> "Bank account"
            SOFTWARE_LICENSE -> "Software licence"
            DOCUMENT -> "Document"
            PASSKEY -> "Passkey"
        }
}

enum class FieldKind { TEXT, HIDDEN, EMAIL, URL, PHONE, DATE, MULTILINE, BOOLEAN }

data class CustomField(
    val name: String,
    val value: String,
    val kind: FieldKind = FieldKind.TEXT
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name); put("value", value); put("kind", kind.name)
    }

    companion object {
        fun fromJson(json: JSONObject) = CustomField(
            name = json.getString("name"),
            value = json.optString("value"),
            kind = FieldKind.valueOf(json.optString("kind", FieldKind.TEXT.name))
        )
    }
}

data class TotpConfig(
    val secretBase32: String,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val periodSeconds: Int = 30,
    val issuer: String = "",
    val account: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("secret", secretBase32); put("algorithm", algorithm); put("digits", digits)
        put("period", periodSeconds); put("issuer", issuer); put("account", account)
    }

    companion object {
        fun fromJson(json: JSONObject) = TotpConfig(
            secretBase32 = json.getString("secret"),
            algorithm = json.optString("algorithm", "SHA1"),
            digits = json.optInt("digits", 6),
            periodSeconds = json.optInt("period", 30),
            issuer = json.optString("issuer"),
            account = json.optString("account")
        )
    }
}

data class AttachmentRef(
    val id: String,
    val fileName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val addedAt: Long
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("fileName", fileName); put("mimeType", mimeType)
        put("size", sizeBytes); put("addedAt", addedAt)
    }

    companion object {
        fun fromJson(json: JSONObject) = AttachmentRef(
            id = json.getString("id"),
            fileName = json.getString("fileName"),
            mimeType = json.optString("mimeType", "application/octet-stream"),
            sizeBytes = json.optLong("size", 0),
            addedAt = json.optLong("addedAt", 0)
        )
    }
}

/**
 * The entire user-visible content of an item, including its title.
 *
 * This whole object is serialised and encrypted as one blob. Nothing here -- not the title, not a
 * URL, not a tag -- is ever written to the database in the clear, so an attacker with the database
 * file learns only how many items exist and when they were touched.
 */
data class ItemPayload(
    val title: String,
    val fields: Map<String, String> = emptyMap(),
    val notes: String = "",
    val tags: List<String> = emptyList(),
    val customFields: List<CustomField> = emptyList(),
    val totp: TotpConfig? = null,
    val recoveryCodes: List<String> = emptyList(),
    val attachments: List<AttachmentRef> = emptyList(),
    val passwordChangedAt: Long? = null,
    val requiresTwoFactor: Boolean = false
) {
    fun field(key: String): String = fields[key].orEmpty()

    fun toJson(): JSONObject = JSONObject().apply {
        put("title", title)
        put("fields", JSONObject().also { obj -> fields.forEach { (k, v) -> obj.put(k, v) } })
        put("notes", notes)
        put("tags", JSONArray(tags))
        put("customFields", JSONArray(customFields.map { it.toJson() }))
        totp?.let { put("totp", it.toJson()) }
        put("recoveryCodes", JSONArray(recoveryCodes))
        put("attachments", JSONArray(attachments.map { it.toJson() }))
        passwordChangedAt?.let { put("passwordChangedAt", it) }
        put("requiresTwoFactor", requiresTwoFactor)
    }

    companion object {
        fun fromJson(json: JSONObject): ItemPayload {
            val fieldsJson = json.optJSONObject("fields") ?: JSONObject()
            val fields = buildMap {
                fieldsJson.keys().forEach { key -> put(key, fieldsJson.optString(key)) }
            }
            return ItemPayload(
                title = json.optString("title"),
                fields = fields,
                notes = json.optString("notes"),
                tags = json.optJSONArray("tags").toStringList(),
                customFields = json.optJSONArray("customFields").toObjectList(CustomField::fromJson),
                totp = json.optJSONObject("totp")?.let { TotpConfig.fromJson(it) },
                recoveryCodes = json.optJSONArray("recoveryCodes").toStringList(),
                attachments = json.optJSONArray("attachments").toObjectList(AttachmentRef::fromJson),
                passwordChangedAt = if (json.has("passwordChangedAt")) json.getLong("passwordChangedAt") else null,
                requiresTwoFactor = json.optBoolean("requiresTwoFactor", false)
            )
        }
    }
}

/** Canonical field keys. Import and export map foreign formats onto these. */
object Fields {
    const val USERNAME = "username"
    const val EMAIL = "email"
    const val PASSWORD = "password"
    const val URL = "url"
    const val CARDHOLDER = "cardholder"
    const val CARD_NUMBER = "cardNumber"
    const val CARD_BRAND = "cardBrand"
    const val EXPIRY = "expiry"
    const val CVV = "cvv"
    const val PIN = "pin"
    const val BANK = "bank"
    const val ACCOUNT_NUMBER = "accountNumber"
    const val IFSC = "ifsc"
    const val IBAN = "iban"
    const val SWIFT = "swift"
    const val FULL_NAME = "fullName"
    const val DATE_OF_BIRTH = "dateOfBirth"
    const val ADDRESS = "address"
    const val PHONE = "phone"
    const val PASSPORT = "passport"
    const val DRIVING_LICENCE = "drivingLicence"
    const val NATIONAL_ID = "nationalId"
    const val SSID = "ssid"
    const val WIFI_PASSWORD = "wifiPassword"
    const val WIFI_SECURITY = "wifiSecurity"
    const val API_KEY = "apiKey"
    const val API_SECRET = "apiSecret"
    const val PRIVATE_KEY = "privateKey"
    const val PUBLIC_KEY = "publicKey"
    const val KEY_PASSPHRASE = "keyPassphrase"
    const val LICENCE_KEY = "licenceKey"
    const val LICENCE_OWNER = "licenceOwner"
    const val RELYING_PARTY = "relyingParty"
    const val CREDENTIAL_ID = "credentialId"

    /** Fields masked in the UI until the user explicitly reveals them. */
    val SECRET_FIELDS = setOf(
        PASSWORD, CVV, PIN, CARD_NUMBER, ACCOUNT_NUMBER, IBAN, WIFI_PASSWORD,
        API_KEY, API_SECRET, PRIVATE_KEY, KEY_PASSPHRASE, LICENCE_KEY,
        PASSPORT, DRIVING_LICENCE, NATIONAL_ID
    )
}

/** An item as the app works with it: metadata plus decrypted payload. */
data class VaultItem(
    val id: String = UUID.randomUUID().toString(),
    val type: ItemType,
    val payload: ItemPayload,
    val folderId: String? = null,
    val favorite: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val lastUsedAt: Long? = null
) {
    val title: String get() = payload.title
    val username: String
        get() = payload.field(Fields.USERNAME).ifEmpty { payload.field(Fields.EMAIL) }
    val password: String get() = payload.field(Fields.PASSWORD)
    val url: String get() = payload.field(Fields.URL)
}

data class Folder(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val parentId: String? = null,
    val createdAt: Long = System.currentTimeMillis()
)

private fun JSONArray?.toStringList(): List<String> =
    if (this == null) emptyList() else (0 until length()).map { optString(it) }

private fun <T> JSONArray?.toObjectList(mapper: (JSONObject) -> T): List<T> =
    if (this == null) emptyList() else (0 until length()).mapNotNull { idx ->
        optJSONObject(idx)?.let(mapper)
    }
