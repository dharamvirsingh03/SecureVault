package app.securevault.core.model

/**
 * Which fields each item type shows, in what order, and how each should be rendered.
 *
 * This lives in the domain layer rather than in a Compose file on purpose. The editor, the detail
 * screen and anything added later all need the same answer to "what does a Wi-Fi record contain",
 * and three copies of that list would drift. It also keeps the UI from inventing field keys: every
 * entry here is a canonical key from [Fields], so an item written by the editor is the same shape
 * as one written by the CSV importer or a backup restore.
 */
data class FieldSpec(
    val key: String,
    val label: String,
    val kind: FieldKind = FieldKind.TEXT,
    /** Hint text. Never an example of a real secret. */
    val hint: String = ""
) {
    /** Masked in the UI until explicitly revealed, and excluded from search text. */
    val isSecret: Boolean get() = key in Fields.SECRET_FIELDS
}

object ItemSchema {

    fun fieldsFor(type: ItemType): List<FieldSpec> = when (type) {
        ItemType.LOGIN -> listOf(
            FieldSpec(Fields.USERNAME, "Username", FieldKind.TEXT),
            FieldSpec(Fields.EMAIL, "Email", FieldKind.EMAIL),
            FieldSpec(Fields.PASSWORD, "Password", FieldKind.HIDDEN),
            FieldSpec(Fields.URL, "Website", FieldKind.URL, "https://")
        )
        ItemType.CARD -> listOf(
            FieldSpec(Fields.CARDHOLDER, "Cardholder name"),
            FieldSpec(Fields.CARD_NUMBER, "Card number", FieldKind.HIDDEN),
            FieldSpec(Fields.CARD_BRAND, "Brand", FieldKind.TEXT, "Visa, Mastercard, RuPay"),
            FieldSpec(Fields.EXPIRY, "Expiry", FieldKind.TEXT, "MM/YY"),
            FieldSpec(Fields.CVV, "Security code", FieldKind.HIDDEN),
            FieldSpec(Fields.PIN, "PIN", FieldKind.HIDDEN),
            FieldSpec(Fields.BANK, "Issuing bank")
        )
        ItemType.IDENTITY -> listOf(
            FieldSpec(Fields.FULL_NAME, "Full name"),
            FieldSpec(Fields.DATE_OF_BIRTH, "Date of birth", FieldKind.DATE),
            FieldSpec(Fields.EMAIL, "Email", FieldKind.EMAIL),
            FieldSpec(Fields.PHONE, "Phone", FieldKind.PHONE),
            FieldSpec(Fields.ADDRESS, "Address", FieldKind.MULTILINE),
            FieldSpec(Fields.PASSPORT, "Passport number", FieldKind.HIDDEN),
            FieldSpec(Fields.DRIVING_LICENCE, "Driving licence", FieldKind.HIDDEN),
            FieldSpec(Fields.NATIONAL_ID, "National ID", FieldKind.HIDDEN)
        )
        ItemType.SECURE_NOTE -> emptyList()
        ItemType.WIFI -> listOf(
            FieldSpec(Fields.SSID, "Network name"),
            FieldSpec(Fields.WIFI_PASSWORD, "Network password", FieldKind.HIDDEN),
            FieldSpec(Fields.WIFI_SECURITY, "Security", FieldKind.TEXT, "WPA3, WPA2, open")
        )
        ItemType.API_KEY -> listOf(
            FieldSpec(Fields.API_KEY, "Key", FieldKind.HIDDEN),
            FieldSpec(Fields.API_SECRET, "Secret", FieldKind.HIDDEN),
            FieldSpec(Fields.URL, "Endpoint", FieldKind.URL)
        )
        ItemType.SSH_KEY -> listOf(
            FieldSpec(Fields.PUBLIC_KEY, "Public key", FieldKind.MULTILINE),
            FieldSpec(Fields.PRIVATE_KEY, "Private key", FieldKind.HIDDEN),
            FieldSpec(Fields.KEY_PASSPHRASE, "Key passphrase", FieldKind.HIDDEN)
        )
        ItemType.BANK_ACCOUNT -> listOf(
            FieldSpec(Fields.BANK, "Bank"),
            FieldSpec(Fields.FULL_NAME, "Account holder"),
            FieldSpec(Fields.ACCOUNT_NUMBER, "Account number", FieldKind.HIDDEN),
            FieldSpec(Fields.IFSC, "IFSC"),
            FieldSpec(Fields.IBAN, "IBAN", FieldKind.HIDDEN),
            FieldSpec(Fields.SWIFT, "SWIFT / BIC"),
            FieldSpec(Fields.PIN, "PIN", FieldKind.HIDDEN)
        )
        ItemType.SOFTWARE_LICENSE -> listOf(
            FieldSpec(Fields.LICENCE_OWNER, "Licensed to"),
            FieldSpec(Fields.LICENCE_KEY, "Licence key", FieldKind.HIDDEN),
            FieldSpec(Fields.EMAIL, "Registered email", FieldKind.EMAIL),
            FieldSpec(Fields.URL, "Vendor", FieldKind.URL)
        )
        ItemType.DOCUMENT -> listOf(
            FieldSpec(Fields.FULL_NAME, "Document holder"),
            FieldSpec(Fields.NATIONAL_ID, "Reference number", FieldKind.HIDDEN)
        )
        // Modelled only. The editor refuses to create these; see README.
        ItemType.PASSKEY -> listOf(
            FieldSpec(Fields.RELYING_PARTY, "Relying party"),
            FieldSpec(Fields.USERNAME, "Account"),
            FieldSpec(Fields.CREDENTIAL_ID, "Credential id")
        )
    }

    /** Types the add-item flow offers. Passkeys are excluded: the provider is not implemented. */
    val CREATABLE = listOf(
        ItemType.LOGIN,
        ItemType.CARD,
        ItemType.IDENTITY,
        ItemType.SECURE_NOTE,
        ItemType.WIFI,
        ItemType.API_KEY,
        ItemType.DOCUMENT,
        ItemType.SSH_KEY,
        ItemType.BANK_ACCOUNT,
        ItemType.SOFTWARE_LICENSE
    )

    /** Types where a one-time code makes sense. */
    fun supportsTotp(type: ItemType) = type == ItemType.LOGIN || type == ItemType.API_KEY

    fun supportsPasswordGeneration(type: ItemType) =
        type == ItemType.LOGIN || type == ItemType.WIFI || type == ItemType.API_KEY

    /** The field the generator should fill for this type. */
    fun generatedFieldFor(type: ItemType): String? = when (type) {
        ItemType.LOGIN -> Fields.PASSWORD
        ItemType.WIFI -> Fields.WIFI_PASSWORD
        ItemType.API_KEY -> Fields.API_SECRET
        else -> null
    }

    fun titleHintFor(type: ItemType): String = when (type) {
        ItemType.LOGIN -> "Google, Netflix, work VPN"
        ItemType.CARD -> "Personal debit card"
        ItemType.IDENTITY -> "My details"
        ItemType.SECURE_NOTE -> "What this note is about"
        ItemType.WIFI -> "Home network"
        ItemType.API_KEY -> "Stripe test key"
        ItemType.DOCUMENT -> "Passport scan"
        ItemType.SSH_KEY -> "Deploy key"
        ItemType.BANK_ACCOUNT -> "Salary account"
        ItemType.SOFTWARE_LICENSE -> "Photoshop licence"
        ItemType.PASSKEY -> "Passkey"
    }
}
