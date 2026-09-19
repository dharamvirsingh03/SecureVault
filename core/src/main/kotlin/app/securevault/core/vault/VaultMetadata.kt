package app.securevault.core.vault

import app.securevault.core.crypto.KdfParams
import org.json.JSONObject
import java.util.Base64
import java.util.UUID

/**
 * The unencrypted vault header. Everything here is safe to be public: it contains no key material
 * and no vault contents. It is written to app-private storage as JSON, never to SharedPreferences.
 *
 * Tampering with it is detected rather than prevented -- the wrapped VEK is authenticated with the
 * vault id as additional data, and altered KDF parameters simply produce the wrong key, so unlock
 * fails cleanly instead of silently using weaker settings.
 */
data class VaultMetadata(
    val vaultId: String,
    val name: String,
    val formatVersion: Int,
    val createdAt: Long,
    val modifiedAt: Long,
    val kdf: KdfParams,
    val wrappedVek: String,
    val recovery: RecoveryBlock?,
    val keyFileRequired: Boolean,
    val backupId: String
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("vaultId", vaultId)
        put("name", name)
        put("formatVersion", formatVersion)
        put("createdAt", createdAt)
        put("modifiedAt", modifiedAt)
        put("kdf", kdf.toJson())
        put("wrappedVek", wrappedVek)
        put("keyFileRequired", keyFileRequired)
        put("backupId", backupId)
        recovery?.let { put("recovery", it.toJson()) }
    }

    companion object {
        const val CURRENT_FORMAT_VERSION = 1

        fun fromJson(json: JSONObject): VaultMetadata = VaultMetadata(
            vaultId = json.getString("vaultId"),
            name = json.getString("name"),
            formatVersion = json.getInt("formatVersion"),
            createdAt = json.getLong("createdAt"),
            modifiedAt = json.getLong("modifiedAt"),
            kdf = KdfParams.fromJson(json.getJSONObject("kdf")),
            wrappedVek = json.getString("wrappedVek"),
            recovery = json.optJSONObject("recovery")?.let { RecoveryBlock.fromJson(it) },
            keyFileRequired = json.optBoolean("keyFileRequired", false),
            backupId = json.optString("backupId", UUID.randomUUID().toString())
        )
    }
}

/**
 * Present only when the user opted in to recovery-code recovery.
 *
 * This is a second, independent wrapping of the same VEK. Enabling it means the recovery code is
 * an alternative to the master password, not an addition to it -- anyone holding the code and a
 * copy of the vault gets in. That trade-off is surfaced in the UI before it is switched on.
 */
data class RecoveryBlock(
    val saltB64: String,
    val wrappedVek: String,
    val createdAt: Long
) {
    val salt: ByteArray get() = Base64.getDecoder().decode(saltB64)

    fun toJson(): JSONObject = JSONObject().apply {
        put("salt", saltB64)
        put("wrappedVek", wrappedVek)
        put("createdAt", createdAt)
    }

    companion object {
        fun fromJson(json: JSONObject) = RecoveryBlock(
            saltB64 = json.getString("salt"),
            wrappedVek = json.getString("wrappedVek"),
            createdAt = json.optLong("createdAt", 0L)
        )
    }
}
