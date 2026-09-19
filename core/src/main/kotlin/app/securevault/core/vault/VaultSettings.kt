package app.securevault.core.vault

import org.json.JSONObject

enum class AppTheme { SYSTEM, LIGHT, DARK }

/**
 * User-controlled security and behaviour settings.
 *
 * Defaults are chosen so that a user who never opens Settings still gets a safe configuration:
 * locking on background, a short clipboard lifetime, screenshot protection on, no telemetry, no
 * network calls, no automatic OTP copying, no destructive wipe.
 */
data class VaultSettings(
    val autoLockMillis: Long = 60_000L,
    val lockOnBackground: Boolean = true,
    val lockOnScreenOff: Boolean = true,
    val lockOnDeviceLock: Boolean = true,
    val biometricUnlockEnabled: Boolean = false,
    val secondFactorTotpEnabled: Boolean = false,
    val keyFileRequired: Boolean = false,
    val clipboardClearSeconds: Int = 30,
    val screenshotProtection: Boolean = true,
    val autoCopyOtpOnOpen: Boolean = false,
    val breachCheckEnabled: Boolean = false,
    val analyticsEnabled: Boolean = false,
    val crashReportingEnabled: Boolean = false,
    val wipeAfterFailures: Int = 0,
    val passwordAgeReminderDays: Int = 365,
    val weakPasswordThreshold: Int = 60,
    val theme: AppTheme = AppTheme.SYSTEM,
    val defaultPasswordLength: Int = 20,
    val defaultPassphraseWords: Int = 4,
    val defaultPassphraseSeparator: String = "-"
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("autoLockMillis", autoLockMillis)
        put("lockOnBackground", lockOnBackground)
        put("lockOnScreenOff", lockOnScreenOff)
        put("lockOnDeviceLock", lockOnDeviceLock)
        put("biometricUnlockEnabled", biometricUnlockEnabled)
        put("secondFactorTotpEnabled", secondFactorTotpEnabled)
        put("keyFileRequired", keyFileRequired)
        put("clipboardClearSeconds", clipboardClearSeconds)
        put("screenshotProtection", screenshotProtection)
        put("autoCopyOtpOnOpen", autoCopyOtpOnOpen)
        put("breachCheckEnabled", breachCheckEnabled)
        put("analyticsEnabled", analyticsEnabled)
        put("crashReportingEnabled", crashReportingEnabled)
        put("wipeAfterFailures", wipeAfterFailures)
        put("passwordAgeReminderDays", passwordAgeReminderDays)
        put("weakPasswordThreshold", weakPasswordThreshold)
        put("theme", theme.name)
        put("defaultPasswordLength", defaultPasswordLength)
        put("defaultPassphraseWords", defaultPassphraseWords)
        put("defaultPassphraseSeparator", defaultPassphraseSeparator)
    }

    companion object {
        val AUTO_LOCK_CHOICES = linkedMapOf(
            "Immediately" to 0L,
            "30 seconds" to 30_000L,
            "1 minute" to 60_000L,
            "5 minutes" to 300_000L,
            "10 minutes" to 600_000L,
            "30 minutes" to 1_800_000L,
            "Never" to Long.MAX_VALUE
        )

        fun fromJson(json: JSONObject): VaultSettings {
            val d = VaultSettings()
            return VaultSettings(
                autoLockMillis = json.optLong("autoLockMillis", d.autoLockMillis),
                lockOnBackground = json.optBoolean("lockOnBackground", d.lockOnBackground),
                lockOnScreenOff = json.optBoolean("lockOnScreenOff", d.lockOnScreenOff),
                lockOnDeviceLock = json.optBoolean("lockOnDeviceLock", d.lockOnDeviceLock),
                biometricUnlockEnabled = json.optBoolean("biometricUnlockEnabled", d.biometricUnlockEnabled),
                secondFactorTotpEnabled = json.optBoolean("secondFactorTotpEnabled", d.secondFactorTotpEnabled),
                keyFileRequired = json.optBoolean("keyFileRequired", d.keyFileRequired),
                clipboardClearSeconds = json.optInt("clipboardClearSeconds", d.clipboardClearSeconds),
                screenshotProtection = json.optBoolean("screenshotProtection", d.screenshotProtection),
                autoCopyOtpOnOpen = json.optBoolean("autoCopyOtpOnOpen", d.autoCopyOtpOnOpen),
                breachCheckEnabled = json.optBoolean("breachCheckEnabled", d.breachCheckEnabled),
                analyticsEnabled = json.optBoolean("analyticsEnabled", d.analyticsEnabled),
                crashReportingEnabled = json.optBoolean("crashReportingEnabled", d.crashReportingEnabled),
                wipeAfterFailures = json.optInt("wipeAfterFailures", d.wipeAfterFailures),
                passwordAgeReminderDays = json.optInt("passwordAgeReminderDays", d.passwordAgeReminderDays),
                weakPasswordThreshold = json.optInt("weakPasswordThreshold", d.weakPasswordThreshold),
                theme = AppTheme.valueOf(json.optString("theme", d.theme.name)),
                defaultPasswordLength = json.optInt("defaultPasswordLength", d.defaultPasswordLength),
                defaultPassphraseWords = json.optInt("defaultPassphraseWords", d.defaultPassphraseWords),
                defaultPassphraseSeparator = json.optString("defaultPassphraseSeparator", d.defaultPassphraseSeparator)
            )
        }
    }
}
