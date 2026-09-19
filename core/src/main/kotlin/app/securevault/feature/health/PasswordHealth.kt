package app.securevault.feature.health

import app.securevault.core.model.ItemType
import app.securevault.core.model.VaultItem
import app.securevault.feature.generator.PasswordStrength
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class HealthIssue(val item: VaultItem, val detail: String)

data class HealthReport(
    val totalWithPasswords: Int,
    val weak: List<HealthIssue>,
    val reused: List<HealthIssue>,
    val old: List<HealthIssue>,
    val missingTwoFactor: List<HealthIssue>,
    val breached: List<HealthIssue>,
    val breachCheckRan: Boolean
) {
    /** A single percentage for the dashboard. Breached and weak count hardest. */
    val score: Int
        get() {
            if (totalWithPasswords == 0) return 100
            val penalty = (weak.size * 3 + reused.size * 2 + old.size + missingTwoFactor.size + breached.size * 4)
            val worst = totalWithPasswords * 4.0
            return (100 - (penalty / worst * 100)).coerceIn(0.0, 100.0).toInt()
        }

    val label: String
        get() = when (score) {
            in 90..100 -> "Strong"
            in 70..89 -> "Good"
            in 50..69 -> "Needs attention"
            else -> "At risk"
        }
}

/**
 * Local analysis of vault health. Runs only on the decrypted in-memory items, produces no files,
 * and makes no network calls -- breach results are passed in by the caller when the user has
 * switched that feature on.
 *
 * Reuse detection compares SHA-256 digests of the passwords rather than the passwords themselves,
 * so the grouping structure never holds plaintext longer than it must.
 */
class PasswordHealthAnalyzer(
    private val weakScoreThreshold: Int = 60,
    private val oldPasswordDays: Int = 365
) {
    fun analyse(
        items: List<VaultItem>,
        breachedItemIds: Set<String> = emptySet(),
        breachCheckRan: Boolean = false
    ): HealthReport {
        val withPasswords = items.filter { it.password.isNotEmpty() }

        val weak = withPasswords.mapNotNull { item ->
            val result = PasswordStrength.evaluate(item.password)
            if (result.score < weakScoreThreshold) {
                HealthIssue(item, "${result.label.name.lowercase().replace('_', ' ')} - ${result.entropyBits.toInt()} bits")
            } else null
        }

        val byDigest = withPasswords.groupBy { sha256(it.password) }
        val reused = byDigest.filterValues { it.size > 1 }.values.flatten().map { item ->
            HealthIssue(item, "Used on ${byDigest[sha256(item.password)]!!.size} accounts")
        }

        val ageCutoff = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(oldPasswordDays.toLong())
        val old = withPasswords.mapNotNull { item ->
            val changed = item.payload.passwordChangedAt ?: item.createdAt
            if (changed < ageCutoff) {
                val days = TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - changed)
                HealthIssue(item, "Last changed $days days ago")
            } else null
        }

        val missingTwoFactor = items.filter { item ->
            item.type == ItemType.LOGIN && item.payload.totp == null && item.payload.requiresTwoFactor
        }.map { HealthIssue(it, "Marked as supporting 2FA but no code is stored") }

        val breached = items.filter { it.id in breachedItemIds }
            .map { HealthIssue(it, "Found in a public breach corpus") }

        return HealthReport(
            totalWithPasswords = withPasswords.size,
            weak = weak,
            reused = reused,
            old = old,
            missingTwoFactor = missingTwoFactor,
            breached = breached,
            breachCheckRan = breachCheckRan
        )
    }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
}
