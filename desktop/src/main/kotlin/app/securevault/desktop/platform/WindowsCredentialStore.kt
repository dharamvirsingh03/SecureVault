package app.securevault.desktop.platform

import java.io.File
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Windows convenience unlock, backed by DPAPI.
 *
 * Reached through PowerShell's `System.Security.Cryptography.ProtectedData`, which is the DPAPI
 * user store. That is a real OS mechanism -- the key is derived from the user's Windows logon
 * credentials and held by the OS, not by SecureVault -- and it mirrors exactly what the Linux side
 * does with `secret-tool`: shell out to the platform's own facility rather than embed a large
 * native interop layer in a password manager.
 *
 * **What is stored:** the wrapped vault key, DPAPI-protected, in a file under `%LOCALAPPDATA%`.
 * Never the master password. Never the raw vault key. Never vault contents.
 *
 * **What DPAPI actually gives you, stated accurately:**
 *
 *  - It is scoped to the Windows *user account*. Anything running as that user, after that user
 *    has logged in, can ask DPAPI to unprotect this blob. It defends against another account on
 *    the machine and against someone reading the file off a stolen disk without the account's
 *    credentials. It does not defend against malware running as you.
 *  - It is **software protection, not hardware.** There is no TPM sealing here, no equivalent of
 *    Android StrongBox or of a key that cannot be exported. Describing it as hardware-backed would
 *    be wrong, and the UI does not.
 *  - Changing the Windows password through an administrator reset (rather than a normal change)
 *    can invalidate DPAPI data. If that happens the convenience credential is lost and the master
 *    password is the way back in -- which is the correct outcome, and why the portable vault never
 *    depends on it.
 *
 * **Windows Hello is deliberately not used.** Gating this blob behind Hello would require
 * `KeyCredentialManager`, which needs WinRT interop this stack does not have. A Hello prompt that
 * merely guards the UI while the key remains DPAPI-readable would be exactly the fake biometric
 * unlock this project refuses. Master password remains authoritative; see DESKTOP.md.
 */
class WindowsCredentialStore : SecureStorage {

    override val displayName = "Windows DPAPI"

    override val protectionSummary =
        "Protected by DPAPI under your Windows account. Software protection, not hardware: it is " +
            "not backed by a TPM and is not equivalent to Android's StrongBox. Anything running " +
            "as you, after you have signed in, can unprotect it."

    private val store: File get() = File(Paths.secured(File(Paths.dataDir, "credentials")), "wrapped.dpapi")

    override fun availability(): SecureStorage.Availability {
        if (!Platform.isWindows) {
            return SecureStorage.Availability.Unavailable("Not running on Windows.")
        }
        val probe = runCatching {
            powershell("[System.Security.Cryptography.ProtectedData] | Out-Null; 'ok'")
        }.getOrNull()
        return when {
            probe == null ->
                SecureStorage.Availability.Unavailable(
                    "PowerShell could not be started, so DPAPI is not reachable."
                )
            probe.exitCode != 0 || !probe.output.contains("ok") ->
                SecureStorage.Availability.Unavailable(
                    "DPAPI did not respond. Convenience unlock is unavailable this session."
                )
            else -> SecureStorage.Availability.Available
        }
    }

    override fun store(key: String, value: String): Boolean = runCatching {
        val encoded = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
        // CurrentUser scope, with no extra entropy: the protection is the user account itself.
        val script = """
            ${'$'}bytes = [Convert]::FromBase64String('$encoded')
            ${'$'}p = [System.Security.Cryptography.ProtectedData]::Protect(
                ${'$'}bytes, ${'$'}null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            [Convert]::ToBase64String(${'$'}p)
        """.trimIndent()
        val result = powershell(script)
        if (result.exitCode != 0 || result.output.isBlank()) return false
        val target = store
        target.writeText(result.output.trim(), Charsets.US_ASCII)
        Paths.restrict(target)
        true
    }.getOrDefault(false)

    override fun lookup(key: String): String? = runCatching {
        val target = store
        if (!target.exists()) return ""
        val protectedB64 = target.readText(Charsets.US_ASCII).trim()
        if (protectedB64.isEmpty()) return ""
        val script = """
            ${'$'}bytes = [Convert]::FromBase64String('$protectedB64')
            ${'$'}u = [System.Security.Cryptography.ProtectedData]::Unprotect(
                ${'$'}bytes, ${'$'}null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            [System.Text.Encoding]::UTF8.GetString(${'$'}u)
        """.trimIndent()
        val result = powershell(script)
        // A non-zero exit means DPAPI refused -- most often because the Windows credentials that
        // derived the key have changed. That is "could not be reached", not "absent": the caller
        // must not treat it as a clean slate.
        if (result.exitCode != 0) null else result.output.trim()
    }.getOrNull()

    override fun clear(key: String): Boolean = runCatching { store.delete() }.getOrDefault(false)

    private data class Result(val exitCode: Int, val output: String)

    private fun powershell(script: String): Result {
        val process = ProcessBuilder(
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", script
        ).redirectErrorStream(false).start()
        runCatching { process.outputStream.close() }
        val output = process.inputStream.bufferedReader().use { it.readText() }
        if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return Result(-1, "")
        }
        return Result(process.exitValue(), output)
    }

    private companion object {
        const val TIMEOUT_SECONDS = 20L
    }
}
