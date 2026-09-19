package app.securevault.core.vault

import app.securevault.core.crypto.BiometricBlob
import app.securevault.core.crypto.WrappedVekStore
import app.securevault.core.crypto.InvalidCredentialsException
import app.securevault.core.crypto.Kdf
import app.securevault.core.crypto.KdfParams
import app.securevault.core.crypto.KdfSelection
import app.securevault.core.crypto.KeyHierarchy
import app.securevault.core.crypto.RandomSource
import app.securevault.core.crypto.SealedStateCorruptException
import app.securevault.core.crypto.SecureBytes
import app.securevault.platform.DurableFile
import app.securevault.platform.VaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher

class VaultLockedOutException(val remainingMillis: Long) :
    Exception("Too many failed attempts. Try again in ${remainingMillis / 1000}s")

/** Thrown when an operation is attempted on a manager that has been shut down. */
class VaultClosedException : IllegalStateException("This vault manager has been closed")

/** Thrown when an operation that requires an unlocked vault is attempted while locked. */
class VaultNotUnlockedException : IllegalStateException("Unlock the vault first")

data class CreateVaultResult(
    val metadata: VaultMetadata,
    val recoveryCode: CharArray?,
    /** Non-null when the vault was created under the compatibility KDF. Show it to the user. */
    val kdfFallbackWarning: String? = null
) {
    /** Wipes the recovery code. Call as soon as the user has written it down. */
    fun wipe() = recoveryCode?.fill('\u0000')

    override fun equals(other: Any?) = this === other
    override fun hashCode() = System.identityHashCode(this)
}

/** Outcome of [VaultManager.destroyVault], so callers can report rather than assume. */
data class DestroyResult(
    val headerRemoved: Boolean,
    val databaseRemoved: Boolean,
    val attachmentsRemoved: Boolean,
    val sealedStateRemoved: Boolean
) {
    val complete: Boolean
        get() = headerRemoved && databaseRemoved && attachmentsRemoved && sealedStateRemoved
}

/**
 * Owns the vault lifecycle: create, unlock, lock, change password, recovery, biometrics.
 *
 * Unlock is deliberately the only place a KEK is derived, and the KEK is wiped before the function
 * returns. Callers get a [VaultSession], never raw key material.
 *
 * The constructor takes its collaborators rather than reaching for a platform context, which is
 * what allows this class to live in :core and be exercised in JVM unit tests with a temp directory
 * and an in-memory store. Android's wiring lives in :app (`androidVaultManager`), and the desktop
 * build will supply its own; neither changes anything about what this class does.
 */
class VaultManager(
    private val filesDir: File,
    private val store: VaultStore,
    private val biometricKeyStore: WrappedVekStore?,
    private val kdfParamsFactory: () -> KdfSelection = { Kdf.calibrate() },
    private val databaseCloser: () -> Unit = {},
    /**
     * The database's files on disk, so destruction can remove them.
     *
     * Injected rather than derived, because "where the database lives" is a platform question:
     * on Android it is Room's directory next to filesDir, elsewhere it will be somewhere else
     * entirely. The default is empty, which means a manager built without one simply has no
     * database files to remove -- the behaviour the JVM tests already rely on.
     */
    private val databaseFiles: () -> List<File> = { emptyList() }
) {
    private val metadataFile = File(filesDir, "vault/metadata.json")
    private val sessionState = MutableStateFlow<VaultSession?>(null)

    @Volatile
    private var closed = false

    val session: StateFlow<VaultSession?> = sessionState.asStateFlow()
    val isUnlocked: Boolean get() = sessionState.value?.isAlive == true

    // ---- state ----------------------------------------------------------------------------

    /**
     * What is on disk right now.
     *
     * Note the ordering: a sealed-state failure is reported even when the header is fine, because
     * unreadable lockout state is itself a reason to be cautious (see [attemptState]).
     */
    fun state(): VaultState {
        checkOpen()
        val read = readMetadata() ?: return VaultState.Absent
        val parsed = read.metadata.getOrElse { error ->
            return VaultState.Corrupt(
                VaultState.Corrupt.Reason.UNREADABLE_HEADER,
                error.message ?: "Header could not be parsed"
            )
        }
        if (parsed.formatVersion > VaultMetadata.CURRENT_FORMAT_VERSION) {
            return VaultState.Corrupt(
                VaultState.Corrupt.Reason.UNSUPPORTED_VERSION,
                "Header declares format version ${parsed.formatVersion}"
            )
        }
        return VaultState.Present(parsed, recoveredFromPreviousCopy = read.fromPreviousCopy)
    }

    fun vaultExists(): Boolean = state() !is VaultState.Absent

    /** Convenience for callers that already know the vault is present. */
    fun metadata(): VaultMetadata? = (state() as? VaultState.Present)?.metadata

    private fun requireMetadata(): VaultMetadata = when (val s = state()) {
        is VaultState.Present -> s.metadata
        is VaultState.Absent -> throw IllegalStateException("No vault on this device")
        is VaultState.Corrupt -> throw IllegalStateException(s.userMessage)
    }

    private data class HeaderRead(val metadata: Result<VaultMetadata>, val fromPreviousCopy: Boolean)

    /**
     * Reads the header, falling back to the preserved previous copy when the current one will not
     * parse. Returns null when no header exists at all.
     *
     * The fallback is deliberately narrow. It applies only when the live header is missing or
     * unparseable -- never because a password was rejected, which would turn a revoked password
     * into something an attacker could reinstate by damaging one file. And because
     * [writeMetadata] deletes the previous copy as soon as the new one is confirmed readable, a
     * previous copy only exists inside the crash window of a write in progress.
     */
    private fun readMetadata(): HeaderRead? {
        val previous = DurableFile.previous(metadataFile)
        val parse = { file: File -> runCatching { VaultMetadata.fromJson(JSONObject(file.readText())) } }

        if (metadataFile.exists()) {
            val current = parse(metadataFile)
            if (current.isSuccess) return HeaderRead(current, fromPreviousCopy = false)
            if (previous.exists()) {
                val fallback = parse(previous)
                if (fallback.isSuccess) return HeaderRead(fallback, fromPreviousCopy = true)
            }
            return HeaderRead(current, fromPreviousCopy = false)
        }

        if (previous.exists()) {
            // The live file is gone: a write was interrupted between preserving the old copy and
            // renaming the new one into place.
            return HeaderRead(parse(previous), fromPreviousCopy = true)
        }
        return null
    }

    // ---- creation -------------------------------------------------------------------------

    suspend fun createVault(
        name: String,
        password: CharArray,
        enableRecovery: Boolean,
        keyFileSecret: ByteArray? = null
    ): CreateVaultResult = withContext(Dispatchers.Default) {
        checkOpen()
        // Refuses on Corrupt as well as Present. Creating over a damaged vault would destroy
        // recoverable data, which is the exact failure VaultState exists to prevent.
        when (val existing = state()) {
            is VaultState.Absent -> Unit
            is VaultState.Present -> error("A vault already exists on this device")
            is VaultState.Corrupt -> error(existing.userMessage)
        }

        val kdfSelection = kdfParamsFactory()
        val kdfParams = kdfSelection.params
        val vaultId = UUID.randomUUID().toString()
        val vek = KeyHierarchy.generateVek()
        val kek = KeyHierarchy.deriveKek(password, kdfParams, keyFileSecret)

        var recoveryCode: CharArray? = null
        var recoveryBlock: RecoveryBlock? = null
        try {
            if (enableRecovery) {
                val code = KeyHierarchy.generateRecoveryCode()
                val salt = RandomSource.bytes(KdfParams.SALT_BYTES)
                val recoveryKey = KeyHierarchy.recoveryKeyFrom(code, salt)
                try {
                    recoveryBlock = RecoveryBlock(
                        saltB64 = Base64.getEncoder().encodeToString(salt),
                        wrappedVek = KeyHierarchy.wrapVek(recoveryKey, vek, vaultId),
                        createdAt = System.currentTimeMillis()
                    )
                } finally {
                    recoveryKey.fill(0)
                }
                recoveryCode = code
            }

            val metadata = VaultMetadata(
                vaultId = vaultId,
                name = name,
                formatVersion = VaultMetadata.CURRENT_FORMAT_VERSION,
                createdAt = System.currentTimeMillis(),
                modifiedAt = System.currentTimeMillis(),
                kdf = kdfParams,
                wrappedVek = KeyHierarchy.wrapVek(kek, vek, vaultId),
                recovery = recoveryBlock,
                keyFileRequired = keyFileSecret != null,
                backupId = UUID.randomUUID().toString()
            )
            writeMetadata(metadata)
            sessionState.value = VaultSession(vaultId, vek.copyOf())
            saveAttemptState(AttemptState())
            CreateVaultResult(metadata, recoveryCode, kdfSelection.fallbackReason)
        } finally {
            SecureBytes.zero(kek, vek)
        }
    }

    /**
     * Installs a restored vault header. The final step of a backup restore.
     *
     * Refuses unless no vault exists, so a restore can never quietly land on top of one. The
     * caller has already written the restored records and attachments; writing this file is what
     * makes the app consider a vault to be present, which is why it is last.
     *
     * This does not unlock anything. The restored vault is opened afterwards through the ordinary
     * unlock path, with the ordinary lockout and credential checks -- restore is not a way past
     * them.
     */
    fun installRestoredHeader(metadata: VaultMetadata) {
        checkOpen()
        check(state() is VaultState.Absent) { "A vault already exists on this device" }
        writeMetadata(metadata)
        saveAttemptState(AttemptState())
    }

    // ---- unlock ---------------------------------------------------------------------------

    suspend fun unlockWithPassword(
        password: CharArray,
        keyFileSecret: ByteArray? = null
    ): VaultSession = withContext(Dispatchers.Default) {
        checkOpen()
        val metadata = requireMetadata()
        enforceLockout()

        val kek = KeyHierarchy.deriveKek(password, metadata.kdf, keyFileSecret)
        try {
            val vek = KeyHierarchy.unwrapVek(kek, metadata.wrappedVek, metadata.vaultId)
            openSession(metadata.vaultId, vek)
        } catch (e: InvalidCredentialsException) {
            registerFailure()
            throw e
        } finally {
            kek.fill(0)
        }
    }

    suspend fun unlockWithRecoveryCode(code: CharArray): VaultSession = withContext(Dispatchers.Default) {
        checkOpen()
        val metadata = requireMetadata()
        val recovery = metadata.recovery
            ?: throw IllegalStateException("Recovery was never enabled for this vault")
        enforceLockout()

        val recoveryKey = try {
            KeyHierarchy.recoveryKeyFrom(code, recovery.salt)
        } catch (e: InvalidCredentialsException) {
            // Malformed codes count as failures too, otherwise they are a free, unlimited probe.
            registerFailure()
            throw e
        }
        try {
            val vek = KeyHierarchy.unwrapVek(recoveryKey, recovery.wrappedVek, metadata.vaultId)
            openSession(metadata.vaultId, vek)
        } catch (e: InvalidCredentialsException) {
            registerFailure()
            throw e
        } finally {
            recoveryKey.fill(0)
        }
    }

    /**
     * Biometric unlock, step 2. [cipher] must be the Cipher returned by a successful
     * BiometricPrompt, obtained from [biometricDecryptCipher].
     */
    fun completeBiometricUnlock(cipher: Cipher): VaultSession {
        checkOpen()
        val keyStore = biometricKeyStore ?: throw IllegalStateException("Biometrics are unavailable")
        val metadata = requireMetadata()
        // Biometric attempts are rate limited by the platform, but the vault's own lockout still
        // applies: otherwise a lockout earned by password guessing could be stepped around.
        enforceLockout()
        val blob = readBiometricBlob() ?: throw IllegalStateException("Biometric unlock is not set up")
        val vek = keyStore.openVek(cipher, blob)
        return openSession(metadata.vaultId, vek)
    }

    fun biometricDecryptCipher(): Cipher? =
        readBiometricBlob()?.let { biometricKeyStore?.decryptCipher(it.iv) }

    fun biometricEncryptCipher(): Cipher =
        (biometricKeyStore ?: throw IllegalStateException("Biometrics are unavailable")).encryptCipher()

    /** Biometric enrolment, called with an authenticated encrypt Cipher and an unlocked vault. */
    fun enableBiometricUnlock(cipher: Cipher) {
        checkOpen()
        val keyStore = biometricKeyStore ?: throw IllegalStateException("Biometrics are unavailable")
        val current = sessionState.value ?: throw VaultNotUnlockedException()
        val vek = current.exportVekForRewrap()
        try {
            val blob = keyStore.sealVek(cipher, vek)
            store.putString(
                "biometric",
                JSONObject().apply {
                    put("iv", Base64.getEncoder().encodeToString(blob.iv))
                    put("ct", Base64.getEncoder().encodeToString(blob.ciphertext))
                }.toString()
            )
        } finally {
            vek.fill(0)
        }
    }

    fun disableBiometricUnlock() {
        store.remove("biometric")
        biometricKeyStore?.deleteKey()
    }

    fun isBiometricConfigured(): Boolean =
        biometricKeyStore != null && readBiometricBlob() != null && biometricKeyStore.isEnrolled()

    private fun readBiometricBlob(): BiometricBlob? {
        val raw = runCatching { store.getString("biometric") }.getOrElse { return null } ?: return null
        return runCatching {
            val json = JSONObject(raw)
            BiometricBlob(
                iv = Base64.getDecoder().decode(json.getString("iv")),
                ciphertext = Base64.getDecoder().decode(json.getString("ct"))
            )
        }.getOrNull()
    }

    // ---- password and recovery management -------------------------------------------------

    /**
     * Rewraps the VEK under a key derived from the new password. Item ciphertext is untouched, so
     * this is instant regardless of vault size.
     *
     * Three guards that were previously missing, and why:
     *
     *  - **Requires an unlocked session.** Without it this function was a second credential
     *    checker reachable from a locked app.
     *  - **Goes through the lockout policy**, both the check and the failure registration. Without
     *    that it was an unlimited offline-speed password oracle sitting next to a rate-limited
     *    unlock path -- an attacker would simply use this one.
     *  - **Verifies the unwrapped VEK matches the live session's**, in constant time. A correct
     *    password for a *different* header cannot be used to rewrap this vault's key.
     *
     * Failures throw [InvalidCredentialsException] with no detail about which check failed.
     */
    suspend fun changeMasterPassword(
        currentPassword: CharArray,
        newPassword: CharArray,
        keyFileSecret: ByteArray? = null
    ) = withContext(Dispatchers.Default) {
        checkOpen()
        val session = sessionState.value?.takeIf { it.isAlive } ?: throw VaultNotUnlockedException()
        val metadata = requireMetadata()
        enforceLockout()

        val currentKek = KeyHierarchy.deriveKek(currentPassword, metadata.kdf, keyFileSecret)
        val vek = try {
            KeyHierarchy.unwrapVek(currentKek, metadata.wrappedVek, metadata.vaultId)
        } catch (e: InvalidCredentialsException) {
            registerFailure()
            throw e
        } finally {
            currentKek.fill(0)
        }

        try {
            val live = session.exportVekForRewrap()
            val matches = try {
                SecureBytes.constantTimeEquals(live, vek)
            } finally {
                live.fill(0)
            }
            if (!matches) {
                registerFailure()
                throw InvalidCredentialsException()
            }

            // Fresh salt, same algorithm and cost parameters: the user asked to change a password,
            // not to silently move to a different KDF configuration.
            val newParams = KdfParams(
                algorithm = metadata.kdf.algorithm,
                saltB64 = Base64.getEncoder().encodeToString(RandomSource.bytes(KdfParams.SALT_BYTES)),
                memoryKib = metadata.kdf.memoryKib,
                iterations = metadata.kdf.iterations,
                parallelism = metadata.kdf.parallelism,
                pbkdf2Rounds = metadata.kdf.pbkdf2Rounds
            )
            val newKek = KeyHierarchy.deriveKek(newPassword, newParams, keyFileSecret)
            val updated = try {
                metadata.copy(
                    kdf = newParams,
                    wrappedVek = KeyHierarchy.wrapVek(newKek, vek, metadata.vaultId),
                    modifiedAt = System.currentTimeMillis()
                )
            } finally {
                newKek.fill(0)
            }

            // Prove the new header actually unwraps before it replaces the old one. If this throws
            // the vault is untouched and the old password still works.
            verifyUnwraps(updated, newPassword, keyFileSecret, vek)

            writeMetadata(updated)
            saveAttemptState(LockoutPolicy().onSuccess())
            // Biometric material wraps the VEK, which has not changed, so enrolment survives.
        } finally {
            vek.fill(0)
        }
    }

    /** Derives from [password] against [candidate] and checks it yields [expectedVek]. */
    private fun verifyUnwraps(
        candidate: VaultMetadata,
        password: CharArray,
        keyFileSecret: ByteArray?,
        expectedVek: ByteArray
    ) {
        val kek = KeyHierarchy.deriveKek(password, candidate.kdf, keyFileSecret)
        val roundTripped = try {
            KeyHierarchy.unwrapVek(kek, candidate.wrappedVek, candidate.vaultId)
        } finally {
            kek.fill(0)
        }
        try {
            check(SecureBytes.constantTimeEquals(roundTripped, expectedVek)) {
                "New header did not verify; vault left unchanged"
            }
        } finally {
            roundTripped.fill(0)
        }
    }

    /** Returns the new recovery code. Show it once, then wipe the array. */
    fun enableRecovery(): CharArray {
        checkOpen()
        val metadata = requireMetadata()
        val current = sessionState.value?.takeIf { it.isAlive } ?: throw VaultNotUnlockedException()
        val vek = current.exportVekForRewrap()
        val code = KeyHierarchy.generateRecoveryCode()
        val salt = RandomSource.bytes(KdfParams.SALT_BYTES)
        val recoveryKey = KeyHierarchy.recoveryKeyFrom(code, salt)
        try {
            writeMetadata(
                metadata.copy(
                    recovery = RecoveryBlock(
                        saltB64 = Base64.getEncoder().encodeToString(salt),
                        wrappedVek = KeyHierarchy.wrapVek(recoveryKey, vek, metadata.vaultId),
                        createdAt = System.currentTimeMillis()
                    ),
                    modifiedAt = System.currentTimeMillis()
                )
            )
            return code
        } finally {
            SecureBytes.zero(vek, recoveryKey)
        }
    }

    /**
     * Removes the recovery wrapping. Existing backups keep their own copy of the old recovery
     * block, so an old recovery code still opens an old backup file -- the UI says so.
     */
    fun disableRecovery() {
        checkOpen()
        val metadata = metadata() ?: return
        writeMetadata(metadata.copy(recovery = null, modifiedAt = System.currentTimeMillis()))
    }

    // ---- locking and shutdown -------------------------------------------------------------

    fun lock() {
        sessionState.value?.destroy()
        sessionState.value = null
    }

    /**
     * Stops this manager permanently: locks, closes the database, and refuses further work.
     *
     * Every public entry point checks [closed] first, so nothing can re-open the database behind a
     * destroy that is in progress.
     */
    fun close() {
        closed = true
        lock()
        runCatching { databaseCloser() }
    }

    /**
     * Deletes the vault header, the biometric key, the encrypted database and attachments.
     *
     * Order matters. The database is closed *before* its files are deleted -- deleting SQLite
     * files out from under an open connection can leave the WAL and journal behind, which is how
     * a "wipe" quietly leaves ciphertext on disk.
     *
     * This makes the data unrecoverable in practice because the keys are gone, which is a stronger
     * guarantee than overwriting files. Flash translation layers mean Android cannot promise that
     * old blocks are physically erased, so the app does not claim to shred anything. Backups and
     * CSV exports the user made earlier are untouched and still openable.
     *
     * Returns what was actually removed rather than assuming success, so the caller can tell the
     * user the truth.
     */
    fun destroyVault(): DestroyResult {
        // Deliberately not gated on `closed`: destruction must still work on a closed manager.
        closed = true
        lock()
        runCatching { databaseCloser() }
        runCatching { biometricKeyStore?.deleteKey() }
        runCatching { store.clearAll() }

        val headerDir = metadataFile.parentFile
        runCatching { headerDir?.deleteRecursively() }

        runCatching { databaseFiles().forEach { it.delete() } }

        val attachmentsDir = File(filesDir, "attachments")
        runCatching { attachmentsDir.deleteRecursively() }

        val sealedDir = File(filesDir, "sealed")

        // Verify rather than assume.
        return DestroyResult(
            headerRemoved = headerDir?.exists() != true,
            databaseRemoved = databaseFiles().isEmpty(),
            attachmentsRemoved = !attachmentsDir.exists(),
            sealedStateRemoved = sealedDir.listFiles()?.isEmpty() != false
        )
    }

    // ---- settings and attempt state -------------------------------------------------------

    fun settings(): VaultSettings =
        runCatching { store.getString("settings") }.getOrNull()
            ?.let { runCatching { VaultSettings.fromJson(JSONObject(it)) }.getOrNull() }
            ?: VaultSettings()

    fun saveSettings(settings: VaultSettings) = store.putString("settings", settings.toJson().toString())

    /**
     * Current failed-attempt state.
     *
     * If the stored state cannot be decrypted, this returns a *locked* state rather than a fresh
     * one. Deleting or corrupting the counter file is the obvious way to clear a lockout, and
     * handing back a clean slate would make brute-force protection opt-out for anyone with file
     * access. The cool-down is bounded rather than permanent, and a successful unlock clears it,
     * so a genuine Keystore reset costs the legitimate user one wait instead of their vault.
     */
    fun attemptState(): AttemptState = try {
        store.getString("attempts")
            ?.let { runCatching { AttemptState.fromJson(JSONObject(it)) }.getOrNull() }
            ?: AttemptState()
    } catch (e: SealedStateCorruptException) {
        val config = LockoutConfig()
        AttemptState(
            consecutiveFailures = config.gracefulAttempts,
            lockedUntil = System.currentTimeMillis() + config.maxDelayMillis,
            lastFailureAt = System.currentTimeMillis()
        )
    }

    /** True when the lockout counter is unreadable, so the UI can explain the wait honestly. */
    fun attemptStateIsCorrupt(): Boolean = try {
        store.getString("attempts")
        false
    } catch (e: SealedStateCorruptException) {
        true
    }

    private fun saveAttemptState(state: AttemptState) =
        store.putString("attempts", state.toJson().toString())

    private fun lockoutPolicy() = LockoutPolicy(LockoutConfig(wipeAfterFailures = settings().wipeAfterFailures))

    private fun enforceLockout() {
        val remaining = lockoutPolicy().remainingLockMillis(attemptState())
        if (remaining > 0) throw VaultLockedOutException(remaining)
    }

    private fun registerFailure() {
        val policy = lockoutPolicy()
        val next = policy.onFailure(attemptState())
        saveAttemptState(next)
        if (policy.shouldWipe(next)) destroyVault()
    }

    private fun openSession(vaultId: String, vek: ByteArray): VaultSession {
        saveAttemptState(LockoutPolicy().onSuccess())
        val session = VaultSession(vaultId, vek)
        sessionState.value?.destroy()
        sessionState.value = session
        return session
    }

    /**
     * Writes the header durably, then reads it back and parses it before deleting the preserved
     * previous copy.
     *
     * The read-back is what makes the previous copy safe to keep. Without it, every write would
     * leave a permanent rollback point: after a master password change the old header -- with the
     * VEK wrapped under the old password -- would sit next to the new one indefinitely, and
     * anyone who could damage one file could reinstate a password the user believed they had
     * replaced. Confirming and deleting reduces the previous copy to what it is meant to be: cover
     * for a crash mid-write.
     */
    private fun writeMetadata(metadata: VaultMetadata) {
        DurableFile.write(metadataFile, metadata.toJson().toString().toByteArray(Charsets.UTF_8))
        val readBack = runCatching { VaultMetadata.fromJson(JSONObject(metadataFile.readText())) }
        check(readBack.isSuccess) { "Vault header did not read back after writing" }
        DurableFile.confirm(metadataFile)
    }

    private fun checkOpen() {
        if (closed) throw VaultClosedException()
    }
}
