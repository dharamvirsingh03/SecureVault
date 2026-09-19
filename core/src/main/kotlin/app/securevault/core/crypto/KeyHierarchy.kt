package app.securevault.core.crypto

import java.util.Base64

/**
 * The key hierarchy.
 *
 *   master password (+ optional key file)
 *        | Argon2id (per-vault random salt)
 *        v
 *   key encryption key (KEK)          -- never stored, lives only during unlock
 *        | AES-256-GCM unwrap
 *        v
 *   vault encryption key (VEK)        -- random, stored only in wrapped form
 *        | HKDF-SHA256 domain separation
 *        v
 *   item key / attachment key / backup key / database key
 *
 * Two consequences worth stating plainly:
 *
 *  - Changing the master password rewraps the VEK. Items are never re-encrypted, so the change is
 *    instant even on a large vault.
 *  - There is no stored password hash. The GCM tag on the wrapped VEK is the verifier: a wrong
 *    password produces a tag mismatch and nothing else. An attacker gets no offline oracle beyond
 *    what the Argon2id work factor already costs them.
 */
object KeyHierarchy {

    private const val WRAP_AAD_PREFIX = "securevault:wrap:v1:"
    const val RECOVERY_CODE_BYTES = 20      // 160 bits -> 32 base32 characters

    fun generateVek(): ByteArray = RandomSource.bytes(Aead.KEY_BYTES)

    /**
     * Derives the KEK. When [keyFileSecret] is present it is mixed in after the KDF, so an
     * attacker who guesses the password still cannot unwrap the VEK without the key file.
     */
    fun deriveKek(password: CharArray, params: KdfParams, keyFileSecret: ByteArray? = null): ByteArray {
        val derived = Kdf.deriveKey(password, params)
        if (keyFileSecret == null) return derived
        return try {
            Hkdf.derive(
                ikm = SecureBytes.concat(derived, keyFileSecret),
                salt = params.salt,
                info = "securevault:v1:kek-with-keyfile"
            )
        } finally {
            derived.fill(0)
        }
    }

    fun wrapVek(kek: ByteArray, vek: ByteArray, vaultId: String): String =
        Base64.getEncoder().encodeToString(Aead.seal(kek, vek, wrapAad(vaultId)))

    /** @throws InvalidCredentialsException when the KEK is wrong or the blob was tampered with. */
    fun unwrapVek(kek: ByteArray, wrappedB64: String, vaultId: String): ByteArray = try {
        Aead.open(kek, Base64.getDecoder().decode(wrappedB64), wrapAad(vaultId))
    } catch (e: VaultIntegrityException) {
        throw InvalidCredentialsException("Wrong password, key file, or the vault header was modified")
    }

    fun subkey(vek: ByteArray, domain: String, context: String = ""): ByteArray =
        Hkdf.derive(ikm = vek, salt = null, info = if (context.isEmpty()) domain else "$domain:$context")

    // ---- recovery code -------------------------------------------------------------------

    /**
     * 160 bits of entropy, grouped for transcription: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
     *
     * Returns a CharArray, not a String, so the caller can wipe it. A String would be immutable
     * and unwipeable, and this value is an alternative to the master password -- see the note on
     * [recoveryKeyFrom] about what that means.
     */
    fun generateRecoveryCode(): CharArray {
        val raw = RandomSource.bytes(RECOVERY_CODE_BYTES)
        return try {
            group(Base32.encodeToChars(raw))
        } finally {
            raw.fill(0)
        }
    }

    /** Inserts a '-' every 4 characters, without building an intermediate String. */
    private fun group(chars: CharArray, size: Int = 4, separator: Char = '-'): CharArray {
        if (chars.isEmpty()) return chars
        val groups = (chars.size + size - 1) / size
        val out = CharArray(chars.size + groups - 1)
        var read = 0
        var write = 0
        while (read < chars.size) {
            if (read > 0 && read % size == 0) out[write++] = separator
            out[write++] = chars[read++]
        }
        chars.fill('\u0000')
        return out
    }

    /**
     * The recovery code is already high-entropy, so HKDF is enough -- there is nothing for a
     * password-cracking KDF to protect against here.
     *
     * @throws InvalidCredentialsException if the code is not valid base32. Callers treat that the
     * same as a wrong code, so a malformed entry cannot be told apart from an incorrect one.
     */
    fun recoveryKeyFrom(code: CharArray, salt: ByteArray): ByteArray {
        val raw = try {
            Base32.decodeChars(code)
        } catch (e: IllegalArgumentException) {
            throw InvalidCredentialsException()
        }
        return try {
            Hkdf.derive(ikm = raw, salt = salt, info = "securevault:v1:recovery")
        } finally {
            raw.fill(0)
        }
    }

    private fun wrapAad(vaultId: String) = (WRAP_AAD_PREFIX + vaultId).toByteArray(Charsets.UTF_8)
}

/** RFC 4648 base32 without padding. Used for recovery codes and TOTP secrets. */
object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer shr (bits - 5)) and 0x1F])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return sb.toString()
    }

    fun decode(encoded: String): ByteArray = decodeChars(encoded.toCharArray())

    /**
     * Decodes without the caller having to hold the encoded form as an immutable String. Ignores
     * padding, spaces and grouping dashes, and is case-insensitive, so a user retyping a recovery
     * code off paper does not have to be exact about formatting.
     */
    fun decodeChars(encoded: CharArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0
        var bits = 0
        for (raw in encoded) {
            if (raw == '=' || raw == ' ' || raw == '-' || raw == '\n' || raw == '\r' || raw == '\t') continue
            val c = raw.uppercaseChar()
            val value = ALPHABET.indexOf(c)
            require(value >= 0) { "Invalid base32 character" }
            buffer = (buffer shl 5) or value
            bits += 5
            if (bits >= 8) {
                out.write((buffer shr (bits - 8)) and 0xFF)
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    /** Encodes into a wipeable CharArray rather than an immutable String. */
    fun encodeToChars(data: ByteArray): CharArray {
        val out = CharArray((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        var index = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                out[index++] = ALPHABET[(buffer shr (bits - 5)) and 0x1F]
                bits -= 5
            }
        }
        if (bits > 0) out[index++] = ALPHABET[(buffer shl (5 - bits)) and 0x1F]
        return out
    }
}
