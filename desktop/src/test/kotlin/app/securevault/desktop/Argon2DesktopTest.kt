package app.securevault.desktop

import app.securevault.core.crypto.Argon2Backend
import app.securevault.core.crypto.Argon2BackendContract
import app.securevault.desktop.platform.BouncyCastleArgon2Backend

/**
 * The desktop Argon2 implementation, held against the same vectors Android's will be.
 *
 * Neither backend is ever compared with the other. Two implementations agreeing proves nothing if
 * both are wrong in the same way; the expected values must come from the reference implementation.
 * See `Argon2Vectors` for the exact commands, and note that they are still unpopulated -- these
 * tests skip until someone runs them.
 */
class Argon2DesktopTest : Argon2BackendContract() {
    override fun backend(): Argon2Backend = BouncyCastleArgon2Backend()
}
