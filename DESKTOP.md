# SecureVault for Ubuntu

The desktop edition of the same product, sharing the same `:core` vault engine and the same
portable `.securevault` format as the Android build.

## Verification status — read this first

**Nothing in this document has been compiled, run, packaged or installed.** The development
environment has no Gradle, no Android SDK, no JDK toolchain for building and no access to Maven
Central or Google Maven, so no command below has been executed. Every dependency version in the
desktop module is marked UNCONFIRMED in `gradle/libs.versions.toml`.

Read "implemented" as "written and reviewed". Nothing here carries "tested".

## Build

```bash
# Android must stay green first
./gradlew :core:test
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug

# Desktop
./gradlew :desktop:test
./gradlew :desktop:run                    # run it from the source tree
./gradlew :desktop:packageDeb             # build the installer
```

The `.deb` lands in `desktop/build/compose/binaries/main/deb/`. jpackage names it
`securevault_1.0.0-1_amd64.deb`; rename it if you want the exact `SecureVault_1.0.0_amd64.deb`
string.

Build host needs JDK 17+ with `jpackage`, plus `fakeroot` and `binutils`.

## Install

```bash
sudo apt install ./securevault_1.0.0-1_amd64.deb
```

Then **Applications → SecureVault**, or `/opt/securevault/bin/SecureVault` from a terminal.

```bash
sudo apt remove securevault     # leaves your vault data alone
```

Removal deliberately does not touch `~/.local/share/securevault`. A package manager should not
delete the only copy of somebody's passwords, and a reinstall should find the vault where it left
it. Delete it yourself if that is what you want.

## Where things live

| | Path |
|---|---|
| Application | `/opt/securevault` |
| Vault, database, attachments | `$XDG_DATA_HOME/securevault`, else `~/.local/share/securevault` |
| Temporarily decrypted attachments | `$XDG_RUNTIME_DIR/securevault/attachment-view` |

Directories are 0700, files 0600. **No user data is ever written under `/opt`.**

## Optional dependency

```bash
sudo apt install libsecret-tools
```

Only needed for Secret Service convenience unlock. Without it that feature is simply unavailable
and the master password works exactly as before.

## What Linux cannot do

Stated here because the Android build can do some of it and the difference matters.

**No screenshot protection, and nothing to implement.** This was investigated rather than assumed:

- **X11 provides no mechanism at all.** Any client on the display can read any window's pixels with
  `XGetImage`. No window property, hint or atom opts out — it is how the protocol works.
  `java.awt.Robot` is itself a client doing exactly that.
- **Wayland is better but not application-controllable.** Clients cannot read each other's buffers
  and capture goes through xdg-desktop-portal, which normally prompts. But there is no per-window
  "exclude from capture" API, and an authorised screencast records this window like any other.
- **AWT and Compose Desktop expose nothing.** There is no counterpart to Windows'
  `SetWindowDisplayAffinity`. Setting a custom window property and calling it protection would be
  fake security.
- **One extra wrinkle:** the JDK has no Wayland AWT backend, so SecureVault runs through XWayland
  on a Wayland session. Among XWayland clients the X11 situation applies again, which makes a Java
  application *more* exposed than a native Wayland one.

Adding an X11 or Wayland native dependency would not change any of this, so none was added. The
Settings screen reports which of these situations the current session is actually in, and points at
the mitigations that are real: lock on focus loss, a short auto-lock, and secrets masked until
revealed.

Android's `FLAG_SECURE` is unchanged and still applied on every Android screen.

**No sensitive-clipboard flag.** Android marks a clip sensitive so it stays out of clipboard
history and previews. Linux has no equivalent. Clipboard managers routinely keep history,
SecureVault cannot see them and cannot stop them, and a copied password may be retained elsewhere
after the timeout expires. The timeout still clears the clipboard itself.

**No hardware-backed key store.** There is no StrongBox, no TEE-backed key, nothing comparable to
Android Keystore. GNOME Keyring unlocks with your login password and holds secrets in ordinary
process memory. Convenience unlock via Secret Service stores **only the wrapped vault key** and is
not described as hardware protection anywhere in the UI.

**No biometric unlock.** `fprintd` exists but going through PAM would gate the interface, not the
key. A fingerprint prompt that does not cryptographically protect anything is theatre, so there
isn't one. The master password is the authoritative unlock.

**No device key for app state.** Android encrypts the failed-attempt counter under a Keystore key.
Linux has no equivalent an attacker with the same user account could not also use, so that state is
plain JSON at 0600. Consequence: someone with access to your account can reset the lockout counter.
Argon2id remains the real defence against offline attack; the counter only slows live guessing.

**No QR scanning.** TOTP secrets are entered by hand or pasted as an `otpauth://` URI.

**Suspend detection is a heuristic.** There is no portable screen-lock or suspend signal available
without a D-Bus dependency, so auto-lock-on-resume compares wall-clock against monotonic time and
locks on a large gap. It will also fire on a big clock correction, and it will not catch a screen
lock that did not involve suspend.

## What is the same as Android

The vault engine is literally the same code: key hierarchy, AES-256-GCM, chunked stream cipher,
HKDF domains, Argon2id parameters, `.securevault` container, restore journal, staging, extraction
bounds, path-traversal guards, per-record AAD binding, lockout policy, breach-check k-anonymity.

The one deliberate difference is the Argon2 **implementation**: Android uses `argon2kt` (JNI),
desktop uses Bouncy Castle (pure Java). Same algorithm, same parameters, same version 0x13 — which
is exactly why `Argon2BackendContract` holds both against reference vectors instead of against each
other.

## Interoperability status

| Direction | Status |
|---|---|
| Format constants pinned | Tested (`WireFormatTest`, written, not executed) |
| Portable reader round-trips its own files | Tested (written, not executed) |
| **Android → Ubuntu** | **UNVERIFIED.** Needs a real Android-generated fixture |
| **Ubuntu → Android** | **UNVERIFIED.** Needs a real exchange on both platforms |

`core/src/test/resources/fixtures/README.md` describes exactly what to produce and where to put it.
Until that exists, the current tests write files with the same code that reads them, which cannot
detect a shared mistake. Interoperability is **designed and format-tested, not verified.**
