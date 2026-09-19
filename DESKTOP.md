# SecureVault for Desktop — Ubuntu and Windows 11

One `:desktop` module serving both, sharing the same `:core` vault engine and the same portable
`.securevault` format as the Android build.

**Why one module and not `:desktop` plus `:windows`:** of seventeen files in the module, three
contain anything OS-specific. Splitting would have duplicated the entire Compose UI, the SQLite
backend, the Argon2 backend, the PDF renderer, auto-lock and the clipboard — roughly 2,400 lines —
to isolate about 300. Every copy is somewhere the two platforms can quietly drift apart, which for
a password manager means two subtly different security models wearing one name. Platform
differences live behind `PlatformPaths`, `SecureStorage` and `ScreenCapture`, chosen once in
`Platform`.

## Verification status — read this first

**Nothing in this document has been compiled, run, packaged or installed.** The development
environment has no Gradle, no Android SDK, no JDK toolchain for building and no access to Maven
Central or Google Maven, so no command below has been executed. Every dependency version in the
desktop module is marked UNCONFIRMED in `gradle/libs.versions.toml`.

Read "implemented" as "written and reviewed". Nothing here carries "tested".

## Windows 11

### Install

Build the MSI on a Windows host (jpackage does not cross-compile), then:

```
SecureVault-1.0.0.msi   →  double-click, or  msiexec /i SecureVault-1.0.0.msi
```

Start Menu → SecureVault. No desktop shortcut is created: a password manager does not need to
plant an icon on your desktop. Uninstall through Settings → Apps.

### Where things live on Windows

| | Path |
|---|---|
| Application | `C:\Program Files\SecureVault` |
| Vault, database, attachments | `%LOCALAPPDATA%\SecureVault` |
| Settings | `%LOCALAPPDATA%\SecureVault\config` |
| Temporarily decrypted attachments | `%LOCALAPPDATA%\SecureVault\cache` |

`%LOCALAPPDATA%`, not `%APPDATA%`: roaming would copy the encrypted vault to a domain server on
every logon. That should be a deliberate choice made with a backup file, not a silent default.

**Uninstalling does not delete `%LOCALAPPDATA%\SecureVault`.** An uninstaller should not destroy
the only copy of somebody's passwords. Delete it yourself if that is what you want.

Directories are ACL-restricted to the owner where the filesystem supports it. That is defence in
depth, not the protection — the encryption is.

### Windows secure storage

Convenience unlock uses **DPAPI** (via PowerShell's `ProtectedData`), storing **only the wrapped
vault key**. Never the master password, never the raw key, never vault contents.

What DPAPI actually gives you: protection scoped to your Windows *account*. It defends against
another account on the machine, and against someone reading the file off a stolen disk without
your credentials. It does **not** defend against malware running as you, it is **software
protection with no TPM sealing**, and it is **not** equivalent to Android StrongBox. An
administrator password reset (as opposed to a normal change) can invalidate DPAPI data; if that
happens the convenience credential is lost and the master password is the way back in — which is
the correct outcome, and why the portable vault never depends on it.

### Windows Hello — deliberately not implemented

Gating the key behind Hello needs `KeyCredentialManager` and WinRT interop this stack does not
have. A Hello prompt that merely guarded the UI while the key stayed DPAPI-readable would be fake
biometric unlock, which this project refuses. **Master password is the authoritative unlock.**
Documented as a future integration point, not claimed today.

### Windows screen capture

Windows **does** have a real mechanism — `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE`
(Windows 10 2004+) genuinely excludes a window from capture at the compositor. **SecureVault does
not use it:** calling it needs the window handle through native interop Compose Desktop does not
expose, and adding a native dependency for this alone was judged the wrong trade.

So on Windows the honest statement is not "the platform cannot do this" but "SecureVault does not
do this yet, and here is exactly what it would take". Screenshot protection is **not** claimed.

### Windows clipboard

Same 15/30/60/Never choices. Windows has no per-item "sensitive" flag an application can set, and
Windows 10/11 Clipboard History (Win+V) and cloud clipboard may retain a copy. SecureVault clears
its own value after the timeout and cannot reach anything that already took a copy.

## Build

```bash
# Android must stay green first
./gradlew :core:test
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug

# Desktop
./gradlew :desktop:test
./gradlew :desktop:run                    # run it from the source tree
./gradlew :desktop:packageDeb             # Linux host → .deb
./gradlew :desktop:packageMsi             # Windows host → .msi
```

jpackage does not cross-compile: build the `.deb` on Ubuntu and the `.msi` on Windows. Both come
from the same module and the same source.

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
| **Android → Windows** | **UNVERIFIED** |
| **Windows → Android** | **UNVERIFIED** |
| **Linux → Windows** | **UNVERIFIED** |
| **Windows → Linux** | **UNVERIFIED** |

`core/src/test/resources/fixtures/README.md` describes exactly what to produce and where to put it.
Until that exists, the current tests write files with the same code that reads them, which cannot
detect a shared mistake. Interoperability is **designed and format-tested, not verified.**
