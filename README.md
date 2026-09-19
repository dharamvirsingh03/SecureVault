# SecureVault

A local-first, offline-first password manager for **Android, Ubuntu/Linux and Windows 11**.

All three run the same `:core` vault engine and read and write the same portable `.securevault`
backup format — one vault format, one encryption protocol, one security model, with only the
operating-system integration differing. See [DESKTOP.md](DESKTOP.md) for the desktop editions. No account, no server, no telemetry. The
encrypted vault lives on the device and only the person holding the master password can read it.

Read [SECURITY.md](SECURITY.md) first if you care about the crypto. It describes the key hierarchy,
the file formats, the recovery design and an honest threat model, including what this app does
**not** protect against.

## Status, stated plainly

**BUILD NOT VERIFIED.** This project has never been compiled. The development environment has no
Android SDK and no access to Google Maven or Maven Central, so `assembleDebug` and
`testDebugUnitTest` cannot be run here. Known configuration errors have been fixed and dependency
versions researched against upstream release notes, but "the build script is now correct" is a
claim about review, not about a green build. Treat the first `./gradlew assembleDebug` as real
work.

The security-critical code is complete and self-contained; the UI is deliberately the thinner half.

Statuses below mean exactly this, and nothing is upgraded on optimism:

- **Implemented** — code exists and has been reviewed. Not compiled, not executed.
- **Tests written** — automated tests exist in `app/src/test/` covering the stated property.
  **They have never been compiled or run.** A written test shows a property was thought about and
  expressed; it does not show the property holds.
- **Unit tested** — tests exist *and have executed successfully*. **Nothing in this project
  carries this status.**
- **Device tested** — actually run on an Android device or emulator. **Nothing carries this
  status either.**

| Area | State |
|---|---|
| AEAD, HKDF, chunked stream cipher, key hierarchy | Implemented; tests written |
| AEAD failure handling: uniform, non-distinguishable errors | Implemented; tests written |
| KDF policy: full four-case matrix, no silent downgrade, no migration path | Implemented; tests written (one row needs a device) |
| Password strength analysis without materialising a String | Implemented; tests written |
| Restore boundary: verification separate, staging only, bounded extraction, traversal guards | Implemented; tests written |
| Argon2id + PBKDF2 compatibility KDF, device calibration | Implemented |
| Vault state: absent / present / corrupt | Implemented; tests written |
| Durable header writes, confirm-then-delete `.prev`, announced rollback | Implemented; tests written |
| Master password change: session required, rate limited, verified before commit | Implemented; tests written |
| Vault shutdown and destruction ordering | Implemented; tests written |
| Lockout policy, including fail-closed on unreadable counter state | Implemented; tests written |
| Recovery code: entropy, CSPRNG, no disk plaintext, rate limiting, regeneration, survives password change | Implemented; tests written |
| Biometric unlock via Keystore-wrapped vault key | Implemented; needs a device |
| Auto-lock: timeout, background, screen-off, device-lock | Implemented; needs a device |
| Encrypted storage: Room + per-record authenticated encryption | Implemented |
| Attachments: chunked encryption, size limit | Implemented |
| TOTP: RFC 6238, SHA-1/256/512, 6/8 digits, otpauth parsing | Implemented; tests written against RFC 6238 vectors |
| Offline QR scan with runtime camera permission | Implemented, not reachable from the UI yet |
| Generators: password, passphrase, strength estimator | Implemented; tests written |
| CSV parser and format detection | Implemented; tests written |
| CSV import pipeline, export with blocking warning | Implemented |
| `.securevault` backup format v2: confidentiality, integrity, versioning, KDF preservation | Implemented; tests written |
| Backup verification (decrypt and check, writing nothing) | Implemented; tests written |
| Emergency recovery kit PDF | Implemented |
| Password health, k-anonymity breach check | Implemented |
| Autofill: domain matching and field classification | Implemented; tests written |
| Autofill: authentication round trip and save flow | Implemented, **not verified** — needs the platform framework |
| Navigation: typed back stack, no secrets in routes | Implemented |
| Vault home: search, favourites, recents, folders, type filters | Implemented |
| Item editors for all ten creatable types (schema-driven) | Implemented |
| Item detail: masked fields, reveal, copy, live TOTP, attachments | Implemented |
| Folder and tag management | Implemented |
| Import wizard (detect, map, preview, duplicates, summary) | Implemented |
| Backup, verify, CSV export, emergency kit, recovery, change password, delete vault screens | Implemented |
| Security dashboard with per-category drill-downs | Implemented |
| Backup restore as a new vault: stage, validate, preview, journalled ordered commit, reopen locked | Implemented; tests written |
| Interrupted-restore recovery journal | Implemented; tests written |
| Restore *replacing* an existing vault | Not implemented by design — back up, delete, then restore |
| QR scan preview and confirm, malformed-code handling | Implemented; tests written for parsing; camera needs a device |
| Generator to login handoff | Implemented |
| CSV export scope: entire vault, folder, selected items | Implemented |
| Clipboard: 15/30/60/Never with confirmation | Implemented |
| Biometric invalidation explanation and recovery path | Implemented; needs a device |
| Attachment in-app view via scoped FileProvider | Implemented; needs a device |
| Dedicated backup-verification and restore failure states | Implemented |
| Accessibility pass: merged row semantics, 48dp targets, live regions | Implemented; needs a screen reader |
| Passkeys | Not implemented. See below |
| Instrumented tests | Not written |

On **passkeys**: **the passkey storage model exists; passkey provider functionality is not
implemented.** Real support means Android's Credential Manager provider APIs, which is separate
work with its own attestation and UI requirements. Modelling it is not implementing it, and
pretending otherwise in a password manager would be the wrong kind of shortcut.

## First build

**Nothing here has been built.** The commands below are what should work, not what did.

### Required

| | Requirement | Why |
|---|---|---|
| Android Studio | Recent stable able to run AGP 9.4 | |
| JDK | 17 or newer (21 is fine) | `compileOptions` targets Java 17; AGP 9 needs 17+ |
| Gradle | **9.x** — AGP 9.4 requires it | An earlier draft of this file said 8.14. That was wrong |
| Gradle wrapper | **Not present in this repository** | Must be generated before `./gradlew` exists |
| Android SDK platform | **API 37** | `compileSdk = 37`, required by Compose 1.12 (BOM 2026.08.00) |
| Build-tools | Whatever the SDK manager pairs with API 37 | |
| `compileSdk` | 37 | Compose 1.12 |
| `targetSdk` | 36 | Deliberately one behind: targeting a platform whose behaviour changes have never been tested on a device is a claim this project cannot back |
| `minSdk` | 28 (Android 9) | StrongBox, `setUnlockedDeviceRequired`, and `BiometricPrompt` with a `CryptoObject` all arrived there |
| Device or emulator | API 28 or newer | |

Install the API 37 platform first. `compileSdk` will not resolve without it.

### Commands

The wrapper does not exist yet, so **`./gradlew` will fail until you create it.** Either open the
project in Android Studio and let it generate one, or:

```bash
gradle wrapper --gradle-version 9.3.1
```

Then:

```bash
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

There are no instrumented tests yet, so `./gradlew :app:connectedDebugAndroidTest` would do
nothing. Once they exist, that is the command.

### Troubleshooting the first build

**Dependency resolution.** Ten versions in `gradle/libs.versions.toml` are marked UNCONFIRMED
because the environment this was written in had no access to Google Maven or Maven Central. They
are best-known values, not resolved ones. If Gradle cannot find one, fix that one — do not start
sweeping versions, because the first real build is the only source of truth about what is
compatible here.

**API 37.** `compileSdk = 37` is not optional with the current Compose BOM. Dropping to 36 means
dropping the Compose version too; do not change one without the other.

**Argon2 native library.** `argon2kt` ships JNI `.so` files and its own README reports
`UnsatisfiedLinkError` on some devices and ABI configurations. If it fails to load, the behaviour
is deliberate and unchanged:

| Situation | What happens |
|---|---|
| New vault, Argon2 loads | Argon2id, calibrated to the device, no warning |
| New vault, Argon2 will not load | PBKDF2, **with an explicit warning shown at the moment the vault is created** |
| Existing Argon2id vault, Argon2 will not load | **Refuses to unlock.** Never falls back. The message says the data is intact and not to create a new vault |
| Existing PBKDF2 vault | PBKDF2, always |

If you see the PBKDF2 warning on a device you expected Argon2 to work on, check your ABI splits
before accepting it. There is no upgrade path from a PBKDF2 vault to an Argon2id one.

### Recommended additions

Drop the EFF large wordlist at `app/src/main/assets/eff_large_wordlist.txt` (7776 words, 12.9 bits
per word). The passphrase generator picks it up automatically and reports the higher entropy. Until
then it uses a small bundled list and reports the smaller, truthful number.

## Project structure

```
app/src/main/java/app/securevault/
├── core/
│   ├── crypto/      Aead, Hkdf, Kdf, StreamAead, KeyHierarchy, BiometricKeyStore, RandomSource
│   ├── vault/       VaultManager, VaultSession, VaultMetadata, LockoutPolicy, AutoLockController
│   └── model/       Item types, payloads, canonical field keys
├── data/
│   ├── db/          Room entities and DAOs. Ciphertext only
│   ├── repo/        ItemRepository (seal/open), VaultIndex (in-memory search)
│   └── attachments/ Encrypted file store
├── feature/
│   ├── totp/        RFC 6238 engine, otpauth URIs, offline QR scanner
│   ├── generator/   Passwords, passphrases, strength estimation
│   ├── csv/         RFC 4180 parser, format detection, import, export
│   ├── backup/      .securevault container
│   ├── recovery/    Emergency recovery kit PDF
│   ├── health/      Health analysis, k-anonymity breach check
│   └── autofill/    Android Autofill provider
├── platform/        SecureClipboard, SecureScreen, SealedStore
├── ui/              Compose screens and the single view model
└── di/              ServiceLocator
```

## Design decisions worth knowing

**Everything sensitive is inside the encrypted payload.** Not just passwords — titles, usernames,
URLs, tags, folders and item type too. The database holds a random UUID, three timestamps and a
ciphertext blob. Someone with the database file learns your item count and nothing else.

**Search decrypts into memory and clears on lock.** There is no plaintext search index on disk,
because an index outside the vault recreates exactly the data the encryption exists to hide and
survives locking. Secret fields are excluded from searchable text, so the search box cannot be
turned into an oracle for a password.

**The recovery code is a trade-off, not a free safety net.** Enabling it means the code is an
alternative to your master password. The app explains this before you enable it rather than after
you regret it.

**No analytics, no crash reporting, no ads, no account.** There is no SDK to disable because none
is present. The single network call is the optional breach check, which is off until you turn it
on.

**CSV is treated as dangerous, because it is.** Export is behind a blocking warning. Import warns
about the source file and never copies it into app storage.

## Device testing

Nothing has run on a device. [DEVICE_TESTS.md](DEVICE_TESTS.md) is the checklist for the first
real validation, ordered so the things that could lose data get found first. The single most
important item on it is killing the process mid-restore-commit and confirming the journal leaves
either no vault or a complete one.

## Before you trust this with real passwords

1. Build it, run the tests, read `SECURITY.md`.
2. Have someone who does this for a living review the crypto. Self-review is not review.
3. Write instrumented tests for what the JVM cannot reach. In rough order of how much damage the
   untested behaviour could do:

   | Area | What needs proving on a device |
   |---|---|
   | **Restore interruption** | Kill the process at each write step and confirm the journal rule leaves either no vault or a complete one — never something in between. The JVM cannot kill a process mid-write, so this is genuinely untested today |
   | Keystore and biometrics | Key invalidation on new enrolment, StrongBox fallback, `setUnlockedDeviceRequired` |
   | Autofill | The `EXTRA_AUTHENTICATION_RESULT` round trip against Chrome, Firefox and a native app. Implemented, completely unexercised |
   | FileProvider | That the grant works, is scoped, and that no viewer can reach anything else |
   | Clipboard | `EXTRA_IS_SENSITIVE`, and that clearing actually happens |
   | Device-lock polling | `KeyguardManager.isDeviceLocked` on real lock and unlock |
   | Camera and QR | ML Kit decoding, runtime permission flow |
   | Process death | State restoration, and that no secret survives it |
   | Accessibility | TalkBack traversal of the security warnings |
   | Durable writes | Whether `fd.sync()` and the directory fsync behave on the target filesystem |
4. Test restore on a second device before relying on a backup. An untested backup is not a backup.
5. Consider what you actually need. Bitwarden and KeePassDXC are open source, audited and free.
   Building your own is an excellent way to learn and a demanding way to store your bank password.

## Licence

No licence file is included. Add one before distributing. If you publish this, publish the source —
a closed-source password manager asks for trust it cannot demonstrate.
