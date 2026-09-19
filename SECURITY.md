# Cryptographic architecture and threat model

This document describes what protects the vault, what does not, and what an attacker gains in each
situation worth worrying about. It is written to be checkable: every claim here corresponds to code
you can read, and the file paths are given.

**Verification status, stated once and meant throughout.** Everything below describes code that
exists and has been read.

Items marked *tests written* have automated tests in `app/src/test/`. **Those tests have never been
compiled or executed.** The project has no Android SDK, no Gradle and no access to Google Maven or
Maven Central in the environment it was written in, so there has been no build. A written test is
evidence that a property was thought about and expressed; it is not evidence that the property
holds.

Nothing in this document has run on an Android device or emulator. Read "implemented" as "written
and reviewed", never as "proven to work".

## 1. Key hierarchy

```
master password  (+ optional key file)
      |  Argon2id, per-vault 128-bit random salt
      v
key encryption key (KEK)          32 bytes, never stored, wiped after each unlock
      |  AES-256-GCM unwrap
      v
vault encryption key (VEK)        32 bytes, random at vault creation, stored only wrapped
      |  HKDF-SHA256, one label per purpose
      v
item key | attachment key | backup key | metadata key | database key
```

`core/crypto/KeyHierarchy.kt`, `core/crypto/Kdf.kt`, `core/crypto/Hkdf.kt`

**The master password is never stored, in any form, anywhere.** There is also no stored password
hash. The GCM authentication tag on the wrapped VEK is the verifier: a wrong password produces a
tag mismatch and nothing else. This matters because a stored verifier hash is an extra thing to get
wrong, and it gives an attacker a second target.

**Changing the master password rewraps the VEK only.** A new salt is generated, a new KEK derived,
and the same VEK is rewrapped under it. No item is re-encrypted, so the operation is instant on a
vault of any size, and biometric enrolment survives it because the biometric path wraps the VEK
rather than the password.

**Domain separation.** The VEK never encrypts anything directly. Each purpose gets its own HKDF
subkey with a distinct label (`core/crypto/Hkdf.kt`, `KeyDomain`). A nonce collision or a flaw
confined to one area cannot reach another.

## 2. Algorithms and parameters

| Purpose | Algorithm | Notes |
|---|---|---|
| Password-based derivation | Argon2id | Calibrated per device, floor 19 MiB / t=3 / p=2, default 64 MiB |
| Fallback derivation | PBKDF2-HMAC-SHA256 | 600,000 rounds. Only if the native Argon2 library will not load |
| Authenticated encryption | AES-256-GCM | 96-bit random nonce, 128-bit tag |
| Large data | AES-256-GCM, 64 KiB chunks | Per-chunk nonce and tag, index and final-flag in the AAD |
| Subkey derivation | HKDF-SHA256 | RFC 5869 |
| TOTP | HMAC-SHA1 / SHA256 / SHA512 | RFC 6238, verified against the published vectors |
| Randomness | `java.security.SecureRandom` | Single source, `core/crypto/RandomSource.kt` |

**On Argon2 calibration.** `Kdf.calibrate()` measures the device and picks the heaviest parameters
that still unlock in about a second, then stores them in the vault header so unlocking is
deterministic afterwards. A budget phone gets weaker parameters than a flagship, which is a real
trade-off and is why the floor is set at 19 MiB rather than allowed to fall further.

**On PBKDF2, and when it is allowed.** *Tests written, not executed.* PBKDF2 is a compatibility KDF, chosen once,
at vault creation, and only when the Argon2 native library will not load on that device. The full
matrix, re-verified and pinned as tests:

| Situation | Behaviour |
|---|---|
| New vault, Argon2 available | Argon2id, calibrated, no warning |
| New vault, Argon2 unavailable | PBKDF2, with a warning shown at the moment of creation |
| Existing Argon2id vault, Argon2 unavailable | Refuses to unlock: `KdfUnavailableException`. No fallback, and **not** counted as a failed attempt |
| Existing PBKDF2 vault | PBKDF2, on every operation, always |

Row one has no test here — the JVM has no Argon2 native library, which is exactly what
makes the other three testable — and is listed as needing device verification. `Kdf.calibrate()` is
called from exactly one place, the factory for new vaults; there is no migration path anywhere in
the codebase, automatic or otherwise. After creation the choice is fixed:

- **Unlock never falls back.** `Kdf.deriveKey` runs exactly the algorithm named in the vault's
  header. If that is Argon2id and the library is unavailable, it throws `KdfUnavailableException`
  — "this vault cannot be opened here, your data is intact" — rather than substituting anything.
  Silently reducing the cost of attacking someone's vault because a shared library failed to load
  is not a trade this app gets to make.
- **Creation never falls back silently.** `Kdf.calibrate()` returns a `KdfSelection` carrying
  `usedFallback` and a plain-language reason, which the app shows at the moment the vault is
  created — while the user can still decide whether to accept it.
- **Password change preserves the algorithm and cost parameters** and changes only the salt. A
  vault created under PBKDF2 stays PBKDF2; there is currently **no upgrade path** to Argon2id for
  such a vault, which is a real gap and is listed under known limitations.
- **Backup and restore carry the vault's KDF unchanged**, as header fields bound to the ciphertext.

The algorithm is never inferred from anything. It is read from `alg` in the header, and a header
that will not parse produces a `Corrupt` state rather than a default.

### Vault portability

*Tests written, not executed.* A vault moved from device A to device B derives the same key, because everything the
derivation needs travels in the header: algorithm, salt, memory, iterations, parallelism, PBKDF2
rounds and output length. Device calibration happens once, at creation; it never runs again and
never adjusts an existing vault. Two installations therefore cannot produce different KDF behaviour
for the same vault — the only thing that differs between devices is whether the vault can be opened
at all, which is the `KdfUnavailableException` case above.

**Nothing here is homemade.** Every primitive is a platform implementation or a published standard.
The only assembled-from-parts constructions are the chunked stream format and the backup container,
both of which are described below and both of which are authenticated end to end.

## 3. What is written to disk, and in what form

| Location | Contents | Protection |
|---|---|---|
| `files/vault/metadata.json` | Vault id, name, timestamps, KDF parameters, salt, wrapped VEK, recovery block | Public by design. Tampering breaks unwrapping rather than weakening it. Written durably, with a `.prev` copy kept (see 3a) |
| Room database `items` table | Item id, three timestamps, ciphertext blob | AES-256-GCM under the item subkey, AAD bound to the row id |
| `files/attachments/*.enc` | Attachment ciphertext | Chunked AES-256-GCM, per-attachment subkey |
| `files/sealed/*.bin` | Failed-attempt state, settings, biometric-wrapped VEK | AES-256-GCM under a non-exportable Keystore key |
| Exported CSV | Plaintext, at the user's explicit instruction | None. This is stated in a blocking dialog before export |
| `.securevault` backup | Header plus encrypted body | See section 5 |

Item title, username, URL, notes, tags, folder and item type all live **inside** the encrypted
payload (`core/model/Items.kt`, `data/repo/ItemRepository.kt`). Somebody holding the database file
learns how many items exist and when they were last touched, and nothing else.

The plaintext timestamps are a deliberate, small leak: they allow sorting and backup merging
without decrypting every row. If that matters for your threat model, move them into the payload and
accept the cost of decrypting the whole vault to sort a list.

**Additional data binds ciphertext to its location.** Item records use the row id as AAD, the
wrapped VEK uses the vault id, attachments use the attachment id. Copying a blob from one row to
another produces an authentication failure, not a wrong-credential silent success.

### 3a. Header durability

`platform/DurableFile.kt`. *Tests written, not executed.*

The vault header is the one file whose loss costs everything: without it the wrapped VEK is gone
and the encrypted items are unopenable even with the correct password. Replacing it goes:

write temp -> `flush()` -> `FileDescriptor.sync()` -> move the outgoing copy to `.prev` -> rename
temp into place -> best-effort `fsync` of the directory -> read the new header back and parse it ->
**delete `.prev`**.

The `sync()` before the rename is the step that matters. Without it a rename can reach the disk
before the bytes it points at, so a power cut in that window leaves a correctly-named, empty
header.

**What this does not claim.** The JDK exposes no portable directory `fsync`; opening a directory as
a stream fails on some runtimes, and when it does the failure is swallowed rather than failing an
otherwise-successful write. Devices also lie: an `fsync` that returns is not proof the flash
controller has committed. This narrows the dangerous window substantially. It does not close it,
which is why the `.prev` copy exists -- the header reader falls back to it when the current file
will not parse.

**The `.prev` copy is crash-window scaffolding, not an archive.** *Tests written, not executed.* This matters more
than it looks. A previous header holds the vault key wrapped under whatever password was current
when it was written. If it survived past a confirmed write, then after a master password change
there would be two openable headers on disk -- and anyone able to damage one file could reinstate a
password the user believed they had replaced. That is a rollback attack on password revocation. So:

- It is created only by a write, and deleted as soon as the new header is read back and parsed.
- It is consulted **only** when the live header is absent or unparseable. A rejected password is
  never a reason to roll back.
- When it is used, the app says so. `VaultState.Present.recoveredFromPreviousCopy` carries a
  warning up to the unlock screen: your header was recovered, a very recent password change may
  have been lost, try your previous password. Silent rollback would be indistinguishable from data
  loss to the person experiencing it.
- It contains a vault header and nothing else -- no plaintext item content -- so it is not an
  additional disclosure beyond the live header.
- Vault destruction removes it along with everything else.

**On encrypted SQLite.** SQLCipher can be layered under Room and is worth doing as defence in
depth. It is not the boundary here, and treating it as one is a common mistake: whole-database
encryption leaves plaintext in journals, temp files and process memory, and it puts every secret
under a single key held open for as long as the connection. Per-record authenticated encryption is
what actually protects this data.

## 4. Authentication and unlock

**Master password.** Minimum 12 characters, no upper bound, spaces allowed, passphrases encouraged.
Strength is estimated locally with an entropy model that penalises dictionary words, keyboard runs,
repeats, years, and the `Password1!` shape that passes naive complexity rules while being trivially
guessable (`feature/generator/PasswordStrength.kt`).

*Tests written:* scoring works on a `CharSequence`, and `CharArrayView` gives a zero-copy view over a
`CharArray`, so analysing the master password no longer produces an intermediate `String`.
Previously `masterPasswordIssues` did `String(password)` on every keystroke of the setup and
change-password screens, leaving an unwipeable copy on the heap each time. Case-insensitive
matching now folds case per character instead of calling `lowercase()`, and the regular expressions
run against the sequence directly — `java.util.regex.Matcher` indexes a `CharSequence` with
`charAt` and does not copy it. `CharArrayView.toString()` returns a redacted marker rather than the
contents, so a future caller that reaches for it leaks nothing; the tests compare `String` and
`CharArray` scoring on exactly the rules that would break if `toString()` were ever on that path.
The algorithm itself is byte-for-byte unchanged, which those same tests assert.

**Biometrics.** A separate AES key in the Android Keystore (StrongBox where available) with
`setUserAuthenticationRequired(true)`, `setInvalidatedByBiometricEnrollment(true)` and
`setUnlockedDeviceRequired(true)` wraps the VEK. `BiometricPrompt` returns an authenticated
`Cipher`; only then is the VEK decrypted. Enrolling a new fingerprint or removing the device lock
invalidates the key, biometric unlock switches off, and the master password is required. That is
correct behaviour, not a bug to work around. The master password is never stored to enable this.

**Second factor.** Two options, with an honest distinction between them:

- A **key file** is mixed into the KEK after the KDF (`KeyHierarchy.deriveKek`). This is
  cryptographic: guessing the password is not enough without the file.
- A **TOTP gate at unlock** is a UI check only. It cannot be cryptographic, because a code that
  changes every 30 seconds cannot contribute to a key that must stay constant. The app says so
  where the setting is offered rather than implying more than it delivers. Storing that second
  factor's secret inside the same vault also removes its independence, which is why the key file
  option exists and why the UI recommends keeping the secret off the device.

**Brute-force resistance.** Argon2id is the real defence, because an attacker with the database
file will attack it offline where no counter can stop them. On-device guessing is slowed with
progressive delays after three failures, doubling to a five-minute cap, with state stored encrypted
under a Keystore key (`core/vault/LockoutPolicy.kt`). An attacker with root or a full device image
can still bypass it. Stated, not hidden.

**Every credential path goes through that counter.** *Tests written, not executed.* Password unlock, recovery-code
unlock, biometric unlock and master-password change all call `enforceLockout()` first and register
failures afterwards. Change-password previously did neither, which made it an unrated password
oracle sitting next to a rate-limited unlock screen -- an attacker would simply have used that one.
Malformed recovery codes count as failures too, so an invalid-format probe is not free.

**Unreadable lockout state locks rather than resets.** *Tests written, not executed.* If the encrypted attempt
counter cannot be decrypted -- file damaged, or the device key replaced -- the vault reports a
bounded cool-down instead of a clean slate. Deleting that file was otherwise the obvious way to
clear a lockout. The cool-down expires and a successful unlock clears it, so a genuine Keystore
reset costs a legitimate user one wait rather than their vault (`VaultManager.attemptState`).

**Changing the master password is verified before it is committed.** *Tests written, not executed.* The current
password must unwrap the VEK, that VEK must match the live session's in constant time, and the
newly built header must be shown to unwrap correctly -- all before anything is written. A failure
at any point leaves the old header and the old password working.

**Optional wipe.** Off by default, opt-in, and honest about what it is: the app deletes the vault
header, the Keystore key, the database and the attachments, which makes the data unrecoverable
because the keys are gone. It does **not** claim to shred anything. Android's flash translation
layer means the physical blocks may persist, and an encrypted backup made earlier is entirely
unaffected.

*Tests written:* destruction closes the Room database **before** deleting its files, and reports what
was actually removed rather than assuming. Deleting SQLite files under an open connection can leave
the write-ahead log and journal behind -- which is how a "wipe" quietly leaves ciphertext on disk.
The same shutdown path is used whether destruction was requested by the user or triggered by the
opt-in failed-attempt wipe.

**Auto-lock.** Configurable timeout from immediate to never, plus independent switches for
background, screen-off and device-lock (`core/vault/AutoLockController.kt`). On lock, every derived
key is zeroed, the VEK is zeroed, the session is marked dead so stale references throw, and the
decrypted item list and its search text are dropped (`core/vault/VaultSession.kt`,
`data/repo/VaultIndex.kt`). A prominent Lock now control sits on the vault screen.

**On device-lock specifically.** An earlier version of this document claimed this trigger worked
when only background and screen-off were wired up. It is now implemented, by polling
`KeyguardManager.isDeviceLocked` on the controller's existing one-second tick. Polling rather than
listening is deliberate: there is no reliable "device locked" broadcast. `ACTION_USER_PRESENT`
fires on *unlock*, and screen-off is a different event -- a device can lock without the screen
turning off and vice versa. **This trigger has not been verified on a device.** Until it has, treat
screen-off and background as the ones you are relying on.

### Absent, present, corrupt

`core/vault/VaultState.kt`. *Tests written, not executed.*

The app distinguishes three states and never collapses them. It used to read the header with
`runCatching{}.getOrNull()`, so a damaged header and no header at all both produced "no vault".
That is dangerous in exactly the moment a user most needs the truth: told there is no vault, the
obvious next move is to create one, and a fresh header over a damaged one destroys the only copy of
the wrapped VEK. Setup now refuses on `Corrupt`, and the UI routes to an explanation rather than an
offer to start over.

## 5. Backup format (`.securevault`)

```
"SVLT" | format version | header length | header JSON | chunked AES-256-GCM body
```

**Format version 2.** *Tests written, not executed.* Version 1 files still open; version 1 is not written any more.
The framing version and the version inside the header JSON must agree, and a file claiming a newer
version is refused rather than guessed at.

The header carries the vault id, backup id, creation time, app version, KDF parameters, salt, the
wrapped VEK and the recovery block if one exists. It is plaintext **by design**: that is exactly
what makes a backup restorable on a new device with nothing but the master password. None of it is
secret, and none of it opens anything.

**What version 2 removed from the plaintext.** Version 1 also put the vault's *name* and its item
and attachment counts in the header, so they could be shown before asking for a password. That was
convenience, not necessity, and a file announcing "Acme Corporation credentials, 240 items" to
anyone who steals it tells them a great deal about whether it is worth attacking. Those three
fields now live in an encrypted `manifest.json` inside the body and are readable only after
authentication. What a thief can still see: that this is a SecureVault backup, its random vault and
backup ids, when it was made, and which KDF will be needed. All four are required to open the file.

**All three readers share one bounded header parser.** `restore()` and `verify()` previously skipped
the length check that `readHeader()` applied, so a crafted file could make them allocate an
arbitrary array before anything was validated.

### Restoring a backup

`feature/backup/VaultRestorer.kt`. *tests written*, including against archives crafted to
authenticate correctly.

Two phases with the user in between. **Stage** decrypts and verifies the whole backup, rebuilds
every item and folder, writes attachments to a private staging directory, and checks that what came
out is a usable vault -- touching nothing the live app can see. **Commit** runs only after the user
has read a preview and confirmed, and it refuses outright if a vault already exists.

- **The vault key is not rewrapped.** A restored vault keeps the backup's own vault id, KDF
  parameters, salt and wrapped VEK. That is what makes the backup's item records and attachment
  ciphertext valid as they stand, and it means restore cannot move a vault onto weaker settings,
  because it never chooses any.
- **The restored vault is left locked.** Opening it goes through the ordinary unlock path with the
  ordinary lockout and credential checks. Restore is not a way past authentication.
- **The password is re-derived at commit** rather than held alive across a confirmation dialog.
- **Validation before commit** covers: header fields, key length, format version, blank and
  duplicate item ids, folders referenced but absent, attachments referenced but missing, files
  present but unreferenced, anything written outside the attachments subdirectory, and anything
  whose canonical path escaped staging. A ZIP that extracted is not a vault.
- **Validation after writing, before the header.** Records are read back with the restored key and
  counted. If they do not decrypt, the header is never written and the app still sees no vault.
- **A journal covers the gap between the first live write and the header.** Room cannot join a
  filesystem transaction, so commit necessarily writes records and attachment blobs into live
  storage before `metadata.json` exists. A marker file (`vault/restore.journal`) is written before
  that first live write and removed after the header lands. It is only ever opened once no vault
  exists, which is what makes the recovery rule safe:

  | On disk | Meaning | Action |
  |---|---|---|
  | Journal, no header | A restore began and did not finish | Purge records and attachments |
  | Journal and header | The commit finished; only the marker survived | Delete the marker |
  | No journal | Nothing in flight | Nothing |

  Recovery runs at app start, before staging a restore, and before creating a vault. Without it,
  a user who abandoned a failed restore and created a fresh vault instead would inherit
  undecryptable ghost records and orphaned attachment blobs -- present, counted, and invisible.
  An earlier version of this code had exactly that hole.
- **Live storage is cleared before it is written, not after.** The clear step runs ahead of the
  attachment copy, so a retry removes debris a previous attempt had already written.
- **This is still not atomic**, and nothing here should be read as claiming it is. A power cut
  between the first live write and the journal removal leaves recoverable debris, not a valid
  vault. Real process-kill behaviour has not been tested; see README.md.
- **Failures are distinguished where it is safe and merged where it is not.** A wrong password and
  a tampered file produce one identical message -- splitting them would hand anyone with a stolen
  backup an oracle for guessing. A KDF this device cannot run gets its own message that says
  explicitly the backup is *not* corrupt.

### The restore boundary

*tests written*, including against archives crafted to authenticate correctly.

The premise: **a backup that authenticates is a backup written by someone holding the key. It is
not a backup written by someone who meant you well.** Authentication proves the bytes are
unaltered; it says nothing about whether the archive inside is sane. So the unpacking step keeps
its own guards.

- **Verification is structurally separate from restoration.** `verify()` takes no destination
  directory, so it cannot write into a vault by accident; it streams to a null sink and returns a
  header. A test asserts the filesystem is byte-identical before and after.
- **Nothing is unpacked before the whole body authenticates.** `StreamAead.decrypt` completes over
  every chunk before the ZIP is opened, so one flipped bit anywhere means no file is written at
  all — not a partial extraction that is then rolled back.
- **Foreign attachments go to a staging directory**, never the live attachment store, so inspecting
  someone else's backup cannot mix two vaults' ciphertext together.
- **Entry names are filtered three ways**: basename only, rejected if they contain `..` or a path
  separator, and then the resolved canonical path is re-checked to confirm it is still inside the
  staging directory after the filesystem has had its say.
- **Extraction is bounded**: at most 10,000 entries and 2 GB written, so a decompression bomb fails
  rather than filling the device behind a progress bar.
- **The KDF travels with the file.** Restore derives from the parameters in the backup's own
  header, never from the current device's. A backup made under different parameters still opens,
  and restoring cannot convert a vault to weaker settings.
- **Restore writes into live storage before the header exists**, and is protected by a journal
  rather than by a transaction. See "Restoring a backup" above for the recovery rule and its
  limits.

The SHA-256 of the header is the AAD for the body, so the header cannot be edited. Swapping in
weaker KDF parameters breaks decryption instead of weakening it.

The body is a ZIP of the manifest, the item JSON and the already-encrypted attachment blobs,
encrypted as a chunked stream. Each chunk carries its index and a final-chunk flag in its AAD, so chunks cannot be
reordered, dropped, duplicated or truncated without the decryption failing. Path traversal in the
archive is rejected on restore.

The master password is not in the file in any form. Without it, or the recovery code where the user
enabled one, the file is ciphertext and stays that way.

## 6. Recovery: what it can and cannot do

There is a real difference between recovering a **password** and recovering a **vault**, and the
app does not blur it.

- Forgotten master password, recovery never enabled: **the vault is gone.** No backdoor, no support
  path, no reset. The app says this during setup rather than after the fact.
- Recovery enabled: a 160-bit recovery code is generated from `SecureRandom`, shown once, and used
  to derive a second key that wraps the same VEK (`core/vault/VaultManager.enableRecovery`).

*Tests written:* the code is 160 bits of CSPRNG output; it never appears on disk in any form; it is
not in the encrypted app-state store; recovery attempts go through the same lockout policy as
password attempts; malformed and wrong codes are indistinguishable; regenerating invalidates the
previous code; disabling removes the path entirely; and recovery **survives a master password
change**, because the recovery block wraps the VEK, which a password change does not alter.
Invalidating a printed recovery kit every time someone changed their password would be its own kind
of data loss.

**Recovery codes are standing credentials, not one-time tokens.** A code keeps working until it is
regenerated or recovery is disabled. This is a deliberate trade-off -- a single-use code that had
already been spent would be worthless in the second emergency -- and it is why the code must be
protected like a master password rather than like a confirmation code.

**The trade-off, stated plainly:** an enabled recovery code is an *alternative* to the master
password, not an addition to it. Anyone holding the code and a copy of the vault or a backup gets
in. That is why it is optional, why the UI explains it before the switch is flipped, and why the
emergency kit prints a blank line for it by default rather than the code itself.

Disabling recovery removes the block from the current vault header. Backups made earlier keep their
own copy, so an old recovery code still opens an old backup file. The UI says so.

The recovery code is high-entropy, so HKDF is used rather than a password-hashing KDF; there is
nothing for an expensive KDF to defend against when the input has 160 bits of entropy.

### Emergency recovery kit PDF

`feature/recovery/RecoveryKitPdf.kt`

Contains: vault name and id, backup id, creation date, vault format version, KDF algorithm and
parameters, the salt, restore instructions, warnings, and a QR code holding the same non-secret
metadata.

Does not contain: passwords, item contents, TOTP secrets, the vault key, or the master password.
The master password and recovery code appear as **blank ruled lines to fill in by hand**. Printing
the recovery code is possible but requires an explicit opt-in and prints a warning beside it.

The PDF is never uploaded and is written only to the location the user picks through the system
file picker.

## 7. Clipboard, screen and logs

- Copies are marked `EXTRA_IS_SENSITIVE` on Android 13+, which keeps the value out of the clipboard
  preview and history. The clip is cleared after a configurable delay, 30 seconds by default, and
  only if our value is still there so a later copy by the user is never wiped
  (`platform/SecureClipboard.kt`). While a secret is on the clipboard any focused app can read it;
  that is the platform, not something this app can fix, and the timeout exists because of it.
- `FLAG_SECURE` is applied at the root of the app rather than per screen, because every screen here
  can surface a secret and a per-screen list is a list somebody eventually forgets to update
  (`platform/SecureScreen.kt`). It stops screenshots, screen recording and the recents thumbnail.
  It does not stop a compromised OS or a camera.
- Release builds strip all `android.util.Log` calls through ProGuard. No secret is logged, and the
  build makes accidental logging impossible rather than relying on discipline.
- `allowBackup="false"`, with cloud backup and device transfer excluded for every domain.

## 7a. Autofill

`feature/autofill/`. *Some parts have tests written; none executed; nothing device tested.*

- **A locked vault returns no credentials.** The service returns an authentication entry that
  launches `AutofillAuthActivity`, which shows only the unlock surface -- vault contents are never
  reachable from an activity another app caused to be launched. After unlocking it returns the
  real response to the platform via `EXTRA_AUTHENTICATION_RESULT`.
- **The authentication PendingIntents are mutable, and must be.** The platform attaches
  `EXTRA_ASSIST_STRUCTURE` to them before launching. The previous `FLAG_IMMUTABLE` version could
  never have worked: the activity received nothing to build a response from. Both intents target
  non-exported activities and are created by this app only.
- **Only matching items are offered.** *Tests written, not executed.* Matching is on registrable host boundaries:
  exact host, or a subdomain relationship anchored on a dot. `evilbank.com` does not match
  `bank.com`, and `mybank.com.evil.net` does not match `mybank.com`. If the request carries neither
  a web domain nor a package name, nothing is offered -- returning everything there would be the
  vault-enumeration hole this service exists to avoid. Results are capped at eight.
- **Dataset labels show the account, never the secret.**
- **Saving a captured credential** requires an unlocked vault and an explicit tap in
  `AutofillSaveActivity`. The captured password is held for that activity's lifetime only, is never
  displayed, and leaves only as ciphertext through the normal repository path.
- **Field classification checks password before username**, because "user password" contains
  "user" and a misfiled input would put the wrong value in the wrong box. Unrecognised fields are
  left alone. *Tests written, not executed.*

**Not verified.** The `EXTRA_AUTHENTICATION_RESULT` round trip and the save flow need the platform
autofill framework and cannot be unit tested. They have not been exercised against Chrome, Firefox,
or any real login form. Do not assume they work.

## 8. Network behaviour

The app makes exactly one kind of outbound request, and only when the user switches it on: the
k-anonymity breach lookup (`feature/health/BreachChecker.kt`).

What leaves the device: the first five hex characters of a password's SHA-1 hash. The service
returns every suffix sharing that prefix and the comparison happens locally. The service never
receives a password, a full hash, a username, a site, or anything identifying the vault. The
`Add-Padding` header is set so the response size does not hint at the query.

What it still reveals: that somebody at this IP asked about a 5-character hash prefix at this time.
That is why it is off by default.

SHA-1 appears here only because the public API is built on it. It is a hash-prefix lookup, not a
security boundary, and nothing in the vault depends on SHA-1.

There is no analytics SDK, no crash reporter and no network client in the app. The `INTERNET`
permission exists solely for the above; remove breach checking and you can remove the permission.

## 9. Threat model

**Defended against**

| Attacker | Outcome |
|---|---|
| Finds the locked phone | Vault is locked, keys are zeroed, FLAG_SECURE blocks shoulder-recording, lockout slows guessing |
| Extracts the app's data directory | Ciphertext only. Needs the master password, and Argon2id makes each guess expensive |
| Steals a `.securevault` backup | Same. Useless without the password or recovery code |
| Malicious app on the device | Cannot read app-private storage; clipboard exposure is bounded by the timeout |
| Tampers with the database or backup | Authentication fails. The app refuses to open rather than serving altered data |
| Network observer | Sees nothing, unless breach checking is on, in which case a 5-char hash prefix |
| The app's own authors | No server, no account, no key escrow. There is nothing to hand over |

**Not defended against, and honestly so**

- A rooted or compromised OS, or a malicious keyboard, while the vault is unlocked. Keys and
  plaintext are necessarily in memory at that point.
- A device image taken while unlocked, or memory forensics. JVM zeroing is best effort; the runtime
  can copy arrays during GC.
- A weak master password. Argon2id buys time; it does not rescue `summer2024`.
- Physical coercion, or a camera pointed at the screen.
- A malicious build. Verify the signature of whatever you install.
- The printed recovery kit if you print the recovery code and then lose the paper.

## 10. Known limitations in this implementation

- **Nothing here has been compiled or run.** See README.md.
- **Compose text fields hold the master password as a `String`.** This is the one copy the app
  cannot eliminate: `TextField` state is String-typed and there is no `CharArray`-backed text field
  in Compose. The copy is confined to the composable that owns the field, converted to a
  `CharArray` at the point of use, and dropped when the screen leaves composition — but it is
  immutable and cannot be wiped, so it survives until garbage collection. The *analysis* path no
  longer adds a second copy (see below); this one remains, and no claim to the contrary should be
  read into anything else in this document.
- **The recovery code cannot be fully wiped.** It is generated as a `CharArray`, carried as one,
  never placed in `SavedStateHandle` or a navigation argument, wiped when the dialog is dismissed,
  wiped when the vault locks, and wiped in `onCleared()`. The dialog keeps it masked until the user
  taps to reveal, so the unwipeable copy is created as late as possible. But displaying it at all
  materialises an immutable `String` inside the Compose text layer, and the JVM offers **no way to
  reach or zero that copy** -- it survives until garbage collection, and possibly beyond that if
  memory is paged. This is a hard limitation of the platform, not something the app is choosing not
  to fix, and nothing in this document should be read as claiming otherwise.
- **A PBKDF2 vault has no upgrade path.** If Argon2 was unavailable at creation, the vault stays on
  PBKDF2 even on a device where Argon2 works. Upgrading would mean re-deriving and rewrapping under
  new parameters -- safe to do, but not implemented, and doing it silently would violate the rule
  that the KDF never changes without the user knowing.
- **Restore creates a new vault only.** It refuses to run when a vault already exists. Replacing
  one means backing it up, deleting it with the typed confirmation, then restoring -- three
  deliberate steps rather than one button, because a second destruction path written for
  convenience is a second destruction path to get wrong.
- **Restore's commit is ordered, not atomic.** Room cannot be enrolled in a filesystem
  transaction, so records and attachments are written first and the vault header last, with a
  journal file marking the gap between them.

  An interruption can leave journaled restore debris on disk. The startup recovery mechanism is
  designed to purge that debris before another restore or a vault creation, and the journal states
  it acts on are covered by tests that construct them directly.

  **This recovery behaviour has not been verified by an actual process-kill or device test.**
  Constructing a state and proving the rule handles it is not the same as proving the state is the
  one a real crash produces. Until that test exists, treat the design as reasoned rather than
  demonstrated -- see DEVICE_TESTS.md, where it is the first item.
- **Viewing an attachment writes a decrypted copy to app-private cache** for as long as the
  external viewer holds it. There is no in-app renderer, and writing one would put a hand-rolled
  PDF or image parser directly in front of the vault. The copy is purged on lock, on app start and
  before each open, the grant is read-only and scoped to one file, and the UI says all of this
  before opening anything. The window is not zero.
- **Argon2 is one unmaintained native dependency.** `argon2kt` was last published in September
  2024. `Kdf.isArgon2Available()` falls back to PBKDF2 if the `.so` will not load, which is a real
  downgrade; the library's own README notes `UnsatisfiedLinkError` on some devices and suggests an
  alternative SO loader. This is the single biggest supply-chain risk in the project.
- **Directory-level write durability is best effort**, see 3a.
- Argon2 calibration runs on the setup thread and will visibly pause on slow devices.
- Attachment decryption streams to a caller-supplied sink. Any viewer that needs a real file path
  must write a cache file, and the caller is responsible for deleting it.
- The bundled passphrase word list is small. The generator reports entropy from the list actually
  in use, so it under-promises rather than over-promises, but ship the EFF large wordlist.
- No hardware-backed attestation of the app itself, and no tamper detection beyond the crypto.
