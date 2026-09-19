# First Android validation — manual checklist

Nothing in SecureVault has run on a device. This is the list to work through once it builds, in
roughly the order that finds problems fastest: the things that could lose data first, the things
that are merely annoying last.

Tick nothing on reasoning. Only on having watched it happen.

## Installation and lifecycle

- [ ] Debug APK installs
- [ ] App launches to the setup screen
- [ ] Create a vault
- [ ] Lock, and confirm the vault list is gone from recents
- [ ] Unlock
- [ ] Destroy the vault, and confirm setup is offered again afterwards

## Master password

- [ ] Fewer than 12 characters is refused
- [ ] Spaces are accepted
- [ ] A long passphrase is accepted
- [ ] Strength meter responds sensibly
- [ ] Change password succeeds
- [ ] The old password is then rejected
- [ ] The new password is accepted
- [ ] Recovery code still works after a password change
- [ ] Biometric unlock still works after a password change

## Biometrics — expect the invalidation case to be the interesting one

- [ ] Enable biometric unlock
- [ ] Unlock with it
- [ ] Disable it
- [ ] Re-enable, then **enrol a new fingerprint in system settings**
- [ ] Confirm the Keystore key is invalidated and the app says so
- [ ] Confirm the master password still opens the vault
- [ ] Re-enable biometric unlock afterwards
- [ ] Confirm removing the device lock entirely produces the same behaviour

## Auto-lock

- [ ] Each timeout value
- [ ] Lock on background
- [ ] Lock on screen-off
- [ ] Lock on device lock (this one is polled, and has never been observed working)
- [ ] Kill the process while unlocked, relaunch, confirm it opens locked
- [ ] Confirm no secret survives process death

## TOTP

- [ ] Enter a setup key by hand
- [ ] Codes match another authenticator for the same secret
- [ ] Camera permission is requested only when Scan QR is chosen
- [ ] Scan a real QR code
- [ ] Preview shows issuer and account, and **not** the secret
- [ ] Confirm populates the editor
- [ ] A non-otpauth QR (a Wi-Fi or URL code) produces the specific error, not silence
- [ ] An `otpauth://hotp/...` code is rejected
- [ ] Replacing an existing TOTP warns first

## Clipboard

- [ ] 15, 30 and 60 second settings each clear on time
- [ ] Never requires confirmation and then does not clear
- [ ] Copied secrets do not appear in the Android 13+ clipboard preview
- [ ] A value copied by another app after ours is not wiped by our timer

## Backup and restore — the highest-risk area

- [ ] Create a backup
- [ ] Verify it; confirm nothing is written
- [ ] Verify with the wrong password → dedicated failure screen, current vault untouched
- [ ] Corrupt a byte of the file, verify → same failure, same wording
- [ ] Restore as new vault on a device with **no** vault
- [ ] Confirm the restored vault opens with the backup's password, not skipped
- [ ] Restore on a **second device** — the real portability test
- [ ] Restore a backup containing attachments; open one afterwards
- [ ] Cancel a restore at the preview; confirm staging is gone
- [ ] Attempt restore with a vault present; confirm it refuses and the vault is unchanged
- [ ] **Kill the process mid-commit** (Android Studio's stop button, or `adb shell am force-stop`),
      relaunch, and confirm the journal leaves either no vault or a complete one — never a partial
      one. This is the single most important untested behaviour in the project

## CSV

- [ ] Import from a real export of another manager
- [ ] Each duplicate strategy behaves as described in the summary
- [ ] Export entire vault
- [ ] Export a folder
- [ ] Export selected items
- [ ] The plaintext warning blocks until acknowledged
- [ ] The file lands only where the picker was pointed

## Autofill — implemented but completely unexercised

- [ ] Chrome, a real login form
- [ ] Firefox, a real login form
- [ ] A native app login form
- [ ] Matching domain offers the right entry
- [ ] Subdomain matches
- [ ] **A lookalike domain offers nothing** (`evilbank.com` against a `bank.com` entry)
- [ ] Locked vault offers the unlock entry, not credentials
- [ ] After unlocking, the credential actually fills
- [ ] Save-credential prompt writes an item

## Attachments

- [ ] Add
- [ ] View in an external app
- [ ] Export a decrypted copy
- [ ] Delete
- [ ] Lock the vault, then confirm the decrypted cache copy is gone
- [ ] Restart the app, confirm the cache is purged
- [ ] An unviewable type offers Save rather than a dead button

## Accessibility

- [ ] TalkBack reads item rows as one coherent announcement
- [ ] Warnings are announced, not conveyed by colour alone
- [ ] Largest system font size leaves every label usable
- [ ] Dark and light mode contrast
- [ ] Focus traversal through the editor and the password forms

## Known limitations to confirm are still true

- [ ] `FLAG_SECURE` blocks screenshots and the recents thumbnail
- [ ] No network traffic at all with breach checking off (check with a proxy)
- [ ] Breach checking sends only a 5-character prefix when on
