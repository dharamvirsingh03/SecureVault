# 🔐 SecureVault

**SecureVault is a local-first, offline-first password manager for Android and Ubuntu/Linux.**

Your vault is encrypted locally on your device. There is no account, cloud server, cloud sync, advertising, analytics, or telemetry.

> **Security first:** SecureVault is designed so that your master password never leaves the device and sensitive vault data is stored encrypted.

---

## ✨ Features

### 🔐 Security

- AES-256-GCM authenticated encryption
- Argon2id key derivation
- PBKDF2-HMAC-SHA256 fallback for supported vault creation scenarios
- HKDF-SHA256 key hierarchy
- Random per-vault encryption keys
- Encrypted database records
- Encrypted attachments
- Automatic locking
- Android biometric unlock
- Recovery code support
- Clipboard auto-clear
- Optional password breach checking using k-anonymity
- No plaintext passwords stored on disk
- No analytics or tracking

### 📱 Android

- Android 9 (API 28) and newer
- Passwords / logins
- Secure notes
- Credit/debit cards
- Identities
- Wi-Fi credentials
- API keys
- TOTP / authenticator codes
- Folders and tags
- Favourites and recent items
- Search
- Password generator
- Passphrase generator
- Password health analysis
- CSV import/export
- Encrypted backups
- Emergency recovery kit
- QR-code support for TOTP
- Android Autofill
- Biometric unlock
- Attachment storage and viewing
- Screenshot protection with Android `FLAG_SECURE`

### 🐧 Ubuntu / Linux

- Native desktop application
- Compose Desktop UI
- Ubuntu `.deb` package
- Local SQLite storage
- XDG-compatible application data
- Optional Linux Secret Service integration
- Clipboard support
- Automatic locking
- Encrypted attachments
- TOTP
- Password generator
- Password health
- CSV import/export
- Backup and restore
- Emergency recovery kit
- Same portable `.securevault` backup format as Android

---

# 🔄 Portable Vault Backups

SecureVault uses a single encrypted:

```text
.securevaultbackup format.

The goal is to allow the same encrypted backup to move between platforms:

Android
   ↕
.securevault
   ↕
Ubuntu / Linux

The backup contains encrypted vault data and preserves the vault's KDF parameters.

Important

Cross-platform interoperability should be considered verified only after testing a real backup between the Android and Linux applications.

🛡️ Security Model

SecureVault uses a layered key hierarchy:

Master Password
       │
       ▼
    Argon2id
       │
       ▼
      KEK
       │
       ▼
Encrypted VEK
       │
       ▼
Vault Encryption Key
       │
       ▼
HKDF-SHA256
       │
       ├── Vault data
       ├── Attachments
       └── Other encrypted data

Sensitive item information—including titles, usernames, URLs, tags, folders and item types—is kept inside encrypted payloads rather than stored as plaintext database fields.

For the complete security design, threat model, cryptographic details and known limitations, see:

SECURITY.md

📦 Downloads
Android

Download the Android APK from the GitHub Releases section.

SecureVault-Android-v1.0.0.apk

Android version:

Android 9 / API 28+
Ubuntu / Linux

Download the .deb package from GitHub Releases:

securevault_1.0.0-1_amd64.deb

Install:

sudo apt install ./securevault_1.0.0-1_amd64.deb

Launch SecureVault from the Ubuntu Applications menu.

🖥️ Linux Security Notes

Linux does not provide an equivalent to Android's FLAG_SECURE.

Therefore SecureVault does not claim to prevent screenshots or screen capture on Linux.

Linux biometric/hardware-backed key storage is also not assumed where the platform cannot provide it securely.

When available, Linux Secret Service can store the wrapped vault key for convenience unlock. SecureVault does not fall back to storing the plaintext vault key in a normal file.

See DESKTOP.md for Linux-specific details.

🔑 Supported Vault Data

SecureVault supports:

🔑 Login credentials
💳 Payment cards
👤 Identities
📝 Secure notes
📶 Wi-Fi credentials
🔌 API keys
🔐 TOTP authenticator entries
📎 Encrypted attachments
📁 Folders
🏷️ Tags
🔄 Import & Export

SecureVault supports:

CSV import
CSV export
Encrypted .securevault backup
Backup verification
Restore as a new vault
Emergency recovery kit

CSV files contain plaintext data, so treat them as sensitive files and delete them securely after use.

🚧 Current Status
Android
✅ Project builds successfully
✅ Unit tests execute successfully
✅ Debug APK builds successfully
✅ Tested during development on a real Android device
⚠️ A production-signed release build should be used for final distribution
Ubuntu / Linux
✅ Desktop project compiles
✅ Desktop tests execute
✅ Desktop application launches
✅ .deb package generated
⚠️ Real Android ↔ Ubuntu .securevault interoperability still needs final end-to-end verification
Security

The cryptographic design and security-sensitive implementation are documented in:

SECURITY.md

SecureVault has not undergone an independent professional security audit.

🧪 Testing

Android:

./gradlew :core:test
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug

Ubuntu:

./gradlew :desktop:test
./gradlew :desktop:run
./gradlew :desktop:packageDeb
🏗️ Project Structure
SecureVault/
├── app/          Android application
├── core/         Shared crypto, vault and business logic
├── desktop/      Ubuntu/Linux desktop application
├── gradle/       Gradle configuration
├── README.md
├── SECURITY.md
├── DESKTOP.md
└── DEVICE_TESTS.md

The shared core module is intended to keep the vault engine and portable backup format independent of Android or Linux.

🔒 Privacy

SecureVault does not require:

An account
Cloud storage
Cloud synchronization
Advertising
Analytics
Crash reporting
Telemetry

The optional password breach check is the only network-dependent feature.

⚠️ Important

SecureVault is a personal/open-source project and should not yet be considered a professionally audited password manager.

Before storing important credentials:

Read SECURITY.md.
Understand the recovery process.
Keep multiple encrypted backups.
Test restoring a backup.
Do not lose your master password.
Do not share your .securevault backup or recovery credentials.
📄 Documentation
Security Model
Desktop / Ubuntu Documentation
Device Testing Checklist
License

See the repository license information.


### I would make one small change before publishing

Your current README says **“BUILD NOT VERIFIED”** and **“Nothing has run on a device”**, which is now outdated based on the actual builds you've performed. :contentReference[oaicite:1]{index=1}

The replacement above fixes that and separates the documentation properly:

- **README.md** → what SecureVault is and how to use/download it
- **SECURITY.md** → detailed cryptography/security
- **DESKTOP.md** → Ubuntu/Linux-specific implementation and limitations
- **DEVICE_TESTS.md** → detailed testing checklist

I also deliberately **did not claim Android ↔ Ubuntu interoperability is verified**, because your own testing history has not yet demonstrated both directions with real `.securevault` backups.

### Easiest way to replace your README

From the SecureVault (14) project:

```bash
nano README.md

Delete the existing contents, paste the README above, then:

git add README.md
git commit -m "Improve project README"
git push
