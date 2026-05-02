# Security

## Reporting a vulnerability

To report a security issue, please email <security@affinidi.com> with a
description of the issue, the steps you took to create it, affected versions,
and, if known, mitigations. Our vulnerability management team will respond
within five working days. Confirmed issues open a Security Advisory; this
project follows a 120-day disclosure timeline.

## Threat model — keyring-stored secrets

`affinidi-tdk-common::secrets::KeyringStore` persists profile secrets to the
OS native credential store. The threat model is:

- **At rest**: secrets are encrypted by the OS and only accessible to processes
  running as the user that owns the keychain, while that keychain is unlocked.
  - **macOS**: User (login) Keychain — unlock follows the user's session.
  - **Windows**: Credential Manager (Enterprise persistence by default).
  - **Linux / BSD**: Secret Service over D-Bus — usually backed by GNOME
    Keyring or KDE Wallet. Communication between this crate and the Secret
    Service daemon is encrypted (`crypto-rust` feature).
- **In memory**: decoded `Vec<Secret>` is held in process memory until inserted
  into the [`affinidi_secrets_resolver`] and then dropped. The intermediate
  JSON/byte-slice is **not** zeroized — keep load windows short and prefer
  `KeyringStore::load_into` which hands secrets to the resolver immediately.
- **Format**: secrets are stored as raw UTF-8 JSON of `Vec<Secret>`. Versions
  ≤ 0.5.x wrapped the JSON in `BASE64_STANDARD_NO_PAD`; the 0.6 reader
  auto-migrates legacy entries on first read. The legacy-format reader will be
  removed in 0.8.

## Out of scope

- Side-channel attacks against the OS keyring (cold-boot, etc.).
- Adversaries with code execution as the same OS user (they can already read
  the unlocked keychain via OS APIs).
- Headless Linux without Secret Service / GNOME-Keyring — the keyring backend
  will fail to initialise; the application is expected to handle the failure
  via `KeyringStore::read` returning `TDKError::Secrets`.
