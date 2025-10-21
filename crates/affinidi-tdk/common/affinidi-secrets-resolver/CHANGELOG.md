# Affinidi Secrets Manager

## 21st October 2025 (0.3.4)

- **FEATURE:** Ability to convert Ed25519 secret to X25519 secret is now public
  - `ed25519_private_to_x25519_private_key()`

## 12th October 2025 (0.3.3)

- **IMPROVEMENT:** Implemented stronger and more consistent zeroize on drop for `Secret`
  - This may cause breaking changes for apps where they were not using references
    to `Secret`

## 9th October 2025 (0.3.2)

- **FIX:** secp256k1 Public point compression was off by a byte causing decrypt
  failures.
  - No loss of security as it hard failed to decrypt

## 8th October 2025 (0.3.1)

- **FIX:** P-256 and P-384 Public point compression was off by a byte causing decrypt
  failures.
  - No loss of security as it hard failed to decrypt
- **FIX:** Incorrect Curve String in JWK representation of public-keys for P-256
  and P-384
  - Changed `P256` to `P-256` and `P384` to `P-384`
- **CHORE:** Additional Unit Tests added (50.77% Coverage)

## 3rd October 2025 (0.3.0)

- **FEATURE:** `Secret::generate_ed25519()` now allows for creation from optional
  seed
- **FEATURE:** `Secret::generate_x25519()` now allows for creation from optional
  seed
- **NOTE:** The above changes causes a breaking API change

## 1st October 2025 (0.2.1, 0.2.2)

- **FIX:** Secret struct deserialization was not correct
  - Added a unit test to check deserialization of Secret
  - serde now correctly names the SecretMaterial fields
- **FIX:** JWK conversions from bytes were not correct for Ecliptic Curves

## 30th September 2025 (0.2.0)

- **IMPROVEMENT:** SSI Crate dependency removed from this library
- **IMPROVEMENT:** Crypto methods added directly to this library for easier 3rd
  party usage

## 13th September 2025 (0.1.18)

- **IMPROVEMENT:** Crate can now be compiled to a WASM compatible library
- **FIX:** Incorrect encoding on multikey public_keys for P-256, P384 and secp256k1

## 10th September 2025 (0.1.16)

- **IMPROVEMENT:** Removing SSI crate as a dependency
- **IMPROVEMENT:** Added ability to create ED25519 keys directly

## 8th September 2025 (0.1.14)

- **FIX:** X25519 Secrets had type set to Ed25519

## 2nd September 2025 (0.1.13)

- **FEATURE:** Ability to convert a ED25519 Secret to a X25519 Secret added
- **MAINTENANCE:** Dependencies updated

## 9th June 2025 (0.1.12)

- **MAINTENANCE:** Dependencies updated
- **MAINTENANCE:** Addressing Rust linting warnings
- **CHANGE:** Hashing of publickeys returns base58 only not multiencode

## 14th June 2025 (0.1.11)

- **MAINTENANCE:** Updated SSI crate from 0.11 to 0.12
- **FEATURE:** Loading JWK format keys will support public/private byte methods
  - This has been implemented using a Inner Shadow struct for Secret `Deseralization`

## 6th June 2025 (0.1.10)

- **FIX:** Generating a hash of the public key `multibase` was incorrect
- **FEATURE:** Added `get_hash()` to `Secrets` allowing for easier hashing of keys
  without converting to a secret
- **TESTS:** Added more unit tests to test functionality of `get_hash()`

## 29th May 2025 (0.1.9)

- **MAINTENANCE:** Crate dependencies updated
- **FEATURE:** `get_public_bytes()` and `get_private_bytes()` methods added
- **FEATURE:** `get_public_multibase()` and `get_private_multibase()` methods added
  - Returns a MultiKey format String
- **FEATURE:** `get_public_multibase_hash()` method added
  - Returns a Base58btc encoded Multihash of the MultiKey Public Key
  - Useful for checks against pre-shared keys without disclosing the key itself

## Release 0.1.7

- Removed drop() trait implementation as was causing the SecretsTask to close early

## Release 0.1.0

- Initial release of crate
