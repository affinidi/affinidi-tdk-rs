# Affinidi Secrets Manager

## 29th May 2025 (0.1.9)

* **MAINTENANCE:** Crate dependencies updated
* **FEATURE:** `get_public_bytes()` and `get_private_bytes()` methods added
* **FEATURE:** `get_public_multibase()` and `get_private_multibase()` methods added
  * Returns a MultiKey format String
* **FEATURE:** `get_public_multibase_hash()` method added
  * Returns a Base58btc encoded Multihash of the MultiKey Public Key
  * Useful for checks against pre-shared keys without disclosing the key itself

## Release 0.1.7

* Removed drop() trait implementation as was causing the SecretsTask to close early

## Release 0.1.0

* Initial release of crate
