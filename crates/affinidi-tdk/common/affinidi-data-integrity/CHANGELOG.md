# Affinidi Data Integrity Changelog

## 29th November 2025 Release 0.3.0

- **BREAKING FEATURE:** `verify_data()` now requires the following changes:
  1. DID Resolver implementing `DIDResolver` trait to be passed in
     - This allows for greater flexibility in DID resolution strategies
  2. function is now async due to DID resolution

This change allows for determination of the proof Verification Method from the
DID Document itself.

## 3rd November 2025 Release 0.2.4

- **MAINTENANCE:** Updated to latest `affinidi-secrets-resolver`
- **CHORE:** Updated to latest dependencies

## 3rd October 2025 Release 0.2.3

- **MAINTENANCE:** Updated to latest `affinidi-secrets-resolver`

## 30th September 2025 Release 0.2.2

- **MAINTENANCE:** Updating crate dependencies

## 10th September 2025 Release 0.2.1

- **IMPROVEMENT:** Removed SSI crate to lessen upstream dependencies
- **MAINTENANCE:** Updating crate dependencies

## 8th July 2025 Release 0.2.0

- **BREAKING:** API Changed to use generics that implement Serialize/Deserialize
  - Fixes a problem where the JCS library converts a JSON Number to a Fixed Floating
    point number causing it to be represented as `ff*`

## 5th July 2025 Release 0.1.4

- **FEATURE:** `sign_jcs_data()` you can now specify a signature `created` attribute
- **TESTING:** Added DataIntegrity Reference Test
- **MAINTENANCE:** Addressing Rust lint warnings
- **MAINTENANCE:** Updating crate dependencies

## 17th June 2025 Release 0.1.3

- **FEATURE:** **BREAKING** `GenericDocument` replaced with `SigningDocument` and
  `SignedDocument`
  - `SigningDocument`: Used when signing data
  - `SignedDocument`: Used when verifying data

## 17th June 2025 Release 0.1.2

- **BREAKING:** `sign_data_jcs()` renamed to `sign_jcs_data()`
- **BREAKING:** `sign_jcs_data()` no longer requires the `vm_id` parameter
- **BREAKING:** `sign_jcs_data()` `data_doc` parameter is now mutable, allowing
  in place insertion of the `DataIntegrityProof`
  - Optimisation that stops an in-memory clone of the entire document
- **FEATURE:** `sign_jcs_proof_only()` Generate Proof only and get `DataIntegrityProof`
  return
  - Optimisation method for witness nodes that only require proof, not the full
    signed document

## 6th June 2025 Release 0.1.1

- **FEATURE:** Can now verify a JSON Document
- **FEATURE:** Added example Verification tool for loading signed documents and
  verifying them
- **FIX:** Serialization of input documents was not correctly handling `@context`
  - It now correctly handles `@context` fields and places them in the proof

## 29th May 2025 Release 0.1.0

- Initial release of crate
