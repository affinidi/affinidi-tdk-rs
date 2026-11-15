# Affinidi Secrets Manager

## [0.5.21] - 2026-11-15

multikeys decode through affinidi-encoding (#1143)

- The `base58` and `multibase` dependencies are gone: encoding and decoding
  go through `affinidi-encoding`, the workspace's one multibase
  implementation. Encoded output is byte-for-byte unchanged.
- **Behaviour changes (R3.6):** `Secret::decode_multikey`,
  `Secret::decode_multikey_zeroizing` and `Secret::from_multibase`
  - accept only base58btc multibase (`z` prefix), the encoding every
    multikey uses; other multibase prefixes (`f`, `u`, ...) used to be decoded
    and are now refused;
  - check the key length for every codec with a known length (the
    `affinidi_encoding::decode_multikey_checked` rule), so a truncated or
    padded key is refused here instead of failing later. Decoded private key
    material is still held in wiped buffers.

## [0.5.20] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-crypto` 0.3
  -> 0.3.2, `affinidi-encoding` 0.1 -> 0.1.7, `zeroize` 1 -> 1.8.

## [0.5.19] - 2026-11-15

JWK-loaded EC secrets match generated ones; JWK key material is validated

**Behaviour changes (R3.6)** (#1050). Released as a patch: no signature
change, and the old behaviour was a bug (a JWK-loaded EC secret could not
produce a multikey).

- **Fixed:** `Secret::from_jwk` (and so every `Secret` deserialized from a
  `privateKeyJwk`, e.g. from a keyring or environment file) stores EC public
  bytes as the SEC1 uncompressed point `0x04 || x || y`, as the
  `generate_*` constructors do. It stored `x || y`, so
  `get_public_keymultibase()` / `get_public_keymultibase_hash()` failed with
  "public_bytes too short to compress" and a serde round trip changed
  `get_public_bytes()`. **`get_public_bytes()` for a JWK-loaded P-256,
  P-384, P-521 or secp256k1 secret is now one byte longer** (65/97/133/65
  bytes, leading `0x04`); a caller that worked around the old 64-byte form
  must drop that workaround.
- **Stricter:** `from_jwk` refuses key material of the wrong length (`d`,
  `x`, `y` must be 32 bytes for Ed25519, X25519, P-256 and secp256k1, 48 for
  P-384, 66 for P-521), an EC JWK naming a non-EC curve, and, where the curve
  is compiled in, a JWK whose public part is not the public key of `d`. Such
  JWKs used to load and then fail later (or panic, see below).
- **Fixed:** `Secret::to_x25519` returns an error instead of panicking on an
  Ed25519 private key shorter than 32 bytes.


## [0.5.18] - 2026-11-13

affinidi-crypto 0.3

- **Changed:** requires `affinidi-crypto` 0.3. `Secret::generate_ed25519`,
  `generate_x25519`, `generate_p256`, `generate_p384`, `generate_p521`,
  `generate_secp256k1`, `generate_ml_dsa_*` and `generate_slh_dsa_sha2_128s`
  take the key out of the generated key pair with `into_parts()`, so the
  private key moves into the `Secret` without a copy and the rest of the key
  pair is wiped.
- **Compatibility (R3.6):** no signature change in this crate. The re-exported
  `KeyType` and the `CryptoError` conversion now refer to `affinidi-crypto`
  0.3; a caller that also uses `affinidi-crypto` directly needs 0.3 for the
  types to match. Released as a patch, per ADR 0003, because `didwebvh-rs`
  pins this crate at `0.5`.

## [0.5.17] - 2026-11-12

fewer unwiped copies of private keys

`Secret` is zeroize-on-drop, but some of the buffers it is built from were
not wiped:

- `Secret::from_multibase` wipes the whole multibase-decoded buffer, not only
  its 32-byte stack copy.
- `Secret::to_x25519` builds the X25519 JWK directly, so the encoded `d` lives
  only in the zeroize-on-drop JWK, and wipes the converted scalar. Before, the
  scalar, its base64 `String` and a `json!` value holding `d` were dropped as
  they were. The result is the same `Secret`: same id, key type, bytes and
  JWK (with `kid` set to the id).
- `Secret::from_jwk_value` deserializes from the borrowed value instead of
  cloning the whole JSON value first.
- `Secret::get_private_keymultibase` wipes the multicodec buffer it encodes.
- `Secret::generate_x25519` wipes the seed copy and takes the private bytes
  without an extra array copy. The generators move the JWK from the key pair
  instead of cloning it.
- **Added:** `Secret::decode_multikey_zeroizing`, which returns the decoded
  key in `Zeroizing<Vec<u8>>`. `Secret::decode_multikey` keeps its signature
  and now wipes its intermediate buffer. Use the new function for private
  keys.
- The `task` module docs said the secrets task removes the need for copying
  secrets. It does not: every `get_secret` returns a clone over a channel.
  The docs now say so, and that each clone is wiped when dropped.

No behaviour change and no breaking API change: one function is added.

## [0.5.16] - 2026-11-12

`ThreadedSecretsResolver` waits for room instead of dropping commands

`ThreadedSecretsResolver` sent every command with `try_send` on a 32-slot
channel and, when the channel was full, logged a warning and carried on:
`insert_vec` lost every secret past the 32nd that was queued before the task
ran (on a current-thread runtime, all of them past the first 32), and reads
answered "not found" (`None`, `vec![]`, `0`, `true`) while the secrets were
still there. Callers could not tell either from a missing key.

- Every command now waits for room on the channel (`send().await`) instead
  of being dropped. Each operation, from queueing its command to the task's
  answer (and, for inserts and removals, the task's confirmation), is bounded
  by one `SECRETS_TASK_TIMEOUT`. `insert_vec` sends the batch as one `AddSecrets` command
  and returns once the task has stored it; `remove_secret` returns once the
  task has removed the key.
- New fallible methods that report a stopped or unresponsive task instead of
  folding it into "not found": `try_insert_vec`, `try_get_secret`,
  `try_find_secrets`, `try_remove_secret` and `try_len`. `Ok(None)` /
  `Ok(vec![])` mean the task does not hold the key.
- New `SecretsResolverError::SecretsTaskClosed` and
  `SecretsResolverError::SecretsTaskTimeout` (the enum is `#[non_exhaustive]`)
  and `SECRETS_TASK_TIMEOUT` (5s), the bound on each whole operation.
- The `SecretsResolver` trait signatures are unchanged. Its methods on
  `ThreadedSecretsResolver` now log a stopped or unresponsive task at
  `error` level; reads still return `None` / `vec![]` / `0` in that case,
  since the trait has no error channel.

Behaviour change (R3.6):

- Inserts and removals now wait for the task to confirm them, up to
  `SECRETS_TASK_TIMEOUT` (5s) in all, where they used to return at once (and
  sometimes lose the command). Reads wait up to 5s in all, where they used to
  give up after one second for the answer.
- Inserts and removals now use `tokio::time`, as reads already did, so they
  need a runtime with the time driver enabled (`enable_time()` / `enable_all()`,
  which `#[tokio::main]` and `#[tokio::test]` turn on). Without it they panic.
- A caller that passes its own channel to `ThreadedSecretsResolver::new(Some(tx))`
  must answer `SecretsStored`, which inserts and removals now send to confirm
  they were applied; otherwise they time out (`SecretsTaskTimeout`, logged at
  `error` by the trait methods). `SecretsTask` does this already.

No caller in this workspace relies on the old timing, and none passes its own
channel.

## [0.5.15] - 2026-10-02

`Secret::from_str` renamed to say what it takes

`Secret::from_str(key_id, &Value)` was named and documented as if it parsed a
JWK string, but it takes a `serde_json::Value` (#893). It is now deprecated in
favour of two correctly named constructors:

- `Secret::from_jwk_value(key_id, &Value)` — the same behaviour under an honest
  name.
- `Secret::from_jwk_str(key_id, &str)` — what the old name suggested: parses a
  JWK JSON string.

`from_str` still works and delegates to `from_jwk_value`, so this is not a
breaking change; it only emits a deprecation warning. Both new constructors have
compiled doctests in place of the old `ignore`d example, which passed a `&str`
and could never have built.

## [0.5.14] - 2026-10-01

wasm32 builds again

`cargo check --target wasm32-unknown-unknown` failed in `getrandom`. 0.5.13
replaced the wasm32 `getrandom` 0.3 pin with 0.4, but `ahash` 0.8 (its
`runtime-rng` default) still pulls 0.3, which then had no `wasm_js` backend.
Both pins are now declared. Earlier releases were also broken on wasm32: from
`rand` 0.10, `getrandom` 0.4 had no backend there. Native builds are unaffected.

## [0.5.13] - 2026-10-01

`getrandom` 0.4 on wasm

No behaviour change. The wasm32 `getrandom` pin moves from 0.3 to 0.4
(`wasm_js`), the version `rand` 0.10 uses; the 0.3 pin was waiting on
ed25519-dalek, which has since moved.

## [0.5.12] - 2026-09-15

ML-DSA secrets can be written down

`Secret::generate_ml_dsa_{44,65,87}` produced a secret whose `secret_material`
was an empty string, so serialising one wrote `"privateKeyMultibase": ""` and
reading it back failed in `Secret::from_multibase`. The seed was never
corrupted — it was simply never written, and the loss only surfaced on the next
process start. Since `private_bytes`, `public_bytes` and `key_type` are all
`#[serde(skip)]`, that one field is the entire persisted form of a secret.

The generators now populate it from the existing `get_private_keymultibase()`,
whose ML-DSA arms were already correct and unreachable.
`ml_dsa_secret_survives_a_serde_round_trip` covers all three parameter sets and
asserts the key type as well, since it travels only as the multicodec prefix of
that string.

SLH-DSA is **deliberately unchanged and still memory-only**: FIPS 205 has no
registered private-key multicodec, so there is no prefix to carry the algorithm
and nothing to write that could be read back. `slh_dsa_secret_does_not_survive_a_serde_round_trip`
pins that, so the resemblance to the ML-DSA defect does not invite someone to
"fix" it by inventing a code point.

## [0.5.11] - 2026-09-07

`sha2` 0.11

No behaviour change and no public API change: these are private dependencies
here, which is what lets each crate move on its own schedule. Verified by
`cargo tree`/grep that no RustCrypto type appears in a public signature anywhere
in the workspace.

Version bump only; no source change. 23 tests green.

## [0.5.10] - 2026-08-23

dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.5.9] - 2026-07-31

Moves to **curve25519-dalek 5** (`ed25519-dalek` 2 -> 3, `x25519-dalek` 2 -> 3),
which brings rand_core 0.10 and signature 3 with it. rand 0.10 renamed `OsRng`
to `SysRng` *and* made it fallible (`TryRng<Error = SysError>`), so it no longer
satisfies dalek's `CryptoRng` bound; key generation moves to `rand::rng()`.

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` pins this crate through
`[patch.crates-io]`, and a minor bump would break the redirect and pull a second
copy from crates.io.

## [0.5.8] - 2026-06-13

Semver wave (W7 — release W11). `SecretsResolverError` is now `#[non_exhaustive]`
(match with a wildcard arm). Patch bump preserves the `didwebvh-rs`
`[patch.crates-io]` coupling — see ADR 0003 and the migration guide.

## [0.5.7] - 2026-06-06

- **Full P-521 secret support (#357).** Added `Secret::generate_p521`
  (load/generate P-521 key-agreement secrets) and wired P-521 into
  `from_multibase` decoding (`P521_PRIV`) — previously a P-521 private key
  could be *written* but not *loaded*. Also unblocked P-521 public-key
  multibase encoding, which had been hard-erroring with "P-521 is not
  supported". This lets a sender/recipient actually use a P-521
  key-agreement key end-to-end. New `p521` feature (on by default).

## [0.5.6] - 2026-05-28

- **SECURITY (HIGH):** Redact private key material in `Debug` output for
  both `Secret` and `SecretMaterial`. `Secret` derived `Debug` while
  holding `private_bytes` (raw key) and `secret_material` (the JWK
  including `d`), so any `{:?}` in a tracing span, error context, panic
  message, or stray `dbg!()` would dump the key to logs. `SecretMaterial`
  is `pub` and every variant (`JWK` with `d`, `PrivateKeyMultibase`,
  `Base58`, `Multibase`) carries the raw private key, so a direct `{:?}`
  on a value would leak there too. Manual `Debug` impls now print
  identifying metadata (id / type / key_type / variant name) and render
  the key bytes as `[REDACTED]`. `ZeroizeOnDrop` continues to cover heap
  lifetime; this closes the print-side leak.

## [0.5.5] - 2026-04-18

- **FEATURE:** `post-quantum` Cargo feature (off by default) with
  `ml-dsa` and `slh-dsa` sub-flags. Adds `Secret::generate_ml_dsa_44`,
  `generate_ml_dsa_65`, `generate_ml_dsa_87`, and
  `generate_slh_dsa_sha2_128s` methods.
- **FEATURE:** Multikey (multibase + multicodec) round-trip for
  ML-DSA-{44,65,67} using the registered `-priv-seed` codecs
  (`0x131a`–`0x131c`). SLH-DSA has no registered private-key codec;
  `get_private_keymultibase` returns a descriptive error so callers
  must persist raw private bytes themselves.
- **SAFETY:** `get_public_keymultibase` for P-256 / P-384 / secp256k1
  now bounds-checks `public_bytes` instead of panicking on out-of-range
  indexing. Pre-existing latent issue surfaced by the PQC review.
- **TESTS:** New varint-prefix pinning tests assert that emitted
  multikeys use the exact official multicodec codes (guards against
  drift toward invented codec values).

## [0.5.3] - 2026-04-15

- **CHANGE:** Removed `multihash` crate dependency (yanked `core2` transitive dep)
  - Multihash encoding now uses inline varint encoding via existing `unsigned-varint`
    dependency — output is byte-identical

## [0.5.2] - 2026-02-13

3rd November October 2025

- **BREAKING:** Now uses the affinidi-crypto library for all cryptographic operations
- **FEATURE:** Added ability to deserialize `Secret` from a privateKeyMultiBase
  string

## [0.4.0] - 2025-11-03

3rd November October 2025

- **BREAKING:** `Secret::from_multibase()` API changed to just need a private string

## [0.3.5] - 2025-10-22

- **FIX:** ed25519 --> x25519 bit swap was inverted

## [0.3.4] - 2025-10-21

- **FEATURE:** Ability to convert Ed25519 secret to X25519 secret is now public
  - `ed25519_private_to_x25519_private_key()`

## [0.3.3] - 2025-10-12

- **IMPROVEMENT:** Implemented stronger and more consistent zeroize on drop for
  `Secret`
  - This may cause breaking changes for apps where they were not using references
    to `Secret`

## [0.3.2] - 2025-10-09

- **FIX:** secp256k1 Public point compression was off by a byte causing decrypt
  failures.
  - No loss of security as it hard failed to decrypt

## [0.3.1] - 2025-10-08

- **FIX:** P-256 and P-384 Public point compression was off by a byte causing decrypt
  failures.
  - No loss of security as it hard failed to decrypt
- **FIX:** Incorrect Curve String in JWK representation of public-keys for P-256
  and P-384
  - Changed `P256` to `P-256` and `P384` to `P-384`
- **CHORE:** Additional Unit Tests added (50.77% Coverage)

## [0.3.0] - 2025-10-03

- **FEATURE:** `Secret::generate_ed25519()` now allows for creation from optional
  seed
- **FEATURE:** `Secret::generate_x25519()` now allows for creation from optional
  seed
- **NOTE:** The above changes causes a breaking API change

## [0.2.2] - 2025-10-01

Also covers 0.2.1, released the same day.

- **FIX:** Secret struct deserialization was not correct
  - Added a unit test to check deserialization of Secret
  - serde now correctly names the SecretMaterial fields
- **FIX:** JWK conversions from bytes were not correct for Ecliptic Curves

## [0.2.0] - 2025-09-30

- **IMPROVEMENT:** SSI Crate dependency removed from this library
- **IMPROVEMENT:** Crypto methods added directly to this library for easier 3rd
  party usage

## [0.1.18] - 2025-09-13

- **IMPROVEMENT:** Crate can now be compiled to a WASM compatible library
- **FIX:** Incorrect encoding on multikey public_keys for P-256, P384 and secp256k1

## [0.1.16] - 2025-09-10

- **IMPROVEMENT:** Removing SSI crate as a dependency
- **IMPROVEMENT:** Added ability to create ED25519 keys directly

## [0.1.14] - 2025-09-08

- **FIX:** X25519 Secrets had type set to Ed25519

## [0.1.13] - 2025-09-02

- **FEATURE:** Ability to convert a ED25519 Secret to a X25519 Secret added
- **MAINTENANCE:** Dependencies updated

## [0.1.12] - 2025-06-09

- **MAINTENANCE:** Dependencies updated
- **MAINTENANCE:** Addressing Rust linting warnings
- **CHANGE:** Hashing of publickeys returns base58 only not multiencode

## [0.1.11] - 2025-06-14

- **MAINTENANCE:** Updated SSI crate from 0.11 to 0.12
- **FEATURE:** Loading JWK format keys will support public/private byte methods
  - This has been implemented using a Inner Shadow struct for Secret `Deseralization`

## [0.1.10] - 2025-06-06

- **FIX:** Generating a hash of the public key `multibase` was incorrect
- **FEATURE:** Added `get_hash()` to `Secrets` allowing for easier hashing of keys
  without converting to a secret
- **TESTS:** Added more unit tests to test functionality of `get_hash()`

## [0.1.9] - 2025-05-29

- **MAINTENANCE:** Crate dependencies updated
- **FEATURE:** `get_public_bytes()` and `get_private_bytes()` methods added
- **FEATURE:** `get_public_multibase()` and `get_private_multibase()` methods added
  - Returns a MultiKey format String
- **FEATURE:** `get_public_multibase_hash()` method added
  - Returns a Base58btc encoded Multihash of the MultiKey Public Key
  - Useful for checks against pre-shared keys without disclosing the key itself

## [0.1.7] - 2025-03-27

- Removed drop() trait implementation as was causing the SecretsTask to close early

## [0.1.0] - 2025-03-03

- Initial release of crate
