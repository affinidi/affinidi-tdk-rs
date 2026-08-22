# affinidi-did-ethr

Minimal `did:ethr` DID method resolver for the Affinidi TDK.

Resolves `did:ethr:[{network}:]{address-or-public-key}` into a DID Document,
with no network access and no dependencies beyond `affinidi-did-common`,
`k256` and `sha3`.

## Scope: genesis documents only

Resolution is a pure derivation from the identifier — what the DID resolves to
before any on-chain change. This crate does **not** replay ERC-1056
`DIDRegistry` events, so delegates, attributes and owner changes recorded
on-chain are not reflected.

This matches the behaviour of the `did-ethr` crate it replaced. It is a
deliberate limit: **a `did:ethr` document from this crate is not proof of
current on-chain control**, because a controller may have rotated keys in the
registry since the DID was minted.

## Identifier forms

| Form | Length | Verification methods |
| --- | --- | --- |
| Account address | `0x` + 40 hex | `#controller` (`EcdsaSecp256k1RecoveryMethod2020`), `#Eip712Method2021` |
| Compressed public key | `0x` + 66 hex | `#controller` (`EcdsaSecp256k1RecoveryMethod2020`), `#controllerKey` (`EcdsaSecp256k1VerificationKey2019`) |

The address form carries the address through exactly as written in the DID.
The public-key form *derives* the address, and emits it EIP-55 checksummed.

Named networks (`mainnet`, `morden`, `ropsten`, `rinkeby`, `goerli`, `kovan`)
map to their chain ids; anything else must be an explicit `0x`-prefixed hex
chain id.

## Stricter than the crate it replaced

The upstream implementation switched on identifier *length* alone and copied
the result into `blockchainAccountId` unchecked, so `did:ethr:0xZZ…` (42
characters, not hex) resolved to a document naming an impossible account. This
crate validates the hex and rejects it.

## Conformance

Both resolution vectors from the `did-ethr` 0.3.2 test suite — the method
specification's "Create (Register)" example and the `tests/did-pk.jsonld`
fixture — are asserted byte-for-byte in `src/lib.rs`.

## Why this crate exists

Upstream `did-ethr` reaches the rest of the `ssi-*` stack, which pulls `im`,
`sized-chunks`, `bitmaps`, `smallstr` and `proc-macro-error` — all unmaintained
and archived upstream with no fixed release (RUSTSEC-2026-0248 / -0251 / -0247 /
-0215, RUSTSEC-2024-0370) — plus `reqwest 0.11` and with it the vulnerable
`h2 0.3.x` (RUSTSEC-2026-0258).

Almost all of that weight is JSON-LD `@context` machinery. Our `Document`
carries `@context` as plain JSON, so re-implementing the derivation here drops
the entire chain. Same reasoning as the sibling `affinidi-did-web` crate.
