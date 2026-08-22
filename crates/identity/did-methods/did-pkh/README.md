# affinidi-did-pkh

Minimal `did:pkh` DID method resolver for the Affinidi TDK.

Resolves a [CAIP-10](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md)
account id into a DID Document:

```text
did:pkh:{chain-namespace}:{chain-reference}:{account-address}
```

Resolution is a pure derivation from the identifier: no network access, no
chain state. The document describes the account the DID names, and nothing
about what that account currently holds.

## Supported chains

| Namespace | Verification methods |
| --- | --- |
| `tezos` | `#blockchainAccountId` (per `tz1`/`tz2`/`tz3` prefix), `#TezosMethod2021` |
| `eip155` | `#blockchainAccountId` (`EcdsaSecp256k1RecoveryMethod2020`) |
| `bip122` | `#blockchainAccountId` (`EcdsaSecp256k1RecoveryMethod2020`) |
| `solana` | `#controller` (`Ed25519VerificationKey2018`), `#SolanaMethod2021` |
| `aleo` | `#blockchainAccountId` (`BlockchainVerificationMethod2021`) |

The deprecated single-token prefixes `tz`, `eth`, `celo`, `poly`, `sol`, `btc`
and `doge` are still resolved, each pinned to its mainnet. The `eth` / `celo` /
`poly` forms keep their distinct `#Recovery2020` fragment (see
[spruceid/ssi#297](https://github.com/spruceid/ssi/issues/297)).

An unknown namespace is **refused**, not resolved generically: a document
naming a chain we cannot pick verification-method types for would assert key
material semantics that have not been established.

## Stricter than the crate it replaced

Upstream validated the Solana and Aleo addresses properly but accepted any
`eip155` address starting with `0x`, and checked only the three-character
prefix of a Tezos address. This crate additionally:

- validates `eip155` addresses as `0x` + exactly 40 hex digits;
- verifies the Tezos base58check checksum;
- enforces the CAIP-2 / CAIP-10 grammar on namespace, reference and address.

A malformed account id is refused here rather than copied into
`blockchainAccountId`, where it would read as a real account to every consumer
of the document.

## Conformance

All 19 `did-*.jsonld` fixtures from the `did-pkh` 0.3.2 test suite are checked
byte-for-byte in `tests/conformance.rs` — every namespace, in both the CAIP-10
and legacy forms.

## Why this crate exists

Upstream `did-pkh` reaches the rest of the `ssi-*` stack, which pulls `im`,
`sized-chunks`, `bitmaps`, `smallstr` and `proc-macro-error` — all unmaintained
and archived upstream with no fixed release — plus `reqwest 0.11` and the
vulnerable `h2 0.3.x`. See `affinidi-did-ethr` for the full rationale.
