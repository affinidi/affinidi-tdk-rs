# affinidi-did-webs

Rust implementation of the `did:webs` DID method: `did:web` discovery with
KERI-verified key state.

```toml
[dependencies]
affinidi-did-webs = "0.1"
```

## What it does

A `did:webs` identifier ends in a KERI **AID**, and publishes two artifacts:

| URL | contents |
|---|---|
| `https://<host>/<path>/<AID>/did.json` | the DID document, as a cache |
| `https://<host>/<path>/<AID>/keri.cesr` | the key event log it must be derived from |

The document this crate returns is **derived from the verified key event log**,
never copied from the published `did.json`. `did.json` carries no authority on
its own: it is cross-checked against the derivation, and a disagreement fails
the resolution rather than being resolved in either direction.

```rust,no_run
# async fn run() -> Result<(), affinidi_did_webs::DidWebsError> {
let doc = affinidi_did_webs::resolve(
    "did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
).await?;
# Ok(())
# }
```

Artifacts already in hand can be verified without any network access, which is
also how this crate is tested:

```rust,no_run
use affinidi_did_webs::{DidWebs, resolve_from_artifacts};

# fn run(keri_cesr: &[u8], did_json: &[u8]) -> Result<(), affinidi_did_webs::DidWebsError> {
let did = DidWebs::parse("did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")?;
let doc = resolve_from_artifacts(&did, keri_cesr, Some(did_json))?;
# Ok(())
# }
```

## What is verified

- Every key event's SAID, before any of its fields are trusted.
- The prior-event digest chain, and sequence ordering.
- Controller signatures, against the keys each event type is signed by.
- Pre-rotation commitments on every rotation.
- **Delegation**: a delegated event is accepted only if the delegator's own
  verified KEL, present in the same stream, anchors a seal naming that exact
  event. Delegation chains are followed, bounded, and cycle-checked.
- **Designated aliases**, which is where `alsoKnownAs` comes from. A DID
  document does not get to assert its own aliases: an alias counts only if the
  AID issued a credential saying so, and that credential is anchored in the
  AID's own key event log. The whole chain is checked — registry inception
  anchored, issuance anchored, attestation signed by the AID's key state, and
  not revoked. A break anywhere yields no aliases rather than a
  partially-trusted list.
- **Witness receipts**, when the key event log declares witnesses. An event
  whose own key state names backers and a threshold is only accepted once that
  many designated witnesses have receipted it — from the event's attachments or
  from separate `rct` messages. A KEL with `bt: 0` is unaffected.
- **Service endpoints**, from signed KERI endpoint authorisations. An endpoint
  appears only when two signed replies agree: `/end/role/add` from this AID
  authorising an identifier in a role, and `/loc/scheme` from *that* identifier
  saying where it is. `/end/role/cut` withdraws it, and the latest `dt` wins.
- The published `did.json`, against the derived key state: it must name this
  identifier (or its `did:web` twin) and publish exactly the keys the KEL
  authorised — no more and no fewer.

## What is not verified yet

- **Credential schema validation.** A designated-aliases attestation is matched
  by its schema SAID and its issuance chain is verified, but the credential body
  is not validated against the schema itself.

## Related crates

- [`affinidi-keri-core`](https://crates.io/crates/affinidi-keri-core) — KEL verification
- [`affinidi-did-web`](../did-web/) — the `did:web` half of the family
- [`affinidi-did-common`](../../affinidi-did-common/) — DID document types

## Contributing

See [CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md).

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
