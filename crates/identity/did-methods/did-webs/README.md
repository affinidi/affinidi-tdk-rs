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

## HTTPS, and the loopback exception

Artifacts are fetched over **HTTPS**. Two exceptions use plain HTTP:

- a **loopback** host (`localhost`, `127.0.0.1`, `::1`), which cannot be
  intercepted from elsewhere and rarely has a certificate;
- any host, if you opt in with `WebsResolver::allow_http(true)`.

The opt-in exists because the reference implementation
(`hyperledger-labs/did-webs-resolver`) fetches over plain HTTP, so
interoperating with it — or with KERI tooling on a private network without TLS
— is otherwise impossible. Leave it off in production: a `did:webs` document is
derived from a self-verifying key event log, so an attacker cannot *forge* one,
but they can serve a **stale** log and hide a key rotation that has already
happened, which is the attack pre-rotation exists to defeat.

## Creating identifiers

Behind the optional `create` feature. Resolution never needs it, and it pulls
`affinidi-keri`.

```rust,no_run
use affinidi_did_webs::create::{CreateConfig, create};
use affinidi_keri::config::InceptionConfig;

# fn run() -> Result<(), affinidi_did_webs::DidWebsError> {
let salt = [42u8; 16];
let result = create(
    CreateConfig::builder("example.com")
        .inception(InceptionConfig::builder().salt(salt.to_vec()).build())
        .build(),
)?;

// Publish these two files; this crate does not.
for (name, bytes) in result.artifacts().files() {
    println!("{name}: {} bytes", bytes.len());
}
# Ok(())
# }
```

`create` and `update` return **bytes plus a custody record**, and publish
nothing. Rotation, interaction and service designation go through `update`,
which takes the prior artifacts as the state — the key event log *is*
`keri.cesr`, so there is nothing else to keep.

### What must survive between events

Rotating later needs the keys the previous event committed to **by digest**, and
a digest cannot be reversed — so they are not recoverable from the published
artifacts. Two things have to be kept, and they belong in different places:

| | where |
|---|---|
| the **salt**, from which every key is derived | wherever the application keeps secrets — `affinidi-secrets-resolver` here. This crate never stores it. |
| the **custody record** (generations, sequence number, last SAID) | not secret; keep it with the artifacts |

A custody record is superseded by every update. Keeping a stale one is
indistinguishable from losing the keys, so `update` refuses one whose sequence
number does not match the published log.

### `did.json` is generated by the resolver's own code path

So the two cannot disagree. That is a constraint rather than a convenience: a
resolver derives the document from the key event log and ignores whatever the
published file adds, so anything not backed by KERI artifacts would be silently
dropped on the way back. Service endpoints are supported because they *can* be
backed — each is emitted as signed `rpy` messages the resolver verifies.

### Designating `alsoKnownAs`

An alias is not something a document may assert about itself. Designating one
issues a credential — a registry, an issuance, and the attestation, each anchored
in the identifier's own key event log — which the resolver verifies before
carrying any alias back. `create` takes `also_known_as`, and `update` takes
`Change::AlsoKnownAs`.

`also_known_as_scid` designates this identifier's own `did:scid:ke:1` form. ⚠️
That format code is *proposed* in the did:scid registry rather than registered,
so its spelling may change.

There is no `also_known_as_web` switch: the `did:web` twin shares this
identifier's location and document, and the resolver adds it unconditionally, so
the switch could only ever be on.

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
