# Attribution for the `did-*.jsonld` fixtures

The 19 `did-*.jsonld` files in this directory are copied **verbatim** from the
`did-pkh` crate, version 0.3.2, part of the [spruceid/ssi](https://github.com/spruceid/ssi)
project (`did-pkh/tests/`).

- Upstream: <https://github.com/spruceid/ssi/tree/main/crates/dids/methods/pkh>
- Upstream licence: Apache-2.0 — the same licence this workspace uses.

They are reproduced unmodified, as conformance vectors: `conformance.rs`
resolves each fixture's own `id` with `affinidi-did-pkh` and asserts the result
matches the file byte-for-byte. Keeping them unmodified is the point — they are
the evidence that replacing `did-pkh` did not change any document this
workspace emits.

Do not edit these files. If a fixture needs to change, the change belongs
upstream, and the divergence should be recorded here.
