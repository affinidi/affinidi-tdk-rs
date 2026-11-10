# A did:webs identifier on KERI 2.0, checked by keripy

`lifecycle.keri.cesr` and `lifecycle.did.json` are one identifier's published
artifacts, written by this crate's public API on KERI 2.0
(`examples/emit_keripy_fixture.rs`): created with designated aliases, key
agreement, a designated service and a controller endpoint; its key agreement
replaced, which revokes the old designation in its registry; rotated; then
given a new endpoint, endorsed under the rotation's key state.
`lifecycle.json` records what this crate read from the stream.

- **keripy accepts the whole stream**: `verify_ours.py` (keripy version in
  affinidi-keri-rs, `crates/affinidi-keri-core/tests/fixtures/keripy-v2/KERIPY_VERSION`)
  parses it as a resolver must, starting in genus 1, and checks keripy reaches
  the same KEL state, accepts the endpoint replies, and verifies every
  designation's SAIDs, framing, BLIDs and status with its own registry
  verifier (`vetBinds`).

  ```sh
  DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib python -I verify_ours.py .
  ```

- **In CI**, without keripy: `tests/ours_v2.rs` checks the committed fixture
  still resolves to what was recorded.

Regenerate after a change to what this crate writes, then re-run
`verify_ours.py`. UUIDs and timestamps are fresh each run, so the bytes differ
every time:

```sh
cargo run -p affinidi-did-webs --features create --example emit_keripy_fixture -- \
    crates/identity/did-methods/did-webs/tests/fixtures/ours-v2
```

## The published stream

Every message is appended as it is made, so key events and registry messages
interleave in the order they happened. Each 2.x message opens with the
genus-version counter `-_AAACAA` (P1). A designation is three messages after
the interaction event that anchors both its registry and its issuance: the
`rip` and its seal source couple, the `acm` (unsigned), and the `bup` with its
seal source couple and disclosed state. A revocation is an interaction event
and a further `bup`. Replies (`rpy`) name their sender in `i` and carry one
`-X` group naming the establishment event by its own sequence number.
