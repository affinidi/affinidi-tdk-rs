# did-webvh Rust implementation

An implementation of the [did:webvh](https://identity.foundation/didwebvh/v1.0/)
method in Rust. Supports version 1.0 spec.

This implementation is part of the [affinidi-did-resolver](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver)
and works with the [Rust SSI Library](https://github.com/spruceid/ssi/)

A helpful implementation site is the [webvh DID Method Information](https://didwebvh.info/)
site

## Everyone likes a wizard

Getting started with webvh at first can be daunting given the complexity of the
specification and supporting infrastructure such as witness and watcher nodes.

To help with getting started, a wizard for webvh has been created to help you.

To run this wizard, you need to have [Rust](https://www.rust-lang.org/)
installed on your machine.

```Bash
cargo run --example wizard -- --help
```

> ***WARNING:*** *This wizard will generate secrets locally on your machine, and
display the secret on the screen.*
>
> **The wizard is meant for demonstration purposes only. Use in a production
environment is not recommended.**

### Default Wizard Files

`did.jsonl` is the default webvh LogEntry file that the wizard will create.

`did.jsonl-secrets` is the default file containing key secrets

## Implementation Status

- [x] Create a did:webvh LogEntry and DID Document
- [x] Resolve a did:webvh method
- [x] Validate webvh LogEntries to v1.0 specification
- [x] Update webvh DID
- [x] Revoke webvh DID
- [x] Witness webvh DID
- [ ] Migration of DID (portability)
- [ ] Validate witness information
- [ ] Witness Node infrastructure
- [ ] Watcher Node infrastructure
- [ ] webvh hosting service
