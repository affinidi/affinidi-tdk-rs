# did:webvh implementation

[![Crates.io](https://img.shields.io/crates/v/did-webvh.svg)](https://crates.io/crates/did-webvh)
[![Documentation](https://docs.rs/did-webvh/badge.svg)](https://docs.rs/did-webvh)
[![Rust](https://img.shields.io/badge/rust-1.88.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-webvh)

An implementation of the [did:webvh](https://identity.foundation/didwebvh/v1.0/)
method in Rust. Supports version 1.0 spec.

This implementation is part of the [affinidi-did-resolver](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver)
and works with the [Rust SSI Library](https://github.com/spruceid/ssi/)

A helpful implementation site is the [webvh DID Method Information](https://didwebvh.info/)
site

## [Change log](../../CHANGELOG.md)

## Features

- [x] Create a did:webvh LogEntry and DID Document
- [x] Resolve a did:webvh method
- [x] Validate webvh LogEntries to v1.0 specification
- [x] Update webvh DID
- [x] Revoke webvh DID
- [x] Witness webvh DID
- [x] Migration of DID (portability)
- [x] Validate witness information

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
did-webvh = "0.1.6"
```

Then:

```rust
use did_webvh::DIDWebVHState;

let mut webvh = DIDWebVHState::default();

// Load LogEntries from a file
webvh.load_log_entries_from_file("did.jsonl")?;
```

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

`did-witness.json` where Witness Proofs are saved.

`did.jsonl-secrets` is the default file containing key secrets

## Is webvh performant?

There is a lot going on with the webvh DID method. A lot of keys, signing and
validations

Depending on how often you are creating LogEntries, number of witnesses etc can
have a big impact on performance.

To help with testing different usage scenario's, there is an example tool that can
help you with testing real-world performance of the webvh method.

To get options for the `generate_history` performance tool, run:

```Bash
cargo run --release --example generate_history -- --help
```

For example, to generate 200 LogEntries with 10 witnesses each, you can run:

```Bash
cargo run --release --example generate_histroy -- -c 200 -w 10
```

This tool will generate the output to

- did.jsonl (LogEntries)
- did-witness.json (Witness Proofs)

## License

Licensed under:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
