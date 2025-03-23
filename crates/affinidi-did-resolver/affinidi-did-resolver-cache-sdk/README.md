# Affinidi DID Resolver- DID Universal Resolver Cache SDK

Provides local caching for DID resolution and caching of DID Documents

You can use this SDK in either local (resolving occurs locally) or in network (requests are forwarded to a remote server) mode.

## Supported DID Methods

- did:key
- did:ethr
- did:jwk
- did:pkh
- did:peer
- did:web
- did:example
  - NOTE: This is enabled using Rust feature `did:example`
  - NOTE: did:example must be manually loaded into the resolver as the DID DOC is NOT deterministic!

## Prerequisites

Rust version 1.85

NOTE: For network mode, you will need access to a running a DID Universal Resolver Cache!

## Local Mode

A local cache is operated and all DID resolving is handled from the client itself.

When handling DID methods that require network access (e.g did:web), then the client will call those network services.

### Example Local mode with defaults

```rust
    use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, errors::DIDCacheError, DIDCacheClient};

    // Create a new local client configuration, use default values
    let local_config = ClientConfigBuilder::default().build();
    let local_resolver = DIDCacheClient::new(local_config).await?;
    let doc = local_resolver.resolve("did:key:...").await?;

    match local_resolver.resolve(peer_did).await {
        Ok(request) => {
            println!(
                "Resolved DID ({}) did_hash({}) Document:\n{:#?}\n",
                request.did, request.did_hash, request.doc
            );
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
```

## Network Mode

NOTE: When in network mode, the SDK will still cache locally to save on remote calls!

All DID resolving is handled remotely, just the DID Document is returned and cached locally.

You will need to enable the crate feature `network` to use Network Mode.

### Example Network mode with optional settings

```rust
    use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, errors::DIDCacheError, DIDCacheClient};

    // create a network client configuration, set the service address.
    let network_config = ClientConfigBuilder::default()
        .with_network_mode("ws://127.0.0.1:8080/did/v1/ws")
        .with_cache_ttl(60) // Change the cache TTL to 60 seconds
        .with_network_timeout(20_000) // Change the network timeout to 20 seconds
        .build();
    let network_resolver = DIDCacheClient::new(network_config).await?;

    match local_resolver.resolve("did:key:...").await {
        Ok((request) => {
            println!(
                "Resolved DID ({}) did_hash({}) Document:\n{:#?}\n",
                request.did, request.did_hash, request.doc
            );
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
```

## Running benchmark suite for testing

A reference benchmark example is included that can be used to measure performance. To run this use the following:

`cargo run --features network --example benchmark -- -g 1000 -r 10000 -n ws://127.0.0.1:8080/did/v1/ws`

Run the above from the $affinidi-did-resolver/affinidi-did-resolver-cache-sdk directory

``` bash
Affinidi DID Cache SDK

Usage: benchmark [OPTIONS] --generate-count <GENERATE_COUNT> --resolve-count <RESOLVE_COUNT>

Options:
-n, --network-address <NETWORK_ADDRESS>
        network address if running in network mode (ws://127.0.0.1:8080/did/v1/ws)
-g, --generate-count <GENERATE_COUNT>
        Number of keys to generate
-r, --resolve-count <RESOLVE_COUNT>
        Number of DIDs to resolve
-h, --help
        Print help
-V, --version
        Print version
```
