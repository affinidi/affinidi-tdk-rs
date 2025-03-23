# Affinidi DID Resolver

Library of useful Decentralized Identifier (DID) libraries.

This resolver running locally will exceed 250k DID Resolutions per second in full cache mode.

Bypassing the cache for simple computational DIDs like did:key for example, it can exceed 500K resolutions/second.

The main goal is to cache network bound DID resolutions like did:web or did:ethr etc.

> **IMPORTANT:**
> Affinidi DID Resolver is provided "as is" without any warranties or guarantees, and by using this framework, users agree to assume all risks associated with its deployment and use including implementing security, and privacy measures in their applications. Affinidi assumes no liability for any issues arising from the use or modification of the project.

## Crate Structure

- affinidi-did-resolver-cache-sdk

  - Developer friendly crate to instantiate either a local or network DID resolver with caching.
  - List of supported DID Methods is listed in the SDK README.

- affinidi-did-resolver-cache-server

  Remote server that resolves and caches DID Documents at scale.

- affinidi-did-resolver-methods

  Individual custom DID Method implementations reside here.

## Getting Started

### I want to start resolving DID's

1. Read the affinidi-did-resolver-cache-sdk documentation, and get started with the example code.

### I want to run a production network server for scale and offloading DID method resolving?

1. Read the affinidi-did-resolver-cache-server documentation, fire it up as a service where ever you like.
