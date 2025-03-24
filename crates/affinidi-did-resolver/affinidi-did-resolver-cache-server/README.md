# Affinidi DID Resolver - DID Universal Resolver Cache

Provides local caching for DID resolution and caching of DID Documents

This crate provides both a production running cache service and a SDK Library for client access to the ATN DID Universal Resolver.

Clients are acting as a DID Document cache locally, all resolving is handled separately.
Benefit of using this crate is that all DID resolver methods can be shifted to a single service so that changes can be more easily deployed.

## Prerequisites

Rust version 1.79

## DID Universal Resolver Cache Service

To run the resolver as a standalone network service, modify the `./conf/cache-conf.toml` configuration file, or set the ENV variables.

`cargo run` will start the service, running in a production environment is beyond the scope of this crate.

The service uses WebSockets for transport, operates a single service wide cache that if a DID lookup results in a hit miss, gets handed to a pool of resolvers for parallel resolving. Requests from clients can be multiplexed and may be responded to out of order, the client side is responsible for matching result to each request.

## Client DID Document Cache

The client side runs a local in-memory cache of DID Documents, if not known locally it will pass the request to the DID Universal Resolver Service and wait for a response.

This implementation is thread-safe and can be cloned into multiple threads.

To use ATN DID Universal Resolver Cache in other services, add this crate to your project Cargo.toml and utilize example code similar to:
