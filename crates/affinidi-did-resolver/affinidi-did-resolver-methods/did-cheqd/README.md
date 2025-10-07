# did-cheqd Rust implementation

This crate contains a resolver for DIDs of the did:cheqd method. The implementation resolves DIDs via gRPC network requests to the configured nodes. Default nodes for cheqd's mainnet & testnet can be used, or custom nodes can be opt-in by supplying a different gRPC URL configuration.

The implementations in this crate are largely inspired from cheqd's own typescript sdk.

This crate uses openwallet-foundation's [did-cheqd](https://github.com/openwallet-foundation/vcx/tree/main/did_core/did_methods/did_cheqd) crate which uses gRPC types and clients generated using tonic.
