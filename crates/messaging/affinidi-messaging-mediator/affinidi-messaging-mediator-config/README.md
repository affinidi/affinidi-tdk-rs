# affinidi-messaging-mediator-config

Raw TOML configuration **schema** for the Affinidi Messaging Mediator — the
serde `*ConfigRaw` types that mirror `mediator.toml`.

This crate is deliberately dependency-light (serde + the lean tier of
`affinidi-messaging-mediator-common`). It contains **only the on-disk shape**;
the resolved runtime `Config` (opened secret backends, JWT keys, the
DID-resolver client, the VTA refresher) and every `ConfigRaw → Config`
conversion live in the `affinidi-messaging-mediator` binary, which re-exports
these types.

The goal is one schema with two consumers — the mediator and the
`mediator-setup` wizard — instead of the wizard hand-rendering TOML that can
drift from what the mediator parses.
