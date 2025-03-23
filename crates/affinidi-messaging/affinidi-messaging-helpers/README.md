# Affinidi Messaging Helpers

Tools to help with setting up, managing and running examples against Affinidi Messaging

This crate contains the following helpers:

  1. `setup-environment` - Configures the initial environment for either local or remote mediators

## Debug logging

To enable logging at DEBUG level just for this crate,

```bash
export RUST_LOG=none,affinidi_messaging_helpers=debug
```

## Set Profile when running examples

You can have multiple environment profiles so that you can easily switch between different mediators.

The configuration file for profiles is generated from the `setup-environment` helper. This is stored in `affinidi-messaging-helpers/conf/profiles.json`

To set the profile you can either set an environment variable, or specify a profile at run-time

Using environment variable:

```bash
export TDK_ENVIRONMENT=local

cargo run --example mediator_ping
```

Using run-time option:

```bash
cargo run --example mediator_ping -- -p local
```

## Examples
