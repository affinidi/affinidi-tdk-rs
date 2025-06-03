# Affinidi Messaging Helpers

Tools to help with setting up, managing and running examples for Affinidi Messaging.

This crate contains the following helpers:

  1. `setup-environment` - Configures the initial environment for either local or remote mediators.

## Debug Logging

To enable logging at the `DEBUG` level just for this crate:

```bash
export RUST_LOG=none,affinidi_messaging_helpers=debug,affinidi_messaging_sdk=info
```

## Set Profile When Running Examples

You can have multiple environment profiles to switch between different mediators easily.

The configuration file for profiles is generated from the `setup-environment` helper. It stores the profile information in `affinidi-messaging-helpers/conf/profiles.json` file.

To set the profile, you can either set an environment variable or specify a profile at run-time.

Using environment variable:

```bash
export TDK_ENVIRONMENT=local

cargo run --example mediator_ping
```

Using run-time option:

```bash
cargo run --example mediator_ping -- -e local
```

Go to the [examples folder](./examples/) to explore and run other examples.