# affinidi-messaging-mediator

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-mediator)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A mediator and relay service supporting
[DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/).
Handles connections, permissions, and message routing between messaging
participants.

## Feature Flags

Protocol and integration support is controlled via Cargo feature flags.

| Feature | Default | Description |
|---|---|---|
| `didcomm` | Yes | DIDComm v2 protocol support (authentication, inbound/outbound, OOB discovery) |
| `tsp` | No | Trust Spanning Protocol support |
| `vta-aws-secrets` | No | VTA credential storage via AWS Secrets Manager |
| `vta-keyring` | No | VTA credential storage via OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| `setup` | No | Interactive `mediator-setup-vta` CLI wizard |

```bash
# DIDComm only (default)
cargo build

# TSP only
cargo build --no-default-features --features tsp

# Both protocols
cargo build --features "didcomm,tsp"

# With VTA support (AWS production)
cargo build --features vta-aws-secrets

# Build the VTA setup wizard
cargo build --bin mediator-setup-vta --features setup
```

## Architecture

```mermaid
graph TD
    A["Alice"] -->|DIDComm / TSP| MED["Mediator Service"]
    B["Bob"] -->|DIDComm / TSP| MED
    MED ---|Message Storage| REDIS[(Redis)]
    MED --- ACL["Access Control<br/>Lists (ACLs)"]
    MED --- PROC["Processors<br/>(Forwarding, Expiry)"]
```

## Prerequisites

- Rust 1.90.0+ (2024 Edition)
- Docker (for Redis)
- Redis 8.0+

## Running the Mediator

### 1. Start Redis

```bash
docker run --name=redis-local --publish=6379:6379 --hostname=redis \
  --restart=on-failure --detach redis:latest
```

### 2. Configure the Environment

Run from the `affinidi-messaging` directory:

```bash
cargo run --bin setup_environment
```

This generates:
- Mediator DID and secrets
- Administration DID and secrets
- SSL certificates for local development
- Optionally, test user DIDs

### 3. Start the Mediator

```bash
cd affinidi-messaging-mediator
export REDIS_URL=redis://@localhost:6379
cargo run
```

## VTA Integration (Centralized Key Management)

The mediator can use a [Verifiable Trust Agent (VTA)](https://github.com/OpenVTC/verifiable-trust-infrastructure)
for centralized DID and key management instead of local file-based secrets.

See [docs/vta-setup-guide.md](docs/vta-setup-guide.md) for the full step-by-step guide.

### Quick Start with Setup Wizard

The fastest way to configure VTA integration:

```bash
# Build the setup wizard
cargo build --bin mediator-setup-vta --features setup

# Run it (uses conf/mediator.toml by default)
cargo run --bin mediator-setup-vta --features setup

# Or specify a config path
cargo run --bin mediator-setup-vta --features setup -- --config path/to/mediator.toml
```

The wizard accepts a **Context Provision Bundle** from `pnm contexts provision`
(recommended) and auto-configures the credential, context, DID, and
`mediator.toml` in a single flow.

### Quick Start without a Secure Credential Store

If you don't have access to AWS Secrets Manager or an OS keyring (e.g. in CI/CD,
Docker containers, or quick local testing), you can pass the VTA credential
directly as a `string://` value. No extra feature flags are required.

**Option A: In `mediator.toml`**

```toml
mediator_did = "vta://mediator"

[security]
mediator_secrets = "vta://mediator"

[vta]
credential = "string://<paste-your-base64url-credential-here>"
context = "mediator"
```

**Option B: Via environment variables**

```bash
export VTA_CREDENTIAL="string://eyJkaWQ..."
export VTA_CONTEXT="mediator"
export MEDIATOR_DID="vta://mediator"
export MEDIATOR_SECRETS="vta://mediator"
cargo run
```

> **Note:** With `string://`, VTA secrets are **not cached** between restarts.
> Every restart will re-fetch secrets from the VTA. For production deployments,
> use `aws_secrets://` or `keyring://` which enable local secret caching for
> offline resilience.

### Manual Configuration

Set `mediator_did` and `mediator_secrets` to use the `vta://` scheme, and add a
`[vta]` section:

```toml
mediator_did = "vta://mediator"

[security]
mediator_secrets = "vta://mediator"

[vta]
credential = "string://eyJkaWQ..."
context = "mediator"
```

See the [VTA setup guide](docs/vta-setup-guide.md) for all credential storage
backends, environment variable configuration, and production deployment
guidance.

## Access Control Lists (ACLs)

The mediator provides granular access control at both the mediator and DID level.

### Mediator-level ACLs

| Flag | Description |
|---|---|
| `explicit_allow` | Deny all DIDs except those explicitly allowed |
| `explicit_deny` | Allow all DIDs unless explicitly denied |
| `local_direct_delivery_allowed` | Allow direct messaging to local DIDs |

### DID-level ACLs

| Flag | Description |
|---|---|
| `ALLOW_ALL` | Allow all operations (default) |
| `DENY_ALL` | Deny all operations |
| `LOCAL` | Store messages for this DID |
| `SEND_MESSAGES` | DID can send messages |
| `RECEIVE_MESSAGES` | DID can receive messages |
| `SEND_FORWARDED` | DID can send forwarded messages |
| `RECEIVE_FORWARDED` | DID can receive forwarded messages |
| `ANON_RECEIVE` | DID can receive anonymous messages |
| `CREATE_INVITES` | DID can create OOB invites |

Self-change flags (e.g., `SEND_MESSAGES_CHANGE`, `SELF_MANAGE_LIST`) allow users
to update their own ACLs when permitted by the administrator.

## Operating Modes

| Mode | Mediator ACL | DID ACL | Direct Delivery | Use Case |
|---|---|---|---|---|
| **Private Closed** | `explicit_allow` | `DENY_ALL + LOCAL + SEND + RECEIVE` | Yes | Restricted corporate network |
| **Private Open** | `explicit_allow` | `ALLOW_ALL` | Yes | Internal company messaging |
| **Public Closed** | `explicit_deny` | `ALLOW_ALL + MODE_EXPLICIT_ALLOW` | No | Consent-based messaging |
| **Public Open** | `explicit_deny` | `ALLOW_ALL` | No | Unrestricted relay |
| **Public Mixed** | `explicit_deny` | `ALLOW_ALL + MODE_EXPLICIT_ALLOW` | No | Discovery + private channels |

See the `mediator.toml` configuration file for details on each mode.

## Sub-crates

| Crate | Description |
|---|---|
| [`affinidi-messaging-mediator-processors`](./affinidi-messaging-mediator-processors/) | Scalable parallel processors (message expiry, forwarding) |
| `affinidi-messaging-mediator-common` | Shared types for the mediator |

## Examples

Ensure the mediator is running, then:

```bash
# Mediator administration
cargo run --bin mediator_administration
```

See [affinidi-messaging-helpers](../affinidi-messaging-helpers/) for additional
examples.

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) — Client SDK
- [`affinidi-messaging-didcomm`](../affinidi-messaging-didcomm/) — DIDComm protocol
- [`affinidi-tsp`](../affinidi-tsp/) — Trust Spanning Protocol
- [`affinidi-messaging-core`](../affinidi-messaging-core/) — Protocol-agnostic messaging traits
- [`affinidi-did-resolver`](../../affinidi-did-resolver/) — DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
