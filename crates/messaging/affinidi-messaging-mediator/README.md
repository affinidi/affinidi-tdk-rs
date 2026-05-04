# affinidi-messaging-mediator

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging/affinidi-messaging-mediator)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A mediator and relay service supporting
[DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/).
Handles connections, permissions, and message routing between messaging
participants.

## Quick Start

### 1. Start the storage backend (Redis-only — Fjall is embedded)

If you picked Fjall in the wizard, skip this step — Fjall stores
its data in a local directory and needs no sidecar. For Redis:

```bash
docker run --name=redis-local --publish=6379:6379 --hostname=redis \
  --restart=on-failure --detach redis:latest
```

### 2. Run the Setup Wizard

The setup wizard generates all configuration, keys, and secrets in one step:

```bash
cargo run --bin mediator-setup
```

The interactive TUI guides you through:

1. **Deployment type** — local dev, headless server, or container
2. **Protocol** — DIDComm v2 (recommended) or TSP (experimental)
3. **DID configuration** — did:peer, did:webvh, or VTA-managed
4. **Key storage** — file (`?encrypt=1` opt-in), OS keyring, AWS
   Secrets Manager, GCP Secret Manager, Azure Key Vault, or
   HashiCorp Vault
5. **SSL/TLS** — none (use a proxy), existing certs, or self-signed
6. **Database** — Redis URL (multi-node cluster) or Fjall data
   directory (single-node embedded LSM, no sidecar)
7. **Admin account** — generate did:key, paste existing, or skip

The wizard generates:
- `conf/mediator.toml` — full configuration with real cryptographic material
- `conf/keys/` — SSL certificates (if using self-signed)
- Admin DID and private key (displayed on screen — save securely)
- Per-key secret-backend entries pushed into your chosen backend
  (no inline secrets in `mediator.toml`)

### 3. Build and Run

After the wizard completes, it prints the exact build and run commands:

```bash
# Default DIDComm build
cargo build --release -p affinidi-messaging-mediator

# Run with generated config
cargo run --release -p affinidi-messaging-mediator -- -c conf/mediator.toml
```

## Non-Interactive Setup (CI/CD)

For automated environments, use the `--non-interactive` flag:

```bash
# Quick local development setup (all defaults)
cargo run --bin mediator-setup -- --non-interactive

# Production server with specific options
cargo run --bin mediator-setup -- --non-interactive \
  --deployment server \
  --did-method webvh \
  --public-url "mediator.example.com/mediator/v1" \
  --secret-storage aws \
  --database-url "redis://redis.internal:6379/"

# Container deployment
cargo run --bin mediator-setup -- --non-interactive \
  --deployment container \
  --did-method peer \
  --secret-storage file
```

Available CLI options:

| Flag | Values | Default |
|---|---|---|
| `--deployment` | `local`, `server`, `container` | `local` |
| `--protocol` | `didcomm`, `tsp` | `didcomm` |
| `--did-method` | `peer`, `webvh`, `vta` | per deployment |
| `--public-url` | URL string | (required for webvh) |
| `--secret-storage` | `file`, `keyring`, `aws`, `gcp`, `azure`, `vault` | per deployment |
| `--ssl` | `none`, `self-signed` | `none` |
| `--database-url` | Redis URL | `redis://127.0.0.1/` |
| `--admin` | `generate`, `skip` | `generate` |
| `--listen-address` | `ip:port` | `0.0.0.0:7037` |
| `-c, --config` | file path | `conf/mediator.toml` |

`--secret-storage` picks the backend kind and uses the per-backend
defaults baked into the wizard (region, project, vault name, etc.).
For non-default per-key configuration — a custom AWS region, a
sovereign-cloud Azure URL, a self-hosted Vault endpoint — use a
recipe TOML and `mediator-setup --from <recipe>`. See
[`docs/setup-guide.md`](docs/setup-guide.md) for the recipe schema.

## Feature Flags

The mediator's behaviour is composed from Cargo features in three
groups: **protocol**, **storage backend**, and **secret backend**.
At least one storage backend and (for any non-trivial deployment) at
least one secret backend must be enabled. Defaults are
`didcomm + redis-backend`.

### Protocol

| Feature | Default | Description |
|---|---|---|
| `didcomm` | Yes | DIDComm v2 — production protocol |
| `tsp` | No | Trust Spanning Protocol — experimental |

### Storage backend (pick one)

| Feature | Default | Use case |
|---|---|---|
| `redis-backend` | Yes | Multi-mediator clusters; cross-process pub/sub |
| `fjall-backend` | No | Single-node persistence; embedded LSM, no sidecar |
| `memory-backend` | No | Tests and in-process integration only |

### Secret backend (pick one for production)

| Feature | Default | Backend |
|---|---|---|
| (built-in) | always | `file://` (optionally `?encrypt=1` for AES-256-GCM + Argon2id) |
| `secrets-keyring` | No | OS keychain (`keyring://`) — macOS Keychain, Windows Credential Manager, Linux Secret Service |
| `secrets-aws` | No | AWS Secrets Manager (`aws_secrets://`) |
| `secrets-gcp` | No | GCP Secret Manager (`gcp_secrets://`) |
| `secrets-azure` | No | Azure Key Vault (`azure_keyvault://`) |
| `secrets-vault` | No | HashiCorp Vault KV v2 (`vault://`) |

The wizard automatically picks the right feature set and writes the
exact `cargo build` / `cargo install` / Dockerfile commands when it
finishes — most operators don't need to memorise these.

### Example builds

```bash
# Default — DIDComm + Redis, file:// or built-in keyring
cargo build -p affinidi-messaging-mediator

# Embedded single-node deployment (Fjall + keyring)
cargo build -p affinidi-messaging-mediator \
  --no-default-features \
  --features didcomm,fjall-backend,secrets-keyring

# Multi-cluster with AWS Secrets Manager
cargo build -p affinidi-messaging-mediator \
  --no-default-features \
  --features didcomm,redis-backend,secrets-aws

# TSP-only build (still needs a storage backend)
cargo build -p affinidi-messaging-mediator \
  --no-default-features \
  --features tsp,redis-backend
```

Picking `--no-default-features` always means you must list at least
one protocol feature and one storage backend feature explicitly —
otherwise the binary won't compile or won't have anywhere to keep
state.

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

## Redis Security

The mediator uses Redis for all message storage, session management, and queue
processing. Securing Redis is critical for production deployments.

### Authentication

Always configure Redis authentication in production:

```bash
# With password (requirepass)
redis://:yourpassword@host:6379/

# With ACL user and password (Redis 6+)
redis://mediator:secretpass@host:6379/
```

Set the password in `mediator.toml`:

```toml
[database]
database_url = "redis://:yourpassword@redis.internal:6379/"
```

Or via environment variable:

```bash
export DATABASE_URL="redis://:yourpassword@redis.internal:6379/"
```

### TLS Encryption

For encrypted connections, use the `rediss://` scheme (note the double `s`):

```toml
[database]
database_url = "rediss://:yourpassword@redis.internal:6379/"
```

### Security Recommendations

| Environment | Minimum Requirements |
|---|---|
| **Local dev** | No auth required (mediator logs a warning) |
| **Shared/staging** | Password authentication (`requirepass`) |
| **Production** | ACL users + TLS (`rediss://`) + network isolation |

The mediator automatically logs warnings at startup:
- **No authentication**: Warning for remote Redis, info-level for localhost
- **No TLS**: Warning when connecting to remote Redis without `rediss://`

### Database Partitions

When sharing a Redis instance across applications, use database partitions:

```toml
database_url = "redis://127.0.0.1/1"  # Uses database 1 (0-15 available)
```

## Secret Storage

The mediator stores its admin credential, JWT signing key, operating
keys, and the VTA cache in a single **unified backend** identified by a
URL in `mediator.toml`:

```toml
[secrets]
backend = "keyring://affinidi-mediator"   # or aws_secrets://, file://, …
cache_ttl = "30d"                          # optional, humantime
```

Pre-`0.14.0` deployments used `[vta].credential`,
`[security].mediator_secrets`, and `[security].jwt_authorization_secret`
fields directly in `mediator.toml`. Those are gone — see the migration
section in [docs/secrets-backend.md](docs/secrets-backend.md) for the
upgrade path.

### Picking a backend in the wizard

```sh
cargo run --bin mediator-setup
```

At the **Key Storage** step the wizard offers all six backends:
`keyring://`, `aws_secrets://`, `gcp_secrets://`,
`azure_keyvault://`, `vault://`, and `file://` (with an opt-in
`?encrypt=1` envelope-encryption flag for AES-256-GCM + Argon2id).
`vta://` is not a backend — the VTA is a key *source*, not a
store; its provisioned bundle is written into whichever real
backend you pick here.

### VTA Integration (Centralized Key Management)

When VTA integration is enabled, the mediator uses a
[Verifiable Trust Agent](https://github.com/OpenVTC/verifiable-trust-infrastructure)
for DID and operating-key management. The wizard's **VTA Online** flow
(or **VTA Sealed handoff** for air-gapped bootstraps) provisions the
admin credential into whichever real backend you chose at the Key
Storage step.

See:

- [docs/setup-guide.md](docs/setup-guide.md) — operator walkthrough
  for the three setup modes (Online / Sealed-mint / Sealed-export).
- [docs/secrets-backend.md](docs/secrets-backend.md) — well-known key
  schemas, HA topology, and the migration path from the legacy schema.

### Re-running the wizard / tearing down

```sh
mediator-setup --force-reprovision   # rotate every well-known key
mediator-setup --uninstall           # delete keys + local config files
mediator rotate-admin --dry-run      # preview an admin rotation
mediator rotate-admin                # actually rotate
```

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
| [`affinidi-messaging-mediator-setup`](./affinidi-messaging-mediator-setup/) | Interactive TUI setup wizard |
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
