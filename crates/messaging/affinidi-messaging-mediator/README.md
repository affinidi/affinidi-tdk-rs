# affinidi-messaging-mediator

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-mediator)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A mediator and relay service supporting
[DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/).
It handles connections, permissions, and message routing between messaging
participants.

## Quick start

### 1. Start Redis (skip for Fjall)

Fjall is embedded and keeps its data in a local directory, so it needs no
sidecar. For Redis:

```bash
docker run --name=redis-local --publish=6379:6379 --hostname=redis \
  --restart=on-failure --detach redis:latest
```

### 2. Run the setup wizard

The wizard generates the configuration, keys, and secrets in one step:

```bash
cargo run --locked --bin mediator-setup
```

It asks for:

1. **Deployment type**: local dev, headless server, or container.
2. **Protocol**: DIDComm v2 only, or DIDComm v2 + TSP.
3. **DID**: did:peer, did:webvh, or VTA-managed.
4. **Key storage**: one of the [secret backends](#secret-storage).
5. **SSL/TLS**: none (use a proxy), existing certificates, or self-signed.
6. **Database**: a Redis URL, or a Fjall data directory (single node).
7. **Admin account**: generate a did:key, paste an existing one, or skip.

It writes:

- `conf/mediator.toml`, the full configuration. It holds no secrets.
- `conf/keys/`, SSL certificates (self-signed mode only).
- The admin DID and private key, shown on screen. Save them securely.
- The mediator's secrets, written to the backend you chose.

### 3. Build and run

The wizard prints the exact build and run commands when it finishes. For the
default build:

```bash
cargo build --release --locked -p affinidi-messaging-mediator
cargo run --release --locked -p affinidi-messaging-mediator -- -c conf/mediator.toml
```

## Non-interactive setup (CI/CD)

```bash
# Local development
cargo run --locked --bin mediator-setup -- --non-interactive --did-method peer

# Production server
cargo run --locked --bin mediator-setup -- --non-interactive \
  --deployment server \
  --did-method webvh \
  --public-url "mediator.example.com/mediator/v1" \
  --secret-storage aws \
  --database-url "redis://redis.internal:6379/"

# Container
cargo run --locked --bin mediator-setup -- --non-interactive \
  --deployment container \
  --did-method peer \
  --secret-storage file
```

| Flag | Values | Default |
|---|---|---|
| `--deployment` | `local`, `server`, `container` | `local` |
| `--protocol` | `didcomm` (DIDComm only), `tsp` (DIDComm + TSP) | `tsp` |
| `--did-method` | `peer`, `webvh`, `vta` | `vta` (see note) |
| `--public-url` | URL | required for `webvh` |
| `--key-suite` | `p256`, `secp256k1` (repeatable) | none (Ed25519 + X25519 only) |
| `--save-did-web` | flag | off |
| `--secret-storage` | `file`, `keyring`, `aws`, `gcp`, `azure`, `vault` | `keyring` |
| `--ssl` | `none`, `self-signed` | `none` |
| `--database-url` | Redis URL | `redis://127.0.0.1/` |
| `--admin` | `generate`, `skip` | `generate` |
| `--listen-address` | `ip:port` | `0.0.0.0:7037` |
| `-c, --config` | file path | `conf/mediator.toml` |
| `--force-reprovision` | flag | refuse to overwrite an existing setup |
| `--uninstall` | flag | delete the stored keys and local config |

`--non-interactive` cannot provision a VTA-managed DID. With the default
`--did-method vta` it writes a placeholder DID that you must replace by hand,
so pass `peer` or `webvh`, or use the TUI or a recipe for VTA setups.

`--secret-storage` picks only the backend kind and uses the wizard's defaults
(region, project, vault name). `k8s://` and any non-default backend URL (a
custom AWS region, a sovereign-cloud Azure URL, a remote Vault) need a recipe:
`mediator-setup --from <recipe.toml>`. See
[docs/setup-guide.md](docs/setup-guide.md#recipe-fields-by-mode) and
`tools/mediator-setup/examples/mediator-build.toml`.

## Feature flags

The default build is `didcomm`, `tsp`, `redis-backend`, `jemalloc` and
`vta`. With `--no-default-features`, list at least one protocol and one
storage backend, and add back `vta` and `jemalloc` if you want them.

### Protocol

| Feature | Default | Description |
|---|---|---|
| `didcomm` | Yes | DIDComm v2. |
| `tsp` | Yes | Trust Spanning Protocol. Run it with `didcomm`: TSP authenticates over the DIDComm session, so a TSP-only build has no auth path. |
| `didcomm-v1` | No | Accepts DIDComm v1 (Aries) forwards alongside v2. Implies `didcomm`. |

**TSP endpoint advertisement.** Other mediators can route TSP to this one
only if its DID document advertises a `TSPTransport` service:

- **did:web**: added automatically at startup, mirroring the
  `DIDCommMessaging` endpoint (both use `/inbound`).
- **did:peer / did:webvh**: the document is bound to the DID, so add the
  `TSPTransport` service when you generate the DID. The mediator logs a
  warning at startup if TSP is enabled and the service is missing.

For TSP usage (sending, receiving, relationships, WebSocket, auth), see the
[TSP cookbook](../../../docs/tsp/cookbook.md).

### Storage backend (pick one)

| Feature | Default | Use case |
|---|---|---|
| `redis-backend` | Yes | Multi-mediator clusters; cross-process pub/sub. |
| `fjall-backend` | No | Single-node persistence; embedded LSM, no sidecar. |
| `memory-backend` | No | Tests and in-process integration only. |

Select the backend at runtime with `[storage].backend` in `mediator.toml`
(env `STORAGE_BACKEND`, `redis` or `fjall`).

### Secret backend

`file://` is always compiled in. Every other backend is one opt-in feature.
See [docs/secrets-backend.md](docs/secrets-backend.md#which-backends-are-compiled-in).

| Feature | Backend URL |
|---|---|
| (built in) | `file://`, optionally `?encrypt=1` (AES-256-GCM, Argon2id) |
| `secrets-keyring` | `keyring://` (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| `secrets-aws` | `aws_secrets://` |
| `secrets-gcp` | `gcp_secrets://` |
| `secrets-azure` | `azure_keyvault://` |
| `secrets-vault` | `vault://` (token, Kubernetes, or AppRole auth) |
| `secrets-k8s` | `k8s://` (one Kubernetes `Secret`) |

### Other

| Feature | Default | Description |
|---|---|---|
| `vta` | Yes | VTA-backed key management and `mediator rotate-admin`. Self-hosted mediators don't need it. |
| `jemalloc` | Yes | jemalloc as the global allocator, so RSS falls back after load. |
| `aws` | No | `aws_parameter_store://` and `s3://` sources for `did_web_self_hosted`. Enabled by `secrets-aws`. |

### Example builds

```bash
# Default: DIDComm + TSP + Redis, file:// secrets
cargo build --locked -p affinidi-messaging-mediator

# Single node: Fjall + OS keyring
cargo build --locked -p affinidi-messaging-mediator \
  --no-default-features \
  --features didcomm,tsp,fjall-backend,secrets-keyring,jemalloc,vta

# Cluster with AWS Secrets Manager
cargo build --locked -p affinidi-messaging-mediator \
  --features secrets-aws
```

## Architecture

```mermaid
graph TD
    A["Alice"] -->|DIDComm / TSP| MED["Mediator Service"]
    B["Bob"] -->|DIDComm / TSP| MED
    MED ---|Message Storage| STORE[(Redis or Fjall)]
    MED --- ACL["Access Control<br/>Lists (ACLs)"]
    MED --- PROC["Processors<br/>(Forwarding, Expiry)"]
```

## Prerequisites

- Rust 1.95.0+ (2024 edition)
- For the Redis backend: Redis 7.1 or later, below 9.0 (checked at startup).
  Docker is the easiest way to run it locally.

## Redis security

With the Redis backend, Redis holds all messages, sessions and queues.

Set the connection URL in `mediator.toml` or with the `DATABASE_URL`
environment variable:

```toml
[database]
database_url = "redis://:yourpassword@redis.internal:6379/"   # requirepass
# database_url = "redis://mediator:secretpass@host:6379/"     # ACL user (Redis 6+)
# database_url = "rediss://:yourpassword@redis.internal:6379/" # TLS
# database_url = "redis://127.0.0.1/1"                         # database 1 of 0-15
```

| Environment | Minimum |
|---|---|
| Local dev | No auth. |
| Shared/staging | Password authentication (`requirepass`). |
| Production | ACL users, TLS (`rediss://`) and network isolation. |

At startup the mediator warns when a remote Redis has no authentication
(info level for localhost) and when a remote Redis is used without
`rediss://`.

## Secret storage

The mediator keeps its admin credential, JWT signing key, operating keys,
and VTA cache in one secret backend, named by a URL:

```toml
[secrets]
backend = "keyring://affinidi-mediator"   # or aws_secrets://, file://, ...
cache_ttl = "30d"                          # optional, humantime
```

On keyring, AWS, GCP, Azure and Vault, everything lives in one backend
secret, `mediator_secrets_bundle` (with the URL's prefix). `file://` and
`k8s://` already use one object. A deployment that still has one secret per
key is migrated on first start; if that fails, the mediator stops and says
why.

`vta://` is not a backend. The VTA is a key source; the wizard writes what it
provisions into the backend you pick.

[docs/secrets-backend.md](docs/secrets-backend.md) is the reference: backend
URLs, the bundle and its migration, IAM permissions, entry schemas, `/readyz`,
and HA.

### VTA integration

With a [Verifiable Trust Agent](https://github.com/OpenVTC/verifiable-trust-infrastructure),
the VTA manages the mediator's DID and operating keys. The wizard's
**Online** flow, or the **sealed handoff** for air-gapped hosts, writes the
admin credential into your secret backend. See
[docs/setup-guide.md](docs/setup-guide.md).

### Re-running the wizard, rotation, teardown

```sh
mediator-setup --force-reprovision   # overwrite an existing setup (rotates every key)
mediator-setup --uninstall           # delete stored keys and local config files
mediator rotate-admin --dry-run      # preview an admin credential rotation
mediator rotate-admin                # rotate it (VTA-linked deployments)
```

## Access control

Access control has four independent layers. [docs/acls.md](docs/acls.md) is
the full guide, including permission flags and deployment recipes.

| Layer | Scope | What it decides |
|---|---|---|
| `mediator_acl_mode` | mediator-wide | Whether unknown DIDs may authenticate, and who may add accounts. |
| `global_acl_default` | mediator-wide | The ACL set given to every new DID. |
| `MediatorACLSet` | per DID | What that DID may do. |
| Access list | per DID | Which senders that DID accepts messages from. |

| `mediator_acl_mode` | Meaning |
|---|---|
| `explicit_deny` | **Open.** Any DID may authenticate; unknown DIDs are registered with `global_acl_default`. |
| `explicit_allow` | **Closed.** Only pre-registered DIDs may authenticate. Only admins may add accounts. |

The shipped configuration is open (`explicit_deny`) with
`global_acl_default = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES"`:
direct messaging only, no relay or invites.

## More documentation

| Doc | Covers |
|---|---|
| [setup-guide.md](docs/setup-guide.md) | VTA setup modes (Online, sealed-mint, sealed-export) and recipes. |
| [secrets-backend.md](docs/secrets-backend.md) | Secret backends, entry schemas, migration, HA. |
| [acls.md](docs/acls.md) | Access control. |
| [cors-and-origin.md](docs/cors-and-origin.md) | CORS and WebSocket origin checks. |
| [didcomm-protocols.md](docs/didcomm-protocols.md) | Supported DIDComm protocols. |
| [mediation-and-routing.md](docs/mediation-and-routing.md) | Addressing: v2 is DID-addressed, v1 is keylist-addressed, and what gates reachability. |
| [multi-mediator.md](docs/multi-mediator.md) | Federating mediators: relay hops, blind vs rewrap, config and ACLs. |
| [memory-tuning.md](docs/memory-tuning.md) | Memory use and throughput knobs for Fjall and Redis. |
| [ERRORS.md](ERRORS.md) | Error codes. |

## Managing the mediator

`mediator-console` operates a running mediator from a terminal: statistics,
account queues, messages (inspect, delete, purge), ACLs and queue limits, the
audit log, and a live traffic monitor. Connect with the administrator profile
the wizard wrote (`conf/admin-monitor.json`) to manage the whole mediator, or
with an account's profile to manage that account.

```bash
cargo run --release -p affinidi-messaging-mediator-tui -- --profile conf/admin-monitor.json
```

See [affinidi-messaging-mediator-tui](../affinidi-messaging-mediator-tui/).

For a scripted example, run the mediator, then:

```bash
cargo run --locked --bin mediator_administration
```

More examples are in [affinidi-messaging-helpers](../affinidi-messaging-helpers/).

## Sub-crates

| Crate | Description |
|---|---|
| [`mediator-setup`](./tools/mediator-setup/) | Setup wizard (TUI and headless). |
| [`affinidi-messaging-mediator-common`](./affinidi-messaging-mediator-common/) | Shared types, storage traits, secret backends. |
| [`affinidi-messaging-mediator-config`](./affinidi-messaging-mediator-config/) | The `mediator.toml` schema. |
| [`affinidi-messaging-mediator-processors`](./affinidi-messaging-mediator-processors/) | Standalone forwarding and expiry processors (Redis). |

## Related crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/): client SDK
- [`affinidi-messaging-didcomm`](../affinidi-messaging-didcomm/): DIDComm protocol
- [`affinidi-tsp`](../affinidi-tsp/): Trust Spanning Protocol
- [`affinidi-messaging-core`](../affinidi-messaging-core/): protocol-agnostic messaging traits
- [`affinidi-did-resolver-cache-sdk`](../../identity/affinidi-did-resolver-cache-sdk/): DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
