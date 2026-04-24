# Mediator Secret Storage

The mediator stores every persistent secret it owns in a single
**unified backend** — a pluggable key-value store fronted by the
[`SecretStore`](../affinidi-messaging-mediator-common/src/secrets/store.rs)
trait. The backend is identified by a URL in `mediator.toml`:

```toml
[secrets]
backend = "keyring://affinidi-mediator"
# Optional VTA cache TTL — humantime, default 30d, 0 = forever.
cache_ttl = "30d"
```

This document is the operator reference for what's *inside* the
backend (the well-known keys), how to bring up the mediator without
running the interactive wizard, and how to migrate from the legacy
`[vta].credential` / `mediator_secrets` schema.

---

## Supported backend URLs

| Scheme | Shape | Encryption | Notes |
|--------|-------|------------|-------|
| `keyring://<service>` | OS keychain entry per key | OS-managed | Single-host only; great for desktop dev |
| `file:///<absolute-path>` | One JSON file, base64 values | none | Dev only — plaintext on disk |
| `file:///<absolute-path>?encrypt=1` | One JSON file, AEAD-sealed | AES-256-GCM, Argon2id-derived key | Requires `MEDIATOR_FILE_BACKEND_PASSPHRASE` (or `_FILE`) at boot |
| `aws_secrets://<region>/<prefix>` | One AWS secret per key, named `<prefix><key>` | AWS server-side | Build with `--features secrets-aws` |
| `gcp_secrets://<project>/<prefix>` | One GCP Secret per key, named `<prefix><key>`; `put` appends a new version | Google-managed | Auth via Application Default Credentials. Build with `--features secrets-gcp` |
| `azure_keyvault://<vault-name-or-url>` | One Key Vault secret per key, names normalised `_` → `-` | Azure-managed | Bare name → `https://<name>.vault.azure.net`; full `https://…` URL passed verbatim (sovereign clouds). Auth via `DeveloperToolsCredential` (Azure CLI). Build with `--features secrets-azure` |
| `vault://<endpoint>/<mount>[/<prefix>]` | KV v2 secret per key under `<mount>`, prefixed path | Vault-managed | First path segment = KV v2 mount; remainder = per-key prefix. Auth via `VAULT_TOKEN`. Build with `--features secrets-vault` |

`string://` (inline secrets in TOML) is **not supported**. Inline
secrets in a config file are unsafe even for CI; use `file://` with
env-var overrides for ephemeral CI tests, and one of the cloud
backends for production.

`vta://` is **not** a backend. The VTA is a key *source* — operating
keys can be fetched live from the VTA at startup — but the mediator's
admin credential, JWT signing key, and (optionally) cached operating
keys all live in whichever real backend the operator picks.

---

## Well-known key schemas

Every mediator entry is wrapped in a schema-versioned envelope:

```json
{
  "version": 1,
  "kind": "<type-tag>",
  "data": { /* type-specific payload */ }
}
```

The `kind` field gates deserialisation — the mediator refuses to
read an entry whose `kind` doesn't match what it expects, so a
hand-edited entry of the wrong shape fails loudly rather than
silently misbehaving.

Operators provisioning the backend by hand (Terraform, k8s
`Secret`, Vault policies) need to know two things per key: the
**name** under which the mediator looks it up, and the **`data`
shape** inside the envelope.

### `mediator_admin_credential` — kind `admin-credential`

The persistent admin identity for a mediator. Two valid shapes
share the same envelope:

- **VTA-linked** (`vta_did` + `vta_url` both set): the mediator
  uses the credential to authenticate to its VTA at boot. Produced
  by the online-VTA or sealed-handoff flows.
- **Self-hosted** (`vta_did` + `vta_url` both omitted / null): the
  mediator does not talk to a VTA; the credential is a persistent
  record of the admin DID + private key so a later wizard run can
  reuse it. The runtime skips the VTA integration branch for these.

Half-set combinations (only one of `vta_did` / `vta_url` populated)
are rejected at write time.

```json
{
  "version": 1,
  "kind": "admin-credential",
  "data": {
    "did": "did:key:z6Mk…",
    "private_key_multibase": "z3u2…",
    "vta_did": "did:webvh:vta.example.com",
    "vta_url": "https://vta.example.com",
    "context": "mediator"
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `did` | string | Mediator's admin DID (must start with `did:`). |
| `private_key_multibase` | string | Ed25519 seed, base58btc-encoded with multibase prefix. |
| `vta_did` | string \| null | DID of the VTA this mediator authenticates against (`null` or absent for self-hosted; must start with `did:` when set). |
| `vta_url` | string \| null | Optional REST URL override. Present iff `vta_did` is. |
| `context` | string | VTA context this mediator lives in. Defaults to `"mediator"` if omitted. Ignored for self-hosted. |

Provision via `mediator-setup` (Online VTA, Sealed handoff, or
self-hosted ADMIN_GENERATE) or hand-write the JSON above. Rotate
via `mediator rotate-admin` (VTA-linked only).

### `mediator_jwt_secret` — kind `jwt-secret`

HMAC secret used to sign the mediator admin API's JWTs. **Required**
in every deployment.

```json
{
  "version": 1,
  "kind": "jwt-secret",
  "data": [/* raw Ed25519 PKCS8 bytes, JSON byte array */]
}
```

The mediator passes the bytes verbatim to
`EncodingKey::from_ed_der(&data)` and `Ed25519KeyPair::from_pkcs8(&data)`
— same shape `ring::signature::Ed25519KeyPair::generate_pkcs8()` emits.

Provision via the wizard (`generate` mode), or pre-provision externally
and choose `provide` mode in the wizard so the mediator reads the key
from `MEDIATOR_JWT_SECRET` / `--jwt-secret-file` at boot.

### `mediator_operating_secrets` — kind `operating-secrets`

Operating keys for the mediator's own DID. Populated in self-hosted
mode (did:peer / did:webvh); **absent** in VTA-managed deployments —
those fetch operating keys from the VTA at startup.

```json
{
  "version": 1,
  "kind": "operating-secrets",
  "data": [
    {
      "id": "did:peer:…#key-1",
      "type": "Ed25519VerificationKey2020",
      "private_key_multibase": "z3u2…"
    },
    /* … one entry per signing / key-agreement key … */
  ]
}
```

`data` is the JSON serialisation of `Vec<affinidi_secrets_resolver::secrets::Secret>`.
Hand-provisioning is unusual — this is normally written by the
wizard when the operator picks did:peer or did:webvh.

### `mediator_operating_did_document` — kind `did-document`

Optional cached copy of the mediator's own DID document (self-hosted
mode). Mediator boots without it; if present, used to short-circuit
DID resolution for the mediator's own identity.

```json
{
  "version": 1,
  "kind": "did-document",
  "data": { /* W3C DID Document JSON */ }
}
```

### `mediator_vta_last_known_bundle` — kind `vta-cached-bundle`

Last-good `DidSecretsBundle` snapshot from the VTA. Used as a
fallback at boot when the VTA is unreachable. Carries an HMAC-SHA256
keyed from the admin credential's private key (HKDF-SHA256, salt
`"mediator-vta-cache-hmac-v1"`) so a tampered or wrong-admin-key
entry is rejected as if absent.

```json
{
  "version": 1,
  "kind": "vta-cached-bundle",
  "data": {
    "fetched_at": 1735689600,
    "ttl_secs": 2592000,
    "hmac": "<hex>",
    "bundle": { /* DidSecretsBundle JSON */ }
  }
}
```

Operators **should not** hand-provision this entry — the HMAC
derivation is private to the mediator. Let the runtime populate it on
the first successful VTA fetch.

### `mediator_bootstrap_ephemeral_seed_<bundle_id_hex>` — kind `ephemeral-seed`

Transient HPKE recipient seed written by the non-interactive
sealed-handoff wizard in phase 1 (`mediator-setup --from <recipe>`)
and consumed in phase 2 (`… --bundle <path>`). Phase 2 deletes the
entry on successful open; a stranded entry is swept automatically
by the next wizard run that ages past the TTL (default 24h,
override via `MEDIATOR_BOOTSTRAP_SEED_TTL` — any `humantime`
duration like `"6h"` or `"7d"`).

```json
{
  "version": 1,
  "kind": "ephemeral-seed",
  "created_at": 1735689600,
  "data": { "seed_b64": "<base64url of 32-byte Ed25519 seed>" }
}
```

Operators should not hand-provision this entry; the wizard owns
both sides of the round-trip.

### `mediator_bootstrap_seed_index` — kind `bootstrap-seed-index`

Sibling index key that `mediator_bootstrap_ephemeral_seed_*` entries
register themselves in so the sweeper can enumerate without a
`list_keys(prefix)` trait call. Each entry carries the bundle id and
a Unix-seconds timestamp.

```json
{
  "version": 1,
  "kind": "bootstrap-seed-index",
  "data": {
    "entries": [
      { "bundle_id_hex": "abcd…", "created_at": 1735689600 }
    ]
  }
}
```

Hand-wiping this key is safe — the worst case is a stranded
ephemeral-seed entry that no longer has a sweep record, which
operators can then clean up with a direct backend delete. The
wizard re-creates the index on the next phase-1 run.

### `mediator_probe_*` — no kind

End-to-end probe sentinels written + deleted in a single call by
`SecretStore::probe()`. Short-lived; no operator interaction.
Listed here only so the `mediator_probe_` prefix isn't a surprise
when operators browse the backend.

---

## Operator quick-reference

### Pre-provisioning a backend without the wizard

For Terraform / k8s rollouts that can't run the interactive TUI:

1. Pick a backend URL and write `mediator.toml`:
   ```toml
   mediator_did = "did://did:webvh:mediator.example.com"

   [secrets]
   backend = "aws_secrets://us-east-1/mediator/"
   cache_ttl = "30d"
   ```
2. Provision the well-known keys above into your backend. The
   envelope must be exactly the shape shown — wrong `kind` or
   missing fields → boot failure with a clear log line.
3. (Encrypted file backend only) ship the passphrase as
   `MEDIATOR_FILE_BACKEND_PASSPHRASE` or via
   `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE=/run/secrets/mediator-fb-pass`.

`/readyz` will return `secrets_backend_reachable: true` +
`operating_keys_loaded: true` once provisioning is correct.

### Inspecting a live deployment

`/readyz` (default `/mediator/v1/readyz`) returns:

```json
{
  "status": "ready",
  "secrets_backend_reachable": true,
  "secrets_backend_url": "aws_secrets://us-east-1/mediator/",
  "vta_cache_age_secs": 1834,
  "operating_keys_loaded": true,
  "checks": [/* per-component pass/fail/warn */]
}
```

`secrets_backend_reachable: false` flips the HTTP status to 503.

### Rotation

```sh
# Preview the rotation against the VTA without writing anything.
mediator rotate-admin --dry-run

# Perform the rotation.
mediator rotate-admin
```

Both forms reuse the existing admin credential to authenticate, mint
a fresh `did:key`, mirror the existing ACL scope onto the new DID,
write the new credential, and revoke the old ACL entry. Old + new
DIDs are logged at `info!` for audit.

---

## High availability

The mediator is **single-writer** by design. The unified secret
backend was specified, and the redis circuit-breaker / rate-limiter
state was implemented, against that assumption. Two mediator
processes pointing at the same backend racing on `mediator/admin/credential`
or `mediator/jwt/secret` would corrupt each other.

For HA you want a *cold standby* topology: one active mediator + one
or more replicas at the orchestrator level (k8s `Deployment` with
`replicas: 1` + a leader-election sidecar; ECS service with
`desired_count: 1` + an external watcher; systemd active/passive
pair). All replicas read the *same* backend so a failover replica
boots with the live credentials, but only one is the active writer
at any moment.

### Backend choice for HA

| Backend | Suitable for HA? | Why |
|---------|------------------|-----|
| `keyring://` | No | Per-host OS keyring; failover replica wouldn't see the same keys. |
| `file://` | No | Local filesystem path; same problem. |
| `file:///shared/path?encrypt=1` | Discouraged | Works in theory if the path is a shared mount, but no flock / atomic-rename — race window during writes. |
| `aws_secrets://…` | **Yes** | All replicas read the same secret. Writes still single-writer. |
| `vault://…` (when implemented) | **Yes (planned)** | Same model. |

The mediator does **no application-level leader election**. If a
deployment needs active/active processing of mediated traffic, that
sits above the mediator — typically by partitioning DIDs across
mediator instances each with its own backend.

### Boot-order during failover

1. Standby boots, opens the unified backend, probes it (fail-fast at
   this stage if the backend is unreachable).
2. Loads `mediator/admin/credential`, authenticates to the VTA, fetches
   the operating-keys bundle, caches it under
   `mediator/vta/last_known_bundle`.
3. `/readyz` flips to `ready`.
4. Orchestrator (LB, DNS) cuts traffic over.

Total time is bounded by the VTA round-trip plus Redis connection
warmup — typically well under 30 seconds.

---

## Migration from the legacy `[vta]` / `mediator_secrets` schema

> **This is a hard-cut.** Pre-`0.14.0` mediators read `[vta].credential`,
> `security.mediator_secrets`, and `security.jwt_authorization_secret`
> directly out of `mediator.toml`. From `0.14.0` onward those fields
> are silently ignored; the mediator only reads `[secrets].backend`.

There is no compatibility shim. Operators upgrading from a
pre-`0.14.0` deployment must take one of two paths.

### Path A — re-run the wizard (recommended)

```sh
# Tear down the previous setup if you want a clean slate.
mediator-setup --uninstall

# Walk through the new wizard. Pick a unified secret backend
# (keyring / aws_secrets / file://?encrypt=1) at the KeyStorage step.
mediator-setup
```

The wizard provisions the well-known keys above and rewrites
`mediator.toml` in the new shape. Old keys / credentials from the
legacy schema are **not** carried forward — the wizard mints fresh
ones. JWTs issued by the previous mediator stop validating; clients
reconnect.

If you want to keep the existing admin DID, complete the wizard
first, then `mediator rotate-admin` is **not** what you want (it
mints a new key). Instead, hand-write the new
`mediator/admin/credential` envelope using your existing key
material before the first boot.

### Path B — reuse existing key material with `--force-reprovision`

```sh
# 1. Manually write the well-known envelopes into your backend.
#    (See "Well-known key schemas" above.)

# 2. Write the new mediator.toml shape pointing at the backend.

# 3. Re-run the wizard with --force-reprovision so the existing
#    setup-detection guard doesn't refuse to start.
mediator-setup --force-reprovision
```

This path is for operators who have automation generating the new
config + backend entries from the old ones (e.g. a one-off Terraform
plan that re-shapes the secret store). Most deployments are simpler
to migrate via Path A.

### What changed at the config level

| Pre-0.14 (`mediator.toml`) | 0.14+ |
|---------------------------|-------|
| `[vta].credential = "string://…"` | `[secrets].backend = "<url>"` + entry at `mediator/admin/credential` |
| `[vta].context` | embedded in the admin-credential envelope |
| `[vta].url_override` | embedded in the admin-credential envelope |
| `[security].mediator_secrets = "string://…"` / `"file://…"` / `"keyring://…"` / `"aws_secrets://…"` | entry at `mediator/operating/secrets` (self-hosted) — backend chosen via `[secrets].backend` |
| `[security].jwt_authorization_secret = "string://…"` | entry at `mediator/jwt/secret` |

If your CI relied on env-var overrides
(`MEDIATOR_SECRETS=`, `JWT_AUTHORIZATION_SECRET=`,
`VTA_CREDENTIAL=…`), replace with `MEDIATOR_SECRETS_BACKEND=<url>`
plus per-key direct-write into the backend.

### Detecting an unmigrated deployment

The mediator refuses to boot if `[secrets].backend` is missing — a
pre-0.14 `mediator.toml` will produce a clear `ConfigError(12)`:

```
Error: ConfigError(12, "NA", "Could not parse default config: missing field `secrets`")
```

That's the signal to run Path A or Path B above.
