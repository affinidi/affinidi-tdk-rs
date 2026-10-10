# Mediator Secret Storage

The mediator keeps every secret it owns in one **secret backend**, a
key-value store behind the
[`SecretStore`](../affinidi-messaging-mediator-common/src/secrets/store.rs)
trait. `mediator.toml` names it with a URL:

```toml
[secrets]
backend = "keyring://affinidi-mediator"   # env MEDIATOR_SECRETS_BACKEND
cache_ttl = "30d"                          # VTA cache TTL, humantime; default 30d, 0 = never expires
```

This document covers the backend URLs, how entries are stored, the entry
schemas, provisioning without the wizard, `/readyz`, rotation, and HA.

---

## Backend URLs

| Scheme | Stored as | Encryption | Notes |
|--------|-----------|------------|-------|
| `keyring://<service>` | One OS keychain entry, `mediator_secrets_bundle` | OS-managed | Single host only. Good for desktop dev. |
| `file:///<absolute-path>` | One JSON file, base64 values | None | Dev only: plaintext on disk. |
| `file:///<absolute-path>?encrypt=1` | One JSON file, AEAD-sealed | AES-256-GCM, Argon2id-derived key | Needs `MEDIATOR_FILE_BACKEND_PASSPHRASE` or `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE` at start. |
| `aws_secrets://<region>/<prefix>` | One secret, `<prefix>mediator_secrets_bundle` | AWS-managed | |
| `gcp_secrets://<project>/<prefix>` | One secret, `<prefix>mediator_secrets_bundle`; each write adds a version | Google-managed | Auth: Application Default Credentials. |
| `azure_keyvault://<vault-name-or-url>` | One secret, `mediator-secrets-bundle` (`_` becomes `-`) | Azure-managed | A bare name means `https://<name>.vault.azure.net`; a full `https://` URL is used as is (sovereign clouds). Auth: `DeveloperToolsCredential` (Azure CLI). |
| `vault://<endpoint>/<mount>[/<prefix>][?auth=…]` | One KV v2 secret, `<mount>/<prefix>/mediator_secrets_bundle` | Vault-managed | First path segment is the KV v2 mount; the rest is the prefix. See [Vault authentication](#vault-authentication). |
| `k8s://[<namespace>/]<secret-name>` | One `Secret`; each entry is one `data` key | etcd (enable encryption at rest) | See [Kubernetes Secrets](#kubernetes-secrets). |

**Per-key backends** in this document means keyring, AWS, GCP, Azure and
Vault: stores that hold one value per secret. On these the mediator packs
every entry into the single `mediator_secrets_bundle` secret (see
[One secret per deployment](#one-secret-per-deployment)). `file://` and
`k8s://` already hold everything in one object and store entries directly.

Not supported:

- `string://` (inline secrets in TOML). Use `file://` for throwaway CI runs
  and a managed backend in production.
- `vta://`. The VTA is a key *source*: operating keys can be fetched from it
  at startup. The admin credential, JWT key and cached operating keys live in
  a real backend.

## Which backends are compiled in

All backends are supported. Only `file://` (plain and encrypted) is in the
default build; each other backend pulls in a large SDK, so it sits behind a
feature:

| Backend | Cargo feature |
|---------|---------------|
| `file://`, `file://…?encrypt=1` | always compiled |
| `keyring://` | `secrets-keyring` |
| `aws_secrets://` | `secrets-aws` |
| `gcp_secrets://` | `secrets-gcp` |
| `azure_keyvault://` | `secrets-azure` |
| `vault://` | `secrets-vault` |
| `k8s://` | `secrets-k8s` |

```bash
cargo build --release --locked --features secrets-aws,secrets-vault
```

A URL whose backend wasn't compiled in fails at startup with a message naming
the feature to add, for example *"compiled without the 'secrets-aws'
feature; rebuild with `cargo build --features secrets-aws` to enable"*. CI
(`checks-features.yaml`) builds the mediator and the wizard with each
`secrets-*` feature.

---

## Vault authentication

`?auth=` selects the method; the default is `token`. Auth secrets never go
in the URL: they come from the environment at login.

| `?auth=` | URL params | Env | Use when |
|----------|------------|-----|----------|
| `token` (default) | none | `VAULT_TOKEN` | You already have a token (dev, CI, external renewer). |
| `kubernetes` | `role=<name>` (required); `k8s_mount=<mount>` (default `kubernetes`); `jwt_path=<path>` (default `/var/run/secrets/kubernetes.io/serviceaccount/token`) | none (uses the pod's ServiceAccount JWT) | The mediator runs in a pod and Vault has Kubernetes auth enabled. |
| `approle` | `approle_mount=<mount>` (default `approle`) | `VAULT_ROLE_ID`, `VAULT_SECRET_ID` | Workloads outside Kubernetes. |

Params for any method:

- `namespace=<ns>`: Vault Enterprise namespace (`X-Vault-Namespace`). Not
  the same as the path prefix.
- `insecure=1`: skip TLS verification. Dev and test only.

With `kubernetes` and `approle`, a `401`/`403` triggers one re-login and
retry, so an expired token or a rotated ServiceAccount JWT recovers without
a restart.

Example: Kubernetes auth in Vault Enterprise namespace `team-a`, KV v2 mount
`secret`, prefix `mediator`:

```toml
[secrets]
backend = "vault://vault.internal:8200/secret/mediator?auth=kubernetes&role=mediator&namespace=team-a"
```

```hcl
# mediator-policy.hcl
path "secret/data/mediator/*"     { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/mediator/*" { capabilities = ["list", "read", "delete"] }
```

```sh
vault policy write mediator mediator-policy.hcl

vault write auth/kubernetes/role/mediator \
    bound_service_account_names=mediator \
    bound_service_account_namespaces=affinidi \
    policies=mediator \
    ttl=1h
```

`delete` on the metadata path lets a delete remove a key completely. Without
it the mediator falls back to a soft delete and the key still shows in
`vault kv list`.

---

## Kubernetes Secrets

`k8s://<namespace>/<secret-name>` keeps every entry as one key in the `data`
map of a single `Secret`. Values are the raw entry bytes (Kubernetes
base64-encodes `data` itself). One object keeps RBAC minimal.

- The namespace is optional (`k8s://mediator-secrets`). Without it, the
  backend uses the pod ServiceAccount's namespace or the kubeconfig context,
  then `default`.
- Auth: the in-cluster ServiceAccount, or your kubeconfig (`~/.kube/config`,
  `$KUBECONFIG`) outside the cluster.
- Writes read the Secret, modify it and `replace` it with the fetched
  `resourceVersion`, retrying on `409`, so concurrent writers don't lose
  each other's keys.
- **Enable [encryption at rest for Secrets](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/).**
  By default etcd stores `Secret` data base64-encoded, not encrypted.

The ServiceAccount needs `get` and `update` on that Secret, and `create`
(which can't be scoped to a name):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mediator
  namespace: affinidi
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mediator-secrets
  namespace: affinidi
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["mediator-secrets"]   # the k8s:// secret-name
    verbs: ["get", "update"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mediator-secrets
  namespace: affinidi
subjects:
  - kind: ServiceAccount
    name: mediator
    namespace: affinidi
roleRef:
  kind: Role
  name: mediator-secrets
  apiGroup: rbac.authorization.k8s.io
```

```toml
[secrets]
backend = "k8s://affinidi/mediator-secrets"
```

The mediator creates the Secret on first start. If policy forbids that,
pre-create an empty `Opaque` Secret with that name.

---

## One secret per deployment

On per-key backends every entry lives inside one backend secret,
`mediator_secrets_bundle` (with the URL's prefix). It is an entry of kind
`secrets-bundle` whose `data.entries` maps each entry name to that entry's
bytes, base64url without padding:

```json
{
  "version": 1,
  "kind": "secrets-bundle",
  "data": {
    "entries": {
      "mediator_admin_credential": "eyJ2ZXJzaW9uIjox…",
      "mediator_jwt_secret": "eyJ2ZXJzaW9uIjox…"
    }
  }
}
```

Probe sentinels and bootstrap seeds are entries in the bundle too, so
`mediator_secrets_bundle` is the only secret the mediator creates.

### Migrating from one secret per key

Mediators before 0.38.0 (mediator-common 0.17.4) wrote one backend secret
per entry (`mediator_admin_credential`, `mediator_jwt_secret`, …). The first
start of a newer mediator, or of `mediator-setup` 0.1.38+, moves them into
the bundle. The per-key secrets stay the source of truth until a mediator
has actually started on the bundle, so a failure at any step leaves a store
that both the new and the previous mediator run against. The bundle records
how far the migration got:

1. **Checked.** Every per-key value must be a readable entry. If one isn't,
   nothing is written.
2. **`staged`.** The values are copied into `mediator_secrets_bundle`, read
   back and compared byte for byte. A staged bundle is ignored; the next
   start copies again.
3. **`mirrored`.** The bundle is marked verified and read back again. Reads
   now come from the bundle. Every write goes to the per-key secret first,
   then to the bundle, so an older mediator keeps working. Each start
   compares the two and copies again if they differ (for example, after an
   older mediator wrote).
4. **`active` (cutover).** Only after the mediator has loaded its
   configuration from the bundle and bound its listener does it compare a
   last time, mark the bundle `active` and read that back. It then deletes
   the per-key secrets and any stray `mediator_probe_<uuid>` sentinels.
   Failed deletes are retried on later starts. If the read-back fails, the
   bundle goes back to `mirrored` and nothing is deleted.

`mediator-setup` and `mediator rotate-admin` migrate as far as `mirrored`
but never cut over.

A deployment with neither layout is fresh and starts `active`.

### When migration fails

Any failure stops the mediator (and `mediator-setup`, before it provisions
anything) with `SecretStoreError::MigrationFailed`. There is no fallback to
the per-key layout. The message says why, whether anything changed, and what
to do. A partial copy is deleted first. Before the cutover the per-key
secrets are never touched, so the previous mediator version still runs
while you fix it.

| Message contains | Do |
|------------|----|
| `mediator_secrets_bundle could not be read` / `could not be written` | Grant the mediator's role read, create and write on `<prefix>mediator_secrets_bundle`, then start again. Typical when IAM grants only the per-key names. |
| `the per-key secret <key> is not a readable entry` | Repair or remove that secret. An older mediator would fail on it too. |
| `read back differently from what was written` | Check whether another process writes `mediator_secrets_bundle`. |
| `the partial copy could not be removed` | The copy is marked unfinished, so it's ignored and the per-key secrets are untouched. Optionally delete it by hand. |
| `the per-key secrets changed while this mediator was starting` | Another (usually older) mediator still writes them. Stop it. |
| `holds an unconfirmed copy, but the per-key secrets it was copied from are gone` | Restore the per-key secrets, or delete `mediator_secrets_bundle` to start fresh. |
| `recording the cutover … could not be undone` | Compare the bundle with the per-key secrets; if they differ, delete `mediator_secrets_bundle` so the next start copies again. |
| `mediator_secrets_bundle exists but can't be read` | The bundle is never overwritten. If the per-key secrets still exist, delete the bundle and restart. Otherwise restore it from a backup. |

A fresh store whose role can't create `mediator_secrets_bundle` fails too; it
never falls back to per-key secrets. If IaC owns the store, create
`<prefix>mediator_secrets_bundle` instead of the per-key secrets, and grant
the mediator write on it. Create it with no value (or an empty one): the
mediator treats an empty bundle as absent and fills it on first write. Don't
write an envelope by hand; backends store it base64url-encoded.

### Rollback

Before the cutover, an older mediator runs unchanged on the per-key secrets;
if it writes to them, the next newer start notices and copies again. After
the cutover the per-key secrets are gone, so a mediator older than 0.38.0
finds nothing. To roll back then, first write the entries back as separate
secrets.

### Permissions

Grant read and write on `<prefix>mediator_secrets_bundle`. A deployment still
on the per-key layout also needs delete on the old per-key names so the
cutover can remove them. On GCP, also grant `secretmanager.versions.destroy`
(see below).

### API call volume

Cloud secret stores bill per call, so the mediator keeps calls down:

- A read of the bundle is reused for 30 s. A process sees its own writes at
  once; another process's writes within 30 s.
- A write that changes nothing is skipped.
- The VTA cache is rewritten only when its content changes or it is older
  than half its TTL. `/readyz` `vta_cache_age_secs` is the age of the last
  write, not of the last VTA fetch.
- `/readyz` reuses a successful backend probe for 30 s.
- On GCP every write adds a billed version, so the superseded version is
  destroyed after each write. This needs `secretmanager.versions.destroy`
  (in `roles/secretmanager.admin`); without it a warning is logged and old
  versions pile up.
- On Vault a delete removes the key's metadata (see
  [Vault authentication](#vault-authentication)).

---

## Entry schemas

Every entry is wrapped in a versioned envelope:

```json
{
  "version": 1,
  "kind": "<type-tag>",
  "data": { /* type-specific payload */ }
}
```

The mediator refuses an entry whose `kind` doesn't match what it expects, so
a hand-edited entry of the wrong shape fails loudly.

To provision by hand (Terraform, a k8s `Secret`) you need each entry's name
and its `data` shape. On per-key backends the name is a key in the bundle's
`entries` map, not a secret of its own.

| Name | Kind | Required? |
|------|------|-----------|
| `mediator_admin_credential` | `admin-credential` | For VTA-linked deployments |
| `mediator_jwt_secret` | `jwt-secret` | Always |
| `mediator_operating_secrets` | `operating-secrets` | Self-hosted DIDs |
| `mediator_operating_did_document` | `did-document` | Optional |
| `mediator_vta_last_known_bundle` | `vta-cached-bundle` | Written by the mediator |
| `mediator_bootstrap_ephemeral_seed_<bundle_id_hex>` | `ephemeral-seed` | Written by the wizard |
| `mediator_bootstrap_seed_index` | `bootstrap-seed-index` | Written by the wizard |
| `mediator_probe_*` | none | Health probes |

`mediator_operating_signing` and `mediator_operating_key_agreement` are
reserved names; nothing reads or writes them today.

### `mediator_admin_credential` (kind `admin-credential`)

The mediator's persistent admin identity. Two shapes:

- **VTA-linked** (`vta_did` set): the mediator authenticates to its VTA with
  it at startup. Written by the Online and sealed-handoff flows.
- **Self-hosted** (`vta_did` and `vta_url` absent or null): a record of the
  admin DID and key so a later wizard run can reuse it. The mediator doesn't
  contact a VTA.

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
| `did` | string | Admin DID; must start with `did:`. |
| `private_key_multibase` | string | Ed25519 seed, multibase base58btc. |
| `vta_did` | string or null | The VTA's DID; must start with `did:` when set. |
| `vta_url` | string or null | Optional REST URL override. Only valid with `vta_did`. |
| `context` | string | VTA context. Default `"mediator"`. Ignored when self-hosted. |

Write it with `mediator-setup` or by hand. Rotate it with
[`mediator rotate-admin`](#rotation) (VTA-linked only).

### `mediator_jwt_secret` (kind `jwt-secret`)

The Ed25519 key that signs the mediator's session JWTs. Required: the
mediator won't start without it.

```json
{
  "version": 1,
  "kind": "jwt-secret",
  "data": [/* Ed25519 PKCS#8 DER bytes, as a JSON byte array */]
}
```

The bytes are what `ring::signature::Ed25519KeyPair::generate_pkcs8()`
produces. The wizard generates it in `jwt_mode = "generate"`. With
`jwt_mode = "provide"`, write this entry yourself before the first start.

### `mediator_operating_secrets` (kind `operating-secrets`)

Keys for the mediator's own DID when it is self-hosted (did:peer,
did:webvh). Absent in VTA-managed deployments, which fetch keys from the VTA.

```json
{
  "version": 1,
  "kind": "operating-secrets",
  "data": [
    {
      "id": "did:peer:…#key-1",
      "type": "Ed25519VerificationKey2020",
      "private_key_multibase": "z3u2…"
    }
  ]
}
```

`data` is a JSON `Vec<affinidi_secrets_resolver::secrets::Secret>`, one per
signing or key-agreement key. The wizard normally writes it.

### `mediator_operating_did_document` (kind `did-document`)

Optional cached copy of the mediator's own DID document (self-hosted). If
present, it saves resolving the mediator's own DID.

```json
{ "version": 1, "kind": "did-document", "data": { /* DID document */ } }
```

### `mediator_vta_last_known_bundle` (kind `vta-cached-bundle`)

The last good `DidSecretsBundle` from the VTA, used at startup when the VTA
is unreachable. It carries an HMAC-SHA256 keyed from the admin credential's
private key (HKDF-SHA256, salt `"mediator-vta-cache-hmac-v1"`), so a tampered
entry, or one from a different admin key, is treated as absent.

```json
{
  "version": 1,
  "kind": "vta-cached-bundle",
  "data": {
    "fetched_at": 1735689600,
    "ttl_secs": 2592000,
    "hmac": "<hex>",
    "bundle": { /* DidSecretsBundle */ }
  }
}
```

Don't write this by hand. The mediator writes it after a successful VTA
fetch.

### `mediator_bootstrap_ephemeral_seed_<bundle_id_hex>` (kind `ephemeral-seed`)

The HPKE recipient seed for a sealed handoff. Phase 1
(`mediator-setup --from <recipe>`) writes it; phase 2 (`… --bundle <path>`)
reads it and deletes it. A leftover seed is deleted by a later wizard run
once it is older than the TTL: 24 h by default, or
`MEDIATOR_BOOTSTRAP_SEED_TTL` (humantime, e.g. `6h`).

```json
{
  "version": 1,
  "kind": "ephemeral-seed",
  "created_at": 1735689600,
  "data": { "seed_b64": "<base64url of 32-byte Ed25519 seed>" }
}
```

### `mediator_bootstrap_seed_index` (kind `bootstrap-seed-index`)

The list of seeds the sweep checks.

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

Deleting it is safe. At worst a seed is no longer swept and you delete it by
hand. The next phase-1 run recreates the index.

### `mediator_probe_*` (no envelope)

Two health checks use this prefix:

- **`SecretStore::probe()`** proves the caller can write. Setup tooling uses
  it. On `file://` and `k8s://` it writes, reads back and deletes
  `mediator_probe_<uuid>`. On per-key backends it rewrites
  `mediator_secrets_bundle` unchanged and reads it back, so no secret is
  created.
- **`SecretStore::probe_readonly()`** checks reachability and credentials
  without writing. It reads `mediator_probe_readonly`, which is never
  written, so a healthy backend answers "absent". `/readyz` uses this, so a
  read-only role is enough to keep the mediator serving. It reads the
  backend directly, not the bundle.

**Read-only roles.** Grant read on `<prefix>mediator_probe_*`, not just the
named entries, or the probe is denied and `/readyz` reports a healthy
backend as down. On AWS that is `secretsmanager:GetSecretValue` on
`arn:aws:secretsmanager:<region>:<acct>:secret:<prefix>mediator_probe_*`. Each
probe shows in CloudTrail or Cloud Audit Logs as a `ResourceNotFound`-style
read. That is expected.

**File backends and a missing file.** The read-only probe checks the disk
each time:

- `file://`: a missing file is healthy (the normal state before
  provisioning). Only unreadable or corrupt data fails.
- `file://…?encrypt=1`: a missing file is an error, because `open()` would
  have created it; the mount has probably gone. The probe re-parses the
  envelope but does not re-run Argon2.

---

## Operations

### Provisioning without the wizard

1. Write `mediator.toml`:
   ```toml
   mediator_did = "did://did:webvh:mediator.example.com"

   [secrets]
   backend = "aws_secrets://us-east-1/mediator/"
   cache_ttl = "30d"
   ```
2. Write the entries above into the backend, in exactly the shapes shown.
   A wrong `kind` or a missing field stops startup with a clear log line. On
   per-key backends, write the entries into `mediator_secrets_bundle`
   ([format](#one-secret-per-deployment)). Writing per-key secrets instead
   still works, and the first start migrates them, but once the bundle
   exists per-key secrets are ignored.
3. For `file://…?encrypt=1`, supply the passphrase as
   `MEDIATOR_FILE_BACKEND_PASSPHRASE` or
   `MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE=/run/secrets/mediator-fb-pass`.

### `/readyz`

`/readyz` (at `<api_prefix>readyz`, by default `/mediator/v1/readyz`) is
unauthenticated:

```json
{
  "status": "ready",
  "version": "0.38.0",
  "uptime_seconds": 86400,
  "checks": [/* name, status (pass/fail/warn), detail */],
  "components": [/* supervised tasks: name, state, restarts */],
  "secrets_backend_reachable": true,
  "vta_cache_age_secs": 1834,
  "operating_keys_loaded": true
}
```

`status` is `ready`, `degraded`, or `not_ready`. Any failing check
(including `secrets_backend_reachable: false`) returns HTTP 503 and
`not_ready`. The backend URL is not exposed; it is in the startup log.

### Rotation

```sh
mediator rotate-admin --dry-run   # authenticate and show the plan; change nothing
mediator rotate-admin             # rotate
```

`rotate-admin` needs a VTA-linked admin credential and the `vta` feature
(default). It:

1. Authenticates to the VTA with the current credential.
2. Mints a new `did:key` and gives it the same ACL scope on the VTA.
3. Writes the new credential, waits 2 s, and reads it back. If another
   writer (such as a running mediator refreshing its VTA cache) overwrote
   it, it writes again, up to 3 attempts.
4. Only after the read-back confirms the new credential does it revoke the
   old ACL entry. If that revoke fails, it warns and you remove the entry
   with `pnm acl delete`.

The old and new DIDs are logged. A running mediator picks up the new
credential on its next restart. If the write never confirms, the command
fails: the mediator keeps the old credential, and the new ACL entry stays on
the VTA until you remove it.

---

## High availability

The mediator is **single-writer**. Two mediators writing to the same backend
at once can overwrite each other's changes to the admin credential, JWT key
or VTA cache (the store has no compare-and-swap).

For HA, run a cold standby: one active mediator, with failover handled by
the orchestrator (a k8s `Deployment` with `replicas: 1` and leader election,
an ECS service with `desired_count: 1` and a watcher, or a systemd
active/passive pair). Every replica reads the same backend, so a standby
starts with live credentials.

| Backend | HA? | Why |
|---------|-----|-----|
| `keyring://` | No | Per-host keychain. |
| `file://` | No | Local file. |
| `file:///shared/path?encrypt=1` | Discouraged | Works on a shared mount, but there is no locking. |
| `aws_secrets://`, `gcp_secrets://`, `azure_keyvault://`, `vault://`, `k8s://` | Yes | Shared managed store. Still one writer. |

The mediator does no leader election. For active/active traffic, partition
DIDs across mediators, each with its own backend.

### Failover sequence

1. The standby starts, opens the backend and probes it (fails fast if it's
   unreachable).
2. It loads `mediator_admin_credential`, authenticates to the VTA, fetches
   the operating keys and caches them in `mediator_vta_last_known_bundle`.
3. `/readyz` reports `ready`.
4. The load balancer or DNS moves traffic.

This usually takes well under 30 seconds: one VTA round trip plus database
connection setup.

---

## Upgrading from before 0.14.0

Mediators before 0.14.0 read secrets from `mediator.toml`
(`[vta].credential`, `[security].mediator_secrets`,
`[security].jwt_authorization_secret`). From 0.14.0 those fields are ignored
and `[secrets].backend` is required. Without it, startup fails with
`ConfigError(12, …)` reporting a missing field `secrets`.

| Before 0.14 (`mediator.toml`) | Now |
|---------------------------|-----|
| `[vta].credential` | `mediator_admin_credential` entry |
| `[vta].context`, `[vta].url_override` | Fields of the admin credential |
| `[security].mediator_secrets` | `mediator_operating_secrets` entry (self-hosted) |
| `[security].jwt_authorization_secret` | `mediator_jwt_secret` entry |
| Env `MEDIATOR_SECRETS`, `JWT_AUTHORIZATION_SECRET`, `VTA_CREDENTIAL` | Env `MEDIATOR_SECRETS_BACKEND=<url>`, entries written to the backend |

Two ways to upgrade:

- **Re-run the wizard** (simplest). Optionally run
  `mediator-setup --uninstall` first. The wizard writes new keys and a new
  `mediator.toml`; nothing is carried over, existing JWTs stop validating
  and clients reconnect. To keep the existing admin DID, write
  `mediator_admin_credential` by hand from your old key material before the
  first start (`rotate-admin` mints a new key, so it doesn't help here).
- **Reuse existing keys.** Write the entries into the backend yourself
  ([Entry schemas](#entry-schemas)) and write a new-style `mediator.toml`.
