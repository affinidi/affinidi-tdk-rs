# Mediator Setup Guide

How to bring up a mediator whose DID and keys come from a Verifiable Trust
Agent (VTA): the three setup modes, what each needs, and what the mediator
ends up with.

The guide ends when `mediator-setup` exits cleanly and the mediator can
authenticate to the VTA. For everything after first start, see the
[mediator README](../README.md). For where the secrets are stored, see
[secrets-backend.md](secrets-backend.md).

## Modes at a glance

Every mode has the same phases: generate a request, hand it to the VTA,
apply the sealed bundle that comes back. Only the transport and the VTA-side
command differ.

| Mode | VTA reachable over network? | VTA has existing state for this mediator? | VTA-side command | Interactive? |
|---|---|---|---|---|
| [Online](#1-online) | Yes | No (greenfield) | `pnm bootstrap provision-integration` via admin PNM session | TUI only |
| [Sealed-mint](#2-sealed-mint) | Optional (file transfer works air-gapped too) | No (greenfield) | `vta bootstrap provision-integration --request req.json` on VTA host | TUI *or* `--from` |
| [Sealed-export](#3-sealed-export) | Optional | **Yes** (ran mode 1 or 2 previously) | `vta contexts reprovision --id <ctx> --recipient req.json` on VTA host | TUI *or* `--from` |

Not sure whether the VTA context already has a mediator DID? Ask your VTA
admin to run `pnm contexts show --id <ctx>`. A DID means sealed-export; no
DID means sealed-mint.

## 1. Online

### When to pick this mode

The VTA is reachable from the mediator host over HTTPS, and you (or a VTA
admin) can drive the setup interactively. This suits most production
deployments.

The wizard runs as a TUI. One step happens out of band: you run
`pnm acl create` on your admin workstation to authorize the wizard's
temporary setup DID. That is deliberate: a person, not automation, signs off
on the admin grant.

### Prerequisites

- A running VTA instance with REST reachable over HTTPS from the
  mediator host
- An admin workstation with `pnm` installed and authenticated against
  the VTA you're targeting
- The VTA's DID (`did:webvh:...` or `did:key:...`) — your VTA admin has
  this
- A context on the VTA you want this mediator to live in (or the
  intent to create one — `pnm contexts create` is the first step)

### Step by step

On the mediator host, launch the wizard:

```bash
mediator-setup
```

Walk through the initial screens (deployment type, protocol, key
storage) and pick `Full setup — VTA mints my mediator DID` on the VTA
intent screen, then `Online` on the transport screen.

The wizard will:

1. Prompt for the VTA DID, context id, and mediator public URL.
2. Generate an ephemeral `did:key` setup identity and print a
   `pnm acl create --acl-did <did:key:...>` command.
3. Wait for you to run that command on your admin workstation. After
   running it, come back to the wizard and press Enter.
4. Open an authenticated DIDComm session, run the provisioning round
   trip, and receive the mediator DID + keys + authorization VC.
5. Drop you onto the remaining config steps (database, admin DID,
   output location).

The wizard finishes by writing `mediator.toml`, pushing the
provisioned keys into your chosen secret backend, and offering to run
`cargo install` for you.

### What the mediator ends up with

- Mediator operational DID (`did:webvh:...`) with signing and
  key-agreement keys in the secret backend
- Authorization VC archived next to `mediator.toml`
- Admin credential for authenticating to the VTA at boot
- JWT secret for the mediator's own admin API
- Cached `DidSecretsBundle` for VTA-unreachable boot fallback

### Common gotchas

| Symptom | Cause | Remedy |
|---|---|---|
| Authentication never succeeds | `pnm acl create` wasn't run, or it targeted the wrong VTA | Re-check the VTA URL in PNM's config; re-run the command shown on the wizard's AwaitingAcl screen |
| `CIRCULAR DEPENDENCY` warning on the final screen | The VTA has this mediator configured as *its* mediator | Proceed — the wizard uses REST bootstrapping to break the cycle. Consider using a separate mediator for the VTA itself before production |
| `context 'X' has no DID assigned` on first mediator start | VTA side: the context exists but the DID wasn't bound to it (older `vta-service`) | Upgrade `vta-service`, or run `pnm contexts update --id <ctx> --did <mediator-did>` |

## 2. Sealed-mint

### When to pick this mode

You want a fully declarative, headless setup (CI, Ansible, Terraform)
AND this is a greenfield deployment — the VTA doesn't have a mediator
DID for this context yet. Also the right pick when the VTA is
air-gapped from the mediator host (no HTTPS reachability).

A sealed-mint run is two `mediator-setup` invocations with a file
transfer between them. Unlike online mode, the wizard doesn't talk to
a live VTA at all — you carry a JSON file to wherever the VTA CLI
lives and bring back a `bundle.armor`.

### Prerequisites

- A build recipe (`.toml` — see [recipe schema](#recipe-fields-by-mode)
  for the sealed-mint fields)
- Shell access to the VTA host (or an intermediate that can run
  `vta bootstrap provision-integration` against the VTA's state)
- A way to move two files between the two hosts (USB, scp, ticket
  attachments — whatever works for your air-gap policy)

### Step by step

**On the mediator host** — phase 1:

```bash
mediator-setup --from recipe.toml
```

The wizard validates the recipe, generates a temporary keypair, and writes
the request to `./bootstrap-request-vp.json`. It stores the HPKE recipient
seed in the secret backend as the entry
`mediator_bootstrap_ephemeral_seed_<bundle-id>`, listed in
`mediator_bootstrap_seed_index` for the 24 h sweep (see
[entry schemas](secrets-backend.md#entry-schemas)). It then prints the
VTA-side command and the phase-2 command, and exits 0: this is a normal
pause, not an error.

Carry `bootstrap-request-vp.json` to the VTA host by whatever transfer
mechanism you use.

**On the VTA host**:

```bash
vta bootstrap provision-integration \
  --request bootstrap-request-vp.json \
  --context mediator \
  --out bundle.armor \
  --assertion pinned-only
```

The VTA mints a fresh mediator DID, keys, and authorization VC,
packages them into a HPKE-sealed bundle addressed to the ephemeral
pubkey from the request, and prints the bundle's SHA-256 digest.
Record the digest for the out-of-band verification step.

Carry `bundle.armor` back to the mediator host.

**On the mediator host** — phase 2:

```bash
mediator-setup --from recipe.toml \
  --bundle bundle.armor \
  --digest <sha256-from-the-vta-host>
```

The wizard:

1. Opens the armored bundle, verifies the digest matches what you
   typed, looks up the ephemeral seed in the secret backend by
   bundle id, and unseals.
2. Auto-detects the `TemplateBootstrap` payload variant and projects
   it onto an internal session.
3. Runs the same config-writing pipeline as the TUI: writes
   `mediator.toml`, pushes operating keys / admin credential / JWT
   secret / cached bundle into the secret backend.
4. Deletes the ephemeral seed from the backend and cleans up the
   request file.

Exit code 0 means the mediator is ready to start.

### What the mediator ends up with

Same as online mode:

- Mediator operational DID with signing + key-agreement keys
- Authorization VC next to `mediator.toml`
- Admin credential (VTA-minted rollover DID) for mediator→VTA auth
- Mediator's own admin-API DID (generated fresh by default — see
  [trust model](#trust-model))
- JWT secret, cached VTA bundle

### Common gotchas

| Symptom | Cause | Remedy |
|---|---|---|
| "A bootstrap is already in progress" on phase 1 | Previous phase-1 run didn't finalise; seed is still in the secret backend's sweep index | Either run phase 2 with `--bundle` to finalise, wait for the 24h auto-sweep (`MEDIATOR_BOOTSTRAP_SEED_TTL` overrides), or re-run with `--force-reprovision` to wipe |
| "could not locate the ephemeral seed" on phase 2 | Phase 2 is pointing at a different secret backend than phase 1, or the seed was swept / manually deleted | Re-run phase 2 with the same recipe (same `[secrets].backend`) as phase 1; confirm the bundle id in the error matches what phase 1 printed |
| "provided digest did not match the bundle" | The digest you typed differs from what the VTA printed | Re-copy the digest from the VTA host; if it still fails, the bundle was tampered with — re-request |
| Phase 1 fails with "requires identity.public_url" | Recipe doesn't set the mediator URL | Add `public_url = "https://..."` under `[identity]` in the recipe — the VTA's `didcomm-mediator` template needs it to render the mediator DID |
| Bundle opens but `did.jsonl` doesn't get written | Config dir is not writable, or `--config` points at a path with no parent directory | Check permissions on the directory holding `mediator.toml` |

## 3. Sealed-export

### When to pick this mode

The mediator was already provisioned at the VTA (via a previous run of
mode 1 or mode 2), and you're either migrating to a new host, backing
up the provisioned state, or rebuilding a corrupted mediator install.
Use this mode any time the VTA already has a DID for your context
and you need to recover the operational material onto a different
host.

If you run sealed-mint against a context that already has a mediator
DID, the VTA mints a NEW one — not what you want for migration. Pick
sealed-export to retrieve the existing material unchanged.

### Prerequisites

Same as sealed-mint, plus:

- The VTA context id the mediator was originally provisioned under
  (ask your VTA admin; they can `pnm contexts show --id <ctx>`)
- A reasonably recent `vta` CLI — `vta contexts reprovision` auto-mints
  the admin key when `--admin-key` is omitted, which is the
  recommended default

### Step by step

**On the mediator host** — phase 1:

```bash
mediator-setup --from recipe.toml
```

Recipe must have `vta_mode = "sealed-export"`. The wizard generates a
simpler v1 `sealed_transfer::BootstrapRequest` (pubkey + nonce, no
template ask — nothing is being minted) at
`./bootstrap-request.json`, and prints the VTA-side command.

**On the VTA host**:

```bash
vta contexts reprovision \
  --id mediator \
  --recipient bootstrap-request.json \
  --out bundle.armor
```

Omit `--admin-key` — the VTA auto-mints a fresh admin identity inside
the context, derives its `did:key`, writes the admin ACL row, and
packs it into the bundle. The DID's operational keys (signing, KA,
pre-rotation) are always auto-included regardless of the flag.

**On the mediator host** — phase 2:

```bash
mediator-setup --from recipe.toml \
  --bundle bundle.armor \
  --digest <sha256>
```

Same apply pipeline as sealed-mint, except the bundle payload is
`ContextProvision` instead of `TemplateBootstrap`. The wizard
auto-detects and routes to the right projector.

### What the mediator ends up with

- The **existing** mediator DID and its operational keys (NOT fresh)
- The **existing** DID document and `did.jsonl` entry
- A freshly-auto-minted admin credential for mediator→VTA auth
- A separate, fresh admin-API DID (see [trust model](#trust-model))
- JWT secret, cached VTA bundle

### Common gotchas

| Symptom | Cause | Remedy |
|---|---|---|
| "OfflineExport bundle has no DID slot" on phase 2 | VTA reprovisioned an admin-only context (no DID attached) | The context doesn't carry a mediator DID. Either pick sealed-mint instead (new mint) or pick a different context |
| `context 'X' has no DID assigned` when the mediator authenticates | Same VTA-side gap as in [Online](#common-gotchas) | Run `pnm contexts update --id <ctx> --did <mediator-did>` on the VTA, then restart the mediator |
| "paste appears to be armored but contains no line breaks" | Tried to paste the armor inline; terminal stripped newlines | Use the file path (`--bundle bundle.armor`) — that's the reliable route |

## Recipe fields by mode

A minimal recipe for each sealed mode. See `examples/mediator-build.toml`
in the repo for the full schema.

### Sealed-mint

```toml
[deployment]
type = "server"
protocols = ["didcomm"]
use_vta = true
vta_mode = "sealed-mint"

[identity]
did_method = "vta"
public_url = "https://mediator.example.com"   # required — VTA template needs URL

[vta]
context = "mediator"                            # optional, defaults to "mediator"
webvh_server = "prod-1"                         # optional, pin VTA to a webvh server
webvh_path = "mediator/v1"                      # optional, server-specific path hint

[secrets]
storage = "keyring://affinidi-mediator"         # or file://, aws_secrets://, vault://, k8s://, ...
# vault:// supports auth methods, e.g.
#   "vault://vault.internal:8200/secret/mediator?auth=kubernetes&role=mediator"
# k8s:// stores every key in one namespaced Secret, e.g.
#   "k8s://affinidi/mediator-secrets"

[security]
ssl = "none"                                    # operator-managed reverse proxy expected
admin = "generate"                              # fresh did:key for mediator's own admin API
jwt_mode = "generate"

[database]
url = "redis://127.0.0.1/"

[output]
config_path = "conf/mediator.toml"
listen_address = "0.0.0.0:7037"
```

### Sealed-export

Same as sealed-mint except `vta_mode = "sealed-export"` and the
`webvh_*` fields are ignored (nothing is being minted).

`identity.public_url` is not required — the exported DID brings its
own URL.

### Legacy

`vta_mode = "sealed"` from older recipes is read as `"sealed-mint"`. Use the
explicit values in new recipes.

## What the wizard collects from you

| Input | Source | Modes |
|---|---|---|
| Deployment type (local / server / container) | Recipe `deployment.type` or TUI | All |
| Mediator public URL | Recipe `identity.public_url` or TUI | Online, sealed-mint |
| VTA context id | Recipe `[vta].context` or TUI, default `"mediator"` | All VTA modes |
| VTA DID | TUI (online only) | Online |
| Secret-backend URL | Recipe `secrets.storage` or TUI | All |
| Database URL | Recipe `database.url` or `$DATABASE_URL` env | All |
| Admin DID mode | Recipe `security.admin` or TUI | All |
| `bundle.armor` + digest | Phase 2 CLI flags or TUI paste | Sealed-mint, sealed-export |

## Trust model

Two orthogonal trust anchors verify what lands on your disk.

**Producer assertion (the bundle tells you who made it).** Every
sealed bundle carries an assertion declaring the producer DID plus a
proof type — `PinnedOnly`, `DidSigned`, or `Attested`. The mediator's
wizard surfaces the proof type after unsealing:

- `PinnedOnly`: trust is anchored entirely by the out-of-band digest
  you typed. Normal for greenfield deployments where the VTA DID
  isn't yet resolvable — the digest is your only protection against
  a swapped bundle.
- `DidSigned`: the producer signed over the bundle with a key derived
  from its declared DID. Stronger, but requires the VTA's DID to be
  publicly resolvable at the time of unsealing. The wizard logs the
  claim today but does not perform the resolve-and-verify step — a
  tracked gap for a future release.
- `Attested`: vendor-format attestation (e.g. AWS Nitro). Not yet
  wired into the mediator wizard.

**Out-of-band SHA-256 digest.** The VTA side prints a digest when it
produces the bundle. You type that into `--digest` (or the TUI's
verify screen). Any mismatch aborts the apply before any key
material leaves the bundle. The optional-ness is intentional — for
low-stakes dev work the bundle's AEAD is sufficient — but for
production rollouts always pass `--digest`.

**Authorization VC inside the bundle.** FullSetup-shaped bundles
include a VC. The mediator archives it next to `mediator.toml` for
operator audit but does not re-verify it in steady-state. Reasoning:
once the mediator has its operational keys and admin credential in
the secret backend, the VC is a historical receipt, not a runtime
check.

**Mediator admin DID separation.** For sealed-export specifically,
the wizard defaults the mediator's *own* admin-API DID to a fresh
`did:key` rather than reusing the VTA-auto-minted admin credential
that ships in the bundle. The reasoning: the bundle's admin
credential is intended for mediator→VTA authentication; reusing it
as the mediator's own admin-API identity overloads one key across
two distinct trust scopes (VTA admin vs. clients calling INTO the
mediator). See `[security].admin` in the recipe to override.

## How the mediator reaches the VTA after setup

At startup the mediator calls the VTA to fetch its keys, using DIDComm when
the VTA's DID document advertises a `DIDCommMessaging` endpoint and REST
otherwise. There is no configuration knob.

If the VTA uses *this* mediator as its own DIDComm mediator, the two depend
on each other. The mediator logs a `CIRCULAR DEPENDENCY` warning at startup
and still starts, because the startup fetch falls back to REST. The
background refresh detects this case and always uses REST. Before
production, consider giving the VTA a separate mediator.

## Troubleshooting

Mode-specific problems are in each mode's *Common gotchas* table above.
`--force-reprovision` overrides the wizard's refusal to overwrite an existing
setup. It is destructive: it replaces existing keys.

| Observed | Diagnosis | Remedy |
|---|---|---|
| Phase 2 fails: `sealed payload was the wrong variant` | Recipe says `sealed-mint` but VTA ran `vta contexts reprovision` (or vice versa) | Match `vta_mode` to the VTA-side command. `sealed-mint` expects `provision-integration`; `sealed-export` expects `contexts reprovision` |
| Mediator starts but logs `VTA integration DEGRADED` | The VTA was unreachable or returned an error; the mediator loaded its cached keys | Check the preceding SDK warning. The mediator serves on the cached keys and refreshes on the next successful VTA call |
| Mediator fails: `VTA is unreachable (or rejected the request) and no cached secrets exist` | The VTA can't be reached and the cache (`mediator_vta_last_known_bundle`) is empty | Make the VTA reachable, or re-run `mediator-setup`, which writes the cache |
| Mediator or wizard stops with a secret-store migration error | An older per-key secret layout couldn't be moved into `mediator_secrets_bundle` | Follow the message; see [When migration fails](secrets-backend.md#when-migration-fails) |
| macOS asks for keychain access repeatedly | Each rebuilt binary has a new code signature | Click "Always Allow" on each prompt |
| Wizard reports `backend unreachable` | The backend's credentials aren't in the environment | AWS: the standard credential chain (e.g. `AWS_ACCESS_KEY_ID`). Vault: `VAULT_TOKEN` (or the `?auth=` method's variables). Encrypted file: `MEDIATOR_FILE_BACKEND_PASSPHRASE`. Keyring: an unlocked OS keychain |

## Cross-references

- [VTA-side operator walkthrough](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/docs/offline-integration-bootstrap.md)
  — the same three-phase flow viewed from the VTA admin's side,
  including `pnm` / `vta` CLI invocations in detail
- [Bootstrap wire-format design brief](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/docs/bootstrap-provision-integration.md)
  — what's inside a sealed bundle, the AEAD / HPKE binding, the
  producer assertion schema
