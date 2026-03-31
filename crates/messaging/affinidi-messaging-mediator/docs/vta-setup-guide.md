# VTA Setup Guide for the Mediator

This guide walks through configuring the mediator to use a
[Verifiable Trust Agent (VTA)](https://github.com/OpenVTC/verifiable-trust-infrastructure)
for centralized DID and key management.

## Overview

When integrated with a VTA, the mediator fetches its DID and cryptographic
secrets from the VTA at startup instead of loading them from local files. This
provides:

- **Centralized key management** -- keys never leave the VTA, secrets are
  fetched on demand
- **Automatic token refresh** -- the SDK handles re-authentication transparently
- **Multiple credential storage backends** -- string, AWS Secrets Manager, OS
  keyring
- **Circular dependency detection** -- the mediator detects and warns if the VTA
  routes DIDComm through this mediator

## Prerequisites

- A running VTA instance with REST enabled
- VTA admin access (via `cnm-cli` or `pnm-cli`)
- Redis 8.0+ (for the mediator's message storage)

## Method 1: Setup Wizard (Recommended)

The interactive wizard handles everything in a single flow.

### Step 1: Provision a Context on the VTA

Using the PNM CLI, create a context with a DID for the mediator:

```bash
pnm contexts provision --context-id mediator --name "Messaging Mediator" --create-did
```

This outputs a **Context Provision Bundle** (a long base64url string). Copy it.

### Step 2: Build and Run the Wizard

```bash
cargo run --bin mediator-setup-vta --features setup
```

The wizard will prompt you to:

1. **Paste the bundle** -- paste the provision bundle from step 1. Input is
   masked with asterisks.
2. **Choose credential storage** -- where the mediator loads the VTA credential
   at runtime:
   - `string://` -- embed in config file (dev/CI)
   - `aws_secrets://` -- AWS Secrets Manager (production)
   - `keyring://` -- OS keychain (local dev)
3. **Confirm context** -- auto-detected from the bundle.
4. **Confirm DID** -- auto-configured from the bundle. Keys are already in the
   VTA. Optionally saves the DID document for did:web self-hosting.
5. **Update config** -- automatically updates `mediator.toml`.

### Step 3: Start the Mediator

```bash
# For AWS credential storage:
cargo run --features vta-aws-secrets

# For OS keyring:
cargo run --features vta-keyring

# For string:// (dev, no extra features needed):
cargo run
```

## Method 2: Manual Configuration

### Step 1: Generate a VTA Credential

Ask the VTA admin to generate a credential for the mediator:

```bash
cnm-cli auth credentials generate
```

This outputs a base64url credential string.

### Step 2: Create a VTA Context

Create a context to group the mediator's DID and keys:

```bash
pnm contexts create --id mediator --name "Messaging Mediator"
```

### Step 3: Set Up the DID

**Option A: Create a new did:webvh via VTA**

```bash
pnm webvh dids create --context mediator
```

**Option B: Import an existing DID**

If you have an existing mediator DID, import its keys into the VTA context:

```bash
pnm keys import --context mediator --key-type ed25519 --multibase <private_key>
pnm keys import --context mediator --key-type x25519 --multibase <private_key>
pnm contexts update mediator --did <your_did>
```

### Step 4: Configure mediator.toml

Update the following fields:

```toml
# Point DID and secrets at the VTA context
mediator_did = "vta://mediator"

[security]
mediator_secrets = "vta://mediator"

# VTA connection configuration
[vta]
# Credential storage (choose one):
#   string://<base64url>         - Direct credential (dev/CI)
#   aws_secrets://<secret_name>  - AWS Secrets Manager (production)
#   keyring://<service>/<user>   - OS keyring (local dev)
credential = "string://eyJkaWQ..."

# VTA context name (must match the context created above)
context = "mediator"

# Optional: override the VTA URL from the credential (useful for dev/testing)
# url = "https://localhost:8080"
```

### Step 5: Build with the Right Feature

```bash
# For string:// credentials (no extra feature needed):
cargo build

# For AWS Secrets Manager:
cargo build --features vta-aws-secrets

# For OS keyring:
cargo build --features vta-keyring
```

### Step 6: Start the Mediator

```bash
cargo run
```

At startup you will see:

```
Authenticating to VTA via REST...
Successfully authenticated to VTA at 'https://vta.example.com:8080' (REST, auto-refresh enabled)
Fetching mediator_did from VTA context 'mediator'
Loading 3 mediator Secrets from VTA context 'mediator'
```

## Environment Variable Configuration

Every VTA setting can be overridden via environment variables, which is useful
for CI/CD and container deployments:

```bash
export MEDIATOR_DID="vta://mediator"
export MEDIATOR_SECRETS="vta://mediator"
export VTA_CREDENTIAL="string://eyJkaWQ..."
export VTA_CONTEXT="mediator"
# export VTA_URL="https://vta.example.com:8080"  # optional override
```

If `VTA_CREDENTIAL` is set and no `[vta]` section exists in the TOML file, the
section is created automatically from environment variables.

## Credential Storage Backends

| Scheme | Feature Required | Use Case |
|---|---|---|
| `string://<base64url>` | None | Dev, CI/CD via env vars |
| `aws_secrets://<secret_name>` | `vta-aws-secrets` | Production on AWS |
| `keyring://<service>/<user>` | `vta-keyring` | Local dev with OS keychain |
| `keyring://<service>` | `vta-keyring` | Same as above (default user: "credential") |

### Storing credentials in AWS Secrets Manager

```bash
aws secretsmanager create-secret \
  --name mediator/vta-credential \
  --secret-string '<base64url_credential>'
```

Then configure:

```toml
[vta]
credential = "aws_secrets://mediator/vta-credential"
```

### Storing credentials in OS keyring

The setup wizard can save to the keyring automatically when built with
`--features setup,vta-keyring`. To store manually:

```bash
# macOS
security add-generic-password -s affinidi-mediator -a vta-credential -w '<credential>'

# Linux (using secret-tool)
echo -n '<credential>' | secret-tool store --label="VTA Credential" service affinidi-mediator username vta-credential
```

Then configure:

```toml
[vta]
credential = "keyring://affinidi-mediator/vta-credential"
```

## DID Sources

The `mediator_did` field supports multiple source schemes:

| Scheme | Description |
|---|---|
| `did://<did_string>` | Direct DID string (no VTA needed) |
| `aws_parameter_store://<param>` | Fetch from AWS SSM Parameter Store |
| `vta://<context>` | Fetch from VTA context (requires `[vta]` section) |

These can be mixed -- for example, `mediator_did` from VTA but `admin_did`
from a direct string.

## Circular Dependency Detection

If the VTA itself routes DIDComm messages through this mediator, a circular
dependency exists. The mediator detects this at startup:

1. **Network failure** -- if the VTA is unreachable via REST, the mediator
   refuses to start with a clear error explaining the deadlock scenario.

2. **DID-level detection** -- after authenticating, the mediator calls the
   VTA's health endpoint and compares the VTA's configured `mediator_did`
   against its own DID. If they match:

   ```
   CIRCULAR DEPENDENCY: This mediator's DID (did:web:...) matches the VTA's
   configured mediator DID. The VTA routes DIDComm through this mediator.
   ```

3. **Why it still works** -- the mediator uses REST (not DIDComm) to
   communicate with the VTA during startup. This breaks the bootstrap
   deadlock. However, if both services restart simultaneously, start the VTA
   first (with REST enabled), then the mediator.

## Troubleshooting

### "Cannot reach VTA via REST"

The mediator requires REST access to the VTA during startup. Verify:
- The VTA is running and healthy: `curl https://vta.example.com:8080/health`
- The VTA URL in the credential or `[vta].url` is correct
- Network/firewall rules allow the mediator to reach the VTA

### "VTA authentication failed"

- The credential may be expired or revoked. Generate a new one.
- Check that the credential was generated for this VTA instance.

### "VTA context has no DID configured"

The VTA context exists but no DID has been assigned. Either:
- Create a DID: `pnm webvh dids create --context mediator`
- Or assign an existing DID: `pnm contexts update mediator --did <did>`

### "aws_secrets:// requires the 'vta-aws-secrets' feature"

Rebuild with:

```bash
cargo build --features vta-aws-secrets
```

### "keyring:// requires the 'vta-keyring' feature"

Rebuild with:

```bash
cargo build --features vta-keyring
```
