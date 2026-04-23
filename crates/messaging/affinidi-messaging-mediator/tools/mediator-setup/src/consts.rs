/// Deployment type display strings
pub const DEPLOYMENT_LOCAL: &str = "Local development";
pub const DEPLOYMENT_SERVER: &str = "Headless server";
pub const DEPLOYMENT_CONTAINER: &str = "Container";

/// DID method display strings
pub const DID_VTA: &str = "VTA managed";
pub const DID_WEBVH: &str = "did:webvh";
pub const DID_PEER: &str = "did:peer";
pub const DID_IMPORT: &str = "Import existing";

/// Secret storage schemes
pub const STORAGE_STRING: &str = "string://";
pub const STORAGE_FILE: &str = "file://";
pub const STORAGE_KEYRING: &str = "keyring://";
pub const STORAGE_AWS: &str = "aws_secrets://";
pub const STORAGE_GCP: &str = "gcp_secrets://";
pub const STORAGE_AZURE: &str = "azure_keyvault://";
pub const STORAGE_VAULT: &str = "vault://";
pub const STORAGE_VTA: &str = "vta://";

/// SSL mode display strings
pub const SSL_NONE: &str = "No SSL (TLS proxy)";
pub const SSL_EXISTING: &str = "Existing certificates";
pub const SSL_SELF_SIGNED: &str = "Self-signed";

/// JWT secret provisioning mode. `generate` (default) tells the wizard to
/// mint a fresh Ed25519 PKCS8 key and push it into the unified secret
/// backend at `mediator/jwt/secret`. `provide` records the operator's
/// intent to supply their own — the mediator then expects either a
/// `MEDIATOR_JWT_SECRET` env var or a `--jwt-secret-file` path at boot.
/// Interactive paste is intentionally NOT supported; private keys never
/// belong in terminal scrollback.
pub const JWT_MODE_GENERATE: &str = "generate";
pub const JWT_MODE_PROVIDE: &str = "provide";

/// Admin DID mode display strings
pub const ADMIN_GENERATE: &str = "Generate did:key";
pub const ADMIN_PASTE: &str = "Paste existing";
pub const ADMIN_VTA: &str = "Copy from VTA";
pub const ADMIN_SKIP: &str = "Skip";

/// VTA connectivity modes.
///
/// `online` is the default — the mediator's setup wizard authenticates
/// against the VTA's REST + DIDComm endpoints to mint the admin
/// credential.
///
/// `sealed` (air-gapped sealed handoff) replaces the legacy
/// `cold-start` mode: the operator generates an ephemeral X25519
/// keypair on the mediator host, ships the public-half bootstrap
/// request to the VTA admin out-of-band, and then pastes back an
/// HPKE-armored bundle. No network call from the mediator host.
/// `cold-start` is intentionally gone — its hand-rolled file format
/// pre-dated the unified sealed-transfer envelope and offered no
/// integrity guarantees on the wire.
pub const VTA_MODE_ONLINE: &str = "online";
pub const VTA_MODE_SEALED: &str = "sealed";
/// Air-gapped *export* of pre-provisioned mediator state. The VTA
/// admin already minted the mediator's context + DID + keys (e.g.
/// during the VTA's own bootstrap); the wizard's job is to retrieve
/// that material via a v1 sealed_transfer::BootstrapRequest the
/// operator carries out-of-band, then the VTA admin runs
/// `vta context reprovision --id <ctx> --recipient <req> --out <bundle>`
/// and ships the sealed `ContextProvision` bundle back. Distinct from
/// `sealed` (which mints fresh material on the VTA in response to a
/// VP-framed request).
pub const VTA_MODE_EXPORT: &str = "export";

/// Default values
pub const DEFAULT_CONFIG_PATH: &str = "conf/mediator.toml";
pub const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1/";
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:7037";
pub const DEFAULT_VTA_CONTEXT: &str = "mediator";
/// Default expiry for the setup-did ACL entry granted via
/// `pnm contexts create --admin-expires`. Gives the operator an hour to
/// finish mediator setup; override to `24h`, `7d`, etc. for slower rollouts.
pub const DEFAULT_VTA_SETUP_EXPIRY: &str = "1h";

/// Name of the built-in VTA DID template the wizard asks the VTA to
/// render for the mediator's own integration DID. Operators may
/// shadow this under the context or global scope via
/// `pnm did-templates upload --name didcomm-mediator …` and the VTA's
/// resolution order (context → global → builtin) will pick up the
/// override on the next wizard run.
pub const DEFAULT_MEDIATOR_TEMPLATE: &str = "didcomm-mediator";

/// Name of the built-in VTA DID template used for the long-term admin
/// DID the VTA mints during provisioning (`adminTemplate` on the VP
/// `ask`). Same shadowing rules as
/// [`DEFAULT_MEDIATOR_TEMPLATE`] — a `vta-admin` template registered
/// at the context scope overrides the builtin.
pub const DEFAULT_VTA_ADMIN_TEMPLATE: &str = "vta-admin";

/// Per-backend sensible defaults for the KeyStorage step.
pub const DEFAULT_SECRET_FILE_PATH: &str = "conf/secrets.json";
pub const DEFAULT_KEYRING_SERVICE: &str = "affinidi-mediator";
pub const DEFAULT_AWS_REGION: &str = "us-east-1";
pub const DEFAULT_AWS_SECRET_PREFIX: &str = "mediator/";
