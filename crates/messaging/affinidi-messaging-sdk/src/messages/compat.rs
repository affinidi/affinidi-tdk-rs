//! Compatibility types for the migration from `affinidi-messaging-didcomm` (legacy) to `affinidi-messaging-didcomm` (new).
//!
//! These types replicate the legacy API surface so that callers of the SDK
//! (e.g. WebSocket cache, protocol handlers) continue to work without changes.

/// Compatibility type matching the legacy `UnpackMetadata`.
///
/// The new `affinidi_messaging_didcomm` crate returns structured `UnpackResult` variants
/// instead of a flat metadata struct. This shim is populated from those variants
/// so that existing SDK callers can keep working.
///
/// **Sealed (`#[non_exhaustive]`).** This is a *returned* value — the SDK
/// constructs it, downstream code only reads its (public) fields — so it is
/// sealed to allow future fields to be added without a breaking change.
/// External crates cannot build it with a struct literal; workspace crates that
/// do produce it (the mediator's `didcomm_compat`) use `UnpackMetadata::default()`
/// followed by field assignment.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct UnpackMetadata {
    pub encrypted: bool,
    pub authenticated: bool,
    pub non_repudiation: bool,
    pub anonymous_sender: bool,
    pub re_wrapped_in_forward: bool,
    pub encrypted_from_kid: Option<String>,
    pub encrypted_to_kids: Vec<String>,
    pub sign_from: Option<String>,
    /// SHA-256 hash of the packed message (computed by the SDK before unpacking)
    pub sha256_hash: String,
    /// The classified envelope wrapping type of the unpacked message
    /// (authcrypt / anoncrypt / signed / layered combinations). Populated by
    /// `unpack`; defaults to [`MessageWrappingType::Plaintext`].
    #[serde(default)]
    pub wrapping: crate::messages::wrapping::MessageWrappingType,
    /// Every verified signer `kid` found across all JWS signature layers
    /// (a signed message may carry multiple signatures). Empty for unsigned
    /// messages.
    #[serde(default)]
    pub signers: Vec<String>,
}

/// Compatibility type for the legacy `PackEncryptedMetadata`.
///
/// Most callers discard this value; it exists only to keep return signatures compatible.
#[derive(Debug, Default, Clone)]
pub struct PackEncryptedMetadata {
    pub from_kid: Option<String>,
    pub sign_by_kid: Option<String>,
    pub to_kids: Vec<String>,
}
