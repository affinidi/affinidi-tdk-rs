//! Authenticated session against the mediator's `/admin/status` endpoint.
//!
//! The mediator gates `/admin/status` on a valid admin-tier JWT. mediator-monitor
//! mints those JWTs by running the standard SDK auth handshake against an
//! admin DID + secrets supplied by the operator. Tokens are cached and
//! refreshed by the SDK's authentication actor; this module just hands the
//! current access token back to the HTTP poller on each request.
//!
//! ## Admin profile file format
//!
//! A JSON file with [`affinidi_tdk_common::profiles::TDKProfile`] shape:
//!
//! ```json
//! {
//!   "alias": "admin",
//!   "did": "did:peer:2.Vz6Mk...",
//!   "mediator": "did:peer:2.Vz6Mk...",
//!   "secrets": [
//!     { "id": "did:peer:2.Vz6Mk...#key-1", "type": "...", "privateKeyJwk": { ... } },
//!     { "id": "did:peer:2.Vz6Mk...#key-2", "type": "...", "privateKeyJwk": { ... } }
//!   ]
//! }
//! ```
//!
//! `mediator` is the mediator's DID (the audience for the JWT), not its URL —
//! the URL comes from `--url` on the CLI.

use std::{path::Path, sync::Arc};

use affinidi_messaging_sdk::{ATM, config::ATMConfig, profiles::ATMProfile};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::{TDKSharedState, config::TDKConfig, profiles::TDKProfile};
use anyhow::{Context, Result};

/// Owns the authenticated session and produces fresh bearer tokens on demand.
pub struct AdminAuth {
    atm: ATM,
    profile_did: String,
    mediator_did: String,
}

impl AdminAuth {
    /// Build an authenticated session from an admin profile JSON file.
    ///
    /// The file must declare a non-empty `mediator` DID — `/admin/status`
    /// authentication is between the admin DID and the mediator DID,
    /// independent of the HTTP URL the monitor is polling.
    pub async fn from_profile_path(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read admin profile file: {}", path.display()))?;
        let mut profile: TDKProfile = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse admin profile JSON: {}", path.display()))?;

        let mediator_did = profile.mediator.clone().with_context(|| {
            format!(
                "admin profile {} is missing a `mediator` field — required to mint admin JWTs",
                path.display()
            )
        })?;
        let profile_did = profile.did.clone();

        let tdk_cfg = TDKConfig::headless().context("building TDK headless config")?;
        let tdk = Arc::new(
            TDKSharedState::new(tdk_cfg)
                .await
                .context("initialising TDK shared state")?,
        );
        // `take_secrets` drains the plaintext into the resolver and zeroizes
        // the source vector promptly.
        tdk.secrets_resolver()
            .insert_vec(&profile.take_secrets())
            .await;

        let atm_config = ATMConfig::builder()
            .build()
            .context("building ATM config")?;
        let atm = ATM::new(atm_config, tdk).await.context("starting ATM")?;

        let atm_profile = ATMProfile::from_tdk_profile(&atm, &profile)
            .await
            .context("constructing ATM profile from admin profile")?;
        // `live_stream=false` — the monitor only needs REST auth, not a
        // websocket. Errors here would surface a misconfigured admin DID
        // (e.g. mediator DID does not resolve). The returned profile Arc
        // is also held inside ATM's profile map; we don't need a second
        // handle on it for token minting.
        atm.profile_add(&atm_profile, false)
            .await
            .context("registering admin profile with ATM")?;

        Ok(Self {
            atm,
            profile_did,
            mediator_did,
        })
    }

    /// Mint or refresh an access token for the admin DID against the
    /// mediator DID. The SDK auth actor caches valid tokens and triggers
    /// refresh when the access token nears expiry, so calling this on
    /// every poll is cheap.
    pub async fn bearer_token(&self) -> Result<String> {
        let tokens = self
            .atm
            .get_tdk()
            .authentication()
            .authenticate(self.profile_did.clone(), self.mediator_did.clone(), 3, None)
            .await
            .context("admin DID auth handshake failed")?;
        Ok(tokens.access_token)
    }

    /// Drop SDK background tasks cleanly. The TUI runs `Drop`-only
    /// at exit; calling this gives the auth/deletion actors a chance
    /// to shut down before the runtime tears down.
    pub async fn shutdown(&self) {
        self.atm.graceful_shutdown().await;
    }
}
