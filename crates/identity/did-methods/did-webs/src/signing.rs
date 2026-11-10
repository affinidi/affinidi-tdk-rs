//! Who signs: a salt-derived [`Hab`], or keys held by the caller.
//!
//! Every event and every signed message a `did:webs` identifier publishes —
//! interaction events anchoring designations, the designations' signature
//! groups, endpoint replies — is signed by the current key state. That is the
//! same whether the keys come from a salt ([`Hab`]) or are held elsewhere and
//! reached through [`KeySigner`]s ([`Held`]), so the code that builds them
//! takes a [`Controller`] and does not know which.

use affinidi_keri::ProtocolVersion;
use affinidi_keri::controller::{ControllerState, KeySigner};
use affinidi_keri::hab::{Hab, SignedEvent};
use affinidi_keri_core::sad::SadValue;
use affinidi_keri_crypto::{Siger, Verfer};

use crate::errors::DidWebsError;

/// Signing by an identifier's current key state.
pub(crate) trait Controller {
    /// The AID.
    fn prefix(&self) -> &str;

    /// Sequence number of the latest event.
    fn sn(&self) -> u64;

    /// The current signing keys, qb64, in key-state order.
    fn current_keys(&self) -> Result<Vec<String>, DidWebsError>;

    /// Indexed signatures over `message`, qb64, by enough current keys to
    /// meet the signing threshold.
    fn sign_current(&self, message: &[u8]) -> Result<Vec<String>, DidWebsError>;

    /// Append an interaction event anchoring `anchors`.
    fn interact(&mut self, anchors: &[SadValue]) -> Result<SignedEvent, DidWebsError>;

    /// The KERI version the next event is written in. Designations and
    /// replies are written in the same version (P2: VTI writes pure v2).
    fn version(&self) -> ProtocolVersion;
}

/// An establishment event, which a signature outside the key event log names:
/// the key state it installed is the one that signed.
///
/// Both halves are written into an endorsement, and a verifier such as keripy
/// looks the event up by its sequence number and then compares the SAID, so
/// the sequence number must be the establishment event's own, not the log's
/// latest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Establishment {
    /// Its sequence number.
    pub sn: u64,
    /// Its SAID.
    pub said: String,
}

impl Controller for Hab {
    fn prefix(&self) -> &str {
        Hab::prefix(self)
    }

    fn sn(&self) -> u64 {
        Hab::sn(self)
    }

    fn current_keys(&self) -> Result<Vec<String>, DidWebsError> {
        self.signers()
            .iter()
            .map(|s| {
                s.verfer()
                    .qb64()
                    .map_err(|e| DidWebsError::Create(format!("key: {e}")))
            })
            .collect()
    }

    fn sign_current(&self, message: &[u8]) -> Result<Vec<String>, DidWebsError> {
        // Every current key signs, at its own index. A resolver holds a
        // signature group to the key state's signing threshold, so signing
        // with the first key alone would fail a multi-key identifier.
        self.signers()
            .iter()
            .enumerate()
            .map(|(index, signer)| {
                signer
                    .sign_indexed(message, index, false)
                    .and_then(|s| s.qb64())
                    .map_err(|e| DidWebsError::Create(format!("could not sign: {e}")))
            })
            .collect()
    }

    fn interact(&mut self, anchors: &[SadValue]) -> Result<SignedEvent, DidWebsError> {
        self.interact_event(anchors)
            .map_err(|e| DidWebsError::Create(format!("interaction failed: {e}")))
    }

    fn version(&self) -> ProtocolVersion {
        Hab::version(self)
    }
}

/// An identifier whose current keys the caller holds, as [`KeySigner`]s.
///
/// The signers given must meet the current signing threshold between them;
/// a signer whose key is not current is refused, so a stale signer is an
/// error rather than a silently missing signature.
pub(crate) struct Held<'a> {
    pub(crate) state: ControllerState,
    signers: &'a [&'a dyn KeySigner],
}

impl<'a> Held<'a> {
    pub(crate) fn new(
        state: ControllerState,
        signers: &'a [&'a dyn KeySigner],
    ) -> Result<Self, DidWebsError> {
        if signers.is_empty() {
            return Err(DidWebsError::Create(
                "no signer for the identifier's current keys".into(),
            ));
        }
        Ok(Self { state, signers })
    }

    /// Each signer with the index of its key in the current key state.
    fn indexed(&self) -> Result<Vec<(usize, &'a dyn KeySigner)>, DidWebsError> {
        let mut out = Vec::with_capacity(self.signers.len());
        for signer in self.signers {
            let key = signer
                .public_key()
                .map_err(|e| DidWebsError::Create(format!("signer key: {e}")))?;
            let index = self
                .state
                .keys
                .iter()
                .position(|k| *k == key)
                .ok_or_else(|| {
                    DidWebsError::Create(format!(
                        "{key} is not a current key of {}",
                        self.state.prefix
                    ))
                })?;
            out.push((index, *signer));
        }
        Ok(out)
    }
}

impl Controller for Held<'_> {
    fn prefix(&self) -> &str {
        &self.state.prefix
    }

    fn sn(&self) -> u64 {
        self.state.sn
    }

    fn current_keys(&self) -> Result<Vec<String>, DidWebsError> {
        Ok(self.state.keys.clone())
    }

    fn sign_current(&self, message: &[u8]) -> Result<Vec<String>, DidWebsError> {
        let indexed = self.indexed()?;
        let indices: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
        if !self
            .state
            .threshold
            .0
            .is_satisfied(&indices, self.state.keys.len())
        {
            return Err(DidWebsError::Create(format!(
                "the signers given do not meet {}'s signing threshold",
                self.state.prefix
            )));
        }
        let mut out = Vec::with_capacity(indexed.len());
        for (index, signer) in indexed {
            let key = &self.state.keys[index];
            let raw = signer
                .sign(message)
                .map_err(|e| DidWebsError::Create(format!("could not sign: {e}")))?;
            let verfer =
                Verfer::from_qb64(key).map_err(|e| DidWebsError::Create(format!("key: {e}")))?;
            if !verfer
                .verify(message, &raw)
                .map_err(|e| DidWebsError::Create(format!("signature: {e}")))?
            {
                return Err(DidWebsError::Create(format!(
                    "the signer for {key} produced a signature that does not verify"
                )));
            }
            let code = indexed_code(key)?;
            out.push(
                Siger::new_with_verfer(code, index, None, raw, verfer)
                    .and_then(|s| s.qb64())
                    .map_err(|e| DidWebsError::Create(format!("signature: {e}")))?,
            );
        }
        Ok(out)
    }

    fn interact(&mut self, anchors: &[SadValue]) -> Result<SignedEvent, DidWebsError> {
        let mut pending = self
            .state
            .interact(anchors)
            .map_err(|e| DidWebsError::Create(format!("interaction failed: {e}")))?;
        for (_, signer) in self.indexed()? {
            pending
                .sign_with(signer)
                .map_err(|e| DidWebsError::Create(format!("could not sign: {e}")))?;
        }
        let (event, state) = pending.finish().map_err(|e| {
            DidWebsError::Create(format!(
                "the signers given do not meet the signing threshold: {e}"
            ))
        })?;
        self.state = state;
        Ok(event)
    }

    fn version(&self) -> ProtocolVersion {
        self.state.version
    }
}

/// The "current only" indexed signature code for a key's algorithm.
fn indexed_code(key: &str) -> Result<&'static str, DidWebsError> {
    if key.starts_with("1AAA") || key.starts_with("1AAB") {
        Ok("C")
    } else if key.starts_with("1AAI") || key.starts_with("1AAJ") {
        Ok("E")
    } else if key.starts_with('D') || key.starts_with('B') {
        Ok("A")
    } else {
        Err(DidWebsError::Create(format!("{key} is not a signing key")))
    }
}
