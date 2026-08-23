//! Verifying the key event logs in a `keri.cesr` stream.
//!
//! A `did:webs` artifact carries the KEL of the AID being resolved, and — when
//! that AID is delegated — the KELs it depends on. Nothing in the stream is
//! trusted for having been served from the right URL: every event is verified
//! against the key state its own KEL establishes.
//!
//! Delegation is what makes this more than a single replay. A delegated event
//! is authorised by a seal anchored in the *delegator's* KEL, so verifying one
//! identifier can require verifying another first. That is handled by
//! resolving each KEL on demand and remembering the result, with a bound on
//! how deep a delegation chain may go.

use std::cell::RefCell;
use std::collections::HashMap;

use affinidi_keri_core::delegation::{DelegationProof, DelegatorAnchors};
use affinidi_keri_core::error::CoreError;
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::key_state::KeyState;
use affinidi_keri_core::parser::{self, ParsedMessage};
use affinidi_keri_crypto::Verfer;

use crate::errors::DidWebsError;

/// How many delegation steps to follow before giving up.
///
/// A delegator may itself be delegated. Real chains are short (GLEIF's vLEI
/// goes root → QVI → legal entity), and an unbounded walk would let a crafted
/// stream spin us in a cycle.
const MAX_DELEGATION_DEPTH: usize = 8;

/// The events of a `keri.cesr` stream, grouped by the identifier they belong
/// to, with verification results remembered as they are computed.
pub struct Kels {
    /// Every message in the stream, in the order it arrived.
    messages: Vec<ParsedMessage>,
    /// Indices into `messages`, grouped by prefix.
    by_prefix: HashMap<String, Vec<usize>>,
    /// Key states already verified, keyed by prefix.
    verified: RefCell<HashMap<String, KeyState>>,
    /// Prefixes currently being verified, to catch a delegation cycle.
    in_progress: RefCell<Vec<String>>,
}

impl Kels {
    /// Parse a `keri.cesr` stream and group its events by identifier.
    ///
    /// Parsing is strict: a stream carrying an attachment group this
    /// implementation cannot interpret is rejected rather than verified with
    /// part of its content ignored.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Stream`] if the stream cannot be parsed.
    pub fn parse(stream: &[u8]) -> Result<Self, DidWebsError> {
        let messages = parser::parse_all(stream)
            .map_err(|e| DidWebsError::Stream(format!("could not parse keri.cesr: {e}")))?;

        let mut by_prefix: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, msg) in messages.iter().enumerate() {
            // Only key events belong to a KEL. Anything else in the stream
            // (registry events, credentials) is indexed by nothing and simply
            // not consulted here.
            let Ok(ilk) = msg.serder.ilk() else { continue };
            if !matches!(ilk.as_str(), "icp" | "rot" | "ixn" | "dip" | "drt") {
                continue;
            }
            let Ok(prefix) = msg.serder.prefix() else {
                continue;
            };
            by_prefix.entry(prefix).or_default().push(i);
        }

        Ok(Self {
            messages,
            by_prefix,
            verified: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(Vec::new()),
        })
    }

    /// Every message in the stream, key events or not.
    pub fn messages(&self) -> &[ParsedMessage] {
        &self.messages
    }

    /// Verify `prefix`'s key event log and return the resulting key state.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Kel`] if the stream has no KEL for `prefix`, an
    /// event fails to verify, or a delegation cannot be established.
    pub fn key_state(&self, prefix: &str) -> Result<KeyState, DidWebsError> {
        if let Some(state) = self.verified.borrow().get(prefix) {
            return Ok(state.clone());
        }

        {
            let mut in_progress = self.in_progress.borrow_mut();
            if in_progress.iter().any(|p| p == prefix) {
                return Err(DidWebsError::Kel(format!(
                    "delegation cycle: {prefix} is its own delegator, directly or through \
                     {} intermediate identifiers",
                    in_progress.len() - 1,
                )));
            }
            if in_progress.len() >= MAX_DELEGATION_DEPTH {
                return Err(DidWebsError::Kel(format!(
                    "delegation chain deeper than {MAX_DELEGATION_DEPTH}"
                )));
            }
            in_progress.push(prefix.to_string());
        }

        let result = self.verify_kel(prefix);

        self.in_progress.borrow_mut().pop();

        let state = result?;
        self.verified
            .borrow_mut()
            .insert(prefix.to_string(), state.clone());
        Ok(state)
    }

    /// Whether `aid`'s verified key event log anchors a seal naming
    /// (`prefix`, `sn`, `said`).
    ///
    /// Anchoring is how a KEL authorises something outside itself — a
    /// delegation, or an entry in a transaction event log. Unlike
    /// [`DelegatorAnchors::anchors_at`] the caller does not know *which* event
    /// carries the seal, so the whole verified log is searched.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Kel`] if `aid`'s key event log does not verify.
    pub fn anchors_seal(
        &self,
        aid: &str,
        prefix: &str,
        sn: u64,
        said: &str,
    ) -> Result<bool, DidWebsError> {
        // Verify first: a seal in an unverified event authorises nothing.
        self.key_state(aid)?;

        let Some(indices) = self.by_prefix.get(aid) else {
            return Ok(false);
        };

        let expected_sn = format!("{sn:x}");
        for i in indices {
            let anchors = self.messages[*i]
                .serder
                .sad()
                .get("a")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();

            for anchor in anchors {
                let matches = anchor.get("i").and_then(|v| v.as_str()) == Some(prefix)
                    && anchor.get("d").and_then(|v| v.as_str()) == Some(said)
                    && anchor.get("s").and_then(|v| v.as_str()) == Some(expected_sn.as_str());
                if matches {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// The first message in the stream whose `d` field is `said`.
    ///
    /// Transaction events and credentials are addressed by SAID rather than by
    /// position, and are not part of any KEL.
    pub fn message_by_said(&self, said: &str) -> Option<&ParsedMessage> {
        self.messages
            .iter()
            .find(|m| m.serder.said().ok().as_deref() == Some(said))
    }

    /// Every message in the stream with no `t` field at all.
    ///
    /// ACDCs are not events and carry no ilk, which is what distinguishes a
    /// credential from a key or transaction event in the same stream.
    pub fn messages_with_ilk_none(&self) -> impl Iterator<Item = &ParsedMessage> {
        self.messages.iter().filter(|m| m.serder.ilk().is_err())
    }

    /// Every message in the stream whose `t` field is `ilk`.
    pub fn messages_with_ilk<'a>(
        &'a self,
        ilk: &'a str,
    ) -> impl Iterator<Item = &'a ParsedMessage> + 'a {
        self.messages
            .iter()
            .filter(move |m| m.serder.ilk().ok().as_deref() == Some(ilk))
    }

    /// Replay one identifier's KEL from its inception.
    fn verify_kel(&self, prefix: &str) -> Result<KeyState, DidWebsError> {
        let indices = self.by_prefix.get(prefix).ok_or_else(|| {
            DidWebsError::Kel(format!("keri.cesr carries no key events for {prefix}"))
        })?;

        let mut events = indices.iter().map(|i| &self.messages[*i]);
        let first = events.next().ok_or_else(|| {
            DidWebsError::Kel(format!("keri.cesr carries no events for {prefix}"))
        })?;

        let mut kever = self.incept(prefix, first)?;

        for (n, msg) in events.enumerate() {
            let ilk = msg
                .serder
                .ilk()
                .map_err(|e| DidWebsError::Kel(format!("event {} has no ilk: {e}", n + 1)))?;
            let sigs = msg.controller_sigs();

            let state = if ilk == "drt" {
                let proof = self.delegation_proof(msg)?;
                kever
                    .verify_update_delegated(&msg.serder, sigs, &proof, self)
                    .map_err(|e| {
                        DidWebsError::Kel(format!("{prefix} delegated rotation {}: {e}", n + 1))
                    })?
            } else {
                kever
                    .verify_update(&msg.serder, sigs)
                    .map_err(|e| DidWebsError::Kel(format!("{prefix} event {}: {e}", n + 1)))?
            };
            kever.apply_verified_update(state);
        }

        Ok(kever.state().clone())
    }

    /// Build the initial key state from an inception or delegated inception.
    fn incept(&self, prefix: &str, msg: &ParsedMessage) -> Result<Kever, DidWebsError> {
        let ilk = msg
            .serder
            .ilk()
            .map_err(|e| DidWebsError::Kel(format!("{prefix} first event has no ilk: {e}")))?;
        let verfers = verfers_from_event(&msg.serder)?;
        let sigs = msg.controller_sigs();

        match ilk.as_str() {
            "icp" => Kever::new(&msg.serder, sigs, &verfers)
                .map_err(|e| DidWebsError::Kel(format!("{prefix} inception: {e}"))),
            "dip" => {
                let proof = self.delegation_proof(msg)?;
                Kever::new_delegated(&msg.serder, sigs, &verfers, &proof, self)
                    .map_err(|e| DidWebsError::Kel(format!("{prefix} delegated inception: {e}")))
            }
            other => Err(DidWebsError::Kel(format!(
                "{prefix}'s key event log starts with a {other:?} event, not an inception"
            ))),
        }
    }

    /// Read the seal source couple a delegated event must carry.
    fn delegation_proof(&self, msg: &ParsedMessage) -> Result<DelegationProof, DidWebsError> {
        let couples = msg.seal_source_couples();
        let (sn, said) = couples.first().ok_or_else(|| {
            DidWebsError::Kel(
                "delegated event carries no seal source couple, so there is nothing \
                 pointing at the delegator's authorisation"
                    .into(),
            )
        })?;
        DelegationProof::from_seal_source_couple(sn, said)
            .map_err(|e| DidWebsError::Kel(format!("unreadable seal source couple: {e}")))
    }
}

/// The delegator lookup: only ever answers from a KEL this type has verified.
impl DelegatorAnchors for Kels {
    fn anchors_at(
        &self,
        delegator: &str,
        sn: u64,
        said: &str,
    ) -> Result<Option<Vec<serde_json::Value>>, CoreError> {
        // Verifying the delegator's own KEL first is the whole contract of this
        // trait. Returning anchors from events that merely parsed would let any
        // stream claim any delegation.
        if self.key_state(delegator).is_err() {
            return Ok(None);
        }

        let Some(indices) = self.by_prefix.get(delegator) else {
            return Ok(None);
        };

        for i in indices {
            let msg = &self.messages[*i];
            if msg.serder.sn().ok() != Some(sn) {
                continue;
            }
            if msg.serder.said().ok().as_deref() != Some(said) {
                continue;
            }
            let anchors = msg
                .serder
                .sad()
                .get("a")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            return Ok(Some(anchors));
        }

        Ok(None)
    }
}

/// The verification keys an establishment event lists in its own `k` field.
fn verfers_from_event(
    serder: &affinidi_keri_core::serder::Serder,
) -> Result<Vec<Verfer>, DidWebsError> {
    let keys = serder
        .sad()
        .get("k")
        .and_then(|k| k.as_array())
        .ok_or_else(|| DidWebsError::Kel("establishment event has no key list".into()))?;

    keys.iter()
        .map(|k| {
            let key = k
                .as_str()
                .ok_or_else(|| DidWebsError::Kel("key list contains a non-string".into()))?;
            Verfer::from_qb64(key)
                .map_err(|e| DidWebsError::Kel(format!("key {key:?} is not usable: {e}")))
        })
        .collect()
}
