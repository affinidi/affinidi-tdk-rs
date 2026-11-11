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
use std::sync::Arc;

use affinidi_keri_core::delegation::{DelegationProof, DelegatorAnchors};
use affinidi_keri_core::error::CoreError;
use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::key_state::KeyState;
use affinidi_keri_core::parser::{self, Attachment, ParsedMessage, TransIdxSigGroup};
use affinidi_keri_crypto::Verfer;

use crate::errors::DidWebsError;

/// How many delegation steps to follow before giving up.
///
/// A delegator may itself be delegated. Real chains are short (GLEIF's vLEI
/// goes root → QVI → legal entity), and an unbounded walk would let a crafted
/// stream spin us in a cycle.
const MAX_DELEGATION_DEPTH: usize = 8;

/// The most messages a `keri.cesr` stream may carry.
///
/// Every message is indexed, and the key events among them verified, so the
/// work a stream asks for grows with its length. A stream past this many
/// messages is refused before anything in it is verified.
pub const MAX_STREAM_MESSAGES: usize = 10_000;

/// The most signatures a `keri.cesr` stream may carry, counting controller
/// and witness signatures, receipt couples and the signatures in every
/// transferable signature group.
///
/// Verification checks each signature a bounded number of times, so this
/// caps the signature checks one resolution performs.
pub const MAX_STREAM_SIGNATURES: usize = 16_384;

/// `rct` messages, keyed by the (`i`, `s`, `d`) of the event they receipt.
type ReceiptIndex = HashMap<(String, String, String), Vec<usize>>;

/// The events of a `keri.cesr` stream, grouped by the identifier they belong
/// to, with verification results remembered as they are computed.
pub struct Kels {
    /// Every message in the stream, in the order it arrived. Shared with
    /// the views [`Kels::view`] takes.
    messages: Arc<Vec<ParsedMessage>>,
    /// Indices into `messages`, grouped by prefix, as far as a read may see
    /// (see [`Kels::as_of`]).
    by_prefix: HashMap<String, Vec<usize>>,
    /// Indices into `messages`, grouped by prefix: the whole stream.
    full_by_prefix: HashMap<String, Vec<usize>>,
    /// The sequence number a read is limited to, per prefix.
    limits: HashMap<String, u64>,
    /// The index into `messages` of the first message with each SAID.
    by_said: Arc<HashMap<String, usize>>,
    /// The `rct` messages, by the event each names.
    receipts: Arc<ReceiptIndex>,
    /// Key states already verified, keyed by prefix.
    verified: RefCell<HashMap<String, KeyState>>,
    /// Prefixes currently being verified, to catch a delegation cycle.
    in_progress: RefCell<Vec<String>>,
    /// Indices into `messages` of interaction events a rotation superseded,
    /// by prefix, as the last verification of that prefix found them. They
    /// are not part of the log: nothing they anchor counts (P7).
    superseded: RefCell<HashMap<String, Vec<usize>>>,
    /// The key state each establishment event installed, by SAID, per
    /// prefix, as the last verification of that prefix found them.
    establishment: RefCell<HashMap<String, HashMap<String, KeyState>>>,
    /// Each prefix's log over the whole stream, as the registry reader takes
    /// it, once a replay has recorded it.
    full_logs: RefCell<HashMap<String, Recorded>>,
}

/// What a replay records: the log for the registry reader, and the key
/// state at each establishment event.
#[derive(Default, Clone)]
struct Recorded {
    /// The log's events, superseded ones removed.
    events: Vec<affinidi_keri_core::registry::LoggedEvent>,
    /// The events a rotation superseded.
    superseded: Vec<affinidi_keri_core::registry::LoggedEvent>,
    /// The key state each establishment event installed, by its SAID.
    establishment: HashMap<String, KeyState>,
}

impl Recorded {
    /// Record the key state an establishment event installed. A SAID seen
    /// again keeps the state it first installed.
    fn establish(&mut self, msg: &ParsedMessage, state: &KeyState) {
        if let Ok(said) = msg.serder.said() {
            self.establishment
                .entry(said)
                .or_insert_with(|| state.clone());
        }
    }
}

impl Kels {
    /// Parse a `keri.cesr` stream and group its events by identifier.
    ///
    /// Parsing is strict: a stream carrying an attachment group this
    /// implementation cannot interpret is rejected rather than verified with
    /// part of its content ignored.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Stream`] if the stream cannot be parsed, or
    /// carries more than [`MAX_STREAM_MESSAGES`] messages or
    /// [`MAX_STREAM_SIGNATURES`] signatures.
    pub fn parse(stream: &[u8]) -> Result<Self, DidWebsError> {
        let messages = parser::parse_all(stream)
            .map_err(|e| DidWebsError::Stream(format!("could not parse keri.cesr: {e}")))?;

        if messages.len() > MAX_STREAM_MESSAGES {
            return Err(DidWebsError::Stream(format!(
                "keri.cesr carries {} messages, more than the {MAX_STREAM_MESSAGES} this \
                 resolver reads",
                messages.len()
            )));
        }
        let signatures = messages
            .iter()
            .flat_map(|m| &m.attachments)
            .map(signature_count)
            .fold(0usize, usize::saturating_add);
        if signatures > MAX_STREAM_SIGNATURES {
            return Err(DidWebsError::Stream(format!(
                "keri.cesr carries {signatures} signatures, more than the \
                 {MAX_STREAM_SIGNATURES} this resolver checks"
            )));
        }

        let mut by_said: HashMap<String, usize> = HashMap::new();
        let mut receipts = ReceiptIndex::new();
        for (i, msg) in messages.iter().enumerate() {
            if let Ok(said) = msg.serder.said() {
                by_said.entry(said).or_insert(i);
            }
            if msg.serder.ilk().ok().as_deref() == Some("rct") {
                let sad = msg.serder.sad();
                let field = |name: &str| sad.get(name).and_then(|v| v.as_str()).map(str::to_owned);
                if let (Some(prefix), Some(sn), Some(said)) = (field("i"), field("s"), field("d")) {
                    receipts.entry((prefix, sn, said)).or_default().push(i);
                }
            }
        }

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
            messages: Arc::new(messages),
            full_by_prefix: by_prefix.clone(),
            by_prefix,
            limits: HashMap::new(),
            by_said: Arc::new(by_said),
            receipts: Arc::new(receipts),
            verified: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(Vec::new()),
            superseded: RefCell::new(HashMap::new()),
            establishment: RefCell::new(HashMap::new()),
            full_logs: RefCell::new(HashMap::new()),
        })
    }

    /// The same stream, sharing its parsed messages, with nothing verified
    /// yet: what [`Kels::as_of`] narrows when the whole stream is also needed.
    ///
    /// The logs over the whole stream recorded so far are carried over when
    /// no read of this one is limited, since they do not depend on any limit
    /// set afterwards on the identifier they belong to (see
    /// [`Kels::as_of`]).
    pub(crate) fn view(&self) -> Self {
        let full_logs = if self.limits.is_empty() {
            self.full_logs.borrow().clone()
        } else {
            HashMap::new()
        };
        Self {
            messages: Arc::clone(&self.messages),
            by_prefix: self.full_by_prefix.clone(),
            full_by_prefix: self.full_by_prefix.clone(),
            limits: HashMap::new(),
            by_said: Arc::clone(&self.by_said),
            receipts: Arc::clone(&self.receipts),
            verified: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(Vec::new()),
            superseded: RefCell::new(HashMap::new()),
            establishment: RefCell::new(HashMap::new()),
            full_logs: RefCell::new(full_logs),
        }
    }

    /// Every message in the stream, key events or not.
    pub fn messages(&self) -> &[ParsedMessage] {
        &self.messages
    }

    /// The SAID of `prefix`'s first key event, if the stream carries one.
    pub fn inception_said(&self, prefix: &str) -> Option<String> {
        let first = self.by_prefix.get(prefix)?.first()?;
        self.messages[*first].serder.said().ok()
    }

    /// The sequence numbers of `prefix`'s key events, in stream order.
    pub fn sequence_numbers(&self, prefix: &str) -> Vec<u64> {
        self.by_prefix
            .get(prefix)
            .into_iter()
            .flatten()
            .filter_map(|i| {
                self.messages[*i]
                    .serder
                    .sad()
                    .get("s")?
                    .as_str()
                    .map(str::to_owned)
            })
            .filter_map(|s| u64::from_str_radix(&s, 16).ok())
            .collect()
    }

    /// This stream with `prefix`'s key events after sequence number `sn`
    /// set aside.
    ///
    /// § Support for `versionId`: a document resolved as of a version is built
    /// from the events up to and including it. Every KEL lookup — key state,
    /// and the anchors that make an alias attestation or its revocation count —
    /// goes through the per-prefix index this narrows, so all of it then sees
    /// only that much of the log.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Kel`] if `prefix` has no event at `sn`.
    pub fn as_of(mut self, prefix: &str, sn: u64) -> Result<Self, DidWebsError> {
        if !self.sequence_numbers(prefix).contains(&sn) {
            return Err(DidWebsError::Kel(format!(
                "{prefix} has no key event at sequence number {sn}"
            )));
        }
        let messages = &self.messages;
        if let Some(indices) = self.by_prefix.get_mut(prefix) {
            indices.retain(|i| {
                messages[*i]
                    .serder
                    .sad()
                    .get("s")
                    .and_then(|s| s.as_str())
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .is_some_and(|event_sn| event_sn <= sn)
            });
        }
        self.limits.insert(prefix.to_string(), sn);
        self.verified.borrow_mut().clear();
        self.superseded.borrow_mut().clear();
        self.establishment.borrow_mut().clear();
        // `prefix`'s own log over the whole stream is the same whatever its
        // limit; another identifier's could rest on `prefix`'s narrowed log
        // through a delegation, so it is recorded again if it is needed.
        self.full_logs.borrow_mut().retain(|p, _| p == prefix);
        Ok(self)
    }

    /// Whether `prefix`'s latest establishment event committed to no next
    /// keys after inception — the `did:webs` deactivation (§ Deactivate).
    ///
    /// An identifier incepted non-transferable was never rotatable; it is not
    /// "deactivated", it was born that way. Only a rotation to no next keys
    /// is a deactivation.
    pub fn is_deactivated(&self, prefix: &str) -> bool {
        let Some(indices) = self.by_prefix.get(prefix) else {
            return false;
        };
        indices
            .iter()
            .map(|i| &self.messages[*i])
            .filter(|m| {
                matches!(
                    m.serder.ilk().ok().as_deref(),
                    Some("icp" | "rot" | "dip" | "drt")
                )
            })
            .last()
            .is_some_and(|last| {
                matches!(last.serder.ilk().ok().as_deref(), Some("rot" | "drt"))
                    && last
                        .serder
                        .sad()
                        .get("n")
                        .and_then(|n| n.as_array())
                        .is_some_and(Vec::is_empty)
            })
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
        let superseded = self.superseded_of(aid);

        let expected_sn = format!("{sn:x}");
        for i in indices.iter().filter(|i| !superseded.contains(i)) {
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
        self.by_said.get(said).map(|i| &self.messages[*i])
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

    /// The key state as it stood at a named establishment event.
    ///
    /// Signatures on messages outside a key event log — the replies that
    /// authorise a service endpoint, the signature on a designated-aliases
    /// attestation — are authorised by the key state at the establishment event
    /// the signature group names, **not** the state the log has since reached.
    ///
    /// Checking them against the current state instead makes every rotation
    /// silently invalidate everything the identifier ever signed: the keys that
    /// signed are no longer the current ones, so the signature stops verifying
    /// and whatever it authorised quietly disappears from the document.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Kel`] if the log does not verify, or contains no
    /// establishment event with that SAID.
    pub fn key_state_at(&self, aid: &str, said: &str) -> Result<KeyState, DidWebsError> {
        // The log must verify in full before any point in it is trusted. Its
        // verification recorded the key state at every establishment event.
        self.key_state(aid)?;

        if let Some(state) = self
            .establishment
            .borrow()
            .get(aid)
            .and_then(|states| states.get(said))
        {
            return Ok(state.clone());
        }

        // A signature group names the establishment event whose keys signed.
        // An interaction event carries the same keys, but its sequence number
        // is not the key state's, and BADA orders replies by that number.
        let named = self.by_said.get(said).filter(|i| {
            self.by_prefix
                .get(aid)
                .is_some_and(|indices| indices.contains(i))
        });
        match named {
            Some(i) => {
                let ilk = self.messages[*i].serder.ilk().unwrap_or_default();
                Err(DidWebsError::Kel(format!(
                    "{said} is a {ilk:?} event, not an establishment event, so it names no key state"
                )))
            }
            None => Err(DidWebsError::Kel(format!(
                "{aid} has no event with SAID {said} to sign under"
            ))),
        }
    }

    /// Stream indices of `prefix`'s superseded events, as its last
    /// verification found them. Call after [`Kels::key_state`].
    fn superseded_of(&self, prefix: &str) -> Vec<usize> {
        self.superseded
            .borrow()
            .get(prefix)
            .cloned()
            .unwrap_or_default()
    }

    /// Verify a transferable signature group from `signer` over `raw`.
    ///
    /// The signatures are checked against the key state at the establishment
    /// event the group names, and together they must meet **that key state's
    /// signing threshold**. One valid signature is not enough for a 2-of-3
    /// identifier: accepting it would let a single compromised key speak for
    /// the controller, which is what the threshold exists to prevent.
    ///
    /// Returns the key state the signatures verified under, whose `sn` is the
    /// establishment event's sequence number — the first half of BADA
    /// ordering.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Kel`] if the group names no establishment event
    /// in `signer`'s verified log, or the valid signatures do not meet its
    /// threshold.
    pub fn verify_signature_group(
        &self,
        signer: &str,
        raw: &[u8],
        group: &TransIdxSigGroup,
    ) -> Result<KeyState, DidWebsError> {
        if group.prefix != signer {
            return Err(DidWebsError::Kel(format!(
                "signature group is from {}, not {signer}",
                group.prefix
            )));
        }
        let state = self.key_state_at(signer, &group.said)?;
        // The group names its establishment event twice, by sequence number and
        // SAID. keripy looks it up by the number and compares the SAID, so both
        // must agree here too, or a reply verifies here and nowhere else.
        let sn = affinidi_keri_core::parser::number_value(&group.sn)
            .map_err(|e| DidWebsError::Kel(format!("signature group from {signer}: {e}")))?;
        if sn != state.sn {
            return Err(DidWebsError::Kel(format!(
                "signature group from {signer} names establishment event {} at sn {sn}, but it \
                 is at sn {}",
                group.said, state.sn
            )));
        }

        let mut verified: Vec<usize> = Vec::new();
        for sig in &group.sigs {
            let index = sig.index();
            if verified.contains(&index) {
                // Two signatures at one index are one signer, not two.
                continue;
            }
            let Some(key) = state.keys.get(index) else {
                continue;
            };
            let verfer = Verfer::from_qb64(key).map_err(|e| {
                DidWebsError::Kel(format!("{signer} key state has an unusable key: {e}"))
            })?;
            if verfer.verify(raw, sig.raw()).unwrap_or(false) {
                verified.push(index);
            }
        }

        if !state.threshold.is_satisfied(&verified, state.keys.len()) {
            return Err(DidWebsError::Kel(format!(
                "{} valid signature(s) from {signer} do not meet its signing threshold at sn {}",
                verified.len(),
                state.sn,
            )));
        }
        Ok(state)
    }

    /// Replay one identifier's KEL from its inception, as far as a read may
    /// see it, and record what the replay found: the events a rotation
    /// superseded, the key state at each establishment event, and — when the
    /// read is not limited — the log over the whole stream.
    fn verify_kel(&self, prefix: &str) -> Result<KeyState, DidWebsError> {
        let indices = self.by_prefix.get(prefix).ok_or_else(|| {
            DidWebsError::Kel(format!("keri.cesr carries no key events for {prefix}"))
        })?;
        let mut recorded = Recorded::default();
        let (state, superseded) = self.replay_over(prefix, indices, &mut recorded)?;

        self.superseded
            .borrow_mut()
            .insert(prefix.to_string(), superseded);
        self.establishment.borrow_mut().insert(
            prefix.to_string(),
            std::mem::take(&mut recorded.establishment),
        );
        if self.full_by_prefix.get(prefix) == Some(indices) {
            self.full_logs
                .borrow_mut()
                .insert(prefix.to_string(), recorded);
        }
        Ok(state)
    }

    /// `aid`'s verified KEL as the credential registry reader takes it: every
    /// event of the whole stream, each with its seals and the key state an
    /// establishment event installs, limited to what this read may see.
    ///
    /// The log is the whole stream's, not the part [`Kels::as_of`] leaves, so
    /// that a registry event anchored after the limit reads as not having
    /// happened yet rather than as never anchored. It is replayed at most
    /// once per prefix.
    ///
    /// # Errors
    /// Returns [`DidWebsError::Kel`] if `aid`'s key event log does not verify,
    /// to the limit or in full.
    pub(crate) fn issuer_log(
        &self,
        aid: &str,
    ) -> Result<affinidi_keri_core::registry::IssuerLog, DidWebsError> {
        self.key_state(aid)?;
        let cached = self.full_logs.borrow().get(aid).cloned();
        let recorded = match cached {
            Some(recorded) => recorded,
            None => {
                let indices = self.full_by_prefix.get(aid).ok_or_else(|| {
                    DidWebsError::Kel(format!("keri.cesr carries no key events for {aid}"))
                })?;
                let mut recorded = Recorded::default();
                self.replay_over(aid, indices, &mut recorded)?;
                self.full_logs
                    .borrow_mut()
                    .insert(aid.to_string(), recorded.clone());
                recorded
            }
        };
        Ok(
            affinidi_keri_core::registry::IssuerLog::new(aid, recorded.events)
                .with_superseded(recorded.superseded)
                .as_of(self.limits.get(aid).copied()),
        )
    }

    /// Replay the events at `indices`, recording each accepted event and the
    /// key state at each establishment event. Returns the final key state
    /// and the stream indices of the events a rotation superseded.
    ///
    /// A rotation that supersedes interaction events takes the log back to
    /// its own sequence number; the events it superseded are recorded apart.
    fn replay_over(
        &self,
        prefix: &str,
        indices: &[usize],
        log: &mut Recorded,
    ) -> Result<(KeyState, Vec<usize>), DidWebsError> {
        let mut events = indices.iter().map(|i| (*i, &self.messages[*i]));
        let (first_index, first) = events.next().ok_or_else(|| {
            DidWebsError::Kel(format!("keri.cesr carries no events for {prefix}"))
        })?;

        let mut kever = self.incept(prefix, first)?;
        self.require_witness_receipts(prefix, first, kever.state())?;
        log.events.push(logged(first, kever.state(), true)?);
        log.establish(first, kever.state());
        // Accepted events still in the log, by stream index and sequence
        // number, and those a rotation superseded.
        let mut accepted: Vec<(usize, u64)> = vec![(first_index, 0)];
        let mut superseded: Vec<usize> = Vec::new();

        for (n, (index, msg)) in events.enumerate() {
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
            self.require_witness_receipts(prefix, msg, &state)?;
            let before = kever.sn();
            kever.apply_verified_update(state);
            let sn = kever.sn();
            if sn <= before {
                // A superseding rotation: what it superseded leaves the log.
                let (kept, gone): (Vec<_>, Vec<_>) =
                    accepted.into_iter().partition(|(_, s)| *s < sn);
                accepted = kept;
                superseded.extend(gone.into_iter().map(|(i, _)| i));
                let (kept, gone): (Vec<_>, Vec<_>) = std::mem::take(&mut log.events)
                    .into_iter()
                    .partition(|e| e.sn < sn);
                log.events = kept;
                log.superseded.extend(gone);
            }
            accepted.push((index, sn));
            let establishment = ilk != "ixn";
            log.events.push(logged(msg, kever.state(), establishment)?);
            if establishment {
                log.establish(msg, kever.state());
            }
        }

        Ok((kever.state().clone(), superseded))
    }

    /// Enforce the witness threshold an event's own key state declares.
    ///
    /// A KEL that names witnesses and a threshold is saying it is only valid
    /// when that many of them have receipted it. Accepting it on controller
    /// signatures alone discards exactly the protection witnessing exists to
    /// provide — a controller that later rotates cannot be caught equivocating
    /// if nobody had to witness the original.
    ///
    /// Events with `bt: 0` (no witnesses) are unaffected, which is the common
    /// case for `did:webs`.
    fn require_witness_receipts(
        &self,
        prefix: &str,
        msg: &ParsedMessage,
        state: &KeyState,
    ) -> Result<(), DidWebsError> {
        if state.backer_threshold == 0 {
            return Ok(());
        }

        let couples = self.receipt_couples_for(msg);

        Kever::verify_witness_receipts_static(
            msg.serder.raw(),
            &couples,
            &state.backers,
            state.backer_threshold,
        )
        .map_err(|e| {
            DidWebsError::Kel(format!(
                "{prefix} event at sn {} declares {} of {} witnesses but {e}",
                state.sn,
                state.backer_threshold,
                state.backers.len(),
            ))
        })
    }

    /// Every witness receipt couple that applies to `msg`.
    ///
    /// Receipts reach a stream two ways: attached to the event itself, or as
    /// separate `rct` messages naming it. Both count, so both are collected —
    /// looking only at the attachments would reject a KEL whose witnesses
    /// receipted it out of band, which is the usual arrangement.
    fn receipt_couples_for(&self, msg: &ParsedMessage) -> Vec<(String, Vec<u8>)> {
        let mut couples: Vec<(String, Vec<u8>)> = msg
            .attachments
            .iter()
            .filter_map(|a| match a {
                Attachment::ReceiptCouples(c) => Some(c.clone()),
                _ => None,
            })
            .flatten()
            .collect();

        let (Ok(said), Ok(prefix), Ok(sn)) =
            (msg.serder.said(), msg.serder.prefix(), msg.serder.sn())
        else {
            return couples;
        };

        let key = (prefix, format!("{sn:x}"), said);
        for rct in self.receipts.get(&key).into_iter().flatten() {
            for att in &self.messages[*rct].attachments {
                if let Attachment::ReceiptCouples(c) = att {
                    couples.extend(c.iter().cloned());
                }
            }
        }

        couples
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
    ) -> Result<Option<Vec<affinidi_keri_core::SadValue>>, CoreError> {
        // Verifying the delegator's own KEL first is the whole contract of this
        // trait. Returning anchors from events that merely parsed would let any
        // stream claim any delegation.
        if self.key_state(delegator).is_err() {
            return Ok(None);
        }

        let Some(indices) = self.by_prefix.get(delegator) else {
            return Ok(None);
        };
        // A delegation anchored only in an event the delegator's recovery
        // superseded was never the delegator's (P7).
        let superseded = self.superseded_of(delegator);

        for i in indices.iter().filter(|i| !superseded.contains(i)) {
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

    fn delegator_traits(&self, delegator: &str) -> Result<Option<Vec<String>>, CoreError> {
        // Only from a KEL this type has verified, like `anchors_at`: a
        // delegator whose KEL does not verify authorises nothing.
        Ok(self.key_state(delegator).ok().map(|state| state.config))
    }
}

/// How many signatures one attachment group carries.
fn signature_count(attachment: &Attachment) -> usize {
    match attachment {
        Attachment::ControllerSigs(sigs) | Attachment::WitnessSigs(sigs) => sigs.len(),
        Attachment::ReceiptCouples(couples) => couples.len(),
        Attachment::TransIdxSigGroups(groups) => groups
            .iter()
            .map(|g| g.sigs.len())
            .fold(0, usize::saturating_add),
        _ => 0,
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

/// One accepted key event as the registry reader takes it.
fn logged(
    msg: &ParsedMessage,
    state: &KeyState,
    establishment: bool,
) -> Result<affinidi_keri_core::registry::LoggedEvent, DidWebsError> {
    let said = msg
        .serder
        .said()
        .map_err(|e| DidWebsError::Kel(format!("key event has no SAID: {e}")))?;
    let seals = msg
        .serder
        .sad()
        .get("a")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(affinidi_keri_core::registry::LoggedEvent::new(
        state.sn,
        said,
        seals,
        establishment.then(|| state.clone()),
    ))
}
