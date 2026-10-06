/*!
 * Receive-leg health for the websocket transport: the rules that decide when
 * the inbound half of a connection has stopped working although the socket is
 * still up, and what to do with a frame that cannot be unpacked.
 *
 * Kept free of the socket so every rule is unit-testable. The transport task
 * (`websocket.rs`) owns the state and calls these on its watchdog tick and on
 * every inbound frame.
 *
 * # Why the socket being up is not enough
 *
 * A mediator holds a message in the recipient's inbox until the recipient
 * deletes it, and every message counts against its **sender's** per-peer queue
 * (`limits.queue.peer`) until then. A recipient whose sends still work but
 * whose receive side has quietly died therefore does not fail itself — it
 * fails everyone talking to it, who start being refused `limits.queue.peer`.
 * Three ways that happens, each handled here:
 *
 * - the mediator stops pushing to a socket that still answers pings (its
 *   streaming registration was lost) — [`probe_step`];
 * - the consumer stops taking frames, reads pause, and nothing is deleted —
 *   [`consumer_stalled`];
 * - a frame that cannot be unpacked is neither delivered nor deleted —
 *   [`unpack_failure_disposition`].
 */

use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use base64::prelude::*;
use tokio::time::Instant;

use crate::errors::ATMError;

/// How long a probe may go unanswered before the receive leg is declared dead.
pub(crate) const PROBE_DEADLINE: Duration = Duration::from_secs(30);

/// How long the consumer may leave frames untaken before it counts as stalled.
pub(crate) const CONSUMER_STALL_AFTER: Duration = Duration::from_secs(60);

/// How many times a frame that failed to unpack *transiently* is offered again
/// before it may be treated as undeliverable.
pub(crate) const TRANSIENT_UNPACK_SIGHTINGS: u32 = 3;

/// How long a transiently failing frame is kept, from its first failed offer,
/// before it may be deleted — whatever the count. Redeliveries can come
/// seconds apart (a reconnect loop, a redelivery request), so a count alone let
/// a short resolver outage discard frames that would have unpacked minutes
/// later. A frame is deleted only once it has failed often *and* for long.
pub(crate) const TRANSIENT_UNPACK_MIN_AGE: Duration = Duration::from_secs(3600);

/// Bounds on the transient-failure memory: entries, and how long one is kept.
/// Longer than [`TRANSIENT_UNPACK_MIN_AGE`], so an entry outlives the age it
/// has to reach.
const SIGHTINGS_CAPACITY: usize = 1024;
const SIGHTINGS_TTL: Duration = Duration::from_secs(6 * 3600);

/// What the receive-leg probe does on a watchdog tick.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeStep {
    /// Nothing to do: probing is off, frames are arriving, or the inbound side
    /// is busy for a reason the probe cannot judge.
    Idle,
    /// Inbound has been silent long enough: ask the mediator for something.
    Send,
    /// A probe is out and still has time.
    Wait,
    /// A probe went unanswered past [`PROBE_DEADLINE`]: nothing the mediator
    /// sends is reaching this socket.
    Dead,
}

/// Decide the probe's next step.
///
/// - `idle_after`: the configured probe threshold; `None` disables probing.
/// - `last_data_frame`: when the last Text/Binary frame arrived (or the socket
///   connected). Pings and pongs do not count — they prove the socket, not the
///   mediator's delivery to it.
/// - `probe_sent`: when the outstanding probe was written, if one is. Any data
///   frame clears it, so an outstanding probe means *nothing at all* has
///   arrived since.
/// - `quiet`: reads are not paused and both inbound caches are empty. A probe
///   is only meaningful then: with frames held, silence is the consumer's, not
///   the mediator's, and a redelivery would only duplicate what is held.
pub(crate) fn probe_step(
    idle_after: Option<Duration>,
    now: Instant,
    last_data_frame: Instant,
    probe_sent: Option<Instant>,
    quiet: bool,
) -> ProbeStep {
    let Some(idle_after) = idle_after else {
        return ProbeStep::Idle;
    };
    if let Some(sent) = probe_sent {
        return if now.saturating_duration_since(sent) >= PROBE_DEADLINE {
            ProbeStep::Dead
        } else {
            ProbeStep::Wait
        };
    }
    if quiet && now.saturating_duration_since(last_data_frame) >= idle_after {
        ProbeStep::Send
    } else {
        ProbeStep::Idle
    }
}

/// Has the consumer stopped taking frames?
///
/// `held` frames are waiting in the transport's caches; `held_since` is when
/// the caches last went from empty to non-empty, `last_take` when a consumer
/// last took one. Stalled when frames have been held, and none taken, for
/// `after`.
pub(crate) fn consumer_stalled(
    held: usize,
    held_since: Option<Instant>,
    last_take: Option<Instant>,
    now: Instant,
    after: Duration,
) -> bool {
    if held == 0 {
        return false;
    }
    let Some(held_since) = held_since else {
        return false;
    };
    let since = match last_take {
        Some(take) if take > held_since => take,
        _ => held_since,
    };
    now.saturating_duration_since(since) >= after
}

/// How an unpack failure is classed for deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnpackFailure {
    /// A resolver or network hiccup (or the unpack timing out). The same bytes
    /// may well unpack next time.
    Transient,
    /// The configured `unpack_policy` refused it (a disallowed wrapping, an
    /// addressing mismatch). Governed by `purge_policy_rejected_messages`,
    /// exactly as on the pickup drain.
    PolicyRejected,
    /// Our own key material is missing. Local configuration, so not poison in
    /// the bytes — the frame is very likely a legitimate message to a key this
    /// profile has not loaded yet (a rotation, a persona still being set up).
    /// **Never deleted**: losing it would be silent data loss, and the
    /// mediator's own expiry bounds how long it stays.
    LocalConfig,
    /// A deterministic property of the bytes — undecryptable, a bad signature.
    /// No redelivery can change it.
    Permanent,
}

/// Class an unpack failure. Shares the transient set with the TSP adapter
/// ([`ATMError::is_transient_unpack_failure`]) so the two inbound paths agree.
///
/// Permanent is an allow-list of what is known to be a property of the bytes.
/// Anything else — including an error variant added later — is treated as
/// transient, so the default for an unrecognised failure is to keep the frame
/// for a while, never to delete it at once.
pub(crate) fn classify_unpack_failure(err: &ATMError) -> UnpackFailure {
    if err.is_transient_unpack_failure() {
        return UnpackFailure::Transient;
    }
    match err {
        ATMError::UnexpectedEnvelope(_) | ATMError::AddressingMismatch(_) => {
            UnpackFailure::PolicyRejected
        }
        ATMError::SecretsError(_) => UnpackFailure::LocalConfig,
        ATMError::DidcommError(..)
        | ATMError::MsgReceiveError(_)
        | ATMError::VerificationFailed(_) => UnpackFailure::Permanent,
        _ => UnpackFailure::Transient,
    }
}

/// Whether a frame that failed to unpack should be deleted from the mediator
/// now, given how often it has now failed (`sightings`, counting this one).
///
/// - `delete_unprocessable == false` keeps the pre-0.33.2 behaviour: nothing
///   is deleted.
/// - Permanent failures are deleted at once — the pickup drain already did
///   this; the live stream did not, which left poison frames in the inbox
///   counting against their sender's queue for as long as they lived.
/// - Policy rejections follow `purge_policy_rejected`, as on the drain.
/// - Transient failures are kept for redelivery until they have failed
///   [`TRANSIENT_UNPACK_SIGHTINGS`] times **and** for at least
///   [`TRANSIENT_UNPACK_MIN_AGE`] since the first failure (`age`): a
///   "transient" failure that repeats for an hour is not transient.
/// - Local-config failures (our own keys missing) are never deleted.
pub(crate) fn unpack_failure_disposition(
    class: UnpackFailure,
    sightings: u32,
    age: Duration,
    delete_unprocessable: bool,
    purge_policy_rejected: bool,
) -> bool {
    if !delete_unprocessable {
        return false;
    }
    match class {
        UnpackFailure::Permanent => true,
        UnpackFailure::PolicyRejected => purge_policy_rejected,
        UnpackFailure::Transient => {
            sightings >= TRANSIENT_UNPACK_SIGHTINGS && age >= TRANSIENT_UNPACK_MIN_AGE
        }
        UnpackFailure::LocalConfig => false,
    }
}

/// Bounded memory of frames that failed to unpack, keyed by mediator message
/// id (`sha256` of the packed frame), counting how often each was offered.
#[derive(Default)]
pub(crate) struct UnpackSightings {
    counts: HashMap<String, (u32, Instant)>,
    order: VecDeque<String>,
}

impl UnpackSightings {
    /// Record one more failed offer of `id` and return how many there have
    /// been, this one included.
    pub(crate) fn record(&mut self, id: &str, now: Instant) -> u32 {
        self.expire(now);
        if let Some((count, _)) = self.counts.get_mut(id) {
            *count += 1;
            return *count;
        }
        self.counts.insert(id.to_string(), (1, now));
        self.order.push_back(id.to_string());
        while self.order.len() > SIGHTINGS_CAPACITY {
            if let Some(evicted) = self.order.pop_front() {
                self.counts.remove(&evicted);
            }
        }
        1
    }

    /// When `id` first failed, while it is remembered.
    pub(crate) fn first_seen(&self, id: &str) -> Option<Instant> {
        self.counts.get(id).map(|(_, first)| *first)
    }

    /// Forget `id` — it was deleted.
    pub(crate) fn forget(&mut self, id: &str) {
        if self.counts.remove(id).is_some() {
            self.order.retain(|x| x != id);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.counts.len()
    }

    fn expire(&mut self, now: Instant) {
        while let Some(front) = self.order.front() {
            match self.counts.get(front) {
                Some((_, first)) if now.saturating_duration_since(*first) < SIGHTINGS_TTL => break,
                _ => {
                    let front = self.order.pop_front().expect("front was just observed");
                    self.counts.remove(&front);
                }
            }
        }
    }
}

/// What can be said about a frame's sender and kind *without* decrypting it —
/// enough for an operator to know whose messages are being discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameHint {
    /// `authcrypt`, `anoncrypt`, `encrypted`, `signed`, `plaintext` or `unknown`.
    pub(crate) envelope: &'static str,
    /// The sender key id or DID the envelope names, when it names one. Not
    /// verified — an attacker can write anything here — so it is a lead for an
    /// operator, never an identity.
    pub(crate) sender: Option<String>,
    /// The plaintext `type`, or the envelope's `typ` header.
    pub(crate) kind: Option<String>,
}

/// Read a [`FrameHint`] off a packed DIDComm frame.
pub(crate) fn frame_hint(raw: &str) -> FrameHint {
    let unknown = FrameHint {
        envelope: "unknown",
        sender: None,
        kind: None,
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return unknown;
    };
    let str_of =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let decode_header = |b64: &str| -> Option<serde_json::Value> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(b64.trim_end_matches('='))
            .ok()?;
        serde_json::from_slice(&bytes).ok()
    };

    // JWE: `ciphertext` + a protected header naming the key agreement.
    if value.get("ciphertext").is_some() {
        let header = value
            .get("protected")
            .and_then(|p| p.as_str())
            .and_then(decode_header);
        let Some(header) = header else {
            return FrameHint {
                envelope: "encrypted",
                sender: None,
                kind: None,
            };
        };
        let alg = str_of(&header, "alg").unwrap_or_default();
        let envelope = if alg.starts_with("ECDH-1PU") {
            "authcrypt"
        } else if alg.starts_with("ECDH-ES") {
            "anoncrypt"
        } else {
            "encrypted"
        };
        let sender = str_of(&header, "skid").or_else(|| {
            str_of(&header, "apu").and_then(|apu| {
                BASE64_URL_SAFE_NO_PAD
                    .decode(apu.trim_end_matches('='))
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
            })
        });
        return FrameHint {
            envelope,
            sender,
            kind: str_of(&header, "typ"),
        };
    }

    // JWS: `payload` + `signatures`, the signer named per signature.
    if value.get("payload").is_some() && value.get("signatures").is_some() {
        let first = value
            .get("signatures")
            .and_then(|s| s.as_array())
            .and_then(|s| s.first());
        let sender = first.and_then(|sig| {
            sig.get("header")
                .and_then(|h| str_of(h, "kid"))
                .or_else(|| {
                    sig.get("protected")
                        .and_then(|p| p.as_str())
                        .and_then(decode_header)
                        .and_then(|h| str_of(&h, "kid"))
                })
        });
        return FrameHint {
            envelope: "signed",
            sender,
            kind: None,
        };
    }

    // Plaintext DIDComm.
    if value.get("type").is_some() || value.get("body").is_some() {
        return FrameHint {
            envelope: "plaintext",
            sender: str_of(&value, "from"),
            kind: str_of(&value, "type"),
        };
    }
    unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn probing_off_never_probes() {
        let t = Instant::now();
        assert_eq!(probe_step(None, at(t, 600), t, None, true), ProbeStep::Idle);
        assert_eq!(
            probe_step(None, at(t, 600), t, Some(t), true),
            ProbeStep::Idle
        );
    }

    #[test]
    fn a_silent_quiet_socket_is_probed() {
        let t = Instant::now();
        let idle = Some(Duration::from_secs(60));
        assert_eq!(probe_step(idle, at(t, 59), t, None, true), ProbeStep::Idle);
        assert_eq!(probe_step(idle, at(t, 60), t, None, true), ProbeStep::Send);
    }

    /// With frames held or reads paused the silence is the consumer's, and a
    /// redelivery would only duplicate what is held — so no probe.
    #[test]
    fn a_busy_inbound_side_is_not_probed() {
        let t = Instant::now();
        let idle = Some(Duration::from_secs(60));
        assert_eq!(
            probe_step(idle, at(t, 600), t, None, false),
            ProbeStep::Idle
        );
    }

    #[test]
    fn an_unanswered_probe_is_dead_after_the_deadline() {
        let t = Instant::now();
        let idle = Some(Duration::from_secs(60));
        let sent = at(t, 60);
        assert_eq!(
            probe_step(idle, at(t, 70), t, Some(sent), true),
            ProbeStep::Wait
        );
        assert_eq!(
            probe_step(idle, sent + PROBE_DEADLINE, t, Some(sent), true),
            ProbeStep::Dead
        );
        // The deadline holds whatever the inbound side is doing: an outstanding
        // probe means nothing at all has arrived since it was sent.
        assert_eq!(
            probe_step(idle, sent + PROBE_DEADLINE, t, Some(sent), false),
            ProbeStep::Dead
        );
    }

    #[test]
    fn held_frames_untaken_past_the_threshold_are_a_stall() {
        let t = Instant::now();
        let after = CONSUMER_STALL_AFTER;
        assert!(!consumer_stalled(0, Some(t), None, at(t, 600), after));
        assert!(!consumer_stalled(3, Some(t), None, at(t, 59), after));
        assert!(consumer_stalled(3, Some(t), None, at(t, 60), after));
        // A recent take restarts the clock.
        assert!(!consumer_stalled(
            3,
            Some(t),
            Some(at(t, 50)),
            at(t, 100),
            after
        ));
        assert!(consumer_stalled(
            3,
            Some(t),
            Some(at(t, 50)),
            at(t, 110),
            after
        ));
    }

    #[test]
    fn failures_are_classed_by_recoverability() {
        assert_eq!(
            classify_unpack_failure(&ATMError::DIDError("resolve".into())),
            UnpackFailure::Transient
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::TransportError("reset".into())),
            UnpackFailure::Transient
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::TDKError("cache".into())),
            UnpackFailure::Transient
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::UnexpectedEnvelope("plaintext".into())),
            UnpackFailure::PolicyRejected
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::AddressingMismatch("to".into())),
            UnpackFailure::PolicyRejected
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::SecretsError("no key".into())),
            UnpackFailure::LocalConfig
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::MsgReceiveError("decrypt".into())),
            UnpackFailure::Permanent
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::VerificationFailed("sig".into())),
            UnpackFailure::Permanent
        );
        // Anything not known to be a property of the bytes is kept, not
        // deleted at once.
        assert_eq!(
            classify_unpack_failure(&ATMError::SDKError("unexpected".into())),
            UnpackFailure::Transient
        );
        assert_eq!(
            classify_unpack_failure(&ATMError::ConfigError("x".into())),
            UnpackFailure::Transient
        );
    }

    #[test]
    fn permanent_failures_are_deleted_at_once_and_transient_ones_only_when_old_and_repeated() {
        let young = Duration::from_secs(5);
        let old = TRANSIENT_UNPACK_MIN_AGE;
        assert!(unpack_failure_disposition(
            UnpackFailure::Permanent,
            1,
            young,
            true,
            true
        ));
        let t = UnpackFailure::Transient;
        assert!(
            !unpack_failure_disposition(t, 2, old, true, true),
            "too few"
        );
        assert!(
            !unpack_failure_disposition(t, 9, young, true, true),
            "many quick redeliveries during a short outage are not enough"
        );
        assert!(unpack_failure_disposition(t, 3, old, true, true));
        // Our own keys missing: never deleted, however long.
        assert!(!unpack_failure_disposition(
            UnpackFailure::LocalConfig,
            99,
            old * 10,
            true,
            true
        ));
        // Policy rejections follow the drain's retention flag.
        assert!(unpack_failure_disposition(
            UnpackFailure::PolicyRejected,
            1,
            young,
            true,
            true
        ));
        assert!(!unpack_failure_disposition(
            UnpackFailure::PolicyRejected,
            9,
            young,
            true,
            false
        ));
        // Opted out: nothing is ever deleted.
        assert!(!unpack_failure_disposition(
            UnpackFailure::Permanent,
            9,
            old,
            false,
            true
        ));
    }

    #[test]
    fn sightings_count_per_frame_and_are_bounded() {
        let t = Instant::now();
        let mut s = UnpackSightings::default();
        assert_eq!(s.record("a", t), 1);
        assert_eq!(s.record("a", t), 2);
        assert_eq!(s.record("b", t), 1);
        s.forget("a");
        assert_eq!(s.record("a", t), 1);

        // Bounded in count…
        for i in 0..(SIGHTINGS_CAPACITY + 10) {
            s.record(&format!("x{i}"), t);
        }
        assert!(s.len() <= SIGHTINGS_CAPACITY);

        // …and in time.
        let mut s = UnpackSightings::default();
        s.record("old", t);
        assert_eq!(
            s.record("old", t + SIGHTINGS_TTL),
            1,
            "expired, counted afresh"
        );
    }

    fn b64(v: serde_json::Value) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
    }

    #[test]
    fn an_authcrypt_frame_names_its_sender_key() {
        let raw = serde_json::json!({
            "protected": b64(serde_json::json!({
                "alg": "ECDH-1PU+A256KW",
                "skid": "did:example:alice#key-x25519-1",
                "typ": "application/didcomm-encrypted+json"
            })),
            "ciphertext": "AA",
        })
        .to_string();
        let hint = frame_hint(&raw);
        assert_eq!(hint.envelope, "authcrypt");
        assert_eq!(
            hint.sender.as_deref(),
            Some("did:example:alice#key-x25519-1")
        );
        assert_eq!(
            hint.kind.as_deref(),
            Some("application/didcomm-encrypted+json")
        );
    }

    #[test]
    fn an_authcrypt_frame_without_skid_falls_back_to_apu() {
        let raw = serde_json::json!({
            "protected": b64(serde_json::json!({
                "alg": "ECDH-1PU+A256KW",
                "apu": BASE64_URL_SAFE_NO_PAD.encode("did:example:bob#key-1"),
            })),
            "ciphertext": "AA",
        })
        .to_string();
        assert_eq!(
            frame_hint(&raw).sender.as_deref(),
            Some("did:example:bob#key-1")
        );
    }

    #[test]
    fn an_anoncrypt_frame_names_no_sender() {
        let raw = serde_json::json!({
            "protected": b64(serde_json::json!({"alg": "ECDH-ES+A256KW"})),
            "ciphertext": "AA",
        })
        .to_string();
        let hint = frame_hint(&raw);
        assert_eq!(hint.envelope, "anoncrypt");
        assert_eq!(hint.sender, None);
    }

    #[test]
    fn a_signed_frame_names_its_signer() {
        let raw = serde_json::json!({
            "payload": "AA",
            "signatures": [{"header": {"kid": "did:example:carol#key-1"}, "signature": "AA"}],
        })
        .to_string();
        let hint = frame_hint(&raw);
        assert_eq!(hint.envelope, "signed");
        assert_eq!(hint.sender.as_deref(), Some("did:example:carol#key-1"));
    }

    #[test]
    fn a_plaintext_frame_names_from_and_type() {
        let raw = serde_json::json!({
            "id": "1",
            "type": "example/v1",
            "from": "did:example:dave",
            "body": {}
        })
        .to_string();
        let hint = frame_hint(&raw);
        assert_eq!(hint.envelope, "plaintext");
        assert_eq!(hint.sender.as_deref(), Some("did:example:dave"));
        assert_eq!(hint.kind.as_deref(), Some("example/v1"));
    }

    #[test]
    fn garbage_is_unknown_not_a_panic() {
        assert_eq!(frame_hint("-ETSP").envelope, "unknown");
        assert_eq!(frame_hint("{}").envelope, "unknown");
    }
}
