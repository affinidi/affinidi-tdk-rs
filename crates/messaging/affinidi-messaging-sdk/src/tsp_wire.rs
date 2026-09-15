//! Classifying a TSP frame **without** the `tsp` feature.
//!
//! Recognising a TSP frame and *processing* one are different jobs with very
//! different requirements. Processing needs the whole TSP stack. Recognising
//! needs one byte.
//!
//! Conflating them cost a downstream deployment a working service. A VTC
//! advertised `#tsp` in its DID document while its binary was built without
//! this crate's `tsp` feature. Classification lived behind that feature, so an
//! inbound CESR frame was never recognised as TSP at all — it fell through to
//! [`crate::ATM::unpack`], and the operator's only clue was
//!
//! ```text
//! Error unpacking message: DidcommError("Cannot parse message as JSON",
//! "invalid number at line 1 column 2")
//! ```
//!
//! CESR qb64 begins with `-`, which `serde_json` reads as the start of a
//! number, hence the column-2 failure. Nothing in that message names TSP, names
//! the missing feature, or hints that the frame was a perfectly well-formed
//! message this build simply could not read.
//!
//! Worse, the two warnings written for exactly this case could never fire.
//! [`crate::transport_adapter`]'s `tsp_to_inbound` has a
//! `#[cfg(not(feature = "tsp"))]` arm that says the right thing — but it is
//! reached only *after* a frame has been classified as TSP, which is the step
//! that was gated. Its comment read "a DIDComm-only build never advertises TSP,
//! so this is unreachable in practice". A build does not control what its
//! operator's DID document advertises, and this one advertised it.
//!
//! So classification moves here, where it is unconditional. A build without
//! `tsp` still cannot *unpack* a TSP frame — that genuinely needs the feature —
//! but it can now say so by name instead of emitting a JSON parse error.

use base64::prelude::*;

/// The leading byte of a TSP message framed with a **short** `-E` count code:
/// the first byte of the binary-CESR `-E##`. DIDComm is JSON or compact JWS, so
/// it starts with `{` (`0x7B`) or `ey…` — making this byte unambiguous
/// against it.
///
/// Deliberately duplicated from `affinidi_tsp::TSP_MAGIC_BYTE` rather than
/// imported: importing it would put this classifier back behind the `tsp`
/// feature, which is the whole defect. The copy is pinned to the original by
/// [`tests::magic_byte_matches_affinidi_tsp`], which compiles only when the
/// feature is on — so the two cannot drift without a test failing.
pub const TSP_MAGIC_BYTE: u8 = 0xF8;

/// The leading byte of a TSP message framed with a **long** `--E#####` count
/// code — two DASH selectors rather than one.
///
/// Spec Rev 2 could never emit this: its `-E` count covered only the envelope
/// header, a couple of dozen quadlets whatever the message size. Rev 3 widened
/// the count to cover the ciphertext, so any message with more than 4095
/// quadlets of content — roughly 12 KB — is framed long. A classifier that
/// knows only [`TSP_MAGIC_BYTE`] silently misroutes those to the DIDComm path.
pub const TSP_MAGIC_BYTE_LONG: u8 = 0xFB;

/// Does `stored` look like a TSP frame?
///
/// `stored` is the transit/storage form the mediator streams: `base64url(qb2)`,
/// no padding. Decodes and inspects the leading byte only.
///
/// A *pre-classifier for routing*, not a validator — exactly the contract of
/// `affinidi_tsp::is_tsp`, which it mirrors. `true` means "hand this to the TSP
/// path, which will validate it"; `false` is conclusive, since no TSP message
/// can start with any other byte. DIDComm JSON and compact JWS are not valid
/// base64url of a TSP frame, so they return `false`.
///
/// Both framings are accepted — see [`TSP_MAGIC_BYTE_LONG`], which Rev 3 made
/// reachable for messages over roughly 12 KB.
///
/// Available in every build. That is the point: see the module docs.
#[must_use]
pub fn looks_like_tsp(stored: &str) -> bool {
    BASE64_URL_SAFE_NO_PAD
        .decode(stored.as_bytes())
        .is_ok_and(|bytes| {
            matches!(
                bytes.first(),
                Some(&TSP_MAGIC_BYTE) | Some(&TSP_MAGIC_BYTE_LONG)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame whose decoded bytes lead with the magic byte, in the qb64 form
    /// the mediator actually streams.
    fn qb64(leading: u8) -> String {
        BASE64_URL_SAFE_NO_PAD.encode([leading, 0x41, 0x42, 0x43])
    }

    #[test]
    fn recognises_a_tsp_frame() {
        let frame = qb64(TSP_MAGIC_BYTE);
        // The property that made this bug so confusing: qb64 of a TSP frame
        // renders as text starting `-`, which serde_json reads as the start of
        // a number and reports as "invalid number at line 1 column 2".
        assert!(frame.starts_with('-'), "expected CESR qb64 text: {frame}");
        assert!(looks_like_tsp(&frame));
    }

    /// DIDComm in both its wire shapes. A false positive here would divert real
    /// DIDComm traffic into the TSP path, which is a worse failure than the one
    /// being fixed — so both are pinned.
    #[test]
    fn does_not_claim_didcomm() {
        assert!(!looks_like_tsp(
            r#"{"typ":"application/didcomm-plain+json"}"#
        ));
        assert!(!looks_like_tsp("eyJhbGciOiJFZERTQSJ9.e30.c2ln"));
    }

    #[test]
    fn does_not_claim_a_non_tsp_binary_frame() {
        assert!(!looks_like_tsp(&qb64(0x7B)));
    }

    #[test]
    fn empty_and_undecodable_input_is_not_tsp() {
        assert!(!looks_like_tsp(""));
        // Not valid base64url — must be `false`, never a panic: this runs on
        // every inbound frame, so untrusted input must not be able to crash a
        // consumer's receive loop.
        assert!(!looks_like_tsp("!!! not base64 !!!"));
        assert!(!looks_like_tsp(&BASE64_URL_SAFE_NO_PAD.encode([])));
    }

    /// The anti-drift pin. `affinidi_tsp` owns the wire definition; this crate
    /// keeps a copy so classification can happen without the feature. If the
    /// upstream constant ever changes, this fails rather than the copy silently
    /// misclassifying every frame.
    #[cfg(feature = "tsp")]
    #[test]
    fn magic_byte_matches_affinidi_tsp() {
        assert_eq!(
            TSP_MAGIC_BYTE,
            affinidi_tsp::TSP_MAGIC_BYTE,
            "the local copy of the TSP magic byte has drifted from affinidi_tsp"
        );
    }

    /// Stronger than the constant check: the two classifiers must agree on
    /// actual frames, so a change to *how* upstream classifies (not just which
    /// byte) is caught too.
    #[cfg(feature = "tsp")]
    #[test]
    fn agrees_with_affinidi_tsp_on_real_frames() {
        for leading in [TSP_MAGIC_BYTE, 0x7B, 0x00, 0xFF] {
            let frame = qb64(leading);
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(frame.as_bytes()).unwrap();
            assert_eq!(
                looks_like_tsp(&frame),
                affinidi_tsp::is_tsp(&decoded),
                "classifiers disagree on a frame leading with {leading:#04x}"
            );
        }
    }

    /// Both framings classify as TSP. Rev 3 widened the `-E` count to cover the
    /// ciphertext, which made the long form reachable for the first time — a
    /// classifier that knows only the short byte drops exactly the large
    /// messages, and silently, because misrouting to the DIDComm path looks
    /// like an unparseable DIDComm frame rather than a lost TSP one.
    #[test]
    fn recognises_both_framings() {
        assert!(looks_like_tsp(&qb64(TSP_MAGIC_BYTE)));
        assert!(looks_like_tsp(&qb64(TSP_MAGIC_BYTE_LONG)));
    }

    /// The predicate is what has to agree with `affinidi_tsp`, not just the
    /// constant. The two constants matched all along while the predicates had
    /// diverged, which is how the long framing came to be dropped here.
    #[test]
    #[cfg(feature = "tsp")]
    fn predicate_agrees_with_affinidi_tsp() {
        for leading in 0u8..=255 {
            let bytes = [leading, 0x41, 0x42, 0x43];
            assert_eq!(
                affinidi_tsp::is_tsp(&bytes),
                looks_like_tsp(&BASE64_URL_SAFE_NO_PAD.encode(bytes)),
                "classifiers disagree on a frame leading with {leading:#04x}"
            );
        }
    }
}
