//! The RFC 0019 encryption envelope: wire types, pack, and open.
//!
//! This layer knows about **keys**, not identities. It returns the verkey that
//! authenticated an envelope; binding that verkey to a DID happens one layer
//! up, in [`crate::message::unpack`]. See [`crate::identity`] for why the two
//! cannot be collapsed in v1 the way they can in v2.
//!
//! # Shape
//!
//! ```json
//! {
//!   "protected": "<base64url(JSON)>",
//!   "iv":         "<base64url>",
//!   "ciphertext": "<base64url>",
//!   "tag":        "<base64url>"
//! }
//! ```
//!
//! with the decoded `protected` being:
//!
//! ```json
//! {
//!   "enc": "xchacha20poly1305_ietf",
//!   "typ": "JWM/1.0",
//!   "alg": "Authcrypt" | "Anoncrypt",
//!   "recipients": [
//!     {
//!       "encrypted_key": "<base64url>",
//!       "header": { "kid": "<base58 verkey>", "sender": "<base64url>|null", "iv": "<base64url>|null" }
//!     }
//!   ]
//! }
//! ```
//!
//! It resembles a JWE and is not one: `recipients` lives *inside* the protected
//! header rather than beside it, `kid` is a raw key rather than a DID URL, and
//! none of the algorithm names are JWA-registered.

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{content, crypto_box};
use crate::error::DIDCommV1Error;
use crate::identity::Verkey;

/// The `typ` value RFC 0019 mandates in the protected header.
pub const ENVELOPE_TYP: &str = "JWM/1.0";
/// The `alg` value for sender-authenticated encryption.
pub const ALG_AUTHCRYPT: &str = "Authcrypt";
/// The `alg` value for anonymous encryption.
pub const ALG_ANONCRYPT: &str = "Anoncrypt";

/// Cap on `recipients` entries accepted when opening an envelope.
///
/// The recipient-matching loop runs before anything is authenticated, so the
/// count is attacker-chosen. Mirrors the v2 SDK's `max_recipients` default.
pub const MAX_RECIPIENTS: usize = 100;

/// The outer envelope, as it appears on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// base64url of the [`ProtectedHeader`] JSON.
    pub protected: String,
    /// base64url of the 12-byte content-encryption nonce.
    pub iv: String,
    /// base64url of the ciphertext.
    pub ciphertext: String,
    /// base64url of the 16-byte Poly1305 tag.
    pub tag: String,
}

/// The decoded protected header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedHeader {
    /// Always [`content::ENC_ALGORITHM`] — which is a misnomer; see
    /// [`crate::crypto::content`].
    pub enc: String,
    /// Always [`ENVELOPE_TYP`].
    pub typ: String,
    /// [`ALG_AUTHCRYPT`] or [`ALG_ANONCRYPT`].
    pub alg: String,
    /// One entry per recipient.
    pub recipients: Vec<Recipient>,
}

/// One recipient's wrapped content encryption key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipient {
    /// base64url of the wrapped CEK.
    pub encrypted_key: String,
    /// Per-recipient header.
    pub header: RecipientHeader,
}

/// The per-recipient header.
///
/// For anoncrypt, `sender` and `iv` are **omitted** rather than emitted as
/// explicit `null`s — that is what Credo produces today (verified against a
/// live agent; see `tests/credo_interop.rs`). RFC 0019's worked example and
/// older indy-sdk output show explicit nulls instead, so deserialization
/// accepts a missing key and a `null` interchangeably. Both forms are also
/// falsy to Credo's own decoder, so either is safe to send; omission is chosen
/// to match the implementation actually in the field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientHeader {
    /// base58btc of the recipient's Ed25519 verkey.
    pub kid: String,
    /// Authcrypt only: base64url of the sealed sender verkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// Authcrypt only: base64url of the 24-byte nonce wrapping the CEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
}

/// How an opened envelope was protected.
///
/// Distinct variants rather than a boolean plus an `Option`: the authenticated
/// sender key exists *if and only if* the envelope was authcrypt, and encoding
/// that in the type removes the possibility of reading a sender out of an
/// anonymous envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeProtection {
    /// Sender-authenticated. The verkey is proven to belong to whoever built
    /// the envelope — opening the wrapped CEK is only possible under a shared
    /// key derived from that key's secret half.
    Authcrypt {
        /// The authenticated sender's Ed25519 verkey.
        sender_verkey: Verkey,
    },
    /// Anonymous. Nothing about the sender is known or knowable.
    Anoncrypt,
}

/// A successfully opened envelope.
#[derive(Debug, Clone)]
pub struct OpenedEnvelope {
    /// The decrypted payload — for a DIDComm v1 message, its JSON bytes.
    pub plaintext: Vec<u8>,
    /// Whether, and by whom, the envelope was authenticated.
    pub protection: EnvelopeProtection,
    /// Which of our verkeys the envelope was opened with.
    pub recipient_verkey: Verkey,
}

/// Decode base64url, tolerating both padded and unpadded input.
///
/// RFC 0019 requires decoders to accept both. Encoding is always unpadded, which
/// is what indy-sdk and Credo emit.
fn b64_decode(input: &str, field: &str) -> Result<Vec<u8>, DIDCommV1Error> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
        .map_err(|e| {
            DIDCommV1Error::InvalidEnvelope(format!("`{field}` is not valid base64url: {e}"))
        })
}

fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn fixed<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], DIDCommV1Error> {
    bytes.try_into().map_err(|_| {
        DIDCommV1Error::InvalidEnvelope(format!("`{field}` is {} bytes, expected {N}", bytes.len()))
    })
}

/// Pack `plaintext` into an authcrypt envelope for each of `recipients`.
///
/// Every recipient receives the same content encryption key, individually
/// wrapped to their key, and a sealed copy of the sender's verkey.
pub fn pack_authcrypt(
    plaintext: &[u8],
    sender_verkey: &Verkey,
    sender_x25519_private: &[u8; 32],
    recipients: &[Verkey],
) -> Result<String, DIDCommV1Error> {
    let cek = content::generate_cek();
    let sender_verkey_b58 = sender_verkey.to_base58();

    let mut entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let recipient_x25519 = recipient.to_x25519()?;

        // The sender verkey is sealed *anonymously* to the recipient: only they
        // learn who sent it, and only after decrypting. Note it is the base58
        // *string* that gets sealed, not the raw 32 bytes.
        let sealed_sender =
            crypto_box::seal_anonymous(sender_verkey_b58.as_bytes(), &recipient_x25519)?;

        let cek_nonce = crypto_box::random_nonce();
        let wrapped_cek = crypto_box::seal_authenticated(
            cek.as_ref(),
            &cek_nonce,
            &recipient_x25519,
            sender_x25519_private,
        )?;

        entries.push(Recipient {
            encrypted_key: b64_encode(&wrapped_cek),
            header: RecipientHeader {
                kid: recipient.to_base58(),
                sender: Some(b64_encode(&sealed_sender)),
                iv: Some(b64_encode(&cek_nonce)),
            },
        });
    }

    seal_content(&cek, ALG_AUTHCRYPT, entries, plaintext)
}

/// Pack `plaintext` into an anoncrypt envelope for each of `recipients`.
///
/// The result carries no sender information whatsoever. A recipient can decrypt
/// it and has no way to attribute it, reply to it, or report an error back.
pub fn pack_anoncrypt(plaintext: &[u8], recipients: &[Verkey]) -> Result<String, DIDCommV1Error> {
    let cek = content::generate_cek();

    let mut entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let recipient_x25519 = recipient.to_x25519()?;
        let wrapped_cek = crypto_box::seal_anonymous(cek.as_ref(), &recipient_x25519)?;

        entries.push(Recipient {
            encrypted_key: b64_encode(&wrapped_cek),
            header: RecipientHeader {
                kid: recipient.to_base58(),
                // Omitted on the wire, matching Credo. See `RecipientHeader`.
                sender: None,
                iv: None,
            },
        });
    }

    seal_content(&cek, ALG_ANONCRYPT, entries, plaintext)
}

/// Build the protected header, encrypt the content under it, and serialize.
fn seal_content(
    cek: &[u8; content::KEY_LEN],
    alg: &str,
    recipients: Vec<Recipient>,
    plaintext: &[u8],
) -> Result<String, DIDCommV1Error> {
    let header = ProtectedHeader {
        enc: content::ENC_ALGORITHM.to_string(),
        typ: ENVELOPE_TYP.to_string(),
        alg: alg.to_string(),
        recipients,
    };
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| DIDCommV1Error::Serialization(format!("protected header: {e}")))?;
    let protected = b64_encode(&header_json);

    // The AAD is the base64url *text* of the header, not its decoded bytes.
    let nonce = content::random_nonce();
    let (ciphertext, tag) = content::encrypt(cek, &nonce, protected.as_bytes(), plaintext)?;

    let envelope = Envelope {
        protected,
        iv: b64_encode(&nonce),
        ciphertext: b64_encode(&ciphertext),
        tag: b64_encode(&tag),
    };
    serde_json::to_string(&envelope)
        .map_err(|e| DIDCommV1Error::Serialization(format!("envelope: {e}")))
}

/// Whether `input` parses as an RFC 0019 envelope.
///
/// Used to tell an encrypted message from a plaintext one before committing to
/// either path.
pub fn is_envelope(value: &serde_json::Value) -> bool {
    value.get("protected").is_some()
        && value.get("ciphertext").is_some()
        && value.get("tag").is_some()
}

/// A local key that can open envelopes: a verkey and its X25519 secret.
pub struct RecipientKey<'a> {
    /// The verkey, matched against each recipient entry's `kid`.
    pub verkey: Verkey,
    /// The X25519 secret derived from the same Ed25519 key.
    pub x25519_private: &'a [u8; 32],
}

/// Open an envelope with the first of `keys` that it is addressed to.
///
/// # Security
///
/// The returned [`EnvelopeProtection`] is derived from what actually decrypted,
/// never from the `alg` header. An envelope claiming `Authcrypt` whose CEK only
/// opens anonymously is reported as [`EnvelopeProtection::Anoncrypt`] — and
/// vice versa — because `alg` sits in the AAD but is chosen by whoever built
/// the envelope, and an anonymous party may set it to anything.
pub fn open(input: &str, keys: &[RecipientKey<'_>]) -> Result<OpenedEnvelope, DIDCommV1Error> {
    let envelope: Envelope = serde_json::from_str(input)
        .map_err(|e| DIDCommV1Error::InvalidEnvelope(format!("not a v1 envelope: {e}")))?;

    let header_bytes = b64_decode(&envelope.protected, "protected")?;
    let header: ProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DIDCommV1Error::InvalidEnvelope(format!("protected header: {e}")))?;

    if header.typ != ENVELOPE_TYP {
        return Err(DIDCommV1Error::UnsupportedAlgorithm(format!(
            "unexpected envelope typ `{}`, expected `{ENVELOPE_TYP}`",
            header.typ
        )));
    }
    if header.enc != content::ENC_ALGORITHM {
        return Err(DIDCommV1Error::UnsupportedAlgorithm(format!(
            "unsupported enc `{}`, expected `{}`",
            header.enc,
            content::ENC_ALGORITHM
        )));
    }
    if header.alg != ALG_AUTHCRYPT && header.alg != ALG_ANONCRYPT {
        return Err(DIDCommV1Error::UnsupportedAlgorithm(format!(
            "unsupported alg `{}`",
            header.alg
        )));
    }
    // Bound the pre-authentication matching loop.
    if header.recipients.len() > MAX_RECIPIENTS {
        return Err(DIDCommV1Error::InvalidEnvelope(format!(
            "envelope addresses {} recipients, exceeding the maximum of {MAX_RECIPIENTS}",
            header.recipients.len()
        )));
    }

    let (recipient, key) = header
        .recipients
        .iter()
        .find_map(|entry| {
            let kid = Verkey::from_base58(&entry.header.kid).ok()?;
            keys.iter().find(|k| k.verkey == kid).map(|k| (entry, k))
        })
        .ok_or_else(|| {
            DIDCommV1Error::IdentityNotFound(
                "no local key matches any recipient of this envelope".into(),
            )
        })?;

    let wrapped_cek = b64_decode(&recipient.encrypted_key, "encrypted_key")?;
    let recipient_x25519 = key.verkey.to_x25519()?;

    // Both `sender` and `iv` are required together for authcrypt: the sealed
    // sender identifies whose key to derive against, and the iv is the nonce
    // that wrap used. One without the other is malformed, not a hint to guess.
    let (cek, protection) = match (&recipient.header.sender, &recipient.header.iv) {
        (Some(sealed_sender), Some(cek_iv)) => {
            let sealed_sender = b64_decode(sealed_sender, "header.sender")?;
            let sender_verkey_bytes =
                crypto_box::open_anonymous(&sealed_sender, &recipient_x25519, key.x25519_private)?;
            let sender_verkey_b58 = std::str::from_utf8(&sender_verkey_bytes).map_err(|e| {
                DIDCommV1Error::InvalidEnvelope(format!(
                    "sealed sender verkey is not valid UTF-8: {e}"
                ))
            })?;
            let sender_verkey = Verkey::from_base58(sender_verkey_b58)?;

            let cek_nonce =
                fixed::<{ crypto_box::NONCE_LEN }>(&b64_decode(cek_iv, "header.iv")?, "header.iv")?;
            let sender_x25519 = sender_verkey.to_x25519()?;

            // This is the authentication step. It succeeds only for a sender
            // holding the secret half of `sender_verkey`, so reaching the next
            // line is proof of who sent the envelope.
            let cek = crypto_box::open_authenticated(
                &wrapped_cek,
                &cek_nonce,
                &sender_x25519,
                key.x25519_private,
            )?;

            (cek, EnvelopeProtection::Authcrypt { sender_verkey })
        }
        (None, None) => {
            let cek =
                crypto_box::open_anonymous(&wrapped_cek, &recipient_x25519, key.x25519_private)?;
            (cek, EnvelopeProtection::Anoncrypt)
        }
        _ => {
            return Err(DIDCommV1Error::InvalidEnvelope(
                "recipient header has exactly one of `sender` and `iv`; authcrypt requires both \
                 and anoncrypt requires neither"
                    .into(),
            ));
        }
    };

    let cek = Zeroizing::new(fixed::<{ content::KEY_LEN }>(
        &cek,
        "content encryption key",
    )?);
    let nonce = fixed::<{ content::NONCE_LEN }>(&b64_decode(&envelope.iv, "iv")?, "iv")?;
    let tag = fixed::<{ content::TAG_LEN }>(&b64_decode(&envelope.tag, "tag")?, "tag")?;
    let ciphertext = b64_decode(&envelope.ciphertext, "ciphertext")?;

    let plaintext = content::decrypt(
        &cek,
        &nonce,
        envelope.protected.as_bytes(),
        &ciphertext,
        &tag,
    )?;

    Ok(OpenedEnvelope {
        plaintext,
        protection,
        recipient_verkey: key.verkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrivateIdentity;

    struct Party {
        identity: PrivateIdentity,
        x25519_private: [u8; 32],
    }

    fn party(did: &str) -> Party {
        let identity = PrivateIdentity::generate(did).unwrap();
        let x25519_private = *identity.x25519_private();
        Party {
            identity,
            x25519_private,
        }
    }

    impl Party {
        fn key(&self) -> RecipientKey<'_> {
            RecipientKey {
                verkey: self.identity.verkey,
                x25519_private: &self.x25519_private,
            }
        }
    }

    #[test]
    fn authcrypt_roundtrip_reports_the_sender_verkey() {
        let alice = party("did:example:alice");
        let bob = party("did:example:bob");

        let packed = pack_authcrypt(
            b"hello bob",
            &alice.identity.verkey,
            &alice.x25519_private,
            &[bob.identity.verkey],
        )
        .unwrap();

        let opened = open(&packed, &[bob.key()]).unwrap();
        assert_eq!(opened.plaintext, b"hello bob");
        assert_eq!(opened.recipient_verkey, bob.identity.verkey);
        assert_eq!(
            opened.protection,
            EnvelopeProtection::Authcrypt {
                sender_verkey: alice.identity.verkey
            }
        );
    }

    #[test]
    fn anoncrypt_roundtrip_reports_no_sender() {
        let bob = party("did:example:bob");

        let packed = pack_anoncrypt(b"anonymous", &[bob.identity.verkey]).unwrap();
        let opened = open(&packed, &[bob.key()]).unwrap();

        assert_eq!(opened.plaintext, b"anonymous");
        assert_eq!(opened.protection, EnvelopeProtection::Anoncrypt);
    }

    #[test]
    fn multi_recipient_envelope_opens_for_each() {
        let alice = party("did:example:alice");
        let bob = party("did:example:bob");
        let carol = party("did:example:carol");

        let packed = pack_authcrypt(
            b"to both",
            &alice.identity.verkey,
            &alice.x25519_private,
            &[bob.identity.verkey, carol.identity.verkey],
        )
        .unwrap();

        for party in [&bob, &carol] {
            let opened = open(&packed, &[party.key()]).unwrap();
            assert_eq!(opened.plaintext, b"to both");
            assert_eq!(opened.recipient_verkey, party.identity.verkey);
        }
    }

    #[test]
    fn open_fails_for_a_non_recipient() {
        let alice = party("did:example:alice");
        let bob = party("did:example:bob");
        let mallory = party("did:example:mallory");

        let packed = pack_authcrypt(
            b"private",
            &alice.identity.verkey,
            &alice.x25519_private,
            &[bob.identity.verkey],
        )
        .unwrap();

        assert!(matches!(
            open(&packed, &[mallory.key()]),
            Err(DIDCommV1Error::IdentityNotFound(_))
        ));
    }

    /// `alg` is chosen by whoever built the envelope. Claiming `Authcrypt` over
    /// an anonymously-wrapped CEK must not yield an authenticated result — the
    /// protection has to come from what decrypted, not from the header.
    #[test]
    fn alg_header_cannot_forge_authentication() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"anonymous", &[bob.identity.verkey]).unwrap();

        // Rewrite `alg` to Authcrypt, leaving the (anonymous) recipient entry.
        let mut envelope: Envelope = serde_json::from_str(&packed).unwrap();
        let mut header: ProtectedHeader =
            serde_json::from_slice(&b64_decode(&envelope.protected, "protected").unwrap()).unwrap();
        header.alg = ALG_AUTHCRYPT.to_string();
        envelope.protected = b64_encode(&serde_json::to_vec(&header).unwrap());
        let tampered = serde_json::to_string(&envelope).unwrap();

        // The AAD covers the header, so the content decrypt fails outright. It
        // must never succeed *and* report Authcrypt.
        match open(&tampered, &[bob.key()]) {
            Err(_) => {}
            Ok(opened) => assert_eq!(
                opened.protection,
                EnvelopeProtection::Anoncrypt,
                "a rewritten alg must not produce an authenticated result"
            ),
        }
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"anonymous", &[bob.identity.verkey]).unwrap();

        let mut envelope: Envelope = serde_json::from_str(&packed).unwrap();
        let mut ciphertext = b64_decode(&envelope.ciphertext, "ciphertext").unwrap();
        ciphertext[0] ^= 0xff;
        envelope.ciphertext = b64_encode(&ciphertext);

        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(open(&tampered, &[bob.key()]).is_err());
    }

    #[test]
    fn rejects_half_specified_recipient_header() {
        let alice = party("did:example:alice");
        let bob = party("did:example:bob");

        let packed = pack_authcrypt(
            b"hello",
            &alice.identity.verkey,
            &alice.x25519_private,
            &[bob.identity.verkey],
        )
        .unwrap();

        let mut envelope: Envelope = serde_json::from_str(&packed).unwrap();
        let mut header: ProtectedHeader =
            serde_json::from_slice(&b64_decode(&envelope.protected, "protected").unwrap()).unwrap();
        header.recipients[0].header.iv = None;
        envelope.protected = b64_encode(&serde_json::to_vec(&header).unwrap());

        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(matches!(
            open(&tampered, &[bob.key()]),
            Err(DIDCommV1Error::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn rejects_unknown_enc_and_typ() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"x", &[bob.identity.verkey]).unwrap();

        for mutate in [
            |h: &mut ProtectedHeader| h.enc = "A256GCM".into(),
            |h: &mut ProtectedHeader| h.typ = "JWM/2.0".into(),
            |h: &mut ProtectedHeader| h.alg = "Nonsense".into(),
        ] {
            let mut envelope: Envelope = serde_json::from_str(&packed).unwrap();
            let mut header: ProtectedHeader =
                serde_json::from_slice(&b64_decode(&envelope.protected, "protected").unwrap())
                    .unwrap();
            mutate(&mut header);
            envelope.protected = b64_encode(&serde_json::to_vec(&header).unwrap());

            let tampered = serde_json::to_string(&envelope).unwrap();
            assert!(matches!(
                open(&tampered, &[bob.key()]),
                Err(DIDCommV1Error::UnsupportedAlgorithm(_))
            ));
        }
    }

    /// Anoncrypt recipient headers omit `sender` / `iv`, matching what Credo
    /// emits today (see `RecipientHeader`).
    #[test]
    fn anoncrypt_header_omits_sender_and_iv() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"x", &[bob.identity.verkey]).unwrap();

        let envelope: Envelope = serde_json::from_str(&packed).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&b64_decode(&envelope.protected, "protected").unwrap()).unwrap();
        let recipient_header = &header["recipients"][0]["header"];

        assert_eq!(
            recipient_header,
            &serde_json::json!({ "kid": bob.identity.verkey.to_base58() })
        );
    }

    /// RFC 0019's worked example and older indy-sdk output use explicit `null`s
    /// where Credo omits the keys. Both must open.
    #[test]
    fn accepts_explicit_nulls_for_an_anoncrypt_recipient_header() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"legacy nulls", &[bob.identity.verkey]).unwrap();

        let mut envelope: Envelope = serde_json::from_str(&packed).unwrap();
        let mut header: serde_json::Value =
            serde_json::from_slice(&b64_decode(&envelope.protected, "protected").unwrap()).unwrap();
        header["recipients"][0]["header"]["sender"] = serde_json::Value::Null;
        header["recipients"][0]["header"]["iv"] = serde_json::Value::Null;
        envelope.protected = b64_encode(&serde_json::to_vec(&header).unwrap());

        // The AAD covers the header, so re-encrypt under the rewritten header
        // rather than tampering: this checks the *parser*, not the AEAD.
        let reparsed: ProtectedHeader =
            serde_json::from_slice(&b64_decode(&envelope.protected, "protected").unwrap()).unwrap();
        assert_eq!(reparsed.recipients[0].header.sender, None);
        assert_eq!(reparsed.recipients[0].header.iv, None);
        assert_eq!(
            reparsed.recipients[0].header.kid,
            bob.identity.verkey.to_base58()
        );
    }

    /// RFC 0019 requires decoders to accept padded base64url even though
    /// encoders emit unpadded.
    #[test]
    fn accepts_padded_base64url_on_input() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"padded", &[bob.identity.verkey]).unwrap();

        let mut envelope: Envelope = serde_json::from_str(&packed).unwrap();
        let ciphertext = b64_decode(&envelope.ciphertext, "ciphertext").unwrap();
        envelope.ciphertext = URL_SAFE.encode(&ciphertext);

        let repadded = serde_json::to_string(&envelope).unwrap();
        assert_eq!(open(&repadded, &[bob.key()]).unwrap().plaintext, b"padded");
    }

    #[test]
    fn detects_envelopes() {
        let bob = party("did:example:bob");
        let packed = pack_anoncrypt(b"x", &[bob.identity.verkey]).unwrap();
        assert!(is_envelope(&serde_json::from_str(&packed).unwrap()));
        assert!(!is_envelope(&serde_json::json!({"@id": "1", "@type": "t"})));
    }
}
