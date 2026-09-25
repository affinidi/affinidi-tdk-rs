//! Builds ECDH-1PU+A256KW JWEs whose protected header is written by hand, so
//! tests can produce headers a conforming sender never would: `skid` and `apu`
//! naming different key ids, either one missing, duplicate members, and so on.
//! The KEK is derived over whatever PartyUInfo the test chooses.
//!
//! Shared by the forgery tests in this crate, `affinidi-messaging-sdk` and
//! `affinidi-messaging-test-mediator` (included there by `#[path]`), so it
//! depends only on `affinidi-crypto` and `serde_json`.
#![allow(dead_code)]

use affinidi_crypto::jose::{
    EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement, aes_kw, content_encryption, ecdh,
};

/// Unpadded base64url.
pub fn b64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// An authcrypt JWE from `sender` to `recipients`.
///
/// `header(epk_jwk_json, apv_b64)` returns the raw protected header JSON.
/// `kdf_apu` is the PartyUInfo the KEK is derived over. `extra` is merged into
/// the top-level JWE object and `recipient_header_extra` into each
/// per-recipient header, neither of which is integrity-protected.
pub fn forge(
    plaintext: &[u8],
    kdf_apu: &[u8],
    sender: &PrivateKeyAgreement,
    recipients: &[(&str, &PublicKeyAgreement)],
    header: impl Fn(&str, &str) -> String,
    extra: Option<serde_json::Value>,
    recipient_header_extra: Option<serde_json::Value>,
) -> String {
    let ephemeral = EphemeralKeyPair::generate(recipients[0].1.curve());
    let apv = b"forged-apv";
    let protected = b64(header(&ephemeral.public.to_jwk().to_string(), &b64(apv)).as_bytes());
    let cek = content_encryption::generate_cek();
    let iv = content_encryption::generate_iv();
    let (ciphertext, tag) =
        content_encryption::encrypt(plaintext, &cek, &iv, protected.as_bytes()).unwrap();
    let mut jwe_recipients = vec![];
    for (kid, public) in recipients {
        let kek =
            ecdh::derive_sender_key_1pu(&ephemeral, sender, public, kdf_apu, apv, &tag).unwrap();
        let mut recipient_header = serde_json::json!({ "kid": kid });
        if let Some(extra) = &recipient_header_extra {
            for (key, value) in extra.as_object().unwrap() {
                recipient_header[key] = value.clone();
            }
        }
        jwe_recipients.push(serde_json::json!({
            "header": recipient_header,
            "encrypted_key": b64(&aes_kw::wrap(&kek, &cek).unwrap()),
        }));
    }
    let mut jwe = serde_json::json!({
        "protected": protected,
        "recipients": jwe_recipients,
        "iv": b64(&iv),
        "ciphertext": b64(&ciphertext),
        "tag": b64(&tag),
    });
    if let Some(extra) = extra {
        for (key, value) in extra.as_object().unwrap() {
            jwe[key] = value.clone();
        }
    }
    jwe.to_string()
}

/// A DIDComm authcrypt protected header with `skid` and `apu` set
/// independently; `None` leaves the member out.
pub fn header_with(skid: Option<&str>, apu: Option<&str>) -> impl Fn(&str, &str) -> String {
    let skid = skid.map(str::to_string);
    let apu = apu.map(str::to_string);
    move |epk, apv| {
        let mut header = String::from(
            r#"{"typ":"application/didcomm-encrypted+json","alg":"ECDH-1PU+A256KW","enc":"A256CBC-HS512""#,
        );
        if let Some(skid) = &skid {
            header.push_str(&format!(
                r#","skid":{}"#,
                serde_json::Value::String(skid.clone())
            ));
        }
        if let Some(apu) = &apu {
            header.push_str(&format!(r#","apu":"{}""#, b64(apu.as_bytes())));
        }
        header.push_str(&format!(r#","apv":"{apv}","epk":{epk}}}"#));
        header
    }
}
