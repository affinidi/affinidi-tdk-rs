use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement};
use affinidi_did_common::{
    document::DocumentExt,
    key_negotiation::{DEFAULT_CURVE_PREFERENCE, negotiate_authcrypt, select_anoncrypt_key},
};
use affinidi_messaging_didcomm::message::{Message, pack};
use affinidi_secrets_resolver::SecretsResolver;
use tracing::{Instrument, Level, debug, span};

use crate::{ATM, SharedState, errors::ATMError};

use super::compat::PackEncryptedMetadata;

impl ATM {
    /// Pack a message for sending to a recipient
    /// from: if None, then will use anonymous encryption
    /// sign_by: currently unused (signing is not yet supported in the new crate bridge)
    /// NOTE: If the recipient DID contains a service endpoint,
    /// the message could be auto-forwarded which default to anonymous
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        _sign_by: Option<&str>,
    ) -> Result<(String, PackEncryptedMetadata), ATMError> {
        self.inner.pack_encrypted(message, to, from).await
    }
}

impl SharedState {
    /// Pack a message for sending to a recipient
    /// from: if None, then will use anonymous encryption
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
    ) -> Result<(String, PackEncryptedMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "pack_encrypted",);

        async move {
            // Resolve recipient DID document (needed for both anoncrypt and authcrypt)
            let recipient_doc = self
                .tdk_common
                .did_resolver()
                .resolve(to)
                .await
                .map_err(|e| {
                    ATMError::DidcommError(
                        "pack_encrypted".into(),
                        format!("Failed to resolve recipient DID: {e}"),
                    )
                })?;
            let recipient_ka_kids = recipient_doc.doc.find_key_agreement(None);

            // Curve-preference policy: a runtime override from config, else
            // the negotiator's documented default order. Shared by both the
            // authcrypt and anoncrypt paths so they never disagree.
            let preference = self
                .config
                .get_curve_preference()
                .unwrap_or(&DEFAULT_CURVE_PREFERENCE);

            if let Some(sender_did) = from {
                // Authcrypt: enumerate the sender's *usable* key-agreement
                // keys (a secret we hold, on a supported curve), then
                // negotiate the best shared curve with the recipient.
                // Selection follows the documented curve preference, so the
                // sender's list order is irrelevant — a later sender curve can
                // still match when the first does not.
                let sender_doc = self
                    .tdk_common
                    .did_resolver()
                    .resolve(sender_did)
                    .await
                    .map_err(|e| {
                        ATMError::DidcommError(
                            "pack_encrypted".into(),
                            format!("Failed to resolve sender DID: {e}"),
                        )
                    })?;
                let sender_ka_kids = sender_doc.doc.find_key_agreement(None);

                let mut sender_keys: Vec<(&str, PrivateKeyAgreement, Curve)> = Vec::new();
                for &kid in &sender_ka_kids {
                    let Some(secret) = self.tdk_common.secrets_resolver().get_secret(kid).await
                    else {
                        continue;
                    };
                    let Ok(curve) = key_type_to_curve(secret.get_key_type()) else {
                        continue;
                    };
                    match PrivateKeyAgreement::from_raw_bytes(curve, secret.get_private_bytes()) {
                        Ok(private) => sender_keys.push((kid, private, curve)),
                        Err(e) => debug!("skipping unusable sender key {kid}: {e}"),
                    }
                }
                if sender_keys.is_empty() {
                    return Err(ATMError::DidcommError(
                        "pack_encrypted".into(),
                        "sender has no usable key agreement key".into(),
                    ));
                }
                let sender_curves: Vec<Curve> = sender_keys.iter().map(|(_, _, c)| *c).collect();

                let pairing = negotiate_authcrypt(
                    &sender_curves,
                    &recipient_doc.doc,
                    &recipient_ka_kids,
                    preference,
                )
                .map_err(|e| ATMError::DidcommError("pack_encrypted".into(), e.to_string()))?;

                // The negotiated curve was drawn from `sender_curves`, so a
                // matching sender key is guaranteed present.
                let (sender_kid, sender_private, _) = sender_keys
                    .iter()
                    .find(|(_, _, c)| *c == pairing.curve)
                    .expect("negotiated curve came from sender_curves");

                let packed = pack::pack_encrypted_authcrypt(
                    message,
                    sender_kid,
                    sender_private,
                    &[(pairing.recipient_kid, &pairing.recipient_pub)],
                )
                .map_err(|e| {
                    ATMError::DidcommError(
                        "SDK".to_string(),
                        format!("pack_encrypted() authcrypt failed. Reason: {e}"),
                    )
                })?;

                let metadata = PackEncryptedMetadata {
                    from_kid: Some(sender_kid.to_string()),
                    sign_by_kid: None,
                    to_kids: vec![pairing.recipient_kid.to_string()],
                };

                Ok((packed, metadata))
            } else {
                // Anoncrypt: pick the first advertised key-agreement key that
                // resolves to a supported curve (skipping undecodable codecs),
                // rather than blindly taking `first()`.
                let (recipient_kid, recipient_pub) =
                    select_anoncrypt_key(&recipient_doc.doc, &recipient_ka_kids, preference)
                        .map_err(|e| {
                            ATMError::DidcommError("pack_encrypted".into(), e.to_string())
                        })?;

                let packed =
                    pack::pack_encrypted_anoncrypt(message, &[(recipient_kid, &recipient_pub)])
                        .map_err(|e| {
                            ATMError::DidcommError(
                                "SDK".to_string(),
                                format!("pack_encrypted() anoncrypt failed. Reason: {e}"),
                            )
                        })?;

                let metadata = PackEncryptedMetadata {
                    from_kid: None,
                    sign_by_kid: None,
                    to_kids: vec![recipient_kid.to_string()],
                };

                Ok((packed, metadata))
            }
        }
        .instrument(_span)
        .await
    }

    /// creates a plaintext (unencrypted and unsigned) message
    #[allow(dead_code)]
    pub async fn pack_plaintext(&self, message: &Message) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "pack_plaintext",);

        async move {
            pack::pack_plaintext(message).map_err(|e| {
                ATMError::DidcommError(
                    "SDK".to_string(),
                    format!("pack_plaintext() failed. Reason: {e}"),
                )
            })
        }
        .instrument(_span)
        .await
    }
}

/// Map from secrets resolver KeyType to DIDComm Curve.
fn key_type_to_curve(
    key_type: affinidi_secrets_resolver::secrets::KeyType,
) -> Result<Curve, ATMError> {
    match key_type {
        affinidi_secrets_resolver::secrets::KeyType::X25519 => Ok(Curve::X25519),
        affinidi_secrets_resolver::secrets::KeyType::P256 => Ok(Curve::P256),
        affinidi_secrets_resolver::secrets::KeyType::Secp256k1 => Ok(Curve::K256),
        affinidi_secrets_resolver::secrets::KeyType::P384 => Ok(Curve::P384),
        affinidi_secrets_resolver::secrets::KeyType::P521 => Ok(Curve::P521),
        other => Err(ATMError::DidcommError(
            "key_type_to_curve".into(),
            format!("unsupported key type for key agreement: {other:?}"),
        )),
    }
}
