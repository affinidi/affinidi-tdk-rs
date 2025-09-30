use crate::document::{DIDCommVerificationMethodExt, did_or_url};
use crate::envelope::MetaEnvelope;
use crate::error::ToResult;
use crate::utils::crypto::AsKnownKeyPair;
use crate::{
    error::{ErrorKind, Result, ResultExt, err_msg},
    jwe::envelope::{Jwe, ProtectedHeader},
};
use affinidi_did_common::document::DocumentExt;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use base64::prelude::*;
use sha2::{Digest, Sha256};
use tracing::debug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedJWE {
    pub jwe: Jwe,
    pub protected: ProtectedHeader,
    pub apu: Option<Vec<u8>>,
    pub apv: Vec<u8>,
    pub to_kids: Vec<String>,
}

pub fn parse(jwe: &str) -> Result<ParsedJWE> {
    Jwe::from_str(jwe)?.parse()
}

impl Jwe {
    pub(crate) fn from_str(s: &str) -> Result<Jwe> {
        serde_json::from_str(s).to_didcomm("Unable parse jwe")
    }

    pub(crate) fn parse(self) -> Result<ParsedJWE> {
        // Strip off base64 padding
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(self.protected.replace('=', ""))
            .kind(ErrorKind::Malformed, "Unable decode protected header")?;

        let protected: ProtectedHeader =
            serde_json::from_slice(&decoded).to_didcomm("Unable parse protected header")?;

        let apv = BASE64_URL_SAFE_NO_PAD
            .decode(protected.apv.clone())
            .kind(ErrorKind::Malformed, "Unable decode apv")?;

        let apu = protected
            .apu
            .as_ref()
            .map(|apu| BASE64_URL_SAFE_NO_PAD.decode(apu))
            .transpose()
            .kind(ErrorKind::Malformed, "Unable decode apu")?;

        let to_kids = self
            .recipients
            .clone()
            .iter()
            .map(|r| r.header.kid.clone())
            .collect();
        let jwe = ParsedJWE {
            jwe: self,
            protected,
            apu,
            apv,
            to_kids,
        };

        Ok(jwe)
    }
}

impl ParsedJWE {
    /// Verifies that apv and apu filled according DID Comm specification.
    pub(crate) fn verify_didcomm(self) -> Result<Self> {
        let did_comm_apv = {
            let mut kids = self
                .jwe
                .recipients
                .iter()
                .map(|r| r.header.kid.clone())
                .collect::<Vec<_>>();

            kids.sort();
            Sha256::digest(kids.join(".").as_bytes())
        };

        if self.apv != did_comm_apv.as_slice() {
            Err(err_msg(ErrorKind::Malformed, "APV mismatch"))?;
        }

        let did_comm_apu = self
            .apu
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .kind(ErrorKind::Malformed, "Invalid utf8 for apu")?;

        match (did_comm_apu, self.protected.skid.clone()) {
            (Some(apu), Some(skid)) if apu != skid => {
                Err(err_msg(ErrorKind::Malformed, "APU mismatch"))?
            }
            (None, Some(_)) => Err(err_msg(ErrorKind::Malformed, "SKID present, but no apu"))?,
            _ => (),
        };

        Ok(self)
    }

    /// Populates various from_* fields for the Envelope
    pub async fn fill_envelope_from(
        &self,
        envelope: &mut MetaEnvelope,
        did_resolver: &DIDCacheClient,
    ) -> Result<&Self> {
        debug!("Checking if APU exists in JWE?");
        if let Some(apu) = &self.apu {
            debug!("Found APU in JWE. Algorithm type ({})", &self.protected.alg);
            let from_kid =
                std::str::from_utf8(apu).kind(ErrorKind::Malformed, "apu is invalid utf8")?;

            let (from_did, from_url) = did_or_url(from_kid);

            if from_url.is_none() {
                Err(err_msg(
                    ErrorKind::Malformed,
                    "Sender key can't be resolved to key agreement",
                ))?;
            }

            envelope.from_did = Some(from_did.into());

            envelope.from_ddoc = Some(
                did_resolver
                    .resolve(from_did)
                    .await
                    .map_err(|e| err_msg(ErrorKind::DIDNotResolved, e))?
                    .doc,
            );

            if let Some(doc) = &envelope.from_ddoc {
                // Valid DID Document
                if doc.contains_key_agreement(from_kid) {
                    // Do we have a key agreement?
                    envelope.from_kid = Some(from_kid.into());
                } else {
                    Err(err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Sender kid not found in did",
                    ))?;
                }

                // COnvert keys from the verification method that matches the sender key-id
                if let Some(vm) = doc.get_verification_method(from_kid) {
                    let jwk = vm.get_jwk().ok_or_else(|| {
                        err_msg(
                            ErrorKind::Malformed,
                            "Can't convert verification method to a JWK",
                        )
                    })?;
                    let key_pair = vm.as_key_pair(&jwk).map_err(|e| {
                        err_msg(
                            ErrorKind::Malformed,
                            format!("Can't convert verification method to a key pair: {}", e),
                        )
                    })?;
                    envelope.from_key = Some(key_pair);
                } else {
                    Err(err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Sender verification method not found in did",
                    ))?;
                }
            }

            envelope.metadata.authenticated = true;
            envelope.metadata.encrypted = true;
            envelope.metadata.encrypted_from_kid = Some(from_kid.into());
        } else {
            debug!("APU not found in JWE. Setting anonymous sender");
            envelope.metadata.anonymous_sender = true;
        }

        // Process info relating to the recipients
        envelope.to_kid = Some(
            self.to_kids
                .first()
                .ok_or_else(|| err_msg(ErrorKind::Malformed, "No recipient keys found"))?
                .into(),
        );

        let (to_did, _) = did_or_url(envelope.to_kid.as_ref().unwrap());
        envelope.to_did = Some(to_did.into());

        if self.to_kids.iter().any(|k| {
            let (k_did, k_url) = did_or_url(k);
            (k_did != to_did) || (k_url.is_none())
        }) {
            Err(err_msg(
                ErrorKind::Malformed,
                "Recipient keys are outside of one did or can't be resolved to key agreement",
            ))?;
        }

        envelope.metadata.encrypted_to_kids = self.to_kids.iter().map(|k| k.to_owned()).collect();

        debug!("envelope\n{:#?}", envelope);

        Ok(self)
    }
}
