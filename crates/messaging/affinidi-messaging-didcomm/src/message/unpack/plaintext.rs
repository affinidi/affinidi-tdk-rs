use affinidi_did_resolver_cache_sdk::DIDCacheClient;

use crate::envelope::{MetaEnvelope, ParsedEnvelope};
use crate::error::Result;
use crate::{FromPrior, Message};

pub(crate) async fn _try_unpack_plaintext(
    msg: &ParsedEnvelope,
    did_resolver: &DIDCacheClient,
    envelope: &mut MetaEnvelope,
) -> Result<Option<Message>> {
    let msg = match msg {
        ParsedEnvelope::Message(msg) => msg.clone().validate()?,
        _ => return Ok(None),
    };

    if let Some(from_prior) = &msg.from_prior {
        let (unpacked_from_prior, from_prior_issuer_kid) =
            FromPrior::unpack(from_prior, did_resolver).await?;

        envelope.metadata.from_prior = Some(unpacked_from_prior);
        envelope.metadata.from_prior_issuer_kid = Some(from_prior_issuer_kid);
    };

    Ok(Some(msg))
}
