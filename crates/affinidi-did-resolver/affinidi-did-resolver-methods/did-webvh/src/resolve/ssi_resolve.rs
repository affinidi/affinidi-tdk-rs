/*!
*   Resolver trait methods for webvh
*/

use crate::{
    DIDWebVHState,
    resolve::DIDWebVH,
    url::{URLType, WebVHURL},
    witness::proofs::WitnessProofCollection,
};
use ssi::dids::{
    DIDMethod, DIDMethodResolver, Document,
    document::{
        self,
        representation::{self, MediaType},
    },
    resolution::{self, Error, Options, Parameter},
};
use std::time::Duration;
use tracing::{Instrument, Level, span, warn};

impl DIDMethodResolver for DIDWebVH {
    /// Resolves a webvh DID
    ///
    /// Does make use of Optional parameters
    /// parameters("network_timeout") (defaults to 10 seconds): Time in seconds before timing out
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<ssi::dids::resolution::Output<Vec<u8>>, Error> {
        let _span = span!(
            Level::DEBUG,
            "DIDWebVH::resolve_method_representation",
            method_specific_id = method_specific_id
        );
        async move {
            let parsed_did_url = WebVHURL::parse_did_url(method_specific_id)
                .map_err(|err| Error::Internal(format!("webvh error: {err}",)))?;

            if parsed_did_url.type_ == URLType::WhoIs {
                // TODO: whois is not implemented yet
                return Err(Error::RepresentationNotSupported(
                    "WhoIs is not implemented yet".to_string(),
                ));
            }

            // Set network timeout values. Will default to 10 seconds for any reasons
            let network_timeout = if let Some(Parameter::String(network_timeout)) =
                options.parameters.additional.get("network_timeout")
            {
                Duration::from_secs(network_timeout.parse().unwrap_or(10_u64))
            } else {
                Duration::from_secs(10)
            };

            // Async download did.jsonl and did-witness.json
            let client = reqwest::Client::new();
            let r1 = tokio::time::timeout(
                network_timeout,
                tokio::spawn(DIDWebVH::get_log_entries(
                    parsed_did_url.clone(),
                    client.clone(),
                )),
            );

            let r2 = tokio::time::timeout(
                network_timeout,
                tokio::spawn(DIDWebVH::get_witness_proofs(
                    parsed_did_url.clone(),
                    client.clone(),
                )),
            );

            let (r1, r2) = (r1.await, r2.await);

            // LogEntry
            let log_entries = if let Ok(log_entries) = r1 {
                match log_entries {
                    Ok(entries) => match entries {
                        Ok(entries) => entries,
                        Err(e) => {
                            warn!("Error downloading LogEntries: {e}");
                            return Err(Error::internal("Error downloading LogEntries for DID"));
                        }
                    },
                    Err(e) => {
                        warn!("tokio join error: {e}");
                        return Err(Error::internal(format!(
                            "Error downloading LogEntries for DID: {e}"
                        )));
                    }
                }
            } else {
                warn!("timeout error on LogEntry download");
                return Err(Error::internal(
                    "Network timeout on downloaded LogEntries for DID",
                ));
            };

            // If there is any error with witness proofs then set witness proofs to an empty proof
            // WitnessProofCollection
            // If a webvh DID is NOT using witnesses then it will still successfully validate
            let witness_proofs = if let Ok(proofs) = r2 {
                match proofs {
                    Ok(proofs) => match proofs {
                        Ok(proofs) => proofs,
                        Err(e) => {
                            warn!("Error downloading witness proofs: {e}");
                            WitnessProofCollection::default()
                        }
                    },
                    Err(e) => {
                        warn!("tokio join error: {e}");
                        WitnessProofCollection::default()
                    }
                }
            } else {
                warn!("Downloading witness proofs timedout. Defaulting to no witness proofs");
                WitnessProofCollection::default()
            };

            // Have LogEntries and Witness Proofs, now can validate the DID
            let mut didwebvh_state = DIDWebVHState {
                log_entries,
                witness_proofs,
            };

            didwebvh_state
                .validate()
                .map_err(|e| Error::internal(format!("validation failed: {e}")))?;

            let last_entry_state = didwebvh_state
                .log_entries
                .last()
                .ok_or_else(|| Error::internal("No log entries found"))?;

            // Get the latest DID Document
            let document: Document =
                serde_json::from_value(last_entry_state.log_entry.state.clone())
                    .map_err(|e| Error::internal(format!("Failed to parse DID Document: {e}")))?;

            let content_type = options.accept.unwrap_or(MediaType::Json);
            let represented = document.into_representation(representation::Options::Json);

            Ok(resolution::Output::new(
                represented.to_bytes(),
                document::Metadata::default(),
                resolution::Metadata::from_content_type(Some(content_type.to_string())),
            ))
        }
        .instrument(_span)
        .await
    }
}

impl DIDMethod for DIDWebVH {
    const DID_METHOD_NAME: &'static str = "webvh";
}
