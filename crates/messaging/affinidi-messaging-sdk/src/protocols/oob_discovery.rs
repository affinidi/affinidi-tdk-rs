/*!
Out Of Band (OOB) Discovery Protocol

Used to help discover 3rd party DID's while protecting your own privacy.
*/

use crate::{
    ATM,
    errors::{ATMError, check_response, check_response_capped},
    messages::{GenericDataStruct, SuccessResponse},
    profiles::ATMProfile,
};
use affinidi_messaging_didcomm::message::Message;
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::debug;
use uuid::Uuid;

/// The most of a shortened invitation URL's response that is read. An
/// invitation is a short DIDComm message; the URL usually arrives from outside
/// (a QR code, a link), so its response is not trusted to be small.
const OOB_INVITATION_MAX_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub struct OOBDiscovery {}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct OOBInviteResponse {
    pub _oobid: String,
}
impl GenericDataStruct for OOBInviteResponse {}

impl OOBDiscovery {
    /// Creates an OOB Invite
    /// atm :: ATM SDK Client
    /// expiry :: Optional - how long should this invitation exist for in seconds?
    ///           Default is 24 hours
    pub async fn create_invite(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        expiry: Option<Duration>,
    ) -> Result<String, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        // Check if authenticated
        let tokens = atm
            .get_tdk()
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut msg = Message::build(
            Uuid::new_v4().to_string(),
            "https://didcomm.org/out-of-band/2.0/invitation".to_string(),
            json!({}),
        )
        .thid(Uuid::new_v4().to_string())
        .from(profile.inner.did.clone())
        .created_time(now);

        if let Some(expiry) = expiry {
            msg = msg.expires_time(now + expiry.as_secs());
        } else {
            msg = msg.expires_time(now + 86_400);
        }

        let msg = msg.finalize();
        let msg = serde_json::to_string(&msg).map_err(|e| {
            ATMError::SDKError(format!("Could not serialize Invitation message: {e:?}"))
        })?;

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::MsgSendError(format!(
                "Profile ({}): Missing a valid mediator URL",
                profile.inner.alias
            )));
        };

        let res = atm
            .rest_request(reqwest::Method::POST, [&mediator_url, "/oob"].concat())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send OOB Invitation request: {e:?}"))
            })?;

        debug!("API response: status({})", res.status());
        let body = check_response("create OOB invitation", res).await?;

        let body = SuccessResponse::<OOBInviteResponse>::parse("create OOB invitation", &body)?;

        if let Some(data) = body.data {
            Ok(data._oobid)
        } else {
            Err(ATMError::MediatorError(
                "EMPTY".into(),
                "Expected to get _oobid, but it was empty...".into(),
            ))
        }
    }

    /// Retrieve an Invitation from a shortened OOB Invitation URL
    /// atm :: ATM SDK Client
    /// url :: Invitation OOB URL
    ///
    /// The request is bounded by the configured request timeout, and a
    /// response body larger than 64 KiB is refused.
    pub async fn retrieve_invite(&self, atm: &ATM, url: &str) -> Result<Message, ATMError> {
        let res = atm
            .rest_request(reqwest::Method::GET, url)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send OOB Invitation request: {e:?}"))
            })?;

        debug!("API response: status({})", res.status());
        let body =
            check_response_capped("retrieve OOB invitation", res, OOB_INVITATION_MAX_BYTES).await?;

        let body = SuccessResponse::<String>::parse("retrieve OOB invitation", &body)?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(data) = body.data {
            // base64 decode the output
            let msg_bytes = BASE64_URL_SAFE_NO_PAD.decode(data).map_err(|e| {
                ATMError::TransportError(format!("OOB invitation is not valid base64url: {e}"))
            })?;
            let msg_str = String::from_utf8(msg_bytes).map_err(|e| {
                ATMError::TransportError(format!("OOB invitation is not valid UTF-8: {e}"))
            })?;
            let msg: Message = serde_json::from_str(&msg_str).map_err(|e| {
                ATMError::TransportError(format!("Couldn't deserialize OOB invitation: {e}"))
            })?;

            if let Some(expires_time) = msg.expires_time
                && expires_time <= now
            {
                return Err(ATMError::MediatorError(
                    "EXPIRED".into(),
                    "Invitation has expired...".into(),
                ));
            }
            Ok(msg)
        } else {
            Err(ATMError::MediatorError(
                "EMPTY".into(),
                "Expected to get OOB Invitation, but it was empty...".into(),
            ))
        }
    }

    /// Deletes OOB Invite
    /// atm :: ATM SDK Client
    /// oobid :: ID of the OOB Invitation to delete
    pub async fn delete_invite(
        &self,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        oobid: &str,
    ) -> Result<String, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        // Check if authenticated
        let tokens = atm
            .get_tdk()
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::MsgSendError(format!(
                "Profile ({}): Missing a valid mediator URL",
                profile.inner.alias
            )));
        };

        let res = atm
            .rest_request(
                reqwest::Method::DELETE,
                format!("{mediator_url}/oob?_oobid={oobid}"),
            )
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not delete OOB Invitation request: {e:?}"))
            })?;

        debug!("API response: status({})", res.status());
        let body = check_response("delete OOB invitation", res).await?;

        let body = SuccessResponse::<String>::parse("delete OOB invitation", &body)?;

        if let Some(data) = body.data {
            Ok(data)
        } else {
            Err(ATMError::MediatorError(
                "EMPTY".into(),
                "Expected to get delete status, but it was empty...".into(),
            ))
        }
    }
}

/// Wrapper struct that holds a reference to ATM, enabling the `atm.oob_discovery().method()` pattern
pub struct OOBDiscoveryOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl<'a> OOBDiscoveryOps<'a> {
    /// Creates an OOB Invite
    /// See [`OOBDiscovery::create_invite`] for full documentation
    pub async fn create_invite(
        &self,
        profile: &Arc<ATMProfile>,
        expiry: Option<Duration>,
    ) -> Result<String, ATMError> {
        OOBDiscovery::default()
            .create_invite(self.atm, profile, expiry)
            .await
    }

    /// Retrieve an Invitation from a shortened OOB Invitation URL
    /// See [`OOBDiscovery::retrieve_invite`] for full documentation
    pub async fn retrieve_invite(&self, url: &str) -> Result<Message, ATMError> {
        OOBDiscovery::default().retrieve_invite(self.atm, url).await
    }

    /// Deletes OOB Invite
    /// See [`OOBDiscovery::delete_invite`] for full documentation
    pub async fn delete_invite(
        &self,
        profile: &Arc<ATMProfile>,
        oobid: &str,
    ) -> Result<String, ATMError> {
        OOBDiscovery::default()
            .delete_invite(self.atm, profile, oobid)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ATMConfig;
    use affinidi_tdk_common::TDKSharedState;
    use affinidi_tdk_common::config::TDKConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn atm_with_request_timeout(request_timeout: Duration) -> ATM {
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        let config = ATMConfig::builder()
            .with_request_timeout(request_timeout)
            .build()
            .unwrap();
        ATM::new(config, tdk).await.unwrap()
    }

    /// A server that answers one request with `response`, or with nothing at
    /// all (holding the connection open) when `response` is `None`.
    async fn serve_once(response: Option<Vec<u8>>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/oob", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            match response {
                Some(response) => {
                    let _ = socket.write_all(&response).await;
                    let _ = socket.shutdown().await;
                }
                None => tokio::time::sleep(Duration::from_secs(60)).await,
            }
        });
        url
    }

    fn ok_response(body: &[u8], with_length: bool) -> Vec<u8> {
        let mut response = if with_length {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes()
        } else {
            b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_vec()
        };
        response.extend_from_slice(body);
        response
    }

    #[tokio::test]
    async fn retrieving_an_invitation_from_a_silent_server_times_out() {
        let atm = atm_with_request_timeout(Duration::from_millis(300)).await;
        let url = serve_once(None).await;
        let started = std::time::Instant::now();
        let err = OOBDiscovery::default()
            .retrieve_invite(&atm, &url)
            .await
            .unwrap_err();
        assert!(matches!(err, ATMError::TransportError(_)), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn an_oversized_invitation_response_is_refused() {
        let atm = atm_with_request_timeout(Duration::from_secs(10)).await;
        let body = vec![b'a'; OOB_INVITATION_MAX_BYTES + 1];
        for with_length in [true, false] {
            let url = serve_once(Some(ok_response(&body, with_length))).await;
            let err = OOBDiscovery::default()
                .retrieve_invite(&atm, &url)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, ATMError::TransportError(text) if text.contains("larger than")),
                "with_length={with_length}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_invitation_response_that_is_not_json_is_an_error() {
        let atm = atm_with_request_timeout(Duration::from_secs(10)).await;
        let url = serve_once(Some(ok_response(b"<html>login</html>", true))).await;
        let err = OOBDiscovery::default()
            .retrieve_invite(&atm, &url)
            .await
            .unwrap_err();
        assert!(matches!(err, ATMError::TransportError(_)), "{err:?}");
    }
}
