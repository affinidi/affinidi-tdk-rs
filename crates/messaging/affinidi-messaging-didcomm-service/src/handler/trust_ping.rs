use affinidi_messaging_didcomm::Message;
use serde::Deserialize;

use crate::error::DIDCommServiceError;
use crate::response::DIDCommResponse;

use super::HandlerContext;

pub const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
pub const TRUST_PONG_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

#[derive(Deserialize)]
struct PingBody {
    #[serde(default = "yes")]
    response_requested: bool,
}

fn yes() -> bool {
    true
}

pub async fn trust_ping_handler(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let body: PingBody = serde_json::from_value(message.body.clone()).unwrap_or(PingBody {
        response_requested: true,
    });

    if !body.response_requested {
        return Ok(None);
    }

    if ctx.sender_did.is_none() {
        return Ok(None);
    }

    Ok(Some(
        DIDCommResponse::new(TRUST_PONG_TYPE, serde_json::Value::Null).thid(message.id),
    ))
}
