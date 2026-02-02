use crate::error::ToResult;
use crate::{
    error::{ErrorKind, Result, ResultExt, err_msg},
    jws::envelope::{CompactHeader, Jws, ProtectedHeader},
};
use base64::prelude::*;
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct ParsedJWS {
    pub jws: Jws,
    pub protected: Vec<ProtectedHeader>,
}

pub fn parse(jws: &str) -> Result<ParsedJWS> {
    Jws::from_str(jws)?.parse()
}

impl Jws {
    pub(crate) fn from_str(s: &str) -> Result<Jws> {
        serde_json::from_str(s).to_didcomm("Unable parse jws")
    }

    pub(crate) fn parse(&self) -> Result<ParsedJWS> {
        let protected = {
            let len = self.signatures.len();
            let mut protected = Vec::<ProtectedHeader>::with_capacity(len);
            let mut buf = Vec::with_capacity(len);
            buf.resize(len, vec![]);

            for (i, b) in buf.iter_mut().enumerate() {
                let signature = self
                    .signatures
                    .get(i)
                    .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Invalid signature index"))?;

                BASE64_URL_SAFE_NO_PAD
                    .decode_vec(&signature.protected, b)
                    .kind(ErrorKind::Malformed, "Unable decode protected header")?;

                let p: ProtectedHeader =
                    serde_json::from_slice(b).to_didcomm("Unable parse protected header")?;

                protected.push(p);
            }

            protected
        };

        Ok(ParsedJWS {
            jws: self.clone(),
            protected,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedCompactJWS {
    pub(crate) header: String,
    pub(crate) parsed_header: CompactHeader,
    pub(crate) payload: String,
    pub(crate) signature: String,
}

pub(crate) fn parse_compact(compact_jws: &str) -> Result<ParsedCompactJWS> {
    let segments: Vec<&str> = compact_jws.split('.').collect();
    if segments.len() != 3 {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Unable to parse compactly serialized JWS",
        ));
    }

    let header = segments[0];
    let payload = segments[1];
    let signature = segments[2];

    let mut buf: Vec<u8> = Vec::new();
    BASE64_URL_SAFE_NO_PAD
        .decode_vec(header, &mut buf)
        .kind(ErrorKind::Malformed, "Unable decode header")?;

    let parsed_header: CompactHeader =
        serde_json::from_slice(buf.as_slice()).kind(ErrorKind::Malformed, "Unable parse header")?;

    Ok(ParsedCompactJWS {
        header: header.into(),
        parsed_header,
        payload: payload.into(),
        signature: signature.into(),
    })
}

#[cfg(test)]
mod tests {
    use crate::jws::{CompactHeader, ParsedCompactJWS};
    use crate::{
        error::ErrorKind,
        jws::{
            self, ParsedJWS,
            envelope::{Algorithm, Header, Jws, ProtectedHeader, Signature},
        },
    };

    #[test]
    fn parse_works() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1"
                  }
               }
            ]
         }
        "#;

        let res = jws::parse(msg);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: Jws {
                signatures: vec![Signature {
                    header: Header { kid: "did:example:alice#key-1".into() },
                    protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ".into(),
                    signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ".into(),
                }],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19".into(),
            },
            protected: vec![ProtectedHeader {
                typ: "application/didcomm-signed+json".into(),
                alg: Algorithm::EdDSA,
            }],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_unknown_fields() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1"
                  }
               }
            ],
            "extra":"value"
         }
        "#;

        let res = jws::parse(msg);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: Jws {
                signatures: vec![Signature {
                    header: Header { kid: "did:example:alice#key-1".into() },
                    protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ".into(),
                    signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ".into(),
                }],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19".into(),
            },
            protected: vec![ProtectedHeader {
                typ: "application/didcomm-signed+json".into(),
                alg: Algorithm::EdDSA,
            }],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_protected_unknown_fields() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EiLCJleHRyYSI6InZhbHVlIn0",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1"
                  }
               }
            ]
         }
        "#;

        let res = jws::parse(msg);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: Jws {
                signatures: vec![Signature {
                    header: Header { kid: "did:example:alice#key-1".into() },
                    protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EiLCJleHRyYSI6InZhbHVlIn0".into(),
                    signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ".into(),
                }],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19".into(),
            },
            protected: vec![ProtectedHeader {
                typ: "application/didcomm-signed+json".into(),
                alg: Algorithm::EdDSA,
            }],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_multiple_signatures() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1"
                  }
               },
               {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header":{
                   "kid":"did:example:alice#key-2"
                }
             }
            ]
         }
        "#;

        let res = jws::parse(msg);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: Jws {
                signatures: vec![
                    Signature {
                        header: Header { kid: "did:example:alice#key-1".into() },
                        protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ".into(),
                        signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ".into(),
                    },
                    Signature {
                        header: Header { kid: "did:example:alice#key-2".into() },
                        protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ".into(),
                        signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ".into(),
                    }
                ],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19".into(),
            },
            protected: vec![
                ProtectedHeader {
                  typ: "application/didcomm-signed+json".into(),
                  alg: Algorithm::EdDSA,
                },
                ProtectedHeader {
                    typ: "application/didcomm-signed+json".into(),
                 alg: Algorithm::EdDSA,
                }
            ],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_unparsable() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1",
                  }
               }
            ]
         }
        "#;

        let res = jws::parse(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable parse jws: trailing comma at line 10 column 19"
        );
    }

    #[test]
    fn parse_works_misstructured() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header":{
                }
            }
            ]
        }
        "#;

        let res = jws::parse(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable parse jws: missing field `kid` at line 9 column 17"
        );
    }

    #[test]
    fn parse_works_undecodable_protected() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"!eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                    "kid":"did:example:alice#key-1"
                 }
               }
            ]
         }
        "#;

        let res = jws::parse(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable decode protected header: Invalid symbol 33, offset 0."
        );
    }

    #[test]
    fn parse_works_unparsable_protected() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"ey4idHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1zaWduZWQranNvbiIsImFsZyI6IkVkRFNBIn0",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                    "kid":"did:example:alice#key-1"
                 }
               }
            ]
         }
        "#;

        let res = jws::parse(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable parse protected header: key must be a string at line 1 column 2"
        );
    }

    #[test]
    fn parse_works_misstructured_protected() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIn0",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                    "kid":"did:example:alice#key-1"
                 }
               }
            ]
         }
        "#;

        let res = jws::parse(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable parse protected header: missing field `alg` at line 1 column 41"
        );
    }

    #[test]
    fn parse_compact_works() {
        let msg = "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let res = jws::parse_compact(msg);
        let res = res.expect("res is err");

        let exp = ParsedCompactJWS {
            header: "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
                     ZSNrZXktMSJ9".into(),
            parsed_header: CompactHeader {
                typ: "example-typ-1".into(),
                alg: Algorithm::EdDSA,
                kid: "did:example:alice#key-1".into(),
            },
            payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
                      eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
                      bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
                      dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
                      YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19".into(),
            signature: "iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
                        bHgtCg".into(),
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_compact_works_header_unknown_fields() {
        let msg = "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSIsImV4dHJhIjoidmFsdWUifQ\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let res = jws::parse_compact(msg);
        let res = res.expect("res is err");

        let exp = ParsedCompactJWS {
            header: "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
                     ZSNrZXktMSIsImV4dHJhIjoidmFsdWUifQ".into(),
            parsed_header: CompactHeader {
                typ: "example-typ-1".into(),
                alg: Algorithm::EdDSA,
                kid: "did:example:alice#key-1".into(),
            },
            payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
                      eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
                      bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
                      dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
                      YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19".into(),
            signature: "iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
                        bHgtCg".into(),
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_compact_works_too_few_segments() {
        let msg = "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19";

        let res = jws::parse_compact(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable to parse compactly serialized JWS"
        );
    }

    #[test]
    fn parse_compact_works_too_many_segments() {
        let msg = "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg\
             .\
             eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9";

        let res = jws::parse_compact(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable to parse compactly serialized JWS"
        );
    }

    #[test]
    fn parse_compact_works_undecodable_header() {
        let msg = "!eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let res = jws::parse_compact(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable decode header: Invalid symbol 33, offset 0."
        );
    }

    #[test]
    fn parse_compact_works_unparsable_header() {
        let msg = "ey4idHlwIjoiZXhhbXBsZS10eXAtMSIsImFsZyI6IkVkRFNBIiwia2lkIjoiZGlkOmV4YW1wbGU6YWxp\
             Y2Uja2V5LTEifQ\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let res = jws::parse_compact(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable parse header: key must be a string at line 1 column 2"
        );
    }

    #[test]
    fn parse_compact_works_misstructured_header() {
        let msg = "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwia2lkIjoiZGlkOmV4YW1wbGU6YWxpY2Uja2V5LTEifQ\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let res = jws::parse_compact(msg);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{err}"),
            "Malformed: Unable parse header: missing field `alg` at line 1 column 55"
        );
    }
}
