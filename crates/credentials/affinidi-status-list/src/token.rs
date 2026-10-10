/*!
 * IETF Token Status List (`draft-ietf-oauth-status-list-21`).
 *
 * The status mechanism of SD-JWT VCs and the EUDI / swiyu profiles. A
 * Referenced Token names its entry as `status.status_list = { idx, uri }`; the
 * `uri` serves a **Status List Token** — a JWT of type `statuslist+jwt` whose
 * `status_list` claim carries `{ bits, lst }`: every entry `bits` wide (1, 2, 4
 * or 8), packed least-significant-bit first, ZLIB-compressed and base64url
 * encoded.
 *
 * Differences from the W3C [`BitstringStatusList`](crate::BitstringStatusList)
 * that matter when reading one:
 *
 * | | W3C Bitstring | Token Status List |
 * |---|---|---|
 * | Compression | GZIP | ZLIB (DEFLATE) |
 * | Bit order | most significant first | least significant first |
 * | Entry width | 1 bit, purpose per list | 1/2/4/8 bits, status per entry |
 * | Envelope | a VC | a `statuslist+jwt` |
 *
 * # Verification order
 *
 * [`VerifiedStatusListToken::verify`] follows §8.3: the token's signature is
 * checked **before** any claim is read or the list decompressed — the signature
 * check is the caller's (key resolution belongs to the caller's trust model),
 * supplied as a closure that returns the payload only once it has verified it.
 * Then `typ`, `sub` = the referenced `uri`, `iat`, `exp`, and finally the list,
 * decompressed under a size cap. Only a [`VerifiedStatusListToken`] answers a
 * status query.
 *
 * Binding the Status List Token's signer to the Referenced Token's issuer
 * (§13.5) is likewise the caller's: the verified header and `iss` are exposed
 * for it.
 */

use std::io::{Read, Write};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde_json::{Value, json};

use crate::error::{Result, StatusListError};

/// The `typ` header of a Status List Token in JWT form.
pub const STATUS_LIST_JWT_TYP: &str = "statuslist+jwt";

/// The media type a Status List Token in JWT form is served as, and the
/// `Accept` value to request one with.
pub const STATUS_LIST_JWT_MEDIA_TYPE: &str = "application/statuslist+jwt";

/// The default cap on a decompressed list: 16 MiB, 134 million one-bit
/// entries. A few kilobytes of ZLIB can otherwise inflate to gigabytes.
pub const DEFAULT_MAX_LIST_BYTES: usize = 16 * 1024 * 1024;

/// The default clock leeway, in seconds, for `iat` and `exp`.
pub const DEFAULT_LEEWAY_SECS: i64 = 60;

/// The status of one entry (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenStatus {
    /// `0x00` — valid, correct or legal.
    Valid,
    /// `0x01` — revoked, annulled, recalled or cancelled.
    Invalid,
    /// `0x02` — temporarily invalid.
    Suspended,
    /// `0x03` or `0x0C`–`0x0F` — reserved for application-specific use.
    ApplicationSpecific(u8),
    /// Any other value — reserved for future registration, so its meaning is
    /// unknown to this implementation.
    Reserved(u8),
}

impl TokenStatus {
    /// The status an entry's value encodes.
    pub fn from_value(value: u8) -> Self {
        match value {
            0x00 => Self::Valid,
            0x01 => Self::Invalid,
            0x02 => Self::Suspended,
            0x03 | 0x0C..=0x0F => Self::ApplicationSpecific(value),
            other => Self::Reserved(other),
        }
    }

    /// The value this status is encoded as.
    pub fn value(&self) -> u8 {
        match self {
            Self::Valid => 0x00,
            Self::Invalid => 0x01,
            Self::Suspended => 0x02,
            Self::ApplicationSpecific(value) | Self::Reserved(value) => *value,
        }
    }
}

/// The `status_list` claim as it travels: `{ bits, lst, aggregation_uri? }`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncodedStatusList {
    /// Bits per entry: 1, 2, 4 or 8.
    pub bits: u8,
    /// The ZLIB-compressed, base64url-encoded byte array.
    pub lst: String,
    /// Where the Status Issuer lists all its Status List Tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
}

/// A decoded Token Status List: entries `bits` wide, least significant first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenStatusList {
    bits: u8,
    bytes: Vec<u8>,
}

impl TokenStatusList {
    /// An all-`VALID` list of at least `entries` entries, each `bits` wide.
    pub fn new(bits: u8, entries: usize) -> Result<Self> {
        check_bits(bits)?;
        let per_byte = usize::from(8 / bits);
        Ok(Self {
            bits,
            bytes: vec![0; entries.div_ceil(per_byte)],
        })
    }

    /// Bits per entry.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// The number of entries the list holds — every entry its bytes encode.
    pub fn len(&self) -> usize {
        self.bytes.len() * usize::from(8 / self.bits)
    }

    /// Whether the list holds no entries.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The uncompressed byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The status at `index`. An index past the end is an error: no statement
    /// about that token's status can be made (§8.3).
    pub fn get(&self, index: usize) -> Result<TokenStatus> {
        let (byte, shift) = self.position(index)?;
        Ok(TokenStatus::from_value(
            (self.bytes[byte] >> shift) & self.mask(),
        ))
    }

    /// Set the status at `index`. A status whose value does not fit in `bits`
    /// is refused rather than truncated.
    pub fn set(&mut self, index: usize, status: TokenStatus) -> Result<()> {
        let value = status.value();
        if value > self.mask() {
            return Err(StatusListError::Invalid(format!(
                "status value {value:#04x} does not fit in {} bits",
                self.bits
            )));
        }
        let (byte, shift) = self.position(index)?;
        self.bytes[byte] = (self.bytes[byte] & !(self.mask() << shift)) | (value << shift);
        Ok(())
    }

    /// Compress and encode the list for a `status_list` claim.
    pub fn encode(&self) -> Result<EncodedStatusList> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&self.bytes)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        Ok(EncodedStatusList {
            bits: self.bits,
            lst: URL_SAFE_NO_PAD.encode(compressed),
            aggregation_uri: None,
        })
    }

    /// Decode a `status_list` claim, inflating at most
    /// [`DEFAULT_MAX_LIST_BYTES`].
    pub fn decode(encoded: &EncodedStatusList) -> Result<Self> {
        Self::decode_with_limit(encoded, DEFAULT_MAX_LIST_BYTES)
    }

    /// Decode a `status_list` claim, refusing one that inflates past
    /// `max_bytes`.
    pub fn decode_with_limit(encoded: &EncodedStatusList, max_bytes: usize) -> Result<Self> {
        check_bits(encoded.bits)?;
        let compressed = URL_SAFE_NO_PAD
            .decode(&encoded.lst)
            .map_err(|e| StatusListError::Encoding(e.to_string()))?;
        let limit = (max_bytes as u64).saturating_add(1);
        let mut bytes = Vec::new();
        ZlibDecoder::new(&compressed[..])
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        if bytes.len() > max_bytes {
            return Err(StatusListError::Invalid(format!(
                "status list inflates past the {max_bytes}-byte limit"
            )));
        }
        if bytes.is_empty() {
            return Err(StatusListError::Invalid("status list is empty".into()));
        }
        Ok(Self {
            bits: encoded.bits,
            bytes,
        })
    }

    fn mask(&self) -> u8 {
        ((1u16 << self.bits) - 1) as u8
    }

    fn position(&self, index: usize) -> Result<(usize, u8)> {
        let per_byte = usize::from(8 / self.bits);
        let byte = index / per_byte;
        if byte >= self.bytes.len() {
            return Err(StatusListError::IndexOutOfBounds {
                index,
                size: self.len(),
            });
        }
        Ok((byte, (index % per_byte) as u8 * self.bits))
    }
}

fn check_bits(bits: u8) -> Result<()> {
    match bits {
        1 | 2 | 4 | 8 => Ok(()),
        other => Err(StatusListError::Invalid(format!(
            "bits must be 1, 2, 4 or 8, not {other}"
        ))),
    }
}

/// A Referenced Token's `status.status_list` entry: which list, and where in it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StatusListReference {
    /// The entry's index in the list.
    pub idx: u64,
    /// The URI the Status List Token is served from — and its `sub`.
    pub uri: String,
}

impl StatusListReference {
    /// Read `status.status_list` from a Referenced Token's verified claims.
    ///
    /// `Ok(None)` when the token carries no `status_list` (it is not tracked by
    /// this mechanism); an error when one is present but malformed — a
    /// non-integer or negative `idx`, or a missing or empty `uri`.
    pub fn from_claims(claims: &Value) -> Result<Option<Self>> {
        let Some(entry) = claims.get("status").and_then(|s| s.get("status_list")) else {
            return Ok(None);
        };
        let idx = entry.get("idx").and_then(Value::as_u64).ok_or_else(|| {
            StatusListError::Invalid("status_list.idx must be a non-negative integer".into())
        })?;
        let uri = entry
            .get("uri")
            .and_then(Value::as_str)
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| StatusListError::Invalid("status_list.uri is missing".into()))?;
        Ok(Some(Self {
            idx,
            uri: uri.to_string(),
        }))
    }

    /// The claim a Referenced Token carries for this entry:
    /// `{ "status_list": { "idx", "uri" } }`, the value of `status`.
    pub fn to_status_claim(&self) -> Value {
        json!({ "status_list": { "idx": self.idx, "uri": self.uri } })
    }
}

/// How a Status List Token is checked beyond its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// The current time, in Unix seconds.
    pub now_unix: i64,
    /// Clock leeway, in seconds, for `iat` in the future and `exp` passed.
    pub leeway_secs: i64,
    /// The cap on the decompressed list.
    pub max_list_bytes: usize,
}

impl VerifyOptions {
    /// The defaults at `now_unix`: [`DEFAULT_LEEWAY_SECS`] and
    /// [`DEFAULT_MAX_LIST_BYTES`].
    pub fn at(now_unix: i64) -> Self {
        Self {
            now_unix,
            leeway_secs: DEFAULT_LEEWAY_SECS,
            max_list_bytes: DEFAULT_MAX_LIST_BYTES,
        }
    }
}

/// A Status List Token whose signature, type, subject and validity period have
/// been checked, and whose list has been decoded. Constructed only by
/// [`Self::verify`].
#[derive(Debug, Clone)]
pub struct VerifiedStatusListToken {
    header: Value,
    payload: Value,
    sub: String,
    iat: i64,
    exp: Option<i64>,
    ttl: Option<u64>,
    list: TokenStatusList,
}

impl VerifiedStatusListToken {
    /// Verify a compact `statuslist+jwt` served for `reference`.
    ///
    /// `verify_signature` receives the compact JWT and its (not yet trusted)
    /// header — for selecting a key by `kid`, `x5c` and the like — and must
    /// return the payload **only after** verifying the signature over it. Its
    /// error is surfaced as [`StatusListError::Signature`]. Nothing in the
    /// payload is read before it returns.
    ///
    /// Then, in order: `typ` is `statuslist+jwt`; `sub` equals
    /// `reference.uri`; `iat` is present and not in the future; `exp`, when
    /// present, has not passed; the list decodes within
    /// `options.max_list_bytes`. The entry at `reference.idx` is not read here:
    /// ask [`Self::status_of`].
    pub fn verify<F, E>(
        jwt: &str,
        reference: &StatusListReference,
        options: &VerifyOptions,
        verify_signature: F,
    ) -> Result<Self>
    where
        F: FnOnce(&str, &Value) -> std::result::Result<Value, E>,
        E: std::fmt::Display,
    {
        let mut segments = jwt.split('.');
        let (Some(header_b64), Some(_), Some(_), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(StatusListError::Token(
                "not a compact JWS (three dot-separated segments)".into(),
            ));
        };
        let header: Value = URL_SAFE_NO_PAD
            .decode(header_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(Value::is_object)
            .ok_or_else(|| StatusListError::Token("header is not a JSON object".into()))?;

        let payload = verify_signature(jwt, &header)
            .map_err(|e| StatusListError::Signature(e.to_string()))?;

        if !typ_is_status_list(header.get("typ")) {
            return Err(StatusListError::Token(format!(
                "typ is not `{STATUS_LIST_JWT_TYP}`"
            )));
        }

        let sub = payload
            .get("sub")
            .and_then(Value::as_str)
            .ok_or_else(|| StatusListError::Token("`sub` is missing".into()))?;
        if sub != reference.uri {
            return Err(StatusListError::Token(format!(
                "`sub` ({sub}) is not the referenced uri ({})",
                reference.uri
            )));
        }

        let iat = payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| StatusListError::Token("`iat` is missing".into()))?;
        if iat > options.now_unix.saturating_add(options.leeway_secs) {
            return Err(StatusListError::Token(format!(
                "`iat` ({iat}) is in the future"
            )));
        }
        let exp = match payload.get("exp") {
            None => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .ok_or_else(|| StatusListError::Token("`exp` is not an integer".into()))?,
            ),
        };
        if let Some(exp) = exp
            && options.now_unix >= exp.saturating_add(options.leeway_secs)
        {
            return Err(StatusListError::Expired {
                exp,
                now: options.now_unix,
            });
        }
        let ttl = match payload.get("ttl") {
            None => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                StatusListError::Token("`ttl` is not a non-negative integer".into())
            })?),
        };

        let encoded: EncodedStatusList = serde_json::from_value(
            payload
                .get("status_list")
                .cloned()
                .ok_or_else(|| StatusListError::Token("`status_list` is missing".into()))?,
        )?;
        let list = TokenStatusList::decode_with_limit(&encoded, options.max_list_bytes)?;

        Ok(Self {
            sub: sub.to_string(),
            header,
            payload,
            iat,
            exp,
            ttl,
            list,
        })
    }

    /// The status of the referenced entry. An index past the end of the list
    /// is an error, never a default.
    pub fn status_of(&self, reference: &StatusListReference) -> Result<TokenStatus> {
        if reference.uri != self.sub {
            return Err(StatusListError::Token(format!(
                "this token is the list at {}, not {}",
                self.sub, reference.uri
            )));
        }
        let index =
            usize::try_from(reference.idx).map_err(|_| StatusListError::IndexOutOfBounds {
                index: usize::MAX,
                size: self.list.len(),
            })?;
        self.list.get(index)
    }

    /// The verified header — `kid`, `x5c` and so on, for binding the signer to
    /// the Referenced Token's issuer.
    pub fn header(&self) -> &Value {
        &self.header
    }

    /// The verified payload.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// `iss`, when the token carries one.
    pub fn issuer(&self) -> Option<&str> {
        self.payload.get("iss").and_then(Value::as_str)
    }

    /// `sub` — the URI this list is served from.
    pub fn subject(&self) -> &str {
        &self.sub
    }

    /// `iat`, in Unix seconds.
    pub fn issued_at(&self) -> i64 {
        self.iat
    }

    /// `exp`, in Unix seconds, when present.
    pub fn expires_at(&self) -> Option<i64> {
        self.exp
    }

    /// `ttl`, in seconds: how long the token may be cached, when present.
    pub fn ttl(&self) -> Option<u64> {
        self.ttl
    }

    /// The decoded list.
    pub fn list(&self) -> &TokenStatusList {
        &self.list
    }
}

/// `typ` as RFC 7515 §4.1.9 compares it: case-insensitive, with the
/// `application/` prefix optional.
fn typ_is_status_list(typ: Option<&Value>) -> bool {
    let Some(typ) = typ.and_then(Value::as_str) else {
        return false;
    };
    let typ = typ.to_ascii_lowercase();
    typ == STATUS_LIST_JWT_TYP || typ == STATUS_LIST_JWT_MEDIA_TYPE
}

/// The payload of a Status List Token for `list`, served at `sub` — for a
/// Status Issuer to sign with `typ: statuslist+jwt`.
pub fn status_list_token_payload(
    sub: &str,
    iat: i64,
    exp: Option<i64>,
    ttl: Option<u64>,
    list: &TokenStatusList,
) -> Result<Value> {
    let mut payload = json!({
        "sub": sub,
        "iat": iat,
        "status_list": list.encode()?,
    });
    if let Some(exp) = exp {
        payload["exp"] = json!(exp);
    }
    if let Some(ttl) = ttl {
        payload["ttl"] = json!(ttl);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "https://issuer.example/statuslists/1";

    fn reference(idx: u64) -> StatusListReference {
        StatusListReference {
            idx,
            uri: URI.to_string(),
        }
    }

    /// A compact JWT whose "signature" is the literal `sig`; the test verifier
    /// accepts exactly that.
    fn jwt(header: &Value, payload: &Value) -> String {
        let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
        format!("{}.{}.sig", encode(header), encode(payload))
    }

    fn accept(jwt: &str, _header: &Value) -> std::result::Result<Value, String> {
        let mut segments = jwt.split('.');
        let payload = segments.nth(1).unwrap();
        if segments.next() != Some("sig") {
            return Err("bad signature".into());
        }
        Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap())
    }

    fn header() -> Value {
        json!({ "alg": "ES256", "typ": "statuslist+jwt", "kid": "did:web:issuer.example#k1" })
    }

    fn token_for(list: &TokenStatusList, exp: Option<i64>) -> String {
        jwt(
            &header(),
            &status_list_token_payload(URI, 1_000, exp, Some(300), list).unwrap(),
        )
    }

    /// §4.1, `bits` = 1: statuses 0–15 are bytes `0xB9 0xA3`.
    #[test]
    fn decodes_the_one_bit_example() {
        let list = TokenStatusList::decode(&EncodedStatusList {
            bits: 1,
            lst: "eNrbuRgAAhcBXQ".into(),
            aggregation_uri: None,
        })
        .unwrap();
        assert_eq!(list.as_bytes(), [0xB9, 0xA3]);
        let statuses: Vec<u8> = (0..16).map(|i| list.get(i).unwrap().value()).collect();
        assert_eq!(statuses, [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]);
    }

    /// §4.1, `bits` = 2: statuses 0–11 are bytes `0xC9 0x44 0xF9`.
    #[test]
    fn decodes_the_two_bit_example() {
        let list = TokenStatusList::decode(&EncodedStatusList {
            bits: 2,
            lst: "eNo76fITAAPfAgc".into(),
            aggregation_uri: None,
        })
        .unwrap();
        assert_eq!(list.as_bytes(), [0xC9, 0x44, 0xF9]);
        let statuses: Vec<u8> = (0..12).map(|i| list.get(i).unwrap().value()).collect();
        assert_eq!(statuses, [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3]);
        assert_eq!(list.get(3).unwrap(), TokenStatus::ApplicationSpecific(3));
    }

    #[test]
    fn every_width_round_trips_without_disturbing_neighbours() {
        for bits in [1u8, 2, 4, 8] {
            let mut list = TokenStatusList::new(bits, 100).unwrap();
            let value_at = |index: usize| (index as u16 % (1u16 << bits)) as u8;
            for index in (0..100).step_by(3) {
                list.set(index, TokenStatus::from_value(value_at(index)))
                    .unwrap();
            }
            let decoded = TokenStatusList::decode(&list.encode().unwrap()).unwrap();
            assert_eq!(decoded, list, "bits = {bits}");
            for index in 0..100 {
                let expected = if index % 3 == 0 { value_at(index) } else { 0 };
                assert_eq!(decoded.get(index).unwrap().value(), expected);
            }
        }
    }

    #[test]
    fn a_status_too_wide_for_the_list_is_refused() {
        let mut list = TokenStatusList::new(1, 8).unwrap();
        assert!(list.set(0, TokenStatus::Suspended).is_err());
        assert_eq!(list.get(0).unwrap(), TokenStatus::Valid);
    }

    #[test]
    fn widths_other_than_1_2_4_8_are_refused() {
        assert!(TokenStatusList::new(3, 8).is_err());
        let encoded = EncodedStatusList {
            bits: 0,
            lst: TokenStatusList::new(1, 8).unwrap().encode().unwrap().lst,
            aggregation_uri: None,
        };
        assert!(TokenStatusList::decode(&encoded).is_err());
    }

    #[test]
    fn an_index_past_the_end_is_an_error() {
        let list = TokenStatusList::new(1, 16).unwrap();
        assert!(matches!(
            list.get(16),
            Err(StatusListError::IndexOutOfBounds {
                index: 16,
                size: 16
            })
        ));
    }

    #[test]
    fn a_list_inflating_past_the_limit_is_refused() {
        let encoded = TokenStatusList::new(8, 1 << 20).unwrap().encode().unwrap();
        assert!(
            encoded.lst.len() < 2_000,
            "a megabyte of zeros compresses small"
        );
        let err = TokenStatusList::decode_with_limit(&encoded, 4_096).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn status_values_map_to_the_registry() {
        assert_eq!(TokenStatus::from_value(0), TokenStatus::Valid);
        assert_eq!(TokenStatus::from_value(1), TokenStatus::Invalid);
        assert_eq!(TokenStatus::from_value(2), TokenStatus::Suspended);
        assert_eq!(
            TokenStatus::from_value(0x0D),
            TokenStatus::ApplicationSpecific(0x0D)
        );
        assert_eq!(TokenStatus::from_value(0x04), TokenStatus::Reserved(0x04));
        assert_eq!(TokenStatus::from_value(0xFF).value(), 0xFF);
    }

    #[test]
    fn references_are_read_strictly() {
        let claims = json!({ "status": { "status_list": { "idx": 7, "uri": URI } } });
        assert_eq!(
            StatusListReference::from_claims(&claims).unwrap(),
            Some(reference(7))
        );
        assert_eq!(
            reference(7).to_status_claim(),
            claims["status"],
            "round trip"
        );
        assert_eq!(
            StatusListReference::from_claims(&json!({ "iss": "x" })).unwrap(),
            None
        );
        for bad in [
            json!({ "status": { "status_list": { "idx": -1, "uri": URI } } }),
            json!({ "status": { "status_list": { "idx": "7", "uri": URI } } }),
            json!({ "status": { "status_list": { "idx": 1.5, "uri": URI } } }),
            json!({ "status": { "status_list": { "idx": 7 } } }),
            json!({ "status": { "status_list": { "idx": 7, "uri": "" } } }),
        ] {
            assert!(StatusListReference::from_claims(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_verified_token_answers_for_its_entries() {
        let mut list = TokenStatusList::new(2, 64).unwrap();
        list.set(7, TokenStatus::Invalid).unwrap();
        list.set(8, TokenStatus::Suspended).unwrap();
        let token = VerifiedStatusListToken::verify(
            &token_for(&list, Some(2_000)),
            &reference(7),
            &VerifyOptions::at(1_500),
            accept,
        )
        .unwrap();
        assert_eq!(
            token.status_of(&reference(7)).unwrap(),
            TokenStatus::Invalid
        );
        assert_eq!(
            token.status_of(&reference(8)).unwrap(),
            TokenStatus::Suspended
        );
        assert_eq!(token.status_of(&reference(9)).unwrap(), TokenStatus::Valid);
        assert!(token.status_of(&reference(64)).is_err());
        assert_eq!(token.ttl(), Some(300));
        assert_eq!(token.header()["kid"], "did:web:issuer.example#k1");

        let other = StatusListReference {
            idx: 7,
            uri: "https://issuer.example/statuslists/2".into(),
        };
        assert!(token.status_of(&other).is_err());
    }

    /// The signature is checked first: a token that fails it is refused as a
    /// signature failure even when its list is garbage, so nothing unverified
    /// is ever decompressed.
    #[test]
    fn the_signature_is_checked_before_the_payload_is_read() {
        let payload =
            json!({ "sub": URI, "iat": 1_000, "status_list": { "bits": 9, "lst": "!!" } });
        let forged = jwt(&header(), &payload).replace(".sig", ".forged");
        let err = VerifiedStatusListToken::verify(
            &forged,
            &reference(0),
            &VerifyOptions::at(1_500),
            accept,
        )
        .unwrap_err();
        assert!(matches!(err, StatusListError::Signature(_)), "{err}");
    }

    #[test]
    fn the_claims_are_checked() {
        let list = TokenStatusList::new(1, 8).unwrap();
        let verify = |token: &str, now: i64| {
            VerifiedStatusListToken::verify(token, &reference(0), &VerifyOptions::at(now), accept)
        };

        let wrong_typ = jwt(
            &json!({ "alg": "ES256", "typ": "JWT" }),
            &status_list_token_payload(URI, 1_000, None, None, &list).unwrap(),
        );
        assert!(
            verify(&wrong_typ, 1_500)
                .unwrap_err()
                .to_string()
                .contains("typ")
        );

        let media_typ = jwt(
            &json!({ "alg": "ES256", "typ": "Application/StatusList+JWT" }),
            &status_list_token_payload(URI, 1_000, None, None, &list).unwrap(),
        );
        verify(&media_typ, 1_500).expect("typ compares as RFC 7515 says");

        let other_sub = jwt(
            &header(),
            &status_list_token_payload("https://evil.example/sl", 1_000, None, None, &list)
                .unwrap(),
        );
        assert!(
            verify(&other_sub, 1_500)
                .unwrap_err()
                .to_string()
                .contains("sub")
        );

        let expired = token_for(&list, Some(2_000));
        assert!(matches!(
            verify(&expired, 2_100),
            Err(StatusListError::Expired {
                exp: 2_000,
                now: 2_100
            })
        ));
        verify(&expired, 2_030).expect("inside the leeway");

        assert!(
            verify(&token_for(&list, None), 500)
                .unwrap_err()
                .to_string()
                .contains("future")
        );

        let no_iat = jwt(
            &header(),
            &json!({ "sub": URI, "status_list": list.encode().unwrap() }),
        );
        assert!(
            verify(&no_iat, 1_500)
                .unwrap_err()
                .to_string()
                .contains("iat")
        );

        let no_list = jwt(&header(), &json!({ "sub": URI, "iat": 1_000 }));
        assert!(
            verify(&no_list, 1_500)
                .unwrap_err()
                .to_string()
                .contains("status_list")
        );
    }

    #[test]
    fn the_list_cap_applies_to_tokens() {
        let list = TokenStatusList::new(8, 1 << 16).unwrap();
        let mut options = VerifyOptions::at(1_500);
        options.max_list_bytes = 1_024;
        let err = VerifiedStatusListToken::verify(
            &token_for(&list, None),
            &reference(0),
            &options,
            accept,
        )
        .unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }
}
