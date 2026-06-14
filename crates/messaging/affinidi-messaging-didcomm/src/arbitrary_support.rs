//! `arbitrary::Arbitrary` impls for the DIDComm wire types (issue #477).
//!
//! Enables **structure-aware** coverage-guided fuzzing: a libFuzzer harness
//! turns raw bytes into well-formed-ish [`Message`] / [`Attachment`] values
//! rather than mutating bytes blindly, which reaches far more of the parser /
//! handler surface than byte mutation alone.
//!
//! Gated behind the off-by-default `arbitrary` feature — it adds no runtime
//! behaviour and is only pulled into a fuzz harness or dev build.
//!
//! The `body`/`extra`/attachment-`json` fields are `serde_json::Value`, for
//! which `arbitrary` ships no upstream impl, so these impls are hand-written
//! around a **depth- and width-bounded** JSON generator ([`arbitrary_json`]).
//! The bound is the whole point: an unbounded generator would have the fuzzer
//! building pathologically deep / huge JSON and exercising the allocator
//! instead of the parser.

use std::collections::HashMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use serde_json::{Map, Number, Value};

use crate::message::{Attachment, AttachmentData, Message};

/// Max nesting depth of a generated JSON value. Past this depth only leaves are
/// produced, so recursion always terminates.
const MAX_JSON_DEPTH: usize = 4;
/// Max children per generated array / object level (and per `extra` map).
const MAX_JSON_WIDTH: usize = 4;

/// Generate a depth-bounded arbitrary [`Value`]. At `depth == 0` only scalar
/// leaves are produced; otherwise arrays/objects may appear, recursing with
/// `depth - 1` and at most [`MAX_JSON_WIDTH`] children.
fn arbitrary_json(u: &mut Unstructured<'_>, depth: usize) -> Result<Value> {
    // 4 leaf shapes always; add array + object only while we still have depth.
    let variants: u32 = if depth == 0 { 4 } else { 6 };
    Ok(match u.int_in_range(0..=variants - 1)? {
        0 => Value::Null,
        1 => Value::Bool(bool::arbitrary(u)?),
        // i64 → Number is always finite/valid (unlike an arbitrary f64, which
        // could be NaN/Inf and is not representable as a JSON number).
        2 => Value::Number(Number::from(i64::arbitrary(u)?)),
        3 => Value::String(String::arbitrary(u)?),
        4 => {
            let len = u.int_in_range(0..=MAX_JSON_WIDTH)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(arbitrary_json(u, depth - 1)?);
            }
            Value::Array(arr)
        }
        _ => Value::Object(arbitrary_json_map(u, depth - 1)?),
    })
}

/// Generate a bounded JSON object: up to [`MAX_JSON_WIDTH`] `String → Value`
/// entries, each value generated at `depth`.
fn arbitrary_json_map(u: &mut Unstructured<'_>, depth: usize) -> Result<Map<String, Value>> {
    let len = u.int_in_range(0..=MAX_JSON_WIDTH)?;
    let mut map = Map::new();
    for _ in 0..len {
        map.insert(String::arbitrary(u)?, arbitrary_json(u, depth)?);
    }
    Ok(map)
}

impl<'a> Arbitrary<'a> for Message {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // `extra` is the `#[serde(flatten)]` catch-all; bound it like any object.
        let extra_len = u.int_in_range(0..=MAX_JSON_WIDTH)?;
        let mut extra: HashMap<String, Value> = HashMap::new();
        for _ in 0..extra_len {
            extra.insert(String::arbitrary(u)?, arbitrary_json(u, MAX_JSON_DEPTH)?);
        }

        Ok(Message {
            id: String::arbitrary(u)?,
            typ: String::arbitrary(u)?,
            from: Option::arbitrary(u)?,
            to: Option::arbitrary(u)?,
            body: arbitrary_json(u, MAX_JSON_DEPTH)?,
            thid: Option::arbitrary(u)?,
            pthid: Option::arbitrary(u)?,
            created_time: Option::arbitrary(u)?,
            expires_time: Option::arbitrary(u)?,
            attachments: Option::arbitrary(u)?,
            extra,
        })
    }
}

impl<'a> Arbitrary<'a> for Attachment {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Attachment {
            id: Option::arbitrary(u)?,
            description: Option::arbitrary(u)?,
            filename: Option::arbitrary(u)?,
            media_type: Option::arbitrary(u)?,
            format: Option::arbitrary(u)?,
            lastmod_time: Option::arbitrary(u)?,
            byte_count: Option::arbitrary(u)?,
            data: AttachmentData::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for AttachmentData {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // `json` is a Value; gate it on a bool so "no json" is reachable, then
        // generate a bounded value when present.
        let json = if bool::arbitrary(u)? {
            Some(arbitrary_json(u, MAX_JSON_DEPTH)?)
        } else {
            None
        };
        Ok(AttachmentData {
            json,
            base64: Option::arbitrary(u)?,
            links: Option::arbitrary(u)?,
            hash: Option::arbitrary(u)?,
            jws: Option::arbitrary(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Driving the impls over a block of bytes must never panic, and every
    /// generated `Message` must serialize to JSON that the real parser accepts.
    /// That — not struct identity — is the contract a fuzz harness relies on.
    ///
    /// (Round-trip is intentionally *not* asserted lossless: `extra` is a
    /// `#[serde(flatten)]` catch-all, so a generated `extra` key that collides
    /// with a reserved field name like `id`/`type` deserializes back into the
    /// named field, not `extra`. Fine for fuzzing — the harness feeds the
    /// serialized bytes to the parser, it doesn't compare structs.)
    #[test]
    fn generated_messages_serialize_to_parseable_json() {
        // A few fixed byte patterns — deterministic, no RNG. Each seeds a
        // different walk through the generator.
        for pattern in [0x00u8, 0x5A, 0xA5, 0xFF] {
            let data = vec![pattern; 512];
            let mut u = Unstructured::new(&data);
            let msg = Message::arbitrary(&mut u).expect("generation should not fail");

            let json = msg.to_json().expect("generated message should serialize");
            Message::from_json(&json).expect("serialized generated message should re-parse");
        }
    }

    #[test]
    fn json_depth_is_bounded() {
        fn depth(v: &Value) -> usize {
            match v {
                Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
                Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
                _ => 0,
            }
        }
        // Lots of structure-biased bytes; depth must still respect the cap.
        let data = vec![0xF4u8; 4096];
        let mut u = Unstructured::new(&data);
        let v = arbitrary_json(&mut u, MAX_JSON_DEPTH).unwrap();
        assert!(
            depth(&v) <= MAX_JSON_DEPTH,
            "depth {} exceeded cap",
            depth(&v)
        );
    }
}
