use base64::prelude::*;
use serde_json::{Map, Value};

pub const ALICE_DID: &str = "did:key:alice";
pub const BOB_DID: &str = "did:key:z6Mki7K3d9U5tH6P8x9g93Dh7LZ6HF1JSF3ECoZZ2PgtMoxH";
pub const CHARLIE_DID: &str = "did:key:z6MkhKzjHrZKpxHqmW9x1BVxgKZ9n7N1WXE3jTtJC26PYASp";

#[allow(dead_code)]
pub fn update_field(msg: &str, field: &str, value: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();
    msg_dict.insert(String::from(field), value.into());
    serde_json::to_string(&msg_dict).unwrap()
}

#[allow(dead_code)]
pub fn remove_field(msg: &str, field: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();
    msg_dict.remove(field);
    serde_json::to_string(&msg_dict).unwrap()
}

#[allow(dead_code)]
pub fn update_protected_field(msg: &str, field: &str, value: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();

    let mut buffer = Vec::<u8>::new();
    BASE64_URL_SAFE_NO_PAD
        .decode_vec(
            msg_dict.get("protected").unwrap().as_str().unwrap(),
            &mut buffer,
        )
        .unwrap();
    let parsed_protected: Value = serde_json::from_slice(&buffer).unwrap();
    let mut protected_dict: Map<String, Value> = parsed_protected.as_object().unwrap().clone();
    protected_dict.insert(String::from(field), value.into());
    let protected_str = serde_json::to_string(&protected_dict).unwrap();
    println!("{}", &protected_str);
    let protected_str_base64 = BASE64_URL_SAFE_NO_PAD.encode(protected_str);
    msg_dict.insert(String::from("protected"), protected_str_base64.into());
    serde_json::to_string(&msg_dict).unwrap()
}

#[allow(dead_code)]
pub fn remove_protected_field(msg: &str, field: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();

    let mut buffer = Vec::<u8>::new();
    BASE64_URL_SAFE_NO_PAD
        .decode_vec(
            msg_dict.get("protected").unwrap().as_str().unwrap(),
            &mut buffer,
        )
        .unwrap();
    let parsed_protected: Value = serde_json::from_slice(&buffer).unwrap();
    let mut protected_dict: Map<String, Value> = parsed_protected.as_object().unwrap().clone();
    protected_dict.remove(field);
    let protected_str = serde_json::to_string(&protected_dict).unwrap();
    let protected_str_base64 = BASE64_URL_SAFE_NO_PAD.encode(protected_str);

    msg_dict.insert(String::from("protected"), protected_str_base64.into());
    serde_json::to_string(&msg_dict).unwrap()
}
