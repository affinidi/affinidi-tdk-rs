use lazy_static::lazy_static;
use serde_json::{Value, json};

#[allow(dead_code)]
pub const ALICE_DID: &str = "did:peer:2.Vz6MkgWJfVmPELozq6aCycK3CpxHN8Upphn3WSuQkWY6iqsjF.EzQ3shfb7vwQaTJqFkt8nRfo7Nu98tmeYpdDfWgrqQitDaqXRz";
#[allow(dead_code)]
pub const MEDIATOR_API: &str = "http://localhost:7037/mediator/v1";
#[allow(dead_code)]
pub const BOB_DID: &str = "did:peer:2.Vz6Mkihn2R3M8nY62EFJ7MAVXu7YxsTnuS5iAhmn3qKJbkdFf.EzQ3shpZRBUtewwzYiueXgDqs1bvGNkSyGoRgsbZJXt3TTb9jD.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ";
#[allow(dead_code)]
pub const SECRETS_PATH: &str = "../affinidi-messaging-mediator/conf/secrets.json";
#[allow(dead_code)]
pub const CONFIG_PATH: &str = "../affinidi-messaging-mediator/conf/mediator.toml";

lazy_static! {
// Signing and verification key
pub static ref ALICE_V1: Value = json!({
    "crv": "Ed25519",
    "d": "LLWCf83n8VsUYq31zlZRe0NNMCcn1N4Dh85dGpIqSFw",
    "kty": "OKP",
    "x": "Hn8T4ZjjT0oJ6rjhqox8AykwC3GDFsJF6KkaYZExwQo"
});

// Encryption key
pub static ref ALICE_E1: Value = json!({
  "crv": "secp256k1",
  "d": "oi-dXG4EqfNODFPjv2vkieoLdbQZH9k6dwPDV8HDoms",
  "kty": "EC",
  "x": "DhfaXbhwo0KkOiyA5V1K1RZx6Ikr86h_lX5GOwxjmjE",
  "y": "PpYqybOwMsm64vftt-7gBCQPIUbglMmyy_6rloSSAPk"
});

pub static ref BOB_V1: Value = json!({
    "crv": "Ed25519",
    "d": "FZMJijqdcp7PCQShgtFj6Ud3vjZY7jFZBVvahziaMMM",
    "kty": "OKP",
    "x": "PybG95kyeSfGRebp4T7hzA7JQuysc6mZ97nM2ety6Vo"
});

pub static ref BOB_E1: Value = json!({
    "crv": "secp256k1",
    "d": "ai7B5fgT3pCBHec0I4Y1xXpSyrEHlTy0hivSlddWHZE",
    "kty": "EC",
    "x": "k2FhEi8WMxr4Ztr4u2xjKzDESqVnGg_WKrN1820wPeA",
    "y": "fq0DnZ_duPWyeFK0k93bAzjNJVVHEjHFRlGOJXKDS18"
});

}
