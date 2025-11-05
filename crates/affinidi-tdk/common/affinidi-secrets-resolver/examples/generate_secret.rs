/*!
*   Utility that generates a new random secret and prints it out to STDOUT in various formats.
*/

use affinidi_secrets_resolver::secrets::Secret;
use clap::{Parser, ValueEnum};

/// CLI Arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None,arg_required_else_help(true))]
struct Args {
    /// Crypto Algorithm to use
    #[arg(value_enum, short, long, required = true)]
    crypto: CryptoAlgos,

    /// Key ID Value (random if not provided)
    #[arg(short, long)]
    id: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum CryptoAlgos {
    /// 25519 Edwards Curve
    Ed25519,

    /// 25519 Montgomery Curve
    X25519,

    /// P256 NIST Curve (secp256r1)
    P256,

    /// P384 NIST Curve
    P384,

    /// Secp256k1 Curve
    Secp256k1,
}

fn main() {
    let args = Args::parse();

    let secret = match args.crypto {
        CryptoAlgos::Ed25519 => Secret::generate_ed25519(args.id.as_deref(), None),
        CryptoAlgos::X25519 => Secret::generate_x25519(args.id.as_deref(), None).unwrap(),
        CryptoAlgos::P256 => Secret::generate_p256(args.id.as_deref(), None).unwrap(),
        CryptoAlgos::P384 => Secret::generate_p384(args.id.as_deref(), None).unwrap(),
        CryptoAlgos::Secp256k1 => Secret::generate_secp256k1(args.id.as_deref(), None).unwrap(),
    };

    println!("JWK: Private");
    println!("============");
    println!("{}", serde_json::to_string_pretty(&secret).unwrap());

    println!();
    println!(
        "Private Key multi-base-encoded : {}",
        secret.get_private_keymultibase().unwrap()
    );
    println!(
        "Public Key multi-base-encoded  : {}",
        secret.get_public_keymultibase().unwrap()
    );
}
