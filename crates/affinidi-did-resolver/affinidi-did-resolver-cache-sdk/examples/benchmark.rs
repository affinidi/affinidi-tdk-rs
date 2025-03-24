//! Runs a series of performance benchmarks against the DID cache.
//! Benchmark references: (Apple M1 Max)
//! - 1 million did:key's generated in ~4.2 seconds, consumes 2.3MiB of memory
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
};
use clap::Parser;
use futures_util::future::join_all;
use num_format::{Locale, ToFormattedString};
use number_prefix::NumberPrefix;
use rand::Rng;
use rayon::prelude::*;
use ssi::prelude::DIDResolver;
use ssi::{
    JWK,
    dids::{DID, DIDKey},
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// network address if running in network mode (ws://127.0.0.1:8080/did/v1/ws)
    #[arg(short, long)]
    network_address: Option<String>,
    /// Number of keys to generate
    #[arg(short, long)]
    generate_count: u32,
    /// Number of DIDs to resolve
    #[arg(short, long)]
    resolve_count: u32,
}

#[tokio::main]
async fn main() -> Result<(), DIDCacheError> {
    // **************************************************************
    // *** Initial setup
    // **************************************************************
    let args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    #[allow(unused_mut)]
    let mut cache_config = DIDCacheConfigBuilder::default();
    if let Some(_address) = &args.network_address {
        #[cfg(feature = "network")]
        {
            println!("Running in network mode with address: {}", _address);
            cache_config = cache_config.with_network_mode(_address);
        }
        #[cfg(not(feature = "network"))]
        panic!(
            "Network mode is not enabled in this build. Enable feature `network` to use network mode."
        );
    } else {
        println!("Running in local mode.");
    }

    let cache = DIDCacheClient::new(cache_config.build()).await?;
    println!("Cache initialized...");

    // **************************************************************
    // *** Generate DIDs
    // **************************************************************

    settle_down(5).await;

    println!(
        "Generating ({}) keys...",
        args.generate_count.to_formatted_string(&Locale::en)
    );
    let dids = generate_dids(args.generate_count).await;
    let dids_arc = Arc::new(dids.clone());

    // **************************************************************
    // *** Resolve DIDs - NO CACHE
    // **************************************************************

    settle_down(5).await;

    resolve_dids_no_cache(dids_arc.clone(), args.resolve_count).await?;

    // **************************************************************
    // *** Resolve DIDs - CACHE
    // **************************************************************

    settle_down(5).await;

    resolve_dids(&cache, dids_arc.clone(), args.resolve_count).await?;

    // **************************************************************
    // *** Resolve DIDs - CACHE - 2nd run (now has local cache)
    // **************************************************************

    settle_down(5).await;

    resolve_dids(&cache, dids_arc.clone(), args.resolve_count).await?;

    Ok(())
}

/// Goes to sleep to let system settle down before/after a benchmark test
async fn settle_down(secs: u64) {
    println!();
    println!("Sleeping for 5 seconds to let the system settle down...");
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// Pretty print a float number (1,000.24)
/// Adds comma's and rounds to 2 decimal places
fn pretty_print_float(f: f64) -> String {
    let a = f as u64;
    let b = (f.fract() * 100.0) as u32;
    format!("{}.{}", a.to_formatted_string(&Locale::en), b)
}

/// Pretty print a binary size (1.2 KiB)
fn pretty_print_binary_size(n: f64) -> String {
    match NumberPrefix::binary(n) {
        NumberPrefix::Standalone(bytes) => {
            format!("{} bytes", bytes)
        }
        NumberPrefix::Prefixed(prefix, n) => {
            format!("{:.1} {}B", n, prefix)
        }
    }
}

/// Generates a set of keys for testing purposes, can do in parallel
/// count: number of keys to generate
async fn generate_dids(count: u32) -> Vec<String> {
    let _start = std::time::Instant::now();
    let dids: Vec<String> = (0..count)
        .into_par_iter()
        .map(|x| {
            let key = if x % 2 == 0 {
                JWK::generate_ed25519().unwrap()
            } else {
                JWK::generate_secp256k1()
            };

            DIDKey::generate(&key).unwrap().to_string()
        })
        .collect();

    let elapsed = _start.elapsed();
    let per_second = count as f64 / elapsed.as_secs_f64();
    println!(
        "Generated {} did:key's in {} seconds :: {} keys/second :: Memory used: {}",
        count,
        pretty_print_float(_start.elapsed().as_secs_f64()),
        pretty_print_float(per_second),
        pretty_print_binary_size(size_of_val(&*dids) as f64)
    );
    dids
}

async fn resolve_dids_no_cache(dids: Arc<Vec<String>>, count: u32) -> Result<(), DIDCacheError> {
    println!("Resolving {} dids, NO-CACHE!!!", count);
    let dids_len = dids.len();
    let mut handles = Vec::new();

    let _start = std::time::Instant::now();
    let mut rng = rand::rng();
    for _ in 0..count {
        let r: u32 = rng.random();
        let r: usize = r as usize % dids_len;
        let _dids = dids.clone();

        //let _cache = cache.clone();
        handles.push(tokio::spawn(async move {
            let method = DIDKey;

            let _ = match method
                .resolve(DID::new::<str>(_dids.get(r).unwrap()).unwrap())
                .await
            {
                Ok(res) => Some(res.document.into_document()),
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    None
                }
            };
        }));
    }
    join_all(handles).await;

    let elapsed = _start.elapsed();
    let per_second = count as f64 / elapsed.as_secs_f64();
    println!(
        "NO-CACHE: Resolved {} did:key's in {} seconds :: {} keys/second",
        count,
        pretty_print_float(_start.elapsed().as_secs_f64()),
        pretty_print_float(per_second)
    );

    Ok(())
}

async fn resolve_dids(
    cache: &DIDCacheClient,
    dids: Arc<Vec<String>>,
    count: u32,
) -> Result<(), DIDCacheError> {
    let cache_hit: Arc<Mutex<i32>> = Arc::new(Mutex::new(0));

    let dids_len = dids.len();
    let mut handles = Vec::new();

    let _start = std::time::Instant::now();
    let mut rng = rand::rng();

    for _ in 0..count {
        let r: usize = rng.random::<u32>() as usize % dids_len;
        let _dids = dids.clone();

        let _cache = cache.clone();
        let _cache_hit = cache_hit.clone();

        handles.push(tokio::spawn(async move {
            match _cache.resolve(_dids.get(r).unwrap()).await {
                Ok(res) => {
                    //println!("Resolved DID: ({}) cache_hit?({})", res.did, res.cache_hit);
                    if res.cache_hit {
                        //let mut lock = _cache_hit.lock().await;
                        //*lock += 1;
                    }
                }
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                }
            }
        }));
    }
    join_all(handles).await;

    let elapsed = _start.elapsed();
    let per_second = count as f64 / elapsed.as_secs_f64();
    let _cache_hit = *cache_hit.lock().await;
    println!(
        "Resolved {} did:key's in {} seconds :: {} keys/second :: cache_hits: {} {}%",
        count,
        pretty_print_float(_start.elapsed().as_secs_f64()),
        pretty_print_float(per_second),
        _cache_hit,
        pretty_print_float((_cache_hit as f64 / count as f64) * 100.0)
    );

    Ok(())
}
