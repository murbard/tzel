//! tzel-verify: CLI bridge for the StarkWare verification stack.
//!
//! Takes a proof bundle JSON and verifies it. Exits 0 on success, 1 on failure.
//!
//! Usage:
//!   tzel-verify --proof <path> [--recursive]
//!
//! The proof file is the JSON produced by tzel-prove.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use clap::Parser;
use privacy_circuit_verify::{PrivacyProofOutput, verify_cairo, verify_recursive_circuit};
use starknet_types_core::felt::Felt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tzel-verify", about = "Verify a privacy STARK proof")]
struct Args {
    /// Path to the proof bundle JSON
    #[arg(long)]
    proof: PathBuf,

    /// Verify as a recursive (two-level) proof
    #[arg(long, default_value_t = false)]
    recursive: bool,
}

#[derive(serde::Deserialize)]
struct ProofBundle {
    proof: String,
    output_preimage: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Load the proof bundle
    let json = fs::read_to_string(&args.proof)?;
    let bundle: ProofBundle = serde_json::from_str(&json)?;

    // Decode
    let proof_bytes = hex::decode(&bundle.proof)?;
    let output_preimage: Vec<Felt> = bundle
        .output_preimage
        .iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).expect("invalid hex in output_preimage");
            Felt::from_bytes_le_slice(&bytes)
        })
        .collect();

    let proof_output = PrivacyProofOutput {
        proof: proof_bytes,
        output_preimage,
    };

    // Verify
    if args.recursive {
        verify_recursive_circuit(&proof_output)?;
    } else {
        verify_cairo(&proof_output)?;
    }

    eprintln!("Proof verified successfully");
    Ok(())
}
