mod custom_circuit;

use std::fs::{self, read_to_string};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
use cairo_program_runner_lib::types::{HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput, TaskSpec};
use cairo_program_runner_lib::{ProgramInput, cairo_run_program};
use clap::Parser;
use privacy_circuit_verify::get_privacy_bootloader_program;
use privacy_prove::consts::{CAIRO_PROVER_PARAMS, CAIRO_RUN_CONFIG};
use serde_json::from_str;
use starknet_types_core::felt::Felt;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_prover::prover::prove_cairo;
use tempfile::NamedTempFile;
use tracing::info;
use tracing_subscriber::fmt;

use crate::custom_circuit::custom_recursive_prove;

#[derive(Parser)]
#[command(name = "reprove", about = "Generate privacy proofs for StarkPrivacy executables")]
struct Cli {
    /// Path to a .executable.json file (Cairo 1 executable)
    executable: PathBuf,

    /// Write compressed proof to this file
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// DEBUG ONLY: single-level Stwo proof (NOT zero-knowledge, leaks witness data)
    #[arg(long)]
    debug_single_level: bool,
}

fn run_privacy_bootloader_cairo1(
    executable_path: &PathBuf,
) -> Result<(stwo_cairo_adapter::ProverInput, Vec<Felt>)> {
    let task = create_cairo1_program_task(executable_path, None, None)
        .map_err(|e| anyhow!("{e}"))?;

    let task_spec = TaskSpec {
        task: Rc::new(task),
        program_hash_function: HashFunc::Blake,
    };

    let output_preimage_file = NamedTempFile::new()?;
    let output_preimage_path = output_preimage_file.path().to_path_buf();

    let bootloader_input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![task_spec],
        },
        output_preimage_dump_path: output_preimage_path.clone(),
    };

    let bootloader_program = get_privacy_bootloader_program()
        .map_err(|e| anyhow!("{e}"))?;

    info!("Running privacy bootloader with Cairo1 executable");
    let runner = cairo_run_program(
        &bootloader_program,
        Some(ProgramInput::Value(Box::new(bootloader_input))),
        CAIRO_RUN_CONFIG,
        None,
    ).map_err(|e| anyhow!("{e}"))?;

    info!("Reading bootloader output preimage");
    let output_preimage_content = read_to_string(&output_preimage_path)?;
    let output_preimage: Vec<Felt> = from_str(&output_preimage_content)?;

    info!("Adapting runner output for prover");
    let prover_input = adapt(&runner).map_err(|e| anyhow!("{e}"))?;

    Ok((prover_input, output_preimage))
}

/// Read peak RSS from /proc/self/status (Linux only).
fn get_peak_memory_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
}

fn main() -> Result<()> {
    fmt().with_max_level(tracing::Level::INFO).init();
    let cli = Cli::parse();

    eprintln!("Loading executable from {:?}", cli.executable);

    let t_total = Instant::now();

    // Run through privacy bootloader
    let (prover_input, output_preimage) = run_privacy_bootloader_cairo1(&cli.executable)?;

    if cli.debug_single_level {
        // WARNING: Single-level Stwo proofs are NOT zero-knowledge.
        // The FRI query responses leak information about the witness trace.
        // Use only for debugging/benchmarking, never for real privacy transactions.
        eprintln!("WARNING: single-level mode is NOT zero-knowledge — witness data may leak");
        eprintln!("Generating Stwo proof...");
        let t_prove = Instant::now();
        let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(prover_input, CAIRO_PROVER_PARAMS)
            .map_err(|e| anyhow!("{e}"))?;
        let prove_ms = t_prove.elapsed().as_millis();

        let json_bytes = serde_json::to_vec(&cairo_proof)?;
        let compressed = zstd::encode_all(&json_bytes[..], 3)?;

        let peak_mem_kb = get_peak_memory_kb();
        eprintln!("Prove: {}ms", prove_ms);
        eprintln!("Proof zstd: {} bytes ({:.1} KB)", compressed.len(), compressed.len() as f64 / 1024.0);
        eprintln!("Total: {}ms", t_total.elapsed().as_millis());
        if let Some(mem) = peak_mem_kb {
            eprintln!("Peak RSS: {:.1} MB", mem as f64 / 1024.0);
        }
        println!("prove_ms={}", prove_ms);
        println!("proof_zstd_bytes={}", compressed.len());
    } else {
        // Recursive proving: Cairo proof → circuit proof (zero-knowledge)
        eprintln!("Running recursive prove...");
        let t_prove = Instant::now();
        let proof_output = custom_recursive_prove(prover_input, output_preimage)?;
        let prove_ms = t_prove.elapsed().as_millis();

        let proof_size = proof_output.proof.len();
        let peak_mem_kb = get_peak_memory_kb();

        eprintln!("--- Results ---");
        eprintln!("Cairo prove: {}ms", proof_output.cairo_prove_ms);
        eprintln!("Circuit prove: {}ms", proof_output.circuit_prove_ms);
        eprintln!("Total prove: {}ms", prove_ms);
        eprintln!("Verify: {}ms", proof_output.verify_ms);
        eprintln!("Circuit proof: {} bytes ({:.1} KB)", proof_size, proof_size as f64 / 1024.0);
        if let Some(mem) = peak_mem_kb {
            eprintln!("Peak RSS: {:.1} MB", mem as f64 / 1024.0);
        }

        if let Some(path) = cli.output {
            fs::write(&path, &proof_output.proof)?;
            eprintln!("Proof written to {:?}", path);
        }

        eprintln!("Total wall: {}ms", t_total.elapsed().as_millis());
        println!("cairo_prove_ms={}", proof_output.cairo_prove_ms);
        println!("circuit_prove_ms={}", proof_output.circuit_prove_ms);
        println!("prove_ms={}", prove_ms);
        println!("verify_ms={}", proof_output.verify_ms);
        println!("proof_bytes={}", proof_size);
        println!("output_preimage_len={}", proof_output.output_preimage.len());
        if let Some(mem) = peak_mem_kb {
            println!("peak_rss_kb={}", mem);
        }
    }

    Ok(())
}
