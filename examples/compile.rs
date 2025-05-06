use clap::Parser;
use plonky2_rsa_ring_signature::gadgets::rsa::create_ring_circuit;
use plonky2_rsa_ring_signature::gadgets::serialize::RSAGateSerializer;

use serde::Serialize;
use std::fs::File;
use std::io::Write;

use base64::prelude::*;

/// Command-line arguments for the Ring Circuit Compiler
#[derive(Parser)]
#[command(name = "Ring Circuit Compiler")]
#[command(version = "1.0")]
#[command(about = "Compiles a ring signature circuit")]
struct Cli {
    /// Path to the output file for the prover circuit
    #[arg(
        short = 'p',
        long = "prover-output",
        default_value = "circuit_prover.json",
        help = "Path to the output file where the circuit with prover data will be saved"
    )]
    prover_output: String,

    /// Path to the output file for the verifier circuit
    #[arg(
        short = 'v',
        long = "verifier-output",
        default_value = "circuit_verifier.json",
        help = "Path to the output file where the circuit with verifier data will be saved"
    )]
    verifier_output: String,
}

#[derive(Serialize)]
struct VerifierCircuitExportData {
    circuit: String,
    verifier_circuit_data: Option<String>,
}

const MAX_NUM_PUBLIC_KEYS: usize = 32;

// TODO: output path
fn main() -> anyhow::Result<()> {
    // Parse command-line arguments using clap
    let args = Cli::parse();

    let circuit = create_ring_circuit(MAX_NUM_PUBLIC_KEYS);

    let prover_json = serde_json::to_string_pretty(&circuit).unwrap();

    // Write CircuitExportData for prover to circuit_prover.json
    let mut prover_file = File::create(args.prover_output)?;
    prover_file.write_all(prover_json.as_bytes())?;

    let data = circuit.circuit;
    let gate_serializer = RSAGateSerializer;
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    let common_data_bytes = data.common.to_bytes(&gate_serializer).unwrap();

    // Create CircuitExportData for verifier
    let verifier_circuit_export_data = VerifierCircuitExportData {
        circuit: BASE64_STANDARD.encode(&common_data_bytes),
        verifier_circuit_data: Some(BASE64_STANDARD.encode(&verifier_only_bytes)),
    };

    // Write CircuitExportData for verifier to circuit_verifier.json
    let verifier_json = serde_json::to_string_pretty(&verifier_circuit_export_data).unwrap();
    let mut verifier_file = File::create(args.verifier_output)?;
    verifier_file.write_all(verifier_json.as_bytes())?;

    Ok(())
}
