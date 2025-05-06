use clap::Parser;
use num::BigUint;
use num_traits::Zero;
use plonky2::field::goldilocks_field::GoldilocksField;

use plonky2_rsa_ring_signature::gadgets::rsa::{RingSignatureCircuit, create_ring_proof};
use plonky2_rsa_ring_signature::rsa::{RSAKeypair, RSAPubkey};

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};

use base64::prelude::*;

/// Command-line arguments for the Ring Signature Prover
#[derive(Parser)]
#[command(name = "Ring Signature Prover")]
#[command(version = "1.0")]
#[command(about = "Generates a ring signature proof")]
struct Cli {
    /// Path to the public input JSON file
    #[arg(
        help = "Path to the JSON file that specifies the public keys set and the message to be signed."
    )]
    public_input_path: String,

    /// Path to the circuit prover JSON file
    #[arg(
        help = "Path to the JSON file containing the circuit prover data. Generate using `cargo run --example compile --release`"
    )]
    circuit_path: String,

    /// Path to the public key JSON file
    #[arg(
        help = "Path to the JSON file containing the public key of the signer. This should have been generated using `cargo run --example keygen --release`, and have a name like 'key.pub.json'"
    )]
    public_key_path: String,

    /// Path to the private key JSON file
    #[arg(
        help = "Path to the JSON file containing the private key of the signer. It should have a name like 'key.json'"
    )]
    private_key_path: String,

    /// Specify the output file for the proof (default: proof.json)
    #[arg(
        short,
        long,
        default_value = "proof.json",
        help = "Path to the output file where the generated proof will be saved."
    )]
    output_path: String,
}

#[derive(Serialize)]
struct ProofExportData {
    proof: String,
}

#[derive(Deserialize)]
struct PublicInputData {
    public_keys: Vec<String>,
    message: String,
}

#[derive(Deserialize)]
struct PublicKeyData {
    public_key: String,
}

#[derive(Deserialize)]
struct PrivateKeyData {
    private_key: String,
}

fn read_file_to_string(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

const MAX_NUM_PUBLIC_KEYS: usize = 32;

fn main() -> anyhow::Result<()> {
    // Parse command-line arguments using derive-based clap
    let args = Cli::parse();

    // Read public keys and message from the specified JSON file
    let public_input_json = read_file_to_string(&args.public_input_path)?;
    let public_input_data: PublicInputData = serde_json::from_str(&public_input_json)?;

    // Read circuit data from circuit.json
    let circuit_json = read_file_to_string(&args.circuit_path)?;
    let circuit: RingSignatureCircuit = serde_json::from_str(&circuit_json).map_err(|_| {
        anyhow::anyhow!(
            "Failed to deserialize circuit data! Did you accidentally use the verifier circuit?"
        )
    })?;

    // Read private key and its public key from the specified JSON file
    let public_key_json = read_file_to_string(&args.public_key_path)?;
    let public_key_data: PublicKeyData = serde_json::from_str(&public_key_json)?;

    // Read private key and its public key from the specified JSON file
    let private_key_json = read_file_to_string(&args.private_key_path)?;
    let private_key_data: PrivateKeyData = serde_json::from_str(&private_key_json)?;

    // Convert message string to GoldilocksField using ASCII values
    let message: Vec<GoldilocksField> = public_input_data
        .message
        .chars()
        .map(|c| GoldilocksField(c as u64))
        .collect();

    // Convert public keys into RSAPubKey
    let mut public_keys = public_input_data
        .public_keys
        .iter()
        .map(|value| RSAPubkey::from_base64(value))
        .collect::<Vec<_>>();

    // Convert private key to RSAKeypair
    let private_key =
        RSAKeypair::from_base64(&public_key_data.public_key, &private_key_data.private_key);

    if public_keys.len() > MAX_NUM_PUBLIC_KEYS {
        eprintln!(
            "Number of public keys exceeds maximum limit of {}.",
            MAX_NUM_PUBLIC_KEYS
        );
        std::process::exit(1);
    }
    public_keys.resize(MAX_NUM_PUBLIC_KEYS, RSAPubkey { n: BigUint::zero() });

    let proof = create_ring_proof(&circuit, &public_keys, &private_key, &message)?;
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof: {}", e))?;
    let proof_export_data = ProofExportData {
        proof: BASE64_STANDARD.encode(&proof_bytes),
    };

    // Write ProofExportData to proof.json
    let proof_json = serde_json::to_string_pretty(&proof_export_data).unwrap();
    let mut proof_file = File::create("proof.json")?;
    proof_file.write_all(proof_json.as_bytes())?;

    Ok(())
}
