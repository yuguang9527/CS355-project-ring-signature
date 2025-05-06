use base64::prelude::*;
use clap::Parser;
use plonky2::plonk::circuit_data::{
    CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_rsa_ring_signature::gadgets::serialize::RSAGateSerializer;
use plonky2_rsa_ring_signature::utils::verify_ring_signature_proof_public_inputs;
use serde_json::Value;
use std::fs::File;
use std::io::Read;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MAX_NUM_PUBLIC_KEYS: usize = 32;

/// Command-line arguments for the Ring Signature Verifier
#[derive(Parser)]
#[command(name = "Ring Signature Verifier")]
#[command(version = "1.0")]
#[command(about = "Verifies a ring signature proof")]
struct Cli {
    /// Path to the circuit JSON file
    #[arg(help = "Path to the JSON file containing the circuit data.")]
    circuit_file: String,

    /// Path to the proof JSON file
    #[arg(help = "Path to the JSON file containing the proof data.")]
    proof_file: String,

    /// Path to the public input JSON file
    #[arg(help = "Path to the JSON file containing the public input data.")]
    public_input_file: String,
}

fn main() {
    // Parse command-line arguments using clap
    let args = Cli::parse();

    // Read and parse the circuit file
    let circuit_data = read_and_parse_json(&args.circuit_file, "circuit file");
    let verifier_circuit_data = circuit_data["verifier_circuit_data"]
        .as_str()
        .unwrap_or_else(|| {
            eprintln!("Missing 'verifier_circuit_data' field in circuit file");
            std::process::exit(1);
        });
    let circuit = circuit_data["circuit"].as_str().unwrap_or_else(|| {
        eprintln!("Missing 'circuit' field in circuit file");
        std::process::exit(1);
    });

    // Read and parse the proof file
    let proof_data = read_and_parse_json(&args.proof_file, "proof file");
    let proof = proof_data["proof"].as_str().unwrap_or_else(|| {
        eprintln!("Missing 'proof' field in proof file");
        std::process::exit(1);
    });

    // Read and parse the public input file
    let public_input_data = read_and_parse_json(&args.public_input_file, "public input file");
    let message = public_input_data["message"].as_str().unwrap_or_else(|| {
        eprintln!("Missing 'message' field in public input file");
        std::process::exit(1);
    });
    let public_keys = public_input_data["public_keys"]
        .as_array()
        .unwrap_or_else(|| {
            eprintln!("Missing or invalid 'public_keys' field in public input file");
            std::process::exit(1);
        });

    // Convert public keys to a vector of strings
    let expected_public_keys: Vec<String> = public_keys
        .iter()
        .filter_map(|key| key.as_str().map(String::from))
        .collect();

    // Call the verification function
    match verify_plonky2_ring_rsa_proof(
        proof,
        verifier_circuit_data,
        circuit,
        message,
        expected_public_keys,
    ) {
        Ok(_) => println!("success"),
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    }
}

// Mock implementation of the verification function
fn verify_plonky2_ring_rsa_proof(
    proof_base64: &str,
    verifier_only_base64: &str,
    common_data_base64: &str,
    expected_message: &str,
    expected_public_keys: Vec<String>,
) -> Result<bool, String> {
    // Decode base64 data
    let proof_bytes = BASE64_STANDARD
        .decode(proof_base64)
        .map_err(|_| String::from("Failed to decode proof from base64"))?;

    let verifier_only_bytes = BASE64_STANDARD
        .decode(verifier_only_base64)
        .map_err(|_| String::from("Failed to decode verifier-only data from base64"))?;

    let common_data_bytes = BASE64_STANDARD
        .decode(common_data_base64)
        .map_err(|_| String::from("Failed to decode common circuit data from base64"))?;

    // Deserialize proof
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof_bytes)
        .map_err(|e| String::from(&format!("Failed to deserialize proof: {}", e)))?;

    // Use the default gate deserializer
    let gate_deserializer = RSAGateSerializer;

    // Deserialize verifier-only data
    let verifier_only: VerifierOnlyCircuitData<C, D> =
        VerifierOnlyCircuitData::from_bytes(verifier_only_bytes).map_err(|e| {
            String::from(&format!(
                "Failed to deserialize verifier-only data: {:?}",
                e
            ))
        })?;

    // Deserialize common circuit data
    let common_data: CommonCircuitData<F, D> =
        CommonCircuitData::from_bytes(common_data_bytes, &gate_deserializer).map_err(|e| {
            String::from(&format!(
                "Failed to deserialize common circuit data: {:?}",
                e
            ))
        })?;

    let verifier_data = VerifierCircuitData {
        verifier_only,
        common: common_data,
    };

    // Verify public inputs
    if !verify_ring_signature_proof_public_inputs(
        &proof,
        MAX_NUM_PUBLIC_KEYS,
        expected_message,
        &expected_public_keys,
    ) {
        return Err(String::from(
            "Public key or message verification failed: Inputs don't match the proof's public inputs",
        ));
    }

    match verifier_data.verify(proof) {
        Ok(_) => Ok(true),
        Err(e) => Err(String::from(&format!("Proof verification failed: {:?}", e))),
    }
}

fn read_and_parse_json(file_path: &str, file_type: &str) -> Value {
    let mut file = File::open(file_path).unwrap_or_else(|_| {
        eprintln!("Failed to open {}: {}", file_type, file_path);
        std::process::exit(1);
    });
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap_or_else(|_| {
        eprintln!("Failed to read {}: {}", file_type, file_path);
        std::process::exit(1);
    });
    serde_json::from_str(&content).unwrap_or_else(|_| {
        eprintln!("Failed to parse {} as JSON", file_type);
        std::process::exit(1);
    })
}
