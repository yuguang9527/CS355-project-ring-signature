use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use base64::prelude::*;
use clap::Parser;
use plonky2_rsa_ring_signature::rsa::RSAKeypair;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate RSA keypairs")]
struct Args {
    /// Output file path for the keypair
    #[arg(
        short,
        long,
        default_value = "key.pub.json",
        help = "Path to the output file where the public key will be saved"
    )]
    public_key_output: PathBuf,

    /// Output file path for the keypair
    #[arg(
        short,
        long,
        default_value = "key.json",
        help = "Path to the output file where the private key will be saved"
    )]
    private_key_output: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct PublicKeyJson {
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct PrivateKeyJson {
    private_key: String,
}

fn prompt_user_for_overwrite() -> bool {
    println!("Key files already exist. Do you want to overwrite them? (yes/[no]):");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    matches!(input.trim().to_lowercase().as_str(), "yes" | "y")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Check if either file exists and prompt the user
    let mut overwrite = true;

    if args.public_key_output.exists() || args.public_key_output.exists() {
        overwrite = prompt_user_for_overwrite();
    }

    // If the user declines to overwrite either file, exit
    if !overwrite {
        println!("Operation canceled. No files were written.");
        return Ok(());
    }

    println!("Generating RSA keypair...");
    let keypair = RSAKeypair::new();
    let pubkey = keypair.get_pubkey();

    println!("RSA keypair generated successfully");

    let public_key_json = PublicKeyJson {
        public_key: pubkey.base64(),
    };

    let private_key_json = PrivateKeyJson {
        private_key: BASE64_STANDARD.encode(keypair.sk.to_bytes_le()),
    };

    let public_key_serialized = serde_json::to_string_pretty(&public_key_json)?;
    let private_key_serialized = serde_json::to_string_pretty(&private_key_json)?;

    println!(
        "Saving public key to {}...",
        args.public_key_output.display()
    );
    let mut file = File::create(args.public_key_output)?;
    file.write_all(public_key_serialized.as_bytes())?;

    println!(
        "Saving private key to {}...",
        args.private_key_output.display()
    );
    let mut file = File::create(args.private_key_output)?;
    file.write_all(private_key_serialized.as_bytes())?;

    println!("Done!");
    Ok(())
}
