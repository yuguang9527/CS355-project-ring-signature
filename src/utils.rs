use crate::gadgets::rsa::{C, D, F, compute_hash, compute_padded_hash};
use crate::rsa::RSAPubkey;
use plonky2::field::types::Field;
use plonky2::plonk::proof::ProofWithPublicInputs;

/// Helper function to verify public inputs against proof
pub fn verify_ring_signature_proof_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    max_num_public_keys: usize,
    expected_message: &str,
    expected_keys: &[String],
) -> bool {
    let expected_message_field_elements = expected_message
        .chars()
        .map(|byte| F::from_canonical_u32(byte as u32))
        .collect::<Vec<_>>();

    // Convert expected inputs to RSAPubkey objects
    let mut pubkeys = Vec::new();
    for base64_str in expected_keys {
        let pubkey = RSAPubkey::from_base64(&base64_str);
        pubkeys.push(pubkey);
    }
    if pubkeys.len() > max_num_public_keys {
        return false; // Too many public keys
    }

    return verify_ring_signature_proof_public_inputs_fields(
        proof,
        max_num_public_keys,
        &expected_message_field_elements,
        &pubkeys,
    );
}

pub fn verify_ring_signature_proof_public_inputs_fields(
    proof: &ProofWithPublicInputs<F, C, D>,
    max_num_public_keys: usize,
    expected_message: &[F],
    expected_keys: &[RSAPubkey],
) -> bool {
    let mut input_index = 0;

    // Generate the padded hash of the message
    let message_hash = compute_hash(&expected_message);
    let padded_hash = compute_padded_hash(&message_hash);

    // Verify the expected padded message hash
    for limb in padded_hash.to_u32_digits() {
        if input_index >= proof.public_inputs.len()
            || proof.public_inputs[input_index] != F::from_canonical_u32(limb)
        {
            println!(
                "Expected {}, got {}",
                F::from_canonical_u32(limb),
                proof.public_inputs[input_index]
            );
            return false;
        }
        input_index += 1;
    }

    // Verify that each RSAPubkey's limbs match the public inputs
    for pubkey in expected_keys {
        for limb in pubkey.n.to_u32_digits() {
            if input_index >= proof.public_inputs.len()
                || proof.public_inputs[input_index] != F::from_canonical_u32(limb)
            {
                return false;
            }
            input_index += 1;
        }
    }
    // Verify the rest are zero
    let remaining_pubkey_inputs = (max_num_public_keys - expected_keys.len()) * 64;
    for _ in 0..remaining_pubkey_inputs {
        if input_index >= proof.public_inputs.len()
            || proof.public_inputs[input_index] != F::from_canonical_u32(0 as u32)
        {
            return false;
        }
        input_index += 1;
    }

    // Ensure we checked all the inputs
    return proof.public_inputs.len() == input_index;
}
