use super::biguint::{BigUintTarget, CircuitBuilderBiguint};
use super::biguint::{CircuitBuilderBiguintFromField, WitnessBigUint};
use crate::gadgets::serialize::serialize_circuit_data;
use crate::rsa::{RSADigest, RSAKeypair, RSAPubkey};
use num::BigUint;
use num::FromPrimitive;
use num_traits::Zero;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};
use serde::{Deserialize, Serialize};

// Circuit configuration parameters
pub type C = PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type F = <C as GenericConfig<D>>::F;

// Helper constants:
// The number of bytes for the RSA Modulus (and signatures)
const RSA_MODULUS_BYTES: usize = 256; // 2048 bits = 256 bytes
// The number of bytes in a Poseidon hash output
const HASH_BYTES: usize = <PoseidonHash as Hasher<GoldilocksField>>::HASH_SIZE;

/// A struct representing a plonky2 ring signature circuit,
/// and the targets for the inputs to the circuit
#[derive(Serialize, Deserialize)]
pub struct RingSignatureCircuit {
    #[serde(with = "serialize_circuit_data")]
    pub circuit: CircuitData<F, C, D>,
    // public input targets
    pub padded_hash_target: BigUintTarget,
    pub pk_targets: Vec<BigUintTarget>,
    // witness targets
    pub sig_target: BigUintTarget,
    pub sig_pk_target: BigUintTarget,
}

/// Computes the RSA signature of a given hash using the private key and modulus.
pub fn rsa_sign(hash: &BigUint, private_key: &BigUint, modulus: &BigUint) -> BigUint {
    hash.modpow(private_key, modulus)
}

/// Circuit function which computes value^65537 mod modulus
fn pow_65537(
    builder: &mut CircuitBuilder<F, D>,
    value: &BigUintTarget,
    modulus: &BigUintTarget,
) -> BigUintTarget {
    // TODO: Implement the circuit to raise value to the power 65537 mod modulus 
    // unimplemented!("TODO: Implement the circuit to raise value to the power 65537 mod modulus");
    // HINT: 65537 = 2^16 + 1. Can you use this to exponentiate efficiently?
    let mut current_power = value.clone();

    // Compute value^(2^16) mod modulus
    // This is done by squaring 16 times, taking modulo at each step.
    for _ in 0..16 {
        let squared = builder.mul_biguint(&current_power, &current_power);
        current_power = builder.rem_biguint(&squared, modulus);
    }

    // Now current_power holds value^(2^16) mod modulus.
    // We need to multiply by the original value one more time and take modulo.
    // result = (value^(2^16) * value) mod modulus
    let final_product = builder.mul_biguint(&current_power, value);
    

    builder.rem_biguint(&final_product, modulus)

}

/// Circuit which computes a hash target from a message
fn hash(builder: &mut CircuitBuilder<F, D>, message: &[Target]) -> BigUintTarget {
    let field_size_const = BigUint::from_u64(GoldilocksField::ORDER).unwrap();
    let field_size = builder.constant_biguint(&field_size_const);
    let hashed_arr = builder.hash_or_noop::<PoseidonHash>(message.into());
    let mut hashed = builder.zero_biguint();
    for x in hashed_arr.elements.iter() {
        let x_big = builder.field_to_biguint(*x);
        hashed = builder.mul_add_biguint(&hashed, &field_size, &x_big);
    }
    hashed
}

/// Computes the hash value from a message
pub fn compute_hash(message: &[GoldilocksField]) -> BigUint {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut message_targets = Vec::with_capacity(message.len());
    for e in message {
        message_targets.push(builder.constant(*e));
    }
    let hash_target = hash(&mut builder, &message_targets);
    let data = builder.build_prover::<C>();
    let witness =
        generate_partial_witness(PartialWitness::new(), &data.prover_only, &data.common).unwrap();
    witness.get_biguint_target(hash_target)
}

/// Pads the message hash with PKCS#1 v1.5 padding in the circuit
/// Padding will look like: 0x00 || 0x01 || 0xff...ff || 0x00 || hash
pub fn compute_padded_hash(message_hash: &BigUint) -> BigUint {
    // TODO: Compute the value of the padded hash for witness generation
    // unimplemented!("TODO: Compute the value of the padded hash for witness generation");
    // HINT: The size of the message hash is always HASH_BYTES
    let raw_hash_bytes = message_hash.to_bytes_be();
    let total_len = RSA_MODULUS_BYTES; // k, e.g., 256 bytes for 2048 bits
    let t_len = HASH_BYTES; // Length of the hash T, e.g., 32 bytes for a 256-bit hash

    // Minimum length of PS (padding string) is 8 bytes.
    // EM = 0x00 || 0x01 || PS || 0x00 || T
    // k = 1  +  1  + len(PS) + 1  + t_len
    // k >= 1  +  1  + 8       + 1  + t_len = 11 + t_len
    if total_len < t_len + 11 {
        panic!(
            "RSA modulus (k={} bytes) is too short for PKCS#1 v1.5 padding with a {}-byte hash (T). Minimum k should be t_len + 11 = {} bytes.",
            total_len,
            t_len,
            t_len + 11
        );
    }
    
    // len(PS) = k - 3 - t_len
    let ps_len = total_len - 3 - t_len;

    // Construct T: the hash, left-padded with zeros to t_len if shorter.
    let mut embedded_hash_t = vec![0u8; t_len];
    if raw_hash_bytes.len() > t_len {
        panic!(
            "Input message_hash ({} bytes) is too large to be represented as a {}-byte hash (T). Expected HASH_BYTES.",
            raw_hash_bytes.len(),
            t_len
        );
    }
    let hash_start_idx = t_len.saturating_sub(raw_hash_bytes.len());
    embedded_hash_t[hash_start_idx..].copy_from_slice(&raw_hash_bytes);

    // Construct the padded message EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut padded_em = Vec::with_capacity(total_len);
    padded_em.push(0x00);                         // Octet 0x00
    padded_em.push(0x01);                         // Block type 0x01 (for private-key operation)
    padded_em.extend(vec![0xFF; ps_len]);         // PS (padding string of 0xFF octets)
    padded_em.push(0x00);                         // Separator 0x00
    padded_em.extend_from_slice(&embedded_hash_t); // T (message digest)

    assert_eq!(padded_em.len(), total_len, "Internal error: Final padded EM length does not match RSA_MODULUS_BYTES.");

    BigUint::from_bytes_be(&padded_em)
}

pub fn create_ring_circuit(max_num_pks: usize) -> RingSignatureCircuit {
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Add circuit targets
    let padded_hash_target = builder.add_virtual_public_biguint_target(64);
    let sig_pk_target = builder.add_virtual_biguint_target(64);

    // Example: Ensure modulus_target is not zero, in case fewer than max_num_pks are given as
    // input to the circuit
    let zero_biguint = builder.zero_biguint();
    // Constrain modulus_is_zero to be 1 if sig_pk_target == 0, and 0 otherwise
    let modulus_is_zero = builder.eq_biguint(&sig_pk_target, &zero_biguint);
    let zero = builder.zero();
    // Ensure modulus_is_zero is 0 (aka false)
    builder.connect(modulus_is_zero.target, zero);

    // TODO: Add additional targets for the signature and public keys
    // unimplemented!("TODO: Add additional targets for the signature and public keys");

    // Define pk_targets: a vector of public_input targets, one for each public key (N) in the ring R.
    let mut pk_targets_vec = Vec::with_capacity(max_num_pks);
    for _ in 0..max_num_pks {
        pk_targets_vec.push(builder.add_virtual_public_biguint_target(64));
    }
    let pk_targets = pk_targets_vec;

    // Define sig_target: a witness (private_input) target for the RSA signature rho.
    let sig_target = builder.add_virtual_biguint_target(64);
    

    // TODO: Construct SNARK circuit for relation R 
    // Relation R: pk_witness ∈ pk_ring AND Vrfy(pk_witness, message_padded_hash, signature) == 1

    // 1. Membership check: pk_witness (sig_pk_target) ∈ pk_ring (pk_targets)
    //    is_member_flag = (sig_pk_target == pk_targets[0]) OR (sig_pk_target == pk_targets[1]) OR ...
    let mut is_member_flag = builder.constant_bool(false); // Initialize to false
    for pk_in_ring in pk_targets.iter() {
        let current_pk_matches_witness = builder.eq_biguint(&sig_pk_target, pk_in_ring);
        is_member_flag = builder.or(is_member_flag, current_pk_matches_witness);
    }
    // Now, is_member_flag.target is 1 if sig_pk_target is in pk_targets, and 0 otherwise.

    // 2. RSA Signature Verification: PaddedHash == Signature^e mod N_witness
    //    PaddedHash is padded_hash_target
    //    Signature is sig_target
    //    N_witness is sig_pk_target (the modulus of the actual signer)
    //    e is 65537
    let sig_pow_e = pow_65537(&mut builder, &sig_target, &sig_pk_target);
    let rsa_verifies = builder.eq_biguint(&padded_hash_target, &sig_pow_e);
    // Now, rsa_verifies.target is 1 if the RSA signature is valid, and 0 otherwise.

    // 3. Combine both conditions: is_member AND rsa_verifies must be true.
    let overall_condition = builder.and(is_member_flag, rsa_verifies);

    // 4. Connect the overall condition to true (i.e., assert it must be 1).
    let true_target = builder.one(); // Target representing true (1)
    builder.connect(overall_condition.target, true_target);

    // unimplemented!("TODO: Build SNARK circuit for relation R");

    // Build the circuit and return it
    let data = builder.build::<C>();
    RingSignatureCircuit {
        circuit: data,
        padded_hash_target,
        pk_targets,
        sig_target,
        sig_pk_target,
    }
}

/// Creates a ring signature proof where the signer proves they know a valid signature
/// for one of the public keys in the ring without revealing which one.
pub fn create_ring_proof(
    circuit: &RingSignatureCircuit,
    public_keys: &[RSAPubkey],   // Public keys as RSAPubkey objects
    private_key: &RSAKeypair,    // Private key as an RSAKeypair object
    message: &[GoldilocksField], // Message as a vector of field elements
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    // Generate the values of the witness, by computing the RSA signature on
    // the message
    let message_hash = compute_hash(message);
    let padded_hash = compute_padded_hash(&message_hash);
    let digest = RSADigest {
        val: padded_hash.clone(), // padded_hash is m in Sig.Vrfy(pk, m, rho)
    };
    let sig_val = private_key.sign(&digest);
    let pk_val = private_key.get_pubkey();

    let mut pw = PartialWitness::new();

    // Set the witness values in pw

    // 1. Set actual signer's public key (N_i from witness)
    pw.set_biguint_target(&circuit.sig_pk_target, &pk_val.n)?;

    // TODO: Set your additional targets in the partial witness
    // unimplemented!("TODO: Set your additional targets in the partial witness");

    // 2. Set padded hash of the message (m - public input, but set via witness pathway for prover)
    pw.set_biguint_target(&circuit.padded_hash_target, &padded_hash)?;

    // 3. Set the ring public keys (R - public input, but set via witness pathway for prover)
    // Ensure the number of provided public keys matches the circuit's expectation.
    if public_keys.len() != circuit.pk_targets.len() {
        anyhow::bail!(
            "Number of public keys ({}) provided does not match circuit configuration ({} targets).",
            public_keys.len(),
            circuit.pk_targets.len()
        );
    }
    for (pk_target_in_circuit, actual_pk_value) in circuit.pk_targets.iter().zip(public_keys.iter()) {
        pw.set_biguint_target(pk_target_in_circuit, &actual_pk_value.n)?;
    }

    // 4. Set the RSA signature (rho - witness)
    pw.set_biguint_target(&circuit.sig_target, &sig_val.sig)?;

    // All witness and public inputs required by the prover have been set.

    let proof = circuit.circuit.prove(pw)?;
    // check that the proof verifies
    circuit.circuit.verify(proof.clone())?;
    Ok(proof)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_compute_padded_hash() {
        let message_hash = BigUint::from_u64(0x12345678).unwrap();
        let expected_padded_hash = BigUint::parse_bytes(
            "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000\
            000000000000000000000000000000000000000012345678"
                .as_bytes(),
            16,
        )
        .expect("Failed to parse expected padded hash");

        // Act
        let padded_hash = compute_padded_hash(&message_hash);

        // Assert
        assert_eq!(
            padded_hash, expected_padded_hash,
            "The computed padded hash does not match the expected value."
        );
    }

    #[test]
    #[should_panic]
    fn empty_public_keys_should_fail() {
        let mut public_keys = vec![];
        public_keys.resize(5, RSAPubkey { n: BigUint::zero() });
        let private_key = RSAKeypair::new();
        let message = vec![
            GoldilocksField(12),
            GoldilocksField(20),
            GoldilocksField(23),
        ];
        let circuit = create_ring_circuit(5);
        create_ring_proof(&circuit, &public_keys, &private_key, &message).unwrap();
    }

    #[test]
    fn public_inputs_should_be_correct() {
        let private_key = RSAKeypair::new();
        let mut public_keys = vec![private_key.get_pubkey()];
        public_keys.resize(5, RSAKeypair::new().get_pubkey());
        let message = vec![
            GoldilocksField(12),
            GoldilocksField(20),
            GoldilocksField(23),
        ];
        let circuit = create_ring_circuit(5);
        let proof = create_ring_proof(&circuit, &public_keys, &private_key, &message).unwrap();

        use crate::utils::verify_ring_signature_proof_public_inputs_fields;
        assert!(verify_ring_signature_proof_public_inputs_fields(
            &proof,
            5,
            &message,
            &public_keys
        ));
        circuit.circuit.verify(proof).unwrap();
    }
}