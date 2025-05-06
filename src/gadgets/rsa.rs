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
    unimplemented!("TODO: Implement the circuit to raise value to the power 65537 mod modulus");
    // HINT: 65537 = 2^16 + 1. Can you use this to exponentiate efficiently?
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
    unimplemented!("TODO: Compute the value of the padded hash for witness generation");
    // HINT: The size of the message hash is always HASH_BYTES
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
    unimplemented!("TODO: Add additional targets for the signature and public keys");

    // TODO: Construct SNARK circuit for relation R 
    unimplemented!("TODO: Build SNARK circuit for relation R");

    // Build the circuit and return it
    let data = builder.build::<C>();
    return RingSignatureCircuit {
        circuit: data,
        padded_hash_target,
        pk_targets,
        sig_target,
        sig_pk_target,
    };
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
    let message_hash = compute_hash(&message);
    let padded_hash = compute_padded_hash(&message_hash);
    let digest = RSADigest {
        val: padded_hash.clone(),
    };
    let sig_val = private_key.sign(&digest);
    let pk_val = private_key.get_pubkey();

    let mut pw = PartialWitness::new();

    // Set the witness values in pw
    pw.set_biguint_target(&circuit.sig_pk_target, &pk_val.n)?;

    // TODO: Set your additional targets in the partial witness
    unimplemented!("TODO: Set your additional targets in the partial witness");

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

