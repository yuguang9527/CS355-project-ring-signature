use base64::prelude::*;
use crypto_bigint::U1024;
use crypto_primes;
use num::{BigUint, Zero};

#[derive(Clone, Debug)]
pub struct RSAKeypair {
    pub n: BigUint,
    pub sk: BigUint,
}

#[derive(Clone, Debug)]
pub struct RSASignature {
    pub sig: BigUint,
}

#[derive(Clone, Debug)]
pub struct RSAPubkey {
    pub n: BigUint,
}

#[derive(Clone, Debug)]
pub struct RSADigest {
    pub val: BigUint,
}

impl RSAKeypair {
    // Since WASM has 32-bit words, to properly compile this we need separate cases
    #[cfg(target_pointer_width = "32")]
    fn crypto_bigint_to_bigint(n: U1024) -> BigUint {
        BigUint::from_slice(
            &n.as_limbs()
                .iter()
                .map(|x| x.0 as u32)
                .collect::<Vec<u32>>(),
        )
    }

    #[cfg(target_pointer_width = "64")]
    fn crypto_bigint_to_bigint(n: U1024) -> BigUint {
        BigUint::from_slice(
            &n.as_limbs()
                .iter()
                .flat_map(|x| {
                    let x64 = x.0;
                    [x64 as u32, (x64 >> 32) as u32]
                })
                .collect::<Vec<u32>>(),
        )
    }

    pub fn new() -> Self {
        const CONSTANT_EXP: u32 = 65537;
        let mut good_primes_found: bool = false;
        let mut p = BigUint::zero(); // initialize so p, q are in scope;
        let mut q = BigUint::zero(); // values will be overwritten
        while !good_primes_found {
            let p_crypto = crypto_primes::generate_prime::<U1024>(1024);
            let q_crypto = crypto_primes::generate_prime::<U1024>(1024);
            p = Self::crypto_bigint_to_bigint(p_crypto);
            q = Self::crypto_bigint_to_bigint(q_crypto);
            good_primes_found = (&p % (CONSTANT_EXP as u32) != BigUint::new(vec![1]))
                && (&q % (CONSTANT_EXP as u32) != BigUint::new(vec![1]));
        }
        let n = &p * &q;
        let order: BigUint = (&p - (1 as u32)) * (&q - (1 as u32));
        let sk = BigUint::new(vec![CONSTANT_EXP]).modinv(&order).unwrap();
        Self { n, sk }
    }

    pub fn get_pubkey(&self) -> RSAPubkey {
        RSAPubkey { n: self.n.clone() }
    }

    pub fn sign(&self, msg: &RSADigest) -> RSASignature {
        RSASignature {
            sig: msg.val.modpow(&self.sk, &self.n),
        }
    }

    pub fn from_base64(public_key: &str, private_key: &str) -> Self {
        let n_bytes = BASE64_STANDARD.decode(public_key).unwrap();
        let n = BigUint::from_bytes_le(&n_bytes);

        let sk_bytes = BASE64_STANDARD.decode(private_key).unwrap();
        let sk = BigUint::from_bytes_le(&sk_bytes);

        Self { n, sk }
    }
}

impl RSAPubkey {
    pub fn verify(&self, msg: &RSADigest, sig: &RSASignature) -> bool {
        const CONSTANT_EXP: u32 = 65537;
        sig.sig.modpow(&BigUint::new(vec![CONSTANT_EXP]), &self.n) == msg.val
    }

    // TODO: use bincode?
    // TODO: better error handling
    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.n.to_bytes_le())
    }

    pub fn from_base64(base64_str: &str) -> Self {
        let bytes = BASE64_STANDARD.decode(base64_str).unwrap();
        let n = BigUint::from_bytes_le(&bytes);
        RSAPubkey { n }
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;

    use super::{RSADigest, RSAKeypair};

    #[test]
    fn test_sign_and_verify() {
        let msg = RSADigest {
            val: BigUint::new(vec![12, 20, 23]),
        };
        let keypair = RSAKeypair::new();
        let sig = keypair.sign(&msg);
        let pk = keypair.get_pubkey();
        let result = pk.verify(&msg, &sig);
        assert_eq!(result, true);
    }
}
