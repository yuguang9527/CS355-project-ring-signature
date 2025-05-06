use core::marker::PhantomData;

use anyhow::Result;
use num::{BigUint, Integer, Zero};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field64, PrimeField, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_u32::gadgets::multiple_comparison::list_le_u32_circuit;
use plonky2_u32::serialization::{ReadU32, WriteU32};
use plonky2_u32::witness::{GeneratedValuesU32, WitnessU32};
use serde::{Deserialize, Serialize};

/// `BigUintTarget` represents a big unsigned integer in a circuit.
/// It stores a vector of 32-bit limbs, with the least significant limb at index 0.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BigUintTarget {
    pub limbs: Vec<U32Target>,
}

impl BigUintTarget {
    /// Returns the number of limbs in this big integer.
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    /// Get the limb at the specified index.
    pub fn get_limb(&self, i: usize) -> U32Target {
        self.limbs[i]
    }
}

/// Trait for circuit builders that can handle big unsigned integers.
/// This trait provides the functionality to create, manipulate, and
/// perform arithmetic operations on `BigUintTarget`s within a circuit.
pub trait CircuitBuilderBiguint<F: RichField + Extendable<D>, const D: usize> {
    /// Create a constant `BigUintTarget` with the provided value.
    fn constant_biguint(&mut self, value: &BigUint) -> BigUintTarget;

    /// Create a `BigUintTarget` with value zero.
    fn zero_biguint(&mut self) -> BigUintTarget;

    /// Connect two `BigUintTarget`s, constraining them to be equal.
    fn connect_biguint(&mut self, lhs: &BigUintTarget, rhs: &BigUintTarget);

    /// Pad two `BigUintTarget`s to have the same number of limbs.
    /// Returns the padded versions, with the shorter one extended with zero limbs.
    fn pad_biguints(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget);

    /// Check if two `BigUintTarget`s are equal, returning a boolean target.
    fn eq_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget;

    /// Compare two `BigUintTarget`s, returning a boolean target that's true if a <= b.
    fn cmp_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget;

    /// Add a virtual `BigUintTarget` to the circuit with the specified number of limbs.
    fn add_virtual_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget;

    /// Add a virtual public `BigUintTarget` to the circuit with the specified number of limbs.
    /// These targets will be part of the public inputs to the circuit.
    fn add_virtual_public_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget;

    /// Add two `BigUintTarget`s.
    fn add_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    /// Subtract two `BigUintTarget`s.
    /// Assumes that the first is larger than the second (a >= b).
    fn sub_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    /// Multiply two `BigUintTarget`s.
    fn mul_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    /// Multiply a `BigUintTarget` by a boolean target (0 or 1).
    fn mul_biguint_by_bool(&mut self, a: &BigUintTarget, b: BoolTarget) -> BigUintTarget;

    /// Returns x * y + z.
    /// This is a convenience method combining multiplication and addition.
    fn mul_add_biguint(
        &mut self,
        x: &BigUintTarget,
        y: &BigUintTarget,
        z: &BigUintTarget,
    ) -> BigUintTarget;

    /// Divide one `BigUintTarget` by another, returning both quotient and remainder.
    fn div_rem_biguint(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget);

    /// Divide one `BigUintTarget` by another, returning just the quotient.
    fn div_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    /// Compute the remainder when dividing one `BigUintTarget` by another.
    fn rem_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;

    /// Conditionally sets a target to zero.
    /// If if_zero is zero, then_zero must be zero.
    fn conditional_zero(&mut self, if_zero: Target, then_zero: Target);
}

/// Trait for circuit builders that can convert field elements to `BigUintTarget`s.
pub trait CircuitBuilderBiguintFromField {
    fn field_to_biguint(&mut self, a: Target) -> BigUintTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderBiguint<F, D>
    for CircuitBuilder<F, D>
{
    /// Create a constant `BigUintTarget` with the given value.
    fn constant_biguint(&mut self, value: &BigUint) -> BigUintTarget {
        let limb_values = value.to_u32_digits();
        let limbs = limb_values.iter().map(|&l| self.constant_u32(l)).collect();

        BigUintTarget { limbs }
    }

    /// Create a `BigUintTarget` with value zero.
    fn zero_biguint(&mut self) -> BigUintTarget {
        self.constant_biguint(&BigUint::zero())
    }

    /// Connect two `BigUintTarget`s, constraining them to be equal.
    fn connect_biguint(&mut self, lhs: &BigUintTarget, rhs: &BigUintTarget) {
        let min_limbs = lhs.num_limbs().min(rhs.num_limbs());
        for i in 0..min_limbs {
            self.connect_u32(lhs.get_limb(i), rhs.get_limb(i));
        }

        // Ensure that any extra limbs are zero
        for i in min_limbs..lhs.num_limbs() {
            self.assert_zero_u32(lhs.get_limb(i));
        }
        for i in min_limbs..rhs.num_limbs() {
            self.assert_zero_u32(rhs.get_limb(i));
        }
    }

    /// Pad two `BigUintTarget`s to have the same number of limbs.
    fn pad_biguints(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget) {
        if a.num_limbs() > b.num_limbs() {
            let mut padded_b = b.clone();
            for _ in b.num_limbs()..a.num_limbs() {
                padded_b.limbs.push(self.zero_u32());
            }

            (a.clone(), padded_b)
        } else {
            let mut padded_a = a.clone();
            for _ in a.num_limbs()..b.num_limbs() {
                padded_a.limbs.push(self.zero_u32());
            }

            (padded_a, b.clone())
        }
    }

    /// Check if two `BigUintTarget`s are equal, returning a boolean target.
    fn eq_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget {
        let (a, b) = self.pad_biguints(a, b);

        let mut result = self.constant_bool(true);
        for i in 0..a.num_limbs() {
            let limb_eq = self.is_equal(a.limbs[i].0, b.limbs[i].0);
            result = self.and(result, limb_eq);
        }
        result
    }

    /// Compare two `BigUintTarget`s, returning a boolean target that's true if a <= b.
    fn cmp_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget {
        let (a, b) = self.pad_biguints(a, b);

        list_le_u32_circuit(self, a.limbs, b.limbs)
    }

    /// Add a virtual `BigUintTarget` to the circuit with the specified number of limbs.
    fn add_virtual_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget {
        let limbs = self.add_virtual_u32_targets(num_limbs);

        BigUintTarget { limbs }
    }

    /// Add a virtual public `BigUintTarget` to the circuit with the specified number of limbs.
    /// These targets will be part of the public inputs to the circuit.
    fn add_virtual_public_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget {
        let limbs = (0..num_limbs)
            .map(|_| self.add_virtual_public_input())
            .map(U32Target::new_unsafe)
            .collect();

        BigUintTarget { limbs }
    }

    /// Add two `BigUintTarget`s.
    fn add_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let num_limbs = a.num_limbs().max(b.num_limbs());

        let mut combined_limbs = vec![];
        let mut carry = self.zero_u32();
        for i in 0..num_limbs {
            let a_limb = (i < a.num_limbs())
                .then(|| a.limbs[i])
                .unwrap_or_else(|| self.zero_u32());
            let b_limb = (i < b.num_limbs())
                .then(|| b.limbs[i])
                .unwrap_or_else(|| self.zero_u32());

            let (new_limb, new_carry) = self.add_many_u32(&[carry, a_limb, b_limb]);
            carry = new_carry;
            combined_limbs.push(new_limb);
        }
        combined_limbs.push(carry);

        BigUintTarget {
            limbs: combined_limbs,
        }
    }

    /// Subtract two `BigUintTarget`s. Assumes that the first is larger than the second (a >= b).
    fn sub_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let (a, b) = self.pad_biguints(a, b);
        let num_limbs = a.limbs.len();

        let mut result_limbs = vec![];

        let mut borrow = self.zero_u32();
        for i in 0..num_limbs {
            let (result, new_borrow) = self.sub_u32(a.limbs[i], b.limbs[i], borrow);
            result_limbs.push(result);
            borrow = new_borrow;
        }
        self.assert_zero_u32(borrow);

        BigUintTarget {
            limbs: result_limbs,
        }
    }

    /// Multiply two `BigUintTarget`s.
    fn mul_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let total_limbs = a.limbs.len() + b.limbs.len();

        let mut to_add = vec![vec![]; total_limbs];
        for i in 0..a.limbs.len() {
            for j in 0..b.limbs.len() {
                let (product, carry) = self.mul_u32(a.limbs[i], b.limbs[j]);
                to_add[i + j].push(product);
                to_add[i + j + 1].push(carry);
            }
        }

        let mut combined_limbs = vec![];
        let mut carry = self.zero_u32();
        for summands in &mut to_add {
            let (new_result, new_carry) = self.add_u32s_with_carry(summands, carry);
            combined_limbs.push(new_result);
            carry = new_carry;
        }
        combined_limbs.push(carry);

        BigUintTarget {
            limbs: combined_limbs,
        }
    }

    /// Multiply a `BigUintTarget` by a boolean target (0 or 1).
    fn mul_biguint_by_bool(&mut self, a: &BigUintTarget, b: BoolTarget) -> BigUintTarget {
        let t = b.target;

        BigUintTarget {
            limbs: a
                .limbs
                .iter()
                .map(|&l| U32Target::new_unsafe(self.mul(l.0, t)))
                .collect(),
        }
    }

    /// Returns x * y + z.
    /// This is a convenience method combining multiplication and addition.
    fn mul_add_biguint(
        &mut self,
        x: &BigUintTarget,
        y: &BigUintTarget,
        z: &BigUintTarget,
    ) -> BigUintTarget {
        let prod = self.mul_biguint(x, y);
        self.add_biguint(&prod, z)
    }

    /// Divide one `BigUintTarget` by another, returning both quotient and remainder.
    fn div_rem_biguint(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget) {
        let a_len = a.limbs.len();
        let b_len = b.limbs.len();
        let div_num_limbs = if b_len > a_len + 1 {
            0
        } else {
            a_len + 1 - b_len
        };
        let div = self.add_virtual_biguint_target(div_num_limbs);
        let rem = self.add_virtual_biguint_target(b_len);

        self.add_simple_generator(BigUintDivRemGenerator::<F, D> {
            a: a.clone(),
            b: b.clone(),
            div: div.clone(),
            rem: rem.clone(),
            _phantom: PhantomData,
        });

        let div_b = self.mul_biguint(&div, b);
        let div_b_plus_rem = self.add_biguint(&div_b, &rem);
        self.connect_biguint(a, &div_b_plus_rem);

        let cmp_rem_b = self.cmp_biguint(&rem, b);
        self.assert_one(cmp_rem_b.target);

        (div, rem)
    }

    /// Divide one `BigUintTarget` by another, returning just the quotient.
    fn div_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let (div, _rem) = self.div_rem_biguint(a, b);
        div
    }

    /// Compute the remainder when dividing one `BigUintTarget` by another.
    fn rem_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let (_div, rem) = self.div_rem_biguint(a, b);
        rem
    }

    /// Conditionally sets a target to zero.
    /// If if_zero is zero, then_zero must be zero.
    fn conditional_zero(&mut self, if_zero: Target, then_zero: Target) {
        let quot = self.add_virtual_target();
        self.add_simple_generator(ConditionalZeroGenerator {
            if_zero,
            then_zero,
            quot,
            _phantom: PhantomData::<F>,
        });
        let prod = self.mul(if_zero, quot);
        self.connect(prod, then_zero);
    }
}

/// Generator that enforces the condition: if if_zero is zero, then then_zero must be zero.
#[derive(Debug, Default)]
pub struct ConditionalZeroGenerator<F: RichField + Extendable<D>, const D: usize> {
    if_zero: Target,
    then_zero: Target,
    quot: Target,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for ConditionalZeroGenerator<F, D>
{
    fn id(&self) -> String {
        "ConditionalZeroGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        vec![self.if_zero, self.then_zero]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let if_zero = witness.get_target(self.if_zero);
        let then_zero = witness.get_target(self.then_zero);
        if if_zero.is_zero() {
            out_buffer.set_target(self.quot, F::ZERO)?;
        } else {
            out_buffer.set_target(self.quot, then_zero / if_zero)?;
        }

        Ok(())
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.if_zero)?;
        dst.write_target(self.then_zero)?;
        dst.write_target(self.quot)
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &CommonCircuitData<F, D>,
    ) -> IoResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            if_zero: src.read_target()?,
            then_zero: src.read_target()?,
            quot: src.read_target()?,
            _phantom: PhantomData,
        })
    }
}

/// Implementation of CircuitBuilderBiguintFromField specifically for GoldilocksField
impl CircuitBuilderBiguintFromField for CircuitBuilder<GoldilocksField, 2> {
    /// Convert a field element to a BigUintTarget.
    /// The field element is split into two 32-bit limbs.
    fn field_to_biguint(&mut self, a: Target) -> BigUintTarget {
        let (low, high) = self.split_low_high(a, 32, 64);
        // make sure that low = 0 if high = 2^32 - 1
        let max = self.constant(GoldilocksField::from_canonical_i64(0xFFFFFFFF));
        let high_minus_max = self.sub(high, max);
        self.conditional_zero(high_minus_max, low);
        let limbs = vec![U32Target::new_unsafe(low), U32Target::new_unsafe(high)];
        BigUintTarget { limbs }
    }
}

/// Trait for handling BigUintTarget in witnesses.
pub trait WitnessBigUint<F: PrimeField64>: Witness<F> {
    fn get_biguint_target(&self, target: BigUintTarget) -> BigUint;
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()>;
}

impl<T: Witness<F>, F: PrimeField64> WitnessBigUint<F> for T {
    /// Extract a BigUint value from a witness.
    fn get_biguint_target(&self, target: BigUintTarget) -> BigUint {
        target
            .limbs
            .into_iter()
            .rev()
            .fold(BigUint::zero(), |acc, limb| {
                (acc << 32) + self.get_target(limb.0).to_canonical_biguint()
            })
    }

    /// Set a BigUint value in a witness.
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()> {
        let mut limbs = value.to_u32_digits();
        assert!(target.num_limbs() >= limbs.len());
        limbs.resize(target.num_limbs(), 0);
        for i in 0..target.num_limbs() {
            self.set_u32_target(target.limbs[i], limbs[i])?;
        }
        Ok(())
    }
}

/// Trait for setting BigUintTarget values in generated values.
pub trait GeneratedValuesBigUint<F: PrimeField> {
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()>;
}

impl<F: PrimeField> GeneratedValuesBigUint<F> for GeneratedValues<F> {
    /// Set a BigUint value in generated values.
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()> {
        let mut limbs = value.to_u32_digits();
        assert!(target.num_limbs() >= limbs.len());
        limbs.resize(target.num_limbs(), 0);
        for i in 0..target.num_limbs() {
            self.set_u32_target(target.get_limb(i), limbs[i])?;
        }
        Ok(())
    }
}

/// Trait for serializing BigUintTarget values.
pub trait WriteBigUint {
    fn write_target_biguint(&mut self, x: &BigUintTarget) -> IoResult<()>;
}

impl<W: WriteU32 + Write> WriteBigUint for W {
    /// Serialize a BigUintTarget to a writer.
    fn write_target_biguint(&mut self, x: &BigUintTarget) -> IoResult<()> {
        self.write_usize(x.num_limbs())?;
        for limb in &x.limbs {
            self.write_target_u32(*limb)?;
        }
        Ok(())
    }
}

/// Trait for deserializing BigUintTarget values.
pub trait ReadBigUint {
    fn read_target_biguint(&mut self) -> IoResult<BigUintTarget>;
}

impl ReadBigUint for Buffer<'_> {
    /// Deserialize a BigUintTarget from a buffer.
    fn read_target_biguint(&mut self) -> IoResult<BigUintTarget> {
        let num_limbs = self.read_usize()?;
        let mut limbs = Vec::with_capacity(num_limbs);
        while limbs.len() < num_limbs {
            limbs.push(self.read_target_u32()?);
        }
        Ok(BigUintTarget { limbs })
    }
}

/// Generator for computing division and remainder of BigUintTargets.
#[derive(Debug, Default)]
pub struct BigUintDivRemGenerator<F: RichField + Extendable<D>, const D: usize> {
    a: BigUintTarget,
    b: BigUintTarget,
    div: BigUintTarget,
    rem: BigUintTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for BigUintDivRemGenerator<F, D>
{
    fn id(&self) -> String {
        "BigUintDivRemGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.a
            .limbs
            .iter()
            .chain(&self.b.limbs)
            .map(|&l| l.0)
            .collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let a = witness.get_biguint_target(self.a.clone());
        let b = witness.get_biguint_target(self.b.clone());
        let (div, rem) = a.div_rem(&b);

        out_buffer.set_biguint_target(&self.div, &div)?;
        out_buffer.set_biguint_target(&self.rem, &rem)?;
        Ok(())
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target_biguint(&self.a)?;
        dst.write_target_biguint(&self.b)?;
        dst.write_target_biguint(&self.div)?;
        dst.write_target_biguint(&self.rem)
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &CommonCircuitData<F, D>,
    ) -> IoResult<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            a: src.read_target_biguint()?,
            b: src.read_target_biguint()?,
            div: src.read_target_biguint()?,
            rem: src.read_target_biguint()?,
            _phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num::{BigUint, FromPrimitive, Integer};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    use crate::gadgets::biguint::{CircuitBuilderBiguint, WitnessBigUint};

    fn random_u128(rng: &mut OsRng) -> Result<u128> {
        let mut bytes = [0u8; 16];
        rng.try_fill_bytes(&mut bytes)?;
        Ok(u128::from_ne_bytes(bytes))
    }

    #[test]
    fn test_biguint_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let x_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let y_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let expected_z_value = &x_value + &y_value;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
        let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());
        let z = builder.add_biguint(&x, &y);
        let expected_z = builder.add_virtual_biguint_target(expected_z_value.to_u32_digits().len());
        builder.connect_biguint(&z, &expected_z);

        pw.set_biguint_target(&x, &x_value)?;
        pw.set_biguint_target(&y, &y_value)?;
        pw.set_biguint_target(&expected_z, &expected_z_value)?;

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_sub() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let mut x_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let mut y_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        if y_value > x_value {
            (x_value, y_value) = (y_value, x_value);
        }
        let expected_z_value = &x_value - &y_value;

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_biguint(&x_value);
        let y = builder.constant_biguint(&y_value);
        let z = builder.sub_biguint(&x, &y);
        let expected_z = builder.constant_biguint(&expected_z_value);

        builder.connect_biguint(&z, &expected_z);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_mul() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let x_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let y_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let expected_z_value = &x_value * &y_value;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
        let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());
        let z = builder.mul_biguint(&x, &y);
        let expected_z = builder.add_virtual_biguint_target(expected_z_value.to_u32_digits().len());
        builder.connect_biguint(&z, &expected_z);

        pw.set_biguint_target(&x, &x_value)?;
        pw.set_biguint_target(&y, &y_value)?;
        pw.set_biguint_target(&expected_z, &expected_z_value)?;

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_cmp() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let x_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let y_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_biguint(&x_value);
        let y = builder.constant_biguint(&y_value);
        let cmp = builder.cmp_biguint(&x, &y);
        let expected_cmp = builder.constant_bool(x_value <= y_value);

        builder.connect(cmp.target, expected_cmp.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_biguint_div_rem() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = OsRng;

        let mut x_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        let mut y_value = BigUint::from_u128(random_u128(&mut rng)?).unwrap();
        if y_value > x_value {
            (x_value, y_value) = (y_value, x_value);
        }
        let (expected_div_value, expected_rem_value) = x_value.div_rem(&y_value);

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.constant_biguint(&x_value);
        let y = builder.constant_biguint(&y_value);
        let (div, rem) = builder.div_rem_biguint(&x, &y);

        let expected_div = builder.constant_biguint(&expected_div_value);
        let expected_rem = builder.constant_biguint(&expected_rem_value);

        builder.connect_biguint(&div, &expected_div);
        builder.connect_biguint(&rem, &expected_rem);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
