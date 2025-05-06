use plonky2::field::extension::Extendable;
use plonky2::gadgets::arithmetic::EqualityGenerator;
use plonky2::gadgets::arithmetic_extension::QuotientGeneratorExtension;
use plonky2::gadgets::range_check::LowHighGenerator;
use plonky2::gadgets::split_base::BaseSumGenerator;
use plonky2::gadgets::split_join::{SplitGenerator, WireSplitGenerator};
use plonky2::gates::arithmetic_base::ArithmeticBaseGenerator;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGenerator;
use plonky2::gates::base_sum::BaseSplitGenerator;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::coset_interpolation::InterpolationGenerator;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::exponentiation::ExponentiationGenerator;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup::LookupGenerator;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::lookup_table::LookupTableGenerator;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::multiplication_extension::MulExtensionGenerator;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::poseidon::PoseidonGenerator;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGenerator;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::random_access::RandomAccessGenerator;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing::ReducingGenerator;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::gates::reducing_extension::ReducingGenerator as ReducingExtensionGenerator;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{
    ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
};
use plonky2_u32::gates::add_many_u32::U32AddManyGate;
use plonky2_u32::gates::arithmetic_u32::U32ArithmeticGate;
use plonky2_u32::gates::comparison::ComparisonGate;
use plonky2_u32::gates::range_check_u32::U32RangeCheckGate;
use plonky2_u32::gates::subtraction_u32::U32SubtractionGate;

use plonky2_u32::gadgets::arithmetic_u32::SplitToU32Generator;
use plonky2_u32::gates::add_many_u32::U32AddManyGenerator;
use plonky2_u32::gates::arithmetic_u32::U32ArithmeticGenerator;
use plonky2_u32::gates::comparison::ComparisonGenerator;
use plonky2_u32::gates::range_check_u32::U32RangeCheckGenerator;
use plonky2_u32::gates::subtraction_u32::U32SubtractionGenerator;

use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::util::serialization::gate_serialization::GateSerializer;
use plonky2::util::serialization::generator_serialization::WitnessGeneratorSerializer;
use plonky2::{
    get_gate_tag_impl, get_generator_tag_impl, impl_gate_serializer, impl_generator_serializer,
    read_gate_impl, read_generator_impl,
};

use crate::gadgets::biguint::{BigUintDivRemGenerator, ConditionalZeroGenerator};

#[derive(Debug)]
pub struct RSAGateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for RSAGateSerializer {
    impl_gate_serializer! {
        RSAGateSerializer,
        ArithmeticGate, ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        U32AddManyGate<F, D>,
        U32ArithmeticGate<F,D>,
        ComparisonGate<F,D>,
        U32RangeCheckGate<F,D>,
        U32SubtractionGate<F,D>
    }
}

#[derive(Debug)]
pub struct RSAGeneratorSerializer;
impl<F, const D: usize> WitnessGeneratorSerializer<F, D> for RSAGeneratorSerializer
where
    F: RichField + Extendable<D>,
{
    impl_generator_serializer! {
        DefaultGeneratorSerializer,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
        ConstantGenerator<F>,
        CopyGenerator,
        EqualityGenerator,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LookupGenerator,
        LookupTableGenerator,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        NonzeroTestGenerator,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingGenerator<D>,
        ReducingExtensionGenerator<D>,
        SplitGenerator,
        WireSplitGenerator,
        // u32
        U32ArithmeticGenerator<F, D>,
        U32AddManyGenerator<F, D>,
        ComparisonGenerator<F, D>,
        U32RangeCheckGenerator<F, D>,
        U32SubtractionGenerator<F, D>,

        SplitToU32Generator<F, D>,
        // biguint
        ConditionalZeroGenerator<F, D>,
        BigUintDivRemGenerator<F, D>
    }
}

// TODO:
pub mod serialize_circuit_data {
    use super::{RSAGateSerializer, RSAGeneratorSerializer};
    use crate::gadgets::rsa::{C, D, F};
    use base64::prelude::*;
    use plonky2::plonk::circuit_data::CircuitData;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &CircuitData<F, C, D>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = value
            .to_bytes(&RSAGateSerializer, &RSAGeneratorSerializer)
            .map_err(|_| serde::ser::Error::custom("Failed to convert CircuitData to bytes"))?;
        let base64_str = BASE64_STANDARD.encode(&bytes);
        serializer.serialize_str(&base64_str)
    }

    pub fn deserialize<'de, DE>(deserializer: DE) -> Result<CircuitData<F, C, D>, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(base64_str)
            .map_err(|_| serde::de::Error::custom("Failed to base64 to bytes for circuit"))?;
        let circuit_data =
            CircuitData::<F, C, D>::from_bytes(&bytes, &RSAGateSerializer, &RSAGeneratorSerializer)
                .map_err(|_| serde::de::Error::custom("Failed to convert bytes to CircuitData"));
        circuit_data
    }
}
