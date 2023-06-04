use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::hash::hash_types::RichField;
use plonky2::field::extension::Extendable;

pub struct InclusionTarget {
    pub jwt: Vec<Target>,
    pub credential: Vec<Target>,
}

pub fn make_fast_inclusion_circut<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    jwt_size: usize,
    credential_size: usize,
    start: usize,
) -> InclusionTarget {
    let mut jwt = Vec::new();
    let mut credential = Vec::new();

    for _ in 0..jwt_size {
        jwt.push(builder.add_virtual_target());
    }

    for _ in 0..credential_size {
        credential.push(builder.add_virtual_target());
    }

    for i in 0..credential_size {
        builder.connect(jwt[i + start], credential[i]);
    }

    InclusionTarget { jwt, credential }
}


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::field::types::Field;

    use crate::utils::find_subsequence_u8;

    use super::make_fast_inclusion_circut;

    #[test]
    fn test_inclusion() -> Result<()> {
        let jwt = "123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000";
        let credential = "qwe";

        let jwt_len = jwt.len();
        let credential_len = credential.len();
        let start = find_subsequence_u8(jwt.as_bytes(), credential.as_bytes()).unwrap();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let targets = make_fast_inclusion_circut(&mut builder, jwt_len, credential_len, start);
        let mut pw = PartialWitness::new();

        for i in 0..jwt.len() {
            pw.set_target(targets.jwt[i], F::from_canonical_u8(jwt.as_bytes()[i] as u8));
        }
        for i in 0..credential.len() {
            pw.set_target(targets.credential[i], F::from_canonical_u8(credential.as_bytes()[i] as u8));
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}