use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;

pub struct InclusionTarget {
    pub jwt: Vec<Target>,
    pub credential: Vec<Target>,
}

pub fn make_inclusion_circut<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    jwt_size: usize,
    credential_size: usize,
    start: usize,
    max_bits_len: usize,
) -> InclusionTarget {
    assert!(credential_size + start <= jwt_size);

    let mut jwt = Vec::new();
    let mut credential = Vec::new();

    for _ in 0..jwt_size {
        jwt.push(builder.add_virtual_target());
    }

    for _ in 0..credential_size {
        credential.push(builder.add_virtual_target());
    }

    /* selector range_check */
    let zero = builder.zero();
    let one = builder.one();
    let two = builder.two();

    let jwt_len = builder.constant(F::from_canonical_usize(jwt_size));
    let max_reached_range = builder.constant(F::from_canonical_usize(start + credential_size));
    let max_avaliable_range = builder.add(jwt_len, one);
    
    // Proof: max_reached_range <= jwt_len 
    // >> max_reached_range < jwt_len + 1
    let mask = builder.exp_u64(two, max_bits_len as u64);
    let front = builder.add(max_reached_range, mask);
    let end = builder.sub(front, max_avaliable_range);

    let comp = builder.split_le(end, max_bits_len + 1);
    builder.connect(comp[max_bits_len].target, zero);
    /* END selector range_check */

    // jwt[start .. start + credential_size].sum() === credential.sum()
    let mut jwt_acc = builder.zero();
    let mut credential_acc = builder.zero();

    for step in 0..credential_size {
        credential_acc = builder.add(credential_acc, credential[step]);
        jwt_acc = builder.add(jwt_acc, jwt[start + step]);
    }

    builder.connect(jwt_acc, credential_acc);

    InclusionTarget { jwt, credential }
}


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::types::Field;

    use crate::circuit::inclusion::make_inclusion_circut;

    #[test]
    fn test_inclusion() -> Result<()> {
        let full = "123qwe1111asd";
        let target = "qwe";
        let start = 3;
        
        let jwt_len = full.len();
        let credential_len = target.len();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len, start, 4);
        let mut pw = PartialWitness::new();

        for i in 0..jwt_len {
            pw.set_target(targets.jwt[i], F::from_canonical_u8(full.as_bytes()[i]));
        }
        for i in 0..credential_len {
            pw.set_target(targets.credential[i], F::from_canonical_u8(target.as_bytes()[i]));
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn overflow() {
        let full = "123qwe1111asd";
        let target = "qwe";
        let start = full.len() - 1;
        
        let jwt_len = full.len();
        let credential_len = target.len();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len, start, 4);
        let mut pw = PartialWitness::new();

        for i in 0..jwt_len {
            pw.set_target(targets.jwt[i], F::from_canonical_u8(full.as_bytes()[i]));
        }
        for i in 0..credential_len {
            pw.set_target(targets.credential[i], F::from_canonical_u8(target.as_bytes()[i]));
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).expect("to pass verification");
    }
}
