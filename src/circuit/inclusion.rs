use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::hash::hash_types::RichField;
use plonky2::field::extension::Extendable;

pub struct InclusionTarget {
    pub jwt: Vec<BoolTarget>,
    pub credential: Vec<BoolTarget>,
}

pub fn make_inclusion_circut<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    jwt_size: usize,
    credential_size: usize,
    start: usize,
) -> InclusionTarget {
    assert!(credential_size + start <= jwt_size);

    let mut jwt = Vec::new();
    let mut credential = Vec::new();

    for _ in 0..jwt_size {
        jwt.push(builder.add_virtual_bool_target_safe());
    }

    for _ in 0..credential_size {
        credential.push(builder.add_virtual_bool_target_safe());
    }

    /* selector range_check */
    // let zero = builder.zero();
    // let one = builder.one();
    // let two = builder.two();

    // let jwt_len = builder.constant(F::from_canonical_usize(jwt_size));
    // let max_reached_range = builder.constant(F::from_canonical_usize(start + credential_size));
    // let max_avaliable_range = builder.add(jwt_len, one);

    // We shouldn't need an array range check here    
    // // Proof: max_reached_range <= jwt_len 
    // // >> max_reached_range < jwt_len + 1
    // let mask = builder.exp_u64(two, max_bits_len as u64);
    // let front = builder.add(max_reached_range, mask);
    // let end = builder.sub(front, max_avaliable_range);

    // let comp = builder.split_le(end, max_bits_len + 1);
    // builder.connect(comp[max_bits_len].target, zero);
    // /* END selector range_check */

    for step in 0..credential_size {
        builder.connect(jwt[start + step].target, credential[step].target);
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

    use crate::circuit::inclusion::make_inclusion_circut;
    use crate::utils::{array_to_bits, find_subsequence};

    #[test]
    fn test_inclusion() -> Result<()> {
        let full = "123qwe1111asd";
        let target = "qwe";

        let jwt_bits = array_to_bits(full.as_bytes());
        let credential_bits = array_to_bits(target.as_bytes());
        let start = find_subsequence(&jwt_bits, &credential_bits).unwrap();

        let jwt_len = jwt_bits.len();
        let credential_len = credential_bits.len();
    
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len, start);
        let mut pw = PartialWitness::new();

        for i in 0..jwt_len {
            pw.set_bool_target(targets.jwt[i], jwt_bits[i]);
        }
        for i in 0..credential_len {
            pw.set_bool_target(targets.credential[i], credential_bits[i]);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn overflow() {
        let full = "123qwe";
        let target = "qwe";
        let start = full.len() - 2;
        
        let jwt_bits = array_to_bits(full.as_bytes());
        let credential_bits = array_to_bits(target.as_bytes());
    
        let jwt_len = jwt_bits.len();
        let credential_len = credential_bits.len();
    
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len, start);
        let mut pw = PartialWitness::new();

        for i in 0..jwt_len {
            pw.set_bool_target(targets.jwt[i], jwt_bits[i]);
        }
        for i in 0..credential_len {
            pw.set_bool_target(targets.credential[i], credential_bits[i]);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
