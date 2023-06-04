// use plonky2::iop::target::Target;
// use plonky2::plonk::circuit_builder::CircuitBuilder;
// use plonky2::hash::hash_types::RichField;
// use plonky2::field::extension::Extendable;

// pub struct InclusionTarget {
//     pub jwt: Vec<Target>,
//     pub credential: Vec<Target>,
// }

// pub fn make_inclusion_circut<F: RichField + Extendable<D>, const D: usize>(
//     builder: &mut CircuitBuilder<F, D>,
//     jwt_size: usize,
//     credential_size: usize,
// ) -> InclusionTarget {
//     let mut jwt = Vec::new();
//     let mut credential = Vec::new();

//     for _ in 0..jwt_size {
//         jwt.push(builder.add_virtual_target());
//     }

//     for _ in 0..credential_size {
//         credential.push(builder.add_virtual_target());
//     }
//     // let start = builder.add_virtual_target();

//     /* selector range_check */
//     // let zero = builder.zero();
//     // let one = builder.one();
//     // let two = builder.two();

//     // let jwt_len = builder.constant(F::from_canonical_usize(jwt_size));
//     // let credential_len = builder.constant(F::from_canonical_usize(credential_size));
//     // let max_reached_range = builder.add(start, credential_len);
//     // let max_avaliable_range = builder.add(jwt_len, one);

//     // // Proof: max_reached_range <= jwt_len 
//     // // >> max_reached_range < jwt_len + 1
//     // let mask = builder.exp_u64(two, 32 as u64);
//     // let front = builder.add(max_reached_range, mask);
//     // let end = builder.sub(front, max_avaliable_range);

//     // let comp = builder.split_le(end, 32 + 1);
//     // builder.connect(comp[32].target, zero);
//     /* END selector range_check */

//     let mut start = 0;
//     let mut final_result = builder._false();
//     while start + credential_size < jwt_size {
//         let mut result = builder._true();
//         for index in 0..credential_size {
//             let j = jwt[index + start];
//             let c = credential[index];

//             let cur_result = builder.is_equal(j, c);
//             result = builder.and(cur_result, result);
//         }
//         final_result = builder.or(final_result, result);

//         start += 1;
//     }

//     let t = builder._true();
//     builder.connect(final_result.target, t.target);

//     // for step in 0..credential_size {
//     //     let s = builder.constant(F::from_canonical_usize(step));
//     //     let index = builder.add(s, start);

//     //     // the jwt
//     //     let j = builder.random_access(index, jwt.clone());
//     //     let c = builder.random_access(s, credential.clone());

//     //     builder.connect(j, c);
//     // }

//     InclusionTarget { jwt, credential }
// }


// #[cfg(test)]
// mod tests {
//     use anyhow::Result;
//     use plonky2::iop::witness::{PartialWitness, WitnessWrite};
//     use plonky2::plonk::circuit_builder::CircuitBuilder;
//     use plonky2::plonk::circuit_data::CircuitConfig;
//     use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
//     use plonky2::field::types::Field;

//     use crate::circuit::inclusion::make_inclusion_circut;

//     #[test]
//     fn test_inclusion() -> Result<()> {
//         let jwt = "123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000123qwe1111asd000";
//         let credential = "qwe";

//         let jwt_len = jwt.len();
//         let credential_len = credential.len();
    
//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

//         let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len);
//         let mut pw = PartialWitness::new();

//         for i in 0..jwt.len() {
//             pw.set_target(targets.jwt[i], F::from_canonical_u8(jwt.as_bytes()[i] as u8));
//         }
//         for i in 0..credential.len() {
//             pw.set_target(targets.credential[i], F::from_canonical_u8(credential.as_bytes()[i] as u8));
//         }

//         let data = builder.build::<C>();
//         let proof = data.prove(pw).unwrap();
//         data.verify(proof)
//     }

//     #[test]
//     #[should_panic]
//     fn overflow() {
//         let jwt = "123qwe1111asd000";
//         let credential = "qwe0";

//         let jwt_len = jwt.len();
//         let credential_len = credential.len();
    
//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

//         let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len);
//         let mut pw = PartialWitness::new();

//         for i in 0..jwt.len() {
//             pw.set_target(targets.jwt[i], F::from_canonical_u8(jwt.as_bytes()[i] as u8));
//         }
//         for i in 0..credential.len() {
//             pw.set_target(targets.credential[i], F::from_canonical_u8(credential.as_bytes()[i] as u8));
//         }

//         let data = builder.build::<C>();
//         let proof = data.prove(pw).unwrap();
//         data.verify(proof).unwrap();
//     }
// }
