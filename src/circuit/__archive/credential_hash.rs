// use plonky2::hash::poseidon::PoseidonHash;
// use plonky2::iop::target::Target;
// use plonky2::plonk::circuit_builder::CircuitBuilder;
// use plonky2::hash::hash_types::{RichField, HashOutTarget};
// use plonky2::field::extension::Extendable;

// pub struct CredentialHashTarget {
//     pub credential: Vec<Target>,
//     pub credential_hash: HashOutTarget,
// }

// pub fn make_credential_hash_circuit<F: RichField + Extendable<D>, const D: usize>(
//     builder: &mut CircuitBuilder<F, D>,
//     credential_size: usize,
// ) -> CredentialHashTarget {
//     let mut credential = Vec::new();
//     let mut credential_hash = builder.add_virtual_hash();

//     for _ in 0..credential_size {
//         credential.push(builder.add_virtual_target());
//     }

//     credential_hash = builder.hash_or_noop::<PoseidonHash>(credential.clone());

//     builder.register_public_inputs(&credential_hash.elements);
//     CredentialHashTarget { credential, credential_hash }
// }

// #[cfg(test)]
// mod tests {
//     use anyhow::Result;
//     use plonky2::iop::witness::{PartialWitness, WitnessWrite};
//     use plonky2::plonk::circuit_builder::CircuitBuilder;
//     use plonky2::plonk::circuit_data::CircuitConfig;
//     use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
//     use plonky2::field::types::Field;

//     use super::make_credential_hash_circuit;

//     #[test]
//     fn test_credential_hash() -> Result<()> {
//         let credential = "xxx@gmail.com";

//         println!("{:?} {:?}", credential.len(), credential.as_bytes());
//         let credential_len = credential.len();

//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

//         let targets = make_credential_hash_circuit(&mut builder, credential_len);
//         let mut pw = PartialWitness::new();

//         for i in 0..credential.len() {
//             pw.set_target(targets.credential[i], F::from_canonical_u8(credential.as_bytes()[i] as u8));
//         }

//         let data = builder.build::<C>();
//         let proof = data.prove(pw).unwrap();

//         for (index, f) in proof.public_inputs.iter().enumerate() {
//             println!("{:?} {:?}", index, f.to_string());
//         }
//         data.verify(proof)
//     }
// }

// // 16077609641986135779733664639008948437400126640357900690929520494375468535663
// // 10908303885807105502714693109461609296821317218363042236688029047615353758563