pub mod inclusion;
pub mod sha256;
pub mod split_base;

use anyhow::Result;
use log::Level;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2_field::types::Field;

use self::sha256::make_sha256;
use crate::circuit::inclusion::make_inclusion_circut;
use crate::utils::{array_to_bits, find_subsequence, max_bit_len};
use sha2::{Digest, Sha256};


pub fn prove(jwt: &[u8], credential: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(jwt);
    let expected_hash = hasher.finalize();

    let jwt_bits = array_to_bits(jwt);
    let len = jwt.len() * 8;

    let jwt_len = jwt.len();
    let credential_len = credential.len();

    let _sha256_proof = {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_sha256(&mut builder, len as u64);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], jwt_bits[i]);
        }

        let expected_res = array_to_bits(expected_hash.as_slice());
        for i in 0..expected_res.len() {
            if expected_res[i] {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        println!(
            "Constructing inner proof with {} gates",
            builder.num_gates()
        );
        let data = builder.build::<C>();
        let timing = TimingTree::new("prove", Level::Debug);
        let proof = data.prove(pw).unwrap();
        timing.print();

        let timing = TimingTree::new("verify", Level::Debug);
        data.verify(proof.clone()).expect("Proof verification error");
        timing.print();

        proof
    };
    
    let _inclusion_proof = {
        let start = find_subsequence(&jwt, &credential).expect("Credential not found in JWT Claims");
        let bit_len = max_bit_len(jwt_len, credential_len);
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_inclusion_circut(&mut builder, jwt_len, credential_len, start, bit_len);
        let mut pw = PartialWitness::new();

        for i in 0..jwt_len {
            pw.set_target(targets.jwt[i], F::from_canonical_u8(jwt[i]));
        }
        for i in 0..credential_len {
            pw.set_target(targets.credential[i], F::from_canonical_u8(credential[i]));
        }

        println!(
            "Constructing inner proof with {} gates",
            builder.num_gates()
        );
        let data = builder.build::<C>();
        let timing = TimingTree::new("prove", Level::Debug);
        let proof = data.prove(pw).unwrap();
        timing.print();

        let timing = TimingTree::new("verify", Level::Debug);
        data.verify(proof.clone()).expect("Proof verification error");
        timing.print();

        proof
    };
    
    Ok(())
}
