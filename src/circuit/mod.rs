use std::fs;

pub mod inclusion;
pub mod sha256;

use anyhow::Result;
use log::Level;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2::util::timing::TimingTree;

use self::sha256::make_sha256;
use crate::circuit::inclusion::make_inclusion_circut;
use crate::utils::{array_to_bits, find_subsequence};
use sha2::{Digest, Sha256};

pub fn prove(jwt: &[u8], credential: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(jwt);
    let expected_hash = hasher.finalize();

    let jwt_bits = array_to_bits(jwt);
    let credential_bits = array_to_bits(credential);
    let expected_hash  = array_to_bits(expected_hash.as_slice());

    let jwt_size = jwt_bits.len();
    let credential_size = credential_bits.len();

    let start = find_subsequence(&jwt_bits, &credential_bits).expect("Credential not found in JWT Claims");
    
    /* START CIRCUIT CONSTRUCTION  */
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // SHA256 Proof Segment
    let targets_sha256 = make_sha256(&mut builder, jwt_size as u64);
    let target_inclusion = make_inclusion_circut(&mut builder, jwt_size, credential_size, start);
    let mut pw = PartialWitness::new();

    for i in 0..jwt_size {
        pw.set_bool_target(targets_sha256.message[i], jwt_bits[i]);
    }

    for i in 0..credential_size {
        pw.set_bool_target(target_inclusion.credential[i], credential_bits[i]);
    }

    for i in 0..jwt_size {
        pw.set_bool_target(target_inclusion.jwt[i], jwt_bits[i]);
    }

    for i in 0..expected_hash.len() {
        if expected_hash[i] {
            builder.assert_one(targets_sha256.digest[i].target);
        } else {
            builder.assert_zero(targets_sha256.digest[i].target);
        }
    }
    /* END CIRCUIT CONSTRUCTION */

    for i in 0..expected_hash.len() {
        builder.register_public_input(targets_sha256.digest[i].target);
    }

    log::info!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();

    /* Serialize Circuit */
    let timing = TimingTree::new("serde_circuit", Level::Debug);
    let common_circuit_data_serialized = serde_json::to_string(&data.common).unwrap();
    fs::write("common_circuit_data.json", common_circuit_data_serialized)
        .expect("Unable to write file");

    let verifier_only_circuit_data_serialized = serde_json::to_string(&data.verifier_only).unwrap();
    fs::write(
        "verifier_only_circuit_data.json",
        verifier_only_circuit_data_serialized,
    )
    .expect("Unable to write file");
    timing.print();

    /* Prove */
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw)?;
    timing.print();

    /* Serde Prove */
    let timing = TimingTree::new("serde_circuit", Level::Debug);
    let proof_serialized = serde_json::to_string(&proof).unwrap();
    fs::write("proof_with_public_inputs.json", proof_serialized).expect("Unable to write file");
    timing.print();

    Ok(())
}
