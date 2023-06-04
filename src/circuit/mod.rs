// pub mod inclusion;
pub mod fast_inclusion;
// pub mod credential_hash;
pub mod sha256;

use anyhow::Result;
use log::Level;

use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2::plonk::proof::CompressedProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use plonky2::util::timing::TimingTree;

use self::sha256::make_sha256;
use crate::circuit::fast_inclusion::make_fast_inclusion_circut;
use crate::utils::{array_to_bits, find_subsequence_u8, extract_hashes_from_public_inputs};
use sha2::{Digest, Sha256};

pub fn prove(jwt: &[u8], credential: &[u8]) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32])> {
    let mut hasher_jwt = Sha256::new();
    hasher_jwt.update(jwt);
    let expected_hash_jwt = hasher_jwt.finalize();
    let expected_hash_jwt = array_to_bits(expected_hash_jwt.as_slice());

    let mut hasher_credential = Sha256::new();
    hasher_credential.update(credential);
    let expected_hash_credential = hasher_credential.finalize();
    let expected_hash_credential = array_to_bits(expected_hash_credential.as_slice());


    let jwt_bits = array_to_bits(jwt);
    let credential_bits = array_to_bits(credential);

    let jwt_size = jwt.len();
    let credential_size = credential.len();

    let inclusion_start = find_subsequence_u8(jwt, credential).expect("Unable to find credential in JWT claim");

    /* START CIRCUIT CONSTRUCTION  */
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // SHA256 Proof Segment
    let targets_sha256_jwt = make_sha256(&mut builder, (jwt_size * 8) as u64);
    let targets_sha256_credential = make_sha256(&mut builder, (credential_size * 8) as u64);
    let target_inclusion = make_fast_inclusion_circut(&mut builder, jwt_size, credential_size, inclusion_start);

    let mut pw = PartialWitness::new();

    for i in 0..jwt_size * 8 {
        pw.set_bool_target(targets_sha256_jwt.message[i], jwt_bits[i]);
    }
    for i in 0..credential_size * 8 {
        pw.set_bool_target(targets_sha256_credential.message[i], credential_bits[i]);
    }

    for i in 0..jwt_size {
        pw.set_target(target_inclusion.jwt[i], F::from_canonical_usize(jwt[i] as usize));
    }
    for i in 0..credential_size {
        pw.set_target(target_inclusion.credential[i], F::from_canonical_usize(credential[i] as usize));
    }

    for i in 0..expected_hash_jwt.len() {
        if expected_hash_jwt[i] {
            builder.assert_one(targets_sha256_jwt.digest[i].target);
        } else {
            builder.assert_zero(targets_sha256_jwt.digest[i].target);
        }
    }

    for i in 0..expected_hash_credential.len() {
        if expected_hash_credential[i] {
            builder.assert_one(targets_sha256_credential.digest[i].target);
        } else {
            builder.assert_zero(targets_sha256_credential.digest[i].target);
        }
    }
    /* END CIRCUIT CONSTRUCTION */

    for i in 0..expected_hash_jwt.len() {
        builder.register_public_input(targets_sha256_jwt.digest[i].target);
    }

    for i in 0..expected_hash_credential.len() {
        builder.register_public_input(targets_sha256_credential.digest[i].target);
    }

    log::info!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();

    /* Serialize Circuit */
    let timing = TimingTree::new("serde_circuit", Level::Debug);
    let verifier_only_circuit_data_serialized = data.verifier_data().to_bytes(&DefaultGateSerializer).expect("Serialize circuit to work");
    timing.print();

    log::info!("Verifier {}", serde_json::to_string(&data.verifier_only).unwrap());
    log::info!("Common {}", serde_json::to_string(&data.common).unwrap());

    /* Prove */
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw)?;

    let (jwt_sha256_hash, credential_sha256_hash) = extract_hashes_from_public_inputs(&proof.public_inputs);
    let compressed_proof = data.compress(proof).expect("Compress proof to work");
    timing.print();

    /* Serde Prove */
    let timing = TimingTree::new("serde_proof", Level::Debug);
    let proof_serialized = compressed_proof.to_bytes();
    timing.print();

    Ok((verifier_only_circuit_data_serialized, proof_serialized, jwt_sha256_hash, credential_sha256_hash))
}

pub fn verify(verifier: &[u8], proof: &[u8]) -> Result<()> {
    /* START VERIFIER CONSTRUCTION */
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let verifier = VerifierCircuitData::<F, C, D>::from_bytes(verifier.to_vec(), &DefaultGateSerializer).expect("Deserialize circuit to work");
    let proof = CompressedProofWithPublicInputs::<F, C, D>::from_bytes(proof.to_vec(), &verifier.common).expect("Deserialize proof to work");

    verifier.verify_compressed(proof)
}