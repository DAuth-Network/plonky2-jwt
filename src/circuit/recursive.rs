use anyhow::Result;
use log::Level;

use plonky2::field::types::Field;

use plonky2::fri::FriConfig;
use plonky2::fri::reduction_strategies::FriReductionStrategy;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig, KeccakGoldilocksConfig, AlgebraicHasher};

use plonky2::hash::hash_types::RichField;
use plonky2::field::extension::Extendable;

use plonky2::gates::noop::NoopGate;
use plonky2::plonk::prover::prove;

use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use plonky2::util::timing::TimingTree;

use crate::circuit::sha256::make_sha256;
use crate::circuit::fast_inclusion::make_fast_inclusion_circut;
use crate::utils::{array_to_bits, find_subsequence_u8, extract_hashes_from_public_inputs};
use sha2::{Digest, Sha256};


pub fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>, // config to the wrapping circuit
    InnerC: GenericConfig<D, F = F>, // Config of the internal circuit 
    const D: usize,
>(
    inner_proof: ProofWithPublicInputs<F, InnerC, D>,
    inner_vd: VerifierCircuitData<F, InnerC, D>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<(
    ProofWithPublicInputs<F, C, D>,
    VerifierCircuitData<F, C, D>,
)>
where
    InnerC::Hasher: AlgebraicHasher<F>
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let proof_target = builder.add_virtual_proof_with_pis(&inner_vd.common);
    pw.set_proof_with_pis_target(&proof_target, &inner_proof);

    let circuit_digest_target = builder.add_virtual_hash();
    pw.set_hash_target(circuit_digest_target, inner_vd.verifier_only.circuit_digest);

    let inner_data_target = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_vd.common.config.fri_config.cap_height),
        circuit_digest: circuit_digest_target,
    };
    pw.set_cap_target(
        &inner_data_target.constants_sigmas_cap,
        &inner_vd.verifier_only.constants_sigmas_cap,
    );

    builder.verify_proof::<InnerC>(&proof_target, &inner_data_target, &inner_vd.common);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will add a
        // few special gates afterward. So just pad to 2^(min_degree_bits - 1) + 1. Then the
        // builder will pad to the next power of two, 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    log::info!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let timing = TimingTree::new("build_recursive_circuit", Level::Info);
    let data = builder.build::<C>();
    timing.print();

    let mut timing = TimingTree::new("prove_recursive_circuit", Level::Info);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();


    data.verify(proof.clone())?;

    Ok((proof, data.verifier_data()))
}

pub fn prove_recursive(jwt: &[u8], credential: &[u8]) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32])> {
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

    /* START CONSTRUCTING INNER PROOF  */
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
    let timing = TimingTree::new("build_circuit", Level::Info);
    let data = builder.build::<C>();
    timing.print();

    /* Prove */
    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw)?;
    timing.print();
    let (jwt_sha256_hash, credential_sha256_hash) = extract_hashes_from_public_inputs(&proof.public_inputs);

    /* END CONSTRUCT INNER PROOF */

    /* CONSTRUCT RECURSIVE PROOF */
    // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
    let standard_config = CircuitConfig::standard_recursion_zk_config();
    let high_rate_config = CircuitConfig {
        fri_config: FriConfig {
            rate_bits: 7,
            proof_of_work_bits: 16,
            num_query_rounds: 12,
            ..standard_config.fri_config.clone()
        },
        ..standard_config
    };
    let (
        initial_recursive_pwpi,
        initial_recursive_verifier_data,
    ) = recursive_proof::<F, C, C, D>(
        proof,
        data.verifier_data(),
        &high_rate_config,
        None,
    )?;

    // A final proof, optimized for size.
    type KC = KeccakGoldilocksConfig;
    let final_config = CircuitConfig {
        num_routed_wires: 37,
        fri_config: FriConfig {
            rate_bits: 8,
            cap_height: 0,
            proof_of_work_bits: 20,
            reduction_strategy: FriReductionStrategy::MinSize(None),
            num_query_rounds: 10,
        },
        ..high_rate_config
    };
    let (
        final_recursive_pwpi,
        final_recursive_verifier_data,
    ) = recursive_proof::<F, KC, C, D>(
        initial_recursive_pwpi,
        initial_recursive_verifier_data,
        &final_config,
        None,
    )?;
    /* END CONSTRUCT RECURSIVE PROOF */

    println!("Recursive Common {:?}", serde_json::to_string(&final_recursive_verifier_data.common).unwrap());

    /* SERIALIZER FOR OUTPUT */
    let verifier_circuit_data_serialized = final_recursive_verifier_data.to_bytes(&DefaultGateSerializer).expect("Serialize circuit to work");
    let proof_serialized = final_recursive_pwpi.to_bytes();

    Ok((verifier_circuit_data_serialized, proof_serialized, jwt_sha256_hash, credential_sha256_hash))
}
