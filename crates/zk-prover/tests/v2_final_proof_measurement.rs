// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Gated end-to-end measurement for the secure-16384 V2 DKG aggregator proof.

mod common;
#[path = "common/node_fold_witness.rs"]
mod node_fold_witness;

use std::{env, fs, path::PathBuf};

use alloy::primitives::Address;
use common::find_bb;
use e3_config::BBPath;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::{
    build_pair_for_preset, create_deterministic_crp_from_default_seed, lbfv_crs_seed,
    lbfv_urs_seed, BfvPreset,
};
use e3_polynomial::CrtPolynomial;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::computation::{Computation, DkgInputType};
use e3_zk_helpers::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::dkg::share_computation::Inputs as ShareComputationInputs;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::ShareEncryptionCircuit;
use e3_zk_helpers::threshold::lbfv_pk_aggregation::{
    LbfvPkAggregationCircuit, LbfvPkAggregationCircuitData,
};
use e3_zk_helpers::threshold::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_zk_helpers::threshold::pk_aggregation::{PkAggregationCircuit, PkAggregationCircuitData};
use e3_zk_helpers::threshold::pk_generation::{LbfvPkGenerationAdapter, PkGenerationCircuit};
use e3_zk_helpers::threshold::rlk_aggregation::{RlkAggregationCircuit, RlkAggregationCircuitData};
use e3_zk_helpers::threshold::rlk_generation::RlkGenerationAdapter;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{
    load_staged_lbfv_pk_generation_limb_vk_hash, load_staged_rlk_generation_limb_vk_hash,
    prove_chunked_share_computation, prove_dkg_aggregation_v2, prove_lbfv_aggregation_fold_step,
    prove_lbfv_generation_fold_step, prove_lbfv_pk_generation_row, prove_node_dkg_fold,
    prove_node_dkg_fold_v2, prove_nodes_fold_v2_step, prove_rlk_generation_row, NodeDkgFoldInput,
    Provable, ZkBackend, ZkProver,
};
use fhe::bfv::{Ciphertext, CommonRandomPolyVec, PublicKey, SecretKey};
use fhe::mbfv::{AggregateIter, PublicKeyShare as MbfvPublicKeyShare};
use fhe::trlbfv::{PublicKeyShare as LbfvPublicKeyShare, RelinKeyShare};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use rand::rng;

const RUN_ENV: &str = "INTERFOLD_RUN_V2_FINAL_PROOF";
const ARTIFACT_ROOT_ENV: &str = "INTERFOLD_SECURE_16384_ARTIFACTS";
const FINAL_CACHE_ENV: &str = "INTERFOLD_V2_FINAL_PROOF_CACHE";
const ARTIFACTS_DIR: &str = "secure-16384/minimum";
const LBFV_ROWS: u32 = 5;

struct NodeInputs {
    party_id: u64,
    c1_data: e3_zk_helpers::threshold::pk_generation::PkGenerationCircuitData,
    c1_proof: Proof,
    c2a_proof: Proof,
    c2b_proof: Proof,
    c3a_inner_proofs: Vec<Proof>,
    c3b_inner_proofs: Vec<Proof>,
    c3_slot_indices: Vec<u32>,
    c3a_ciphertexts: Vec<Option<Ciphertext>>,
    c3b_ciphertexts: Vec<Option<Ciphertext>>,
    sk_inputs: ShareComputationInputs,
    esm_inputs: ShareComputationInputs,
    lbfv_pk_share: LbfvPublicKeyShare,
    rlk_share: RelinKeyShare,
    generation_fold: Proof,
    mbfv_share: MbfvPublicKeyShare,
}

fn final_cache_path() -> Option<PathBuf> {
    env::var_os(FINAL_CACHE_ENV).map(PathBuf::from)
}

fn load_final_cache() -> Option<Proof> {
    let directory = final_cache_path()?;
    let data = fs::read(directory.join("dkg_aggregator_v2.proof")).ok()?;
    let public_signals = fs::read(directory.join("dkg_aggregator_v2.public")).ok()?;
    Some(Proof::new(
        CircuitName::DkgAggregatorV2,
        ArcBytes::from_bytes(&data),
        ArcBytes::from_bytes(&public_signals),
    ))
}

fn store_final_cache(proof: &Proof) {
    let Some(directory) = final_cache_path() else {
        return;
    };
    fs::create_dir_all(&directory).expect("final proof cache directory");
    let proof_data: &[u8] = proof.data.as_ref();
    let public_signals: &[u8] = proof.public_signals.as_ref();
    fs::write(directory.join("dkg_aggregator_v2.proof"), proof_data).expect("cached final proof");
    fs::write(directory.join("dkg_aggregator_v2.public"), public_signals)
        .expect("cached final public signals");
}

fn print_measurement(label: &str, proof: &Proof) {
    println!(
        "{label}: proof_bytes={}, public_signal_bytes={}, public_fields={}",
        proof.data.len(),
        proof.public_signals.len(),
        proof.public_signals.len() / 32
    );
}

fn report_phase(label: &str) {
    println!("v2-final phase: {label}");
}

fn share_row_for_recipient(
    inputs: &ShareComputationInputs,
    recipient: usize,
    mod_idx: usize,
    modulus: u64,
) -> Vec<u64> {
    inputs
        .y
        .iter()
        .map(|coefficient| {
            let mut value = coefficient[mod_idx][recipient + 1].clone() % BigInt::from(modulus);
            if value.is_negative() {
                value += BigInt::from(modulus);
            }
            value.to_u64().expect("share coefficient fits u64")
        })
        .collect()
}

fn c4_data_for_recipient(
    inputs: &[ShareComputationInputs],
    ciphertexts: &[Vec<Option<Ciphertext>>],
    dkg_secret_key: &SecretKey,
    recipient: usize,
    input_type: DkgInputType,
    committee: e3_zk_helpers::CiphernodesCommittee,
    threshold_moduli: &[u64],
) -> ShareDecryptionCircuitData {
    let mut honest_ciphertexts = Vec::with_capacity(committee.h);
    for sender in 0..committee.h {
        if sender == recipient {
            honest_ciphertexts.push(None);
            continue;
        }

        let recipient_slot = recipient * threshold_moduli.len();
        let row = (0..threshold_moduli.len())
            .map(|mod_idx| {
                ciphertexts[sender][recipient_slot + mod_idx]
                    .as_ref()
                    .expect("external recipient ciphertext")
                    .clone()
            })
            .collect();
        honest_ciphertexts.push(Some(row));
    }

    let own_plaintext_share = (0..threshold_moduli.len())
        .map(|mod_idx| {
            share_row_for_recipient(
                &inputs[recipient],
                recipient,
                mod_idx,
                threshold_moduli[mod_idx],
            )
        })
        .collect();

    ShareDecryptionCircuitData {
        secret_key: dkg_secret_key.clone(),
        honest_ciphertexts,
        recipient_party_id: recipient as u64,
        own_plaintext_share,
        dkg_input_type: input_type,
        chunk_size: 512,
        committee,
    }
}

fn prove_c3_chain(
    prover: &ZkProver,
    preset: BfvPreset,
    committee: e3_zk_helpers::CiphernodesCommittee,
    share_inputs: &ShareComputationInputs,
    dkg_secret_key: &SecretKey,
    dkg_public_key: &PublicKey,
    input_type: DkgInputType,
    party_id: usize,
    artifacts_dir: &str,
    label: &str,
) -> (Vec<Proof>, Vec<u32>, Vec<Option<Ciphertext>>) {
    report_phase(&format!("{label} C3 start"));
    let total_slots = committee.n * preset.metadata().num_moduli;
    let slots_per_party = total_slots / committee.n;
    let mut inner_proofs = Vec::new();
    let mut slot_indices = Vec::new();
    let mut ciphertexts = (0..total_slots).map(|_| None).collect::<Vec<_>>();

    for slot in 0..total_slots {
        if slot / slots_per_party == party_id {
            continue;
        }

        let data = node_fold_witness::share_encryption_for_slot(
            preset,
            dkg_secret_key,
            dkg_public_key,
            share_inputs,
            slot,
            input_type,
            committee.clone(),
        )
        .expect("C3 share encryption data");
        ciphertexts[slot] = Some(data.ciphertext.clone());
        inner_proofs.push(
            ShareEncryptionCircuit
                .prove_with_variant(
                    prover,
                    &preset,
                    &data,
                    &format!("{label}-c3-{slot}"),
                    CircuitVariant::Recursive,
                    artifacts_dir,
                )
                .expect("C3 share encryption proof"),
        );
        slot_indices.push(slot as u32);
    }

    report_phase(&format!("{label} C3 complete"));
    (inner_proofs, slot_indices, ciphertexts)
}

fn prove_generation_fold(
    prover: &ZkProver,
    preset: BfvPreset,
    committee: e3_zk_helpers::CiphernodesCommittee,
    party_id: u32,
    secret_key: &SecretKey,
    lbfv_pk_share: &LbfvPublicKeyShare,
    rlk_share: &RelinKeyShare,
    rlk_witness: &fhe::trlbfv::RlkWitness,
    artifacts_dir: &str,
    label: &str,
) -> Proof {
    let generation_adapter = LbfvPkGenerationAdapter::new(preset).expect("l-BFV PK adapter");
    let rlk_adapter = RlkGenerationAdapter::new(preset).expect("RLK adapter");
    let pk_limb_vk_hash = load_staged_lbfv_pk_generation_limb_vk_hash(prover, artifacts_dir)
        .expect("staged public-key limb VK hash");
    let rlk_limb_vk_hash = load_staged_rlk_generation_limb_vk_hash(prover, artifacts_dir)
        .expect("staged RLK limb VK hash");

    let mut accumulator = None;
    for row in 0..LBFV_ROWS {
        report_phase(&format!("{label} generation row {row} start"));
        let pk_data = generation_adapter
            .row_data(
                committee.clone(),
                sample_lbfv_proof_domain(),
                party_id,
                row,
                secret_key,
                lbfv_pk_share,
            )
            .expect("l-BFV PK row data");
        let pk_proof = prove_lbfv_pk_generation_row(
            prover,
            preset,
            &pk_data,
            &pk_limb_vk_hash,
            &format!("{label}-pk-{row}"),
            artifacts_dir,
        )
        .expect("l-BFV PK row proof")
        .terminal_proof;

        let rlk_data = rlk_adapter
            .row_data(
                committee.clone(),
                sample_lbfv_proof_domain(),
                party_id,
                row,
                secret_key,
                rlk_share,
                rlk_witness,
            )
            .expect("RLK row data");
        let rlk_proofs = prove_rlk_generation_row(
            prover,
            preset,
            &rlk_data,
            &rlk_limb_vk_hash,
            &format!("{label}-rlk-{row}"),
            artifacts_dir,
        )
        .expect("RLK row proof");

        let next = prove_lbfv_generation_fold_step(
            prover,
            &pk_proof,
            &rlk_proofs.terminal_proof,
            accumulator.as_ref(),
            row,
            &ArcBytes::from_bytes(&pk_limb_vk_hash),
            &ArcBytes::from_bytes(&rlk_limb_vk_hash),
            &format!("{label}-fold-{row}"),
            artifacts_dir,
        )
        .expect("l-BFV generation fold proof");
        accumulator = Some(next);
        report_phase(&format!("{label} generation row {row} complete"));
    }

    accumulator.expect("generation fold accumulator")
}

fn build_node(
    prover: &ZkProver,
    preset: BfvPreset,
    committee: e3_zk_helpers::CiphernodesCommittee,
    dkg_secret_key: &SecretKey,
    dkg_public_key: &PublicKey,
    party_id: usize,
    artifacts_dir: &str,
) -> NodeInputs {
    report_phase(&format!("node {party_id} C1 start"));
    let (c1_data, esi, secret_key, mbfv_share) =
        node_fold_witness::pk_generation_sample_with_esi_and_share(preset, committee.clone())
            .expect("correlated C1 data");
    let c1_proof = PkGenerationCircuit
        .prove_with_variant(
            prover,
            &preset,
            &c1_data,
            &format!("v2-final-c1-{party_id}"),
            CircuitVariant::Recursive,
            artifacts_dir,
        )
        .expect("C1 proof");
    report_phase(&format!("node {party_id} C1 complete"));

    let share_sk = node_fold_witness::share_computation_sk_from_pk(
        preset,
        committee.clone(),
        &c1_data,
        &secret_key,
    )
    .expect("correlated C2a data");
    let share_esm = node_fold_witness::share_computation_esm_from_esi(
        preset,
        committee.clone(),
        &c1_data,
        &esi,
    )
    .expect("correlated C2b data");
    let sk_inputs = ShareComputationInputs::compute(preset, &share_sk).expect("C2a inputs");
    let esm_inputs = ShareComputationInputs::compute(preset, &share_esm).expect("C2b inputs");

    let c2a_proof = prove_chunked_share_computation(
        prover,
        preset,
        &share_sk,
        &format!("v2-final-c2a-{party_id}"),
        artifacts_dir,
    )
    .expect("C2a proof")
    .proof;
    let c2b_proof = prove_chunked_share_computation(
        prover,
        preset,
        &share_esm,
        &format!("v2-final-c2b-{party_id}"),
        artifacts_dir,
    )
    .expect("C2b proof")
    .proof;
    report_phase(&format!("node {party_id} C2 complete"));

    let (c3a_inner_proofs, c3_slot_indices, c3a_ciphertexts) = prove_c3_chain(
        prover,
        preset,
        committee.clone(),
        &sk_inputs,
        dkg_secret_key,
        dkg_public_key,
        DkgInputType::SecretKey,
        party_id,
        artifacts_dir,
        &format!("v2-final-a-{party_id}"),
    );
    let (c3b_inner_proofs, c3b_slot_indices, c3b_ciphertexts) = prove_c3_chain(
        prover,
        preset,
        committee.clone(),
        &esm_inputs,
        dkg_secret_key,
        dkg_public_key,
        DkgInputType::SmudgingNoise,
        party_id,
        artifacts_dir,
        &format!("v2-final-b-{party_id}"),
    );
    assert_eq!(c3_slot_indices, c3b_slot_indices);
    report_phase(&format!("node {party_id} C3 complete"));

    let (threshold_params, _) = build_pair_for_preset(preset).expect("threshold parameters");
    let crp_a = CommonRandomPolyVec::from_seed(
        &threshold_params,
        lbfv_crs_seed(preset).expect("l-BFV CRS seed"),
    )
    .expect("l-BFV CRS");
    let crp_d1 = CommonRandomPolyVec::from_seed(
        &threshold_params,
        lbfv_urs_seed(preset).expect("l-BFV URS seed"),
    )
    .expect("l-BFV URS");
    let mut proof_rng = rng();
    let lbfv_pk_share =
        LbfvPublicKeyShare::contribute_with_crp(&secret_key, &crp_a, &mut proof_rng)
            .expect("l-BFV public key share");
    let (rlk_share, rlk_witness) = RelinKeyShare::contribution_with_crp_extended(
        &secret_key,
        &crp_d1,
        &crp_a,
        0,
        0,
        &mut proof_rng,
    )
    .expect("RLK share");
    let generation_fold = prove_generation_fold(
        prover,
        preset,
        committee,
        party_id as u32,
        &secret_key,
        &lbfv_pk_share,
        &rlk_share,
        &rlk_witness,
        artifacts_dir,
        &format!("v2-final-generation-{party_id}"),
    );
    report_phase(&format!("node {party_id} generation complete"));

    NodeInputs {
        party_id: party_id as u64,
        c1_data,
        c1_proof,
        c2a_proof,
        c2b_proof,
        c3a_inner_proofs,
        c3b_inner_proofs,
        c3_slot_indices,
        c3a_ciphertexts,
        c3b_ciphertexts,
        sk_inputs,
        esm_inputs,
        lbfv_pk_share,
        rlk_share,
        generation_fold,
        mbfv_share,
    }
}

#[tokio::test]
async fn secure_dkg_aggregator_v2_proves_and_verifies_evm() {
    if env::var_os(RUN_ENV).is_none() {
        println!("skipping: {RUN_ENV} is not set");
        return;
    }

    let Some(artifact_root) = env::var_os(ARTIFACT_ROOT_ENV).map(PathBuf::from) else {
        panic!("{ARTIFACT_ROOT_ENV} is required when {RUN_ENV} is set");
    };
    let Some(bb) = find_bb().await else {
        panic!("bb is required when {RUN_ENV} is set");
    };
    let required = artifact_root
        .join(ARTIFACTS_DIR)
        .join("evm/recursive_aggregation/dkg_aggregator_v2/dkg_aggregator_v2.json");
    assert!(
        required.is_file(),
        "secure artifact is missing: {}",
        required.display()
    );

    let work = tempfile::tempdir().expect("temporary prover work directory");
    let backend = ZkBackend::new(BBPath::Default(bb), artifact_root, work.path().join("work"));
    let prover = ZkProver::new(&backend);
    let preset = BfvPreset::SecureThreshold16384;
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());

    if let Some(cached) = load_final_cache() {
        print_measurement("dkg_aggregator_v2.cached", &cached);
        assert!(prover
            .verify_evm_proof(&cached, "v2-final-cached", 0, ARTIFACTS_DIR)
            .expect("cached final EVM proof verification"));
        return;
    }

    let (_, dkg_params) = build_pair_for_preset(preset).expect("DKG parameters");
    let mut dkg_rng = rng();
    let dkg_secret_key = SecretKey::random(&dkg_params, &mut dkg_rng);
    let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut dkg_rng);
    let c0_data = PkCircuitData {
        public_key: dkg_public_key.clone(),
    };
    let c0_proof = PkCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &c0_data,
            "v2-final-c0",
            CircuitVariant::Recursive,
            artifacts_dir.as_str(),
        )
        .expect("C0 proof");
    report_phase("C0 complete");

    let mut nodes = Vec::with_capacity(committee.h);
    for party_id in 0..committee.h {
        nodes.push(build_node(
            &prover,
            preset,
            committee.clone(),
            &dkg_secret_key,
            &dkg_public_key,
            party_id,
            artifacts_dir.as_str(),
        ));
        report_phase(&format!("node {party_id} complete"));
    }

    let threshold_moduli = build_pair_for_preset(preset)
        .expect("threshold parameters")
        .0
        .moduli()
        .to_vec();
    let mut c4a_proofs = Vec::with_capacity(committee.h);
    let mut c4b_proofs = Vec::with_capacity(committee.h);
    for recipient in 0..committee.h {
        report_phase(&format!("C4 recipient {recipient} start"));
        let c4a_data = c4_data_for_recipient(
            &nodes
                .iter()
                .map(|node| node.sk_inputs.clone())
                .collect::<Vec<_>>(),
            &nodes
                .iter()
                .map(|node| node.c3a_ciphertexts.clone())
                .collect::<Vec<_>>(),
            &dkg_secret_key,
            recipient,
            DkgInputType::SecretKey,
            committee.clone(),
            &threshold_moduli,
        );
        let c4b_data = c4_data_for_recipient(
            &nodes
                .iter()
                .map(|node| node.esm_inputs.clone())
                .collect::<Vec<_>>(),
            &nodes
                .iter()
                .map(|node| node.c3b_ciphertexts.clone())
                .collect::<Vec<_>>(),
            &dkg_secret_key,
            recipient,
            DkgInputType::SmudgingNoise,
            committee.clone(),
            &threshold_moduli,
        );
        c4a_proofs.push(
            ShareDecryptionCircuit
                .prove_with_variant(
                    &prover,
                    &preset,
                    &c4a_data,
                    &format!("v2-final-c4a-{recipient}"),
                    CircuitVariant::Recursive,
                    artifacts_dir.as_str(),
                )
                .expect("C4a proof"),
        );
        c4b_proofs.push(
            ShareDecryptionCircuit
                .prove_with_variant(
                    &prover,
                    &preset,
                    &c4b_data,
                    &format!("v2-final-c4b-{recipient}"),
                    CircuitVariant::Recursive,
                    artifacts_dir.as_str(),
                )
                .expect("C4b proof"),
        );
        report_phase(&format!("C4 recipient {recipient} complete"));
    }

    let mut node_fold_v2_proofs = Vec::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        report_phase(&format!("legacy node fold {index} start"));
        let legacy = prove_node_dkg_fold(
            &prover,
            &NodeDkgFoldInput {
                c0_proof: &c0_proof,
                c1_proof: &node.c1_proof,
                c2a_proof: &node.c2a_proof,
                c2b_proof: &node.c2b_proof,
                c3a_inner_proofs: &node.c3a_inner_proofs,
                c3b_inner_proofs: &node.c3b_inner_proofs,
                c3_slot_indices_a: &node.c3_slot_indices,
                c3_slot_indices_b: &node.c3_slot_indices,
                c3_total_slots: committee.n * preset.metadata().num_moduli,
                c4a_proof: &c4a_proofs[index],
                c4b_proof: &c4b_proofs[index],
                party_id: node.party_id,
            },
            &format!("v2-final-legacy-node-{index}"),
            artifacts_dir.as_str(),
        )
        .expect("legacy NodeFold proof");
        assert!(prover
            .verify_fold_proof(
                &legacy.proof,
                &format!("v2-final-legacy-node-verify-{index}"),
                0,
                artifacts_dir.as_str(),
            )
            .expect("legacy NodeFold verification"));

        node_fold_v2_proofs.push(
            prove_node_dkg_fold_v2(
                &prover,
                &legacy.proof,
                &node.c1_proof,
                &node.generation_fold,
                node.party_id,
                &format!("v2-final-node-v2-{index}"),
                artifacts_dir.as_str(),
            )
            .expect("NodeFoldV2 proof"),
        );
        report_phase(&format!("legacy/V2 node fold {index} complete"));
    }

    let mut nodes_fold_v2 = None;
    for (index, proof) in node_fold_v2_proofs.iter().enumerate() {
        nodes_fold_v2 = Some(
            prove_nodes_fold_v2_step(
                &prover,
                proof,
                nodes_fold_v2.as_ref(),
                index as u32,
                nodes.len(),
                &format!("v2-final-nodes-fold-{index}"),
                artifacts_dir.as_str(),
            )
            .expect("NodesFoldV2 proof"),
        );
    }
    let nodes_fold_v2 = nodes_fold_v2.expect("NodesFoldV2 accumulator");
    report_phase("NodesFoldV2 complete");

    let threshold_params = build_pair_for_preset(preset)
        .expect("threshold parameters")
        .0;
    let c5_public_key: PublicKey = nodes
        .iter()
        .map(|node| node.mbfv_share.clone())
        .aggregate()
        .expect("C5 aggregate public key");
    let c5_data = PkAggregationCircuitData {
        committee: committee.clone(),
        public_key: c5_public_key,
        pk0_shares: nodes
            .iter()
            .map(|node| node.c1_data.pk0_share.clone())
            .collect(),
        a: CrtPolynomial::from_fhe_polynomial(
            &create_deterministic_crp_from_default_seed(&threshold_params).poly(),
        ),
    };
    let c5_proof = PkAggregationCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &c5_data,
            "v2-final-c5",
            CircuitVariant::Default,
            artifacts_dir.as_str(),
        )
        .expect("C5 proof");
    report_phase("C5 complete");

    let mut aggregation_fold = None;
    for row in 0..LBFV_ROWS {
        report_phase(&format!("aggregation row {row} start"));
        let pk_data = LbfvPkAggregationCircuitData {
            committee: committee.clone(),
            proof_domain: sample_lbfv_proof_domain(),
            aggregator_party_id: 0,
            party_ids: (0..committee.h as u32).collect(),
            row_index: row,
            shares: nodes
                .iter()
                .map(|node| node.lbfv_pk_share.clone())
                .collect(),
        };
        let rlk_data = RlkAggregationCircuitData {
            committee: committee.clone(),
            proof_domain: sample_lbfv_proof_domain(),
            aggregator_party_id: 0,
            party_ids: (0..committee.h as u32).collect(),
            row_index: row,
            shares: nodes.iter().map(|node| node.rlk_share.clone()).collect(),
        };
        let pk_proof = LbfvPkAggregationCircuit
            .prove_with_variant(
                &prover,
                &preset,
                &pk_data,
                &format!("v2-final-aggregation-pk-{row}"),
                CircuitVariant::Recursive,
                artifacts_dir.as_str(),
            )
            .expect("l-BFV PK aggregation proof");
        let rlk_proof = RlkAggregationCircuit
            .prove_with_variant(
                &prover,
                &preset,
                &rlk_data,
                &format!("v2-final-aggregation-rlk-{row}"),
                CircuitVariant::Recursive,
                artifacts_dir.as_str(),
            )
            .expect("RLK aggregation proof");
        aggregation_fold = Some(
            prove_lbfv_aggregation_fold_step(
                &prover,
                &pk_proof,
                &rlk_proof,
                aggregation_fold.as_ref(),
                row,
                committee.h,
                &format!("v2-final-aggregation-fold-{row}"),
                artifacts_dir.as_str(),
            )
            .expect("l-BFV aggregation fold proof"),
        );
        report_phase(&format!("aggregation row {row} complete"));
    }
    let aggregation_fold = aggregation_fold.expect("aggregation fold accumulator");
    report_phase("aggregation fold complete");

    let committee_addresses = vec![
        Address::repeat_byte(0x01),
        Address::repeat_byte(0x02),
        Address::repeat_byte(0x03),
    ];
    let party_ids = vec![0, 1];
    let final_proof = prove_dkg_aggregation_v2(
        &prover,
        &nodes_fold_v2,
        &c5_proof,
        &aggregation_fold,
        &party_ids,
        &committee_addresses,
        "v2-final-dkg-aggregator",
        preset,
        CiphernodesCommitteeSize::Minimum,
    )
    .expect("DkgAggregatorV2 proof");
    report_phase("DkgAggregatorV2 complete");
    print_measurement("dkg_aggregator_v2", &final_proof);
    assert!(prover
        .verify_evm_proof(
            &final_proof,
            "v2-final-dkg-aggregator-verify",
            0,
            ARTIFACTS_DIR,
        )
        .expect("final EVM proof verification"));
    store_final_cache(&final_proof);
}
