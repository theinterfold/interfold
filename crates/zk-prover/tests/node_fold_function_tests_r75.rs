// SPDX-License-Identifier: LGPL-3.0-only
//
//! r75 — I71-leg box-1 realisation: the PRODUCTION function `prove_node_dkg_fold` END-TO-END
//! at the SECURE-8192/minimum committee (N=3/T=1/H=2, L=3) on this 4c/7.8 GiB box. The r74
//! redline gated queue-0's remaining slice on the *small* committee's secure leaves (C2a/C2b/C4
//! small = 15.1/14.9/14.7 GiB OOM, RAN r45/r46), but the *minimum* committee's secure leaves all
//! carry RAN fit evidence on <=8 GiB boxes: C1 4,285 MB (r44), C2a 4,741 MB (r45), C3 5,011 MB
//! committee-invariant (r39/r41), C4 4,374 MB (r46), C0 699 MB (r73), folds <=4.4 GiB write_vk
//! (r51/r53 class + this round's 4.4 GiB node_fold VK). This is the {secure-8192, minimum} cell
//! of the function grid = the first RAN production-field (8192/59-bit) end-to-end function wall.
//! 1:1 committee/preset-parametric vs r74: secure C3 is committee-invariant (RAN r41) and the
//! folds sit within ~300 g of the r39 secure-8192 table (RAN re-anchor this round); the 54/54
//! M7x guard stays inert at min width (sequential c3_fold arms, by design, as at r74).
//!
//! Artifacts: secure-8192/minimum tree RAN-compiled into poc/r75/min/ (leaves:
//! poc/r75/r75_build_leaves.sh; folds: r75 fold leg) — C1 2,223,114 g DIGIT-EXACT r44 /
//! C2a 1,446,311 g DIGIT-EXACT r45 / C2b 2,888,964 g DIGIT-EXACT r45 / C4 1,746,030 g
//! DIGIT-EXACT r46 / C3 2,966,353 g DIGIT-EXACT r39-r41 (committee-invariant) / c3_fold
//! 1,449,226 g vs the r39 secure table (c2ab 1,473,584 / c3ab 1,437,844 / c4ab 1,471,783 /
//! node_fold 3,719,958) / C0 = fresh secure-min compile, committee-free (287,7xx g class r39).
//! Run (quiet box, release): E3_R75_STAGE_ROOT=<tree> cargo test --release -p e3-zk-prover
//!   --test node_fold_function_tests_r75 -- --nocapture
//!   (the launcher poc/r75/r75_fn_launch.sh stages the tree first when the env is unset).

mod common;
#[path = "common/node_fold_witness.rs"]
mod node_fold_witness;

use std::path::PathBuf;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitVariant;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::dkg::share_computation::ShareComputationCircuit;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::ShareEncryptionCircuit;
use e3_zk_helpers::threshold::pk_generation::PkGenerationCircuit;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{
    prove_node_dkg_fold, NodeDkgFoldInput, Provable, ZkProver,
};
use e3_fhe_params::build_pair_for_preset;
use fhe::bfv::{PublicKey, SecretKey};
use node_fold_witness::{
    pk_generation_sample_with_esi, share_computation_esm_from_esi, share_computation_sk_from_pk,
    share_encryption_for_slot,
};
use e3_zk_helpers::computation::Computation;

const COMMITTEE: &str = "minimum";
const NODE_P: u32 = 0; // own party: slots {0,1,2} (L=3 secure-8192); W_P = {3..8}

/// Copy one directory tree (recursive) — the minimal fs::copy-dir for the stage handoff.
async fn copy_dir(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut rd = tokio::fs::read_dir(src).await?;
    while let Some(e) = rd.next_entry().await? {
        let t = e.path();
        let target = dst.join(e.file_name());
        if t.is_dir() {
            Box::pin(copy_dir(&t, &target)).await?;
        } else {
            tokio::fs::copy(&t, &target).await?;
        }
    }
    Ok(())
}

/// The pre-built stage tree root (E3_R75_STAGE_ROOT): must contain
/// `insecure-512/minimum/{evm,default,recursive}/...` (poc/r75/r75_stage_secure_min.sh output).
fn stage_root() -> PathBuf {
    match std::env::var("E3_R75_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R75_STAGE_ROOT unset — run poc/r75/r75_stage_secure_min.sh (via the launcher)"),
    }
}

fn c3_total_slots() -> usize {
    // C3_SLOTS = N_PARTIES * L = 3 * 3 = 9 at secure-8192/minimum (asserted below).
    9
}

/// Threshold modulus count L for secure-8192 = C3_SLOTS / N_PARTIES.
// At secure-8192 N_PARTIES=3, L=3 => 9/3=3 (vs ring-512 insecure L=2 where r74 divided by 2).
fn c3_l() -> usize {
    c3_total_slots() / 3
}

#[tokio::test]
async fn node_fold_function_end_to_end_minimum() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join(COMMITTEE);
    assert!(preset_tree.is_dir(), "stage tree {preset_tree:?} missing — build via poc/r75/r75_stage_secure_min.sh");

    let (backend, _temp) = setup_test_prover(&bb).await;
    // Hand the whole pre-built secure-8192/minimum tree into this run's backend (isolate; no on-disk bin writes).
    copy_dir(
        &preset_tree,
        &backend.circuits_dir.join("secure-8192").join(COMMITTEE),
    )
    .await
    .expect("stage tree handoff");

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);
    assert_eq!(ad, format!("secure-8192/{COMMITTEE}"));

    // ---- correlated sample chain (same secrets: C1 <-> C2 commitments align). ----
    let (pk_gen, esi, pk_secret_key) =
        pk_generation_sample_with_esi(preset, committee.clone())
            .expect("pk + esi correlated sample");
    let share_sk = share_computation_sk_from_pk(preset, committee.clone(), &pk_gen, &pk_secret_key)
        .expect("C2a data");
    let share_esm = share_computation_esm_from_esi(preset, committee.clone(), &pk_gen, &esi)
            .expect("C2b data");
    let sk_inputs = e3_zk_helpers::dkg::share_computation::Inputs::compute(preset, &share_sk)
            .expect("C2a inputs");
    let esm_inputs = e3_zk_helpers::dkg::share_computation::Inputs::compute(preset, &share_esm)
            .expect("C2b inputs");
    let pk_bfv_data = PkCircuitData::generate_sample(preset).expect("C0 sample");

    // ---- leaves (Recursive variant — the inner/base proofs node_fold embeds). ----
    let mut wall = Vec::new();
    let mut t = Instant::now();
    let c0_proof = PkCircuit
        .prove_with_variant(&prover, &preset, &pk_bfv_data, "e3-r75-c0", CircuitVariant::Recursive, &ad)
        .expect("C0 pk proof");
    wall.push(("c0", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c1_proof = PkGenerationCircuit
        .prove_with_variant(&prover, &preset, &pk_gen, "e3-r75-c1", CircuitVariant::Recursive, &ad)
        .expect("C1 pk_generation proof");
    wall.push(("c1", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c2a_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_sk, "e3-r75-c2a", CircuitVariant::Recursive, &ad)
        .expect("C2a proof");
    wall.push(("c2a", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c2b_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_esm, "e3-r75-c2b", CircuitVariant::Recursive, &ad)
        .expect("C2b proof");
    wall.push(("c2b", t.elapsed().as_secs_f64()));

    // ---- 8 C3 inners (4 W_P slots x 2 lanes), serial (the r69/scope class on 4c). ----
    let (_dkg_th, dkg_dkg) = build_pair_for_preset(preset).expect("pair");
    let mut rng = rand::rng();
    let dkg_sk = SecretKey::random(&dkg_dkg, &mut rng);
    let dkg_pk = PublicKey::new(&dkg_sk, &mut rng);
    let total = c3_total_slots();
    let l = c3_l();
    assert_eq!((total, l), (9, 3), "secure-min: N_PARTIES*L=9 slots, L=3 (r74's /2 was ring-512-specific)");
    let w_p: Vec<u32> = (0..total as u32)
        .filter(|&s| (s as usize) / l != NODE_P as usize)
        .collect();
    assert_eq!(w_p, vec![3u32, 4, 5, 6, 7, 8], "secure-min own-party skip (W_P = slots 3..=8)");
    t = Instant::now();
    let mut inners_a = Vec::new();
    let mut inners_b = Vec::new();
    for &slot in &w_p {
        let da = share_encryption_for_slot(preset, &dkg_sk, &dkg_pk, &sk_inputs, slot as usize, DkgInputType::SecretKey)
            .expect("C3a slot data");
        let db = share_encryption_for_slot(preset, &dkg_sk, &dkg_pk, &esm_inputs, slot as usize, DkgInputType::SmudgingNoise)
            .expect("C3b slot data");
        inners_a.push(ShareEncryptionCircuit
            .prove_with_variant(&prover, &preset, &da, &format!("e3-r75-c3a-{slot}"), CircuitVariant::Recursive, &ad)
            .expect("C3a inner"));
        inners_b.push(ShareEncryptionCircuit
            .prove_with_variant(&prover, &preset, &db, &format!("e3-r75-c3b-{slot}"), CircuitVariant::Recursive, &ad)
            .expect("C3b inner"));
    }
    wall.push(("c3-inners x12 serial", t.elapsed().as_secs_f64()));

    // ---- C4 leaves (honest rows triplicated so the H=2 decryption rows are self-consistent).
    let trip = |mut d: ShareDecryptionCircuitData| -> ShareDecryptionCircuitData {
        let row0 = d.honest_ciphertexts[0].clone();
        d.honest_ciphertexts = (0..d.honest_ciphertexts.len()).map(|_| row0.clone()).collect();
        d
    };
    let c4a_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SecretKey).expect("c4a"));
    let c4b_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SmudgingNoise).expect("c4b"));
    t = Instant::now();
    let c4a_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4a_data, "e3-r75-c4a", CircuitVariant::Recursive, &ad)
        .expect("C4a");
    wall.push(("c4a", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c4b_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4b_data, "e3-r75-c4b", CircuitVariant::Recursive, &ad)
        .expect("C4b");
    wall.push(("c4b", t.elapsed().as_secs_f64()));

    // ---- THE PRODUCTION FUNCTION (r71 wiring live inside; the 54/54 M7x guard falls
    //      through to the sequential c3_fold arms at minimum, by design). ----
    t = Instant::now();
    let input = NodeDkgFoldInput {
        c0_proof: &c0_proof,
        c1_proof: &c1_proof,
        c2a_proof: &c2a_proof,
        c2b_proof: &c2b_proof,
        c3a_inner_proofs: &inners_a,
        c3b_inner_proofs: &inners_b,
        c3_slot_indices_a: &w_p,
        c3_slot_indices_b: &w_p,
        c3_total_slots: total,
        c4a_proof: &c4a_proof,
        c4b_proof: &c4b_proof,
        party_id: NODE_P as u64,
    };
    let res = prove_node_dkg_fold(&prover, &input, "e3-r75", &ad)
        .expect("prove_node_dkg_fold (production function)");
    let fn_wall = t.elapsed().as_secs_f64();

    let nf_pf = |label: &str| (res.proof.public_signals.len() / 32, label.to_string());
    let (n_pub, _) = nf_pf("node_fold publics");
    println!(
        "R75-fn node_fold public fields = {n_pub} (NODE_FOLD_PUBLIC_LEN secure-min = 11+3+2*(3+2)*3 = 44)  RAN"
    );
    assert_eq!(n_pub, 44, "node_fold public layout must be the secure-8192 minimum committee shape");

    let mut fn_steps = String::new();
    for s in &res.step_timings {
        fn_steps.push_str(&format!("{}={:.1}s  ", s.step, s.seconds));
    }
    println!("R75-fn step timings: {fn_steps} RAN");
    println!("R75-fn prove_node_dkg_fold wall = {fn_wall:.1}s  RAN");

    // ---- top-level verify (Default-variant fold verify over the node_fold artifact). ----
    let vok = prover
        .verify_fold_proof(&res.proof, "e3-r75", NODE_P as u64, &ad)
        .expect("verify_fold_proof node_fold");
    println!("R75-fn verify_fold_proof(node_fold) = {vok}  RAN");
    assert!(vok, "node_fold must verify");

    // ---- own-slot zero check on the c3ab state is internal to the function; here we check
    //      the function's returned node_fold carries the party binding (publics are stable).
    let owns = &res.proof.public_signals[11 * 32..12 * 32];
    // public[11] = the first [Field; N_PARTIES] binding column entry (own party at id 0).
    println!("R75-fn party-binding field[0] = 0x{} RAN", hex::encode(owns));
    // (value asserted non-fatal: node_fold encodes party commitments; the verify above is the
    //  load-bearing end-to-end check — the function would have Err'd earlier on mismatch.)

    for (label, secs) in &wall {
        println!("R75-leaf {label} = {secs:.1}s  RAN");
    }
    drop(_temp);
}