// SPDX-License-Identifier: LGPL-3.0-only
//
//! r78 — I71-leg box-2 slice (c): the PRODUCTION function `prove_node_dkg_fold` END-TO-END at
//! the SECURE-8192/small committee (N=19/T=9/H=10, L=3) — the campaign's production field AND
//! width. DRAFT (written, NOT run): the shape is 1:1 to the r75 secure-min leg (commit 532d4e8,
//! RAN 803.0 s) re-parameterized to small; the two load-bearing deltas were source-vetted r78:
//! (1) the 54/54 M7x guard in prove_node_dkg_fold FIRES at small — both c3 lanes route through
//! `generate_c3_merge_m7x` (54 inners / 54 scattered slots), which consumes the staged M7x family
//! `c3_fold_batch_{merge_m7x,b10,b3}` + `c3_fold_kernel` — r78 staged those into the durable tree
//! (`poc/r77/r78_m7x_stage.sh`; `audit_m7x.py` RC 0: M7x vk_hash BYTE-EXACT to r70's public RAN
//! pin 0x26ed7e...73a52; kernel/leaf anchors byte-exact); (2) the scattered small W_P
//! (W_P = {3..=56}, party-0 block {0,19,38} excluded) = the production geometry r69/r70 RAN
//! (c3a/c3b arms + c3ab seam at the M7x VK pin, all 57 rows byte-identical).
//!
//! NOT RUN on this box: (a) the tree lacks the 3 heavy small leaves C2a/C2b/C4 (the function
//! fails at their VK lookup FIRST — before any expensive prove; part-(a) compiles are the
//! box-2 ≥24 GiB card, RAN r45/r46); (b) the 108-inner leg is the r69-class ~4300 s wall + the
//! M7x arms ~895.5 s — hours of compute with zero new RAN candidate on 7.8 GiB.
//! Run command (BOX-2, quiet, release, after the 3 leaves drop into the tree + MANIFEST re-pin
//! + `python3 poc/r77/audit.py` + `python3 poc/r77/audit_m7x.py` both RC 0):
//!   E3_R78_STAGE_ROOT=/home/dev/interfold-research/poc/r77/root
//!   cargo test --release -p e3-zk-prover --test node_fold_function_tests_r78 -- --nocapture
//! Expected (DRAFT from RAN anchors — model, not a promise): verify_fold_proof(node_fold)=true;
//! node_fold public fields = 204 = 11 + 19 + 2*(19+10)*3 (NODE_FOLD_PUBLIC_LEN, main.nr:50, reduced;
//! ABI-gated RAN r85: the on-disk small node_fold public_parameters = 204 — the r84 typo 223 fixed);
//! wall dominated by 108 inners (r69 4196.3 s @4c class) + M7x merges (r70 495.8/479.7 s class)
//! + the six r39-cited folds (node_fold 3,719,958 g DIGIT-EXACT, staged r73/r77).
//! DE-RISK HISTORY (box-1 RAN, zero compute): r85 fixed the publics assert (223->204, typo);
//! r90 fixed the part-(a) guard to check the RECURSIVE leaf dir the function actually loads;
//! r91 fixed the committee param (Minimum->Small with an invariant assert) — the r78 test was a
//! 1:1 copy of the r75 template whose committee line was re-parameterized everywhere EXCEPT
//! the witness-chain committee (CommitteeSize::Minimum = N=3/T=1 had silently survived).
//! r92 fixed the part-(a) guard's first leaf token: on disk it was a 15-byte non-ASCII
//! transport-redaction artifact (the lossy authoring channel redacts sk_-prefixed key
//! dir names) instead of the real 20-byte C2a leaf dir name - so the RAN-gated guard
//! (the box-2 fail-fast that must PASS a part-(a)-complete tree) could NEVER pass: the
//! leg would die at the guard even after the 3 box-2 compiles landed. Fixed byte-exact
//! (on-disk token == sk_ C2a leaf dir, RAN: real name 20-byte sha-prefix-end "omputation");
//! guard re-verified RAN on the two real trees (r84 micro = PASS, r77 small = FIRE).

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

const COMMITTEE: &str = "small";
const NODE_P: u32 = 0; // own party: block {0,19,38} (L=3 secure-8192); W_P = {3..=56} (54 scattered slots)

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

/// The pre-built stage tree root (E3_R78_STAGE_ROOT): must contain
/// `secure-8192/small/{evm,default,recursive}/...` (r77 + r78 M7x family; the 3 heavy
/// small leaves' dkg slots must also be filled by the box-2 part-(a) session — tested below).
fn stage_root() -> PathBuf {
    match std::env::var("E3_R78_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R78_STAGE_ROOT unset — the durable tree is poc/r77/root (r77 + r78 M7x family)"),
    }
}

fn c3_total_slots() -> usize {
    // C3_SLOTS = N_PARTIES * L = 19 * 3 = 57 at secure-8192/small (asserted below).
    57
}

/// Threshold modulus count L for secure-8192 = C3_SLOTS / N_PARTIES.
// At secure-8192/small N_PARTIES=19, L=3 => 57/19=3 (secure-8192 always runs L=3; ring-512 insecure is L=2 — r74's /2).
fn c3_l() -> usize {
    c3_total_slots() / 19
}

#[tokio::test]
async fn node_fold_function_end_to_end_small() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join(COMMITTEE);
    assert!(preset_tree.is_dir(), "stage tree {preset_tree:?} missing — see r77/r78 staging");
    // Box-2 part-(a) prereq: the 3 heavy small leaves' dkg slots must be filled by then.
        // (Checked cheaply up front so a run on an un-part-(a) tree fails fast, not after 108 inners.)
        // r90 (premise fix): the leg proves EVERY leaf with CircuitVariant::Recursive
        // (prove_with_variant(..., CircuitVariant::Recursive, ...)) and the production function
        // prove_node_dkg_fold loads the C2a/C2b/C4 leaf VKs from the RECURSIVE dir
        // (node_dkg_fold.rs:180-185 / 398-398, vk::load_vk_artifacts(circuits_dir(Recursive), …)).
        // The r78 original guard checked the DEFAULT dir — a different variant tree — so on a
        // runbook that leaves leaves only in default/ it stays GREEN (r87/r88/bracket class)
        // while the leg dies later at the recursive VK load, AFTER some inners. The RAN-GREEN
        // r84 micro function tree stages each heavy leaf in all 3 variant dirs (recursive/
        // included, verified this round). The guard must check the dir the leg ACTUALLY loads.
        for leaf in ["sk_share_computation", "e_sm_share_computation", "share_decryption"] {
            let p = preset_tree.join("recursive").join("dkg").join(leaf);
        assert!(p.join("share_computation.json").is_file() || p.join(format!("{leaf}.json")).is_file(),
            "part-(a) leaf slot not filled: {p:?} (box-2 24 GiB compiles C2a/C2b/C4 first — RAN r45/r46)");
    }

    let (backend, _temp) = setup_test_prover(&bb).await;
    // Hand the whole pre-built secure-8192/small tree into this run's backend (isolate; no on-disk bin writes).
    copy_dir(
        &preset_tree,
        &backend.circuits_dir.join("secure-8192").join(COMMITTEE),
    )
    .await
    .expect("stage tree handoff");

    let preset = BfvPreset::SecureThreshold8192;
    // r91 fix: this leg is the secure-8192/SMALL committee — the r75 template copy carried
    // CiphernodesCommitteeSize::Minimum (N=3/T=1) past the committee re-parameterization
    // (its own asserts below pin (57,3), W_P={3..=56}, and 204 publics, all small). The
    // minimum-width witness chain is rejected by the small circuit's committee gate (or its
    // parity-share sizing) before any expensive prove — but the leg had no guard, so the
    // silent misfit survived 3 rounds. Invariant assert keeps it dead forever.
    let committee = CiphernodesCommitteeSize::Small.values();
    assert_eq!((committee.n, committee.h, committee.threshold), (19, 10, 9),
        "r78 leg committee must be secure-8192/small (N=19/T=9/H=10)");
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
        .prove_with_variant(&prover, &preset, &pk_bfv_data, "e3-r78-c0", CircuitVariant::Recursive, &ad)
        .expect("C0 pk proof");
    wall.push(("c0", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c1_proof = PkGenerationCircuit
        .prove_with_variant(&prover, &preset, &pk_gen, "e3-r78-c1", CircuitVariant::Recursive, &ad)
        .expect("C1 pk_generation proof");
    wall.push(("c1", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c2a_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_sk, "e3-r78-c2a", CircuitVariant::Recursive, &ad)
        .expect("C2a proof");
    wall.push(("c2a", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c2b_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_esm, "e3-r78-c2b", CircuitVariant::Recursive, &ad)
        .expect("C2b proof");
    wall.push(("c2b", t.elapsed().as_secs_f64()));

    // ---- 108 C3 inners (54 W_P slots x 2 lanes), serial (the r69/scope class on 4c). ----
    let (_dkg_th, dkg_dkg) = build_pair_for_preset(preset).expect("pair");
    let mut rng = rand::rng();
    let dkg_sk = SecretKey::random(&dkg_dkg, &mut rng);
    let dkg_pk = PublicKey::new(&dkg_sk, &mut rng);
    let total = c3_total_slots();
    let l = c3_l();
    assert_eq!((total, l), (57, 3), "secure-small: N_PARTIES*L=57 slots, L=3");
    let w_p: Vec<u32> = (0..total as u32)
        .filter(|&s| (s as usize) / l != NODE_P as usize)
        .collect();
    assert_eq!(w_p, (3u32..=56).collect::<Vec<u32>>(), "small scattered W_P = slots 3..=56 (54 slots; party-0 block 0,19,38 excluded)");
    t = Instant::now();
    let mut inners_a = Vec::new();
    let mut inners_b = Vec::new();
    for &slot in &w_p {
        let da = share_encryption_for_slot(preset, &dkg_sk, &dkg_pk, &sk_inputs, slot as usize, DkgInputType::SecretKey)
            .expect("C3a slot data");
        let db = share_encryption_for_slot(preset, &dkg_sk, &dkg_pk, &esm_inputs, slot as usize, DkgInputType::SmudgingNoise)
            .expect("C3b slot data");
        inners_a.push(ShareEncryptionCircuit
            .prove_with_variant(&prover, &preset, &da, &format!("e3-r78-c3a-{slot}"), CircuitVariant::Recursive, &ad)
            .expect("C3a inner"));
        inners_b.push(ShareEncryptionCircuit
            .prove_with_variant(&prover, &preset, &db, &format!("e3-r78-c3b-{slot}"), CircuitVariant::Recursive, &ad)
            .expect("C3b inner"));
    }
    wall.push(("c3-inners x108 serial", t.elapsed().as_secs_f64()));

    // ---- C4 leaves (honest rows triplicated so the H=10 decryption rows are self-consistent).
    let trip = |mut d: ShareDecryptionCircuitData| -> ShareDecryptionCircuitData {
        let row0 = d.honest_ciphertexts[0].clone();
        d.honest_ciphertexts = (0..d.honest_ciphertexts.len()).map(|_| row0.clone()).collect();
        d
    };
    let c4a_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SecretKey).expect("c4a"));
    let c4b_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SmudgingNoise).expect("c4b"));
    t = Instant::now();
    let c4a_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4a_data, "e3-r78-c4a", CircuitVariant::Recursive, &ad)
        .expect("C4a");
    wall.push(("c4a", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c4b_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4b_data, "e3-r78-c4b", CircuitVariant::Recursive, &ad)
        .expect("C4b");
    wall.push(("c4b", t.elapsed().as_secs_f64()));

    // ---- THE PRODUCTION FUNCTION (r71 wiring live inside; at small the 54/54 M7x guard
    //      FIRES: both c3 lanes route through generate_c3_merge_m7x — the r70 RAN arm-leg
    //      geometry, r78-staged M7x family). ----
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
    let res = prove_node_dkg_fold(&prover, &input, "e3-r78", &ad)
        .expect("prove_node_dkg_fold (production function)");
    let fn_wall = t.elapsed().as_secs_f64();

    let nf_pf = |label: &str| (res.proof.public_signals.len() / 32, label.to_string());
    let (n_pub, _) = nf_pf("node_fold publics");
    println!(
        "R78-fn node_fold public fields = {n_pub} (NODE_FOLD_PUBLIC_LEN secure-small = 11+19+2*(19+10)*3 = 204)  RAN"
    );
    // 204 = 6 pub inputs + 5 + N + 2*(N+H)*L pub outputs (NODE_FOLD_PUBLIC_LEN, main.nr:50,
    // reduced for N=19/H=10/L=3); fixes the r84-found arithmetic typo (223 -> 204, 2026-09-02).
    assert_eq!(n_pub, 204, "node_fold public layout must be the secure-8192 small committee shape (11+19+2*(19+10)*3)");

    let mut fn_steps = String::new();
    for s in &res.step_timings {
        fn_steps.push_str(&format!("{}={:.1}s  ", s.step, s.seconds));
    }
    println!("R78-fn step timings: {fn_steps} RAN");
    println!("R78-fn prove_node_dkg_fold wall = {fn_wall:.1}s  RAN");

    // ---- top-level verify (Default-variant fold verify over the node_fold artifact). ----
    let vok = prover
        .verify_fold_proof(&res.proof, "e3-r78", NODE_P as u64, &ad)
        .expect("verify_fold_proof node_fold");
    println!("R78-fn verify_fold_proof(node_fold) = {vok}  RAN");
    assert!(vok, "node_fold must verify");

    // ---- own-slot zero check on the c3ab state is internal to the function; here we check
    //      the function's returned node_fold carries the party binding (publics are stable).
    let owns = &res.proof.public_signals[11 * 32..12 * 32];
    // public[11] = the first [Field; N_PARTIES] binding column entry (own party at id 0).
    println!("R78-fn party-binding field[0] = 0x{} RAN", hex::encode(owns));
    // (value asserted non-fatal: node_fold encodes party commitments; the verify above is the
    //  load-bearing end-to-end check — the function would have Err'd earlier on mismatch.)

    for (label, secs) in &wall {
        println!("R78-leaf {label} = {secs:.1}s  RAN");
    }
    drop(_temp);
}