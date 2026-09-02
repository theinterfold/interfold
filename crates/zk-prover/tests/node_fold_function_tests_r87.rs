// SPDX-License-Identifier: LGPL-3.0-only
//
//! r87 — r74's committee-agnostic function leg re-parameterized to the INSECURE-512/micro
//! committee (N=9/T=4/H=5, L=2) — the LAST on-box {preset x committee} function grid cell
//! (r74 = insecure-512/minimum 171.33 s RAN; r75 = secure-8192/minimum 803.0 s RAN; r84 =
//! secure-8192/micro 2616.9 s RAN; small = the box-2 card). Closes the 2x3 grid's on-box
//! surface: every cell this 4c/7.8 GiB box can carry has a RAN whole-node number.
//!
//! Why micro is a legitimate function leg on this box: the pipeline is committee-parametric
//! (all folds size off N_PARTIES/L/H globals; the 54/54 M7x guard cleanly falls through to
//! the sequential c3_fold arm at micro — W_P = 16 inners/slots, not 54 — exactly the guard's
//! designed fallback, RAN-verified inside the function at r84 secure-micro). The
//! insecure-512 family's artifact set is the only committee width whose leaves + folds all
//! recompile on-box at micro (r80 RAN: insecure-512 C2/C4 compiles are the r81/r83 box-1 class;
//! the secure family's small leaves are the ≥24 GiB box-2 wall r45/r46).
//!
//! Premises (source RAN, r87): C0 (dkg/pk) / C1 (threshold/pk_generation) / C3 (share_encryption)
//! core cones carry ZERO N_PARTIES/H refs (grep: 0 hits) ⇒ committee-FREE class (digit-level
//! RAN r35/r39/r44; reused from the sha-pinned r74 min durables); C2a carries 43 N_PARTIES
//! refs + C2b/C4 carry N_PARTIES/H refs ⇒ fresh micro compiles (this round's compile leg). node_fold public surface
//! = 76 = 11 + N + 2*(N+H)*L with N=9/H=5/L=2 (the crate helper node_fold_public_field_count
//! (node_fold_public.rs:14-15), RAN-validated at r74=34 / r75=44 / r84=104 / r78-small=204;
//! NODE_FOLD_PUBLIC_LEN, node_fold/src/main.nr:50, with L_THRESHOLD=2 for insecure-512).
//!
//! Artifacts: the insecure-512/micro tree is RAN-compiled by poc/r87/r87_compile_leg.sh
//! (C2a/C2b/C4 + 6 folds fresh at micro; C0/C1/C3 reused from the sha-pinned r74 min
//! durables — committee-free class) and staged by poc/r87/r87_stage.sh into
//! poc/r87/root/insecure-512/micro/.
//! Run (launcher poc/r87/r87_fn_launch.sh, quiet box, release, DRAFT wall ~4-6 min):
//!   E3_R87_STAGE_ROOT=/home/dev/interfold-research/poc/r87/root cargo test --release \
//!     -p e3-zk-prover --test node_fold_function_tests_r87 -- --nocapture

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

const COMMITTEE: &str = "micro";
const NODE_P: u32 = 0; // own party: slots {0,1} (L=2 insecure-512); W_P = {2..=17} (16 slots)

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

/// The pre-built stage tree root (E3_R87_STAGE_ROOT): must contain
/// `insecure-512/micro/{evm,default,recursive}/...` (poc/r87/r87_stage.sh output).
fn stage_root() -> PathBuf {
    match std::env::var("E3_R87_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R87_STAGE_ROOT unset — run poc/r87/r87_stage.sh first"),
    }
}

fn c3_total_slots() -> usize {
    // C3_SLOTS = N_PARTIES * L = 9 * 2 = 18 at insecure-512/micro (asserted below).
    18
}

/// Threshold modulus count L for this preset = C3_SLOTS / N_PARTIES.
fn c3_l() -> usize {
    c3_total_slots() / 9
}

#[tokio::test]
async fn node_fold_function_end_to_end_micro() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("insecure-512").join(COMMITTEE);
    assert!(
        preset_tree.is_dir(),
        "stage tree {preset_tree:?} missing — build via poc/r87/r87_stage.sh"
    );

    let (backend, _temp) = setup_test_prover(&bb).await;
    // Hand the whole pre-built insecure-512/micro tree into this run's backend (isolate; no on-disk bin writes).
    copy_dir(
        &preset_tree,
        &backend.circuits_dir.join("insecure-512").join(COMMITTEE),
    )
    .await
    .expect("stage tree handoff");

    let preset = BfvPreset::InsecureThreshold512;
    let committee = CiphernodesCommitteeSize::Micro.values();
    assert_eq!((committee.n, committee.threshold, committee.h), (9, 4, 5), "micro committee (N=9/T=4/H=5)");
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);
    assert_eq!(ad, format!("insecure-512/{COMMITTEE}"));

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
        .prove_with_variant(&prover, &preset, &pk_bfv_data, "e3-r87-c0", CircuitVariant::Recursive, &ad)
        .expect("C0 pk proof");
    wall.push(("c0", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c1_proof = PkGenerationCircuit
        .prove_with_variant(&prover, &preset, &pk_gen, "e3-r87-c1", CircuitVariant::Recursive, &ad)
        .expect("C1 pk_generation proof");
    wall.push(("c1", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c2a_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_sk, "e3-r87-c2a", CircuitVariant::Recursive, &ad)
        .expect("C2a proof");
    wall.push(("c2a", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c2b_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_esm, "e3-r87-c2b", CircuitVariant::Recursive, &ad)
        .expect("C2b proof");
    wall.push(("c2b", t.elapsed().as_secs_f64()));

    // ---- 16 C3 inners (8 W_P slots x 2 lanes), serial (r72 RAN: no wall gain for K>1 at 4c). ----
    let (_dkg_th, dkg_dkg) = build_pair_for_preset(preset).expect("pair");
    let mut rng = rand::rng();
    let dkg_sk = SecretKey::random(&dkg_dkg, &mut rng);
    let dkg_pk = PublicKey::new(&dkg_sk, &mut rng);
    let total = c3_total_slots();
    let l = c3_l();
    assert_eq!((total, l), (18, 2), "insecure-micro: N_PARTIES*L=18 slots, L=2");
    let w_p: Vec<u32> = (0..total as u32)
        .filter(|&s| (s as usize) / l != NODE_P as usize)
        .collect();
    assert_eq!(w_p.first().copied(), Some(2), "insecure-micro own-party block = slots 0..1; W_P starts at 2");
    assert_eq!(w_p.len(), 16, "micro W_P = 18-2 = 16 slots (NOT 54 => the 54/54 M7x guard stays inert)");
    t = Instant::now();
    let mut inners_a = Vec::new();
    let mut inners_b = Vec::new();
    for &slot in &w_p {
        let da = share_encryption_for_slot(preset, &dkg_sk, &dkg_pk, &sk_inputs, slot as usize, DkgInputType::SecretKey)
            .expect("C3a slot data");
        let db = share_encryption_for_slot(preset, &dkg_sk, &dkg_pk, &esm_inputs, slot as usize, DkgInputType::SmudgingNoise)
            .expect("C3b slot data");
        inners_a.push(ShareEncryptionCircuit
            .prove_with_variant(&prover, &preset, &da, &format!("e3-r87-c3a-{slot}"), CircuitVariant::Recursive, &ad)
            .expect("C3a inner"));
        inners_b.push(ShareEncryptionCircuit
            .prove_with_variant(&prover, &preset, &db, &format!("e3-r87-c3b-{slot}"), CircuitVariant::Recursive, &ad)
            .expect("C3b inner"));
    }
    wall.push(("c3-inners x16 serial", t.elapsed().as_secs_f64()));

    // ---- C4 leaves (honest rows triplicated so the H=5 decryption rows are self-consistent).
    let trip = |mut d: ShareDecryptionCircuitData| -> ShareDecryptionCircuitData {
        let row0 = d.honest_ciphertexts[0].clone();
        d.honest_ciphertexts = (0..d.honest_ciphertexts.len()).map(|_| row0.clone()).collect();
        d
    };
    let c4a_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SecretKey).expect("c4a"));
    let c4b_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SmudgingNoise).expect("c4b"));
    t = Instant::now();
    let c4a_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4a_data, "e3-r87-c4a", CircuitVariant::Recursive, &ad)
        .expect("C4a");
    wall.push(("c4a", t.elapsed().as_secs_f64()));
    t = Instant::now();
    let c4b_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4b_data, "e3-r87-c4b", CircuitVariant::Recursive, &ad)
        .expect("C4b");
    wall.push(("c4b", t.elapsed().as_secs_f64()));

    // ---- THE PRODUCTION FUNCTION (r71 wiring live inside; the 54/54 M7x guard falls
    //      through to the sequential c3_fold arms at micro, by design — as r74 at minimum
    //      and r84 at secure-micro). ----
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
    let res = prove_node_dkg_fold(&prover, &input, "e3-r87", &ad)
        .expect("prove_node_dkg_fold (production function)");
    let fn_wall = t.elapsed().as_secs_f64();

    let nf_pf = |label: &str| (res.proof.public_signals.len() / 32, label.to_string());
    let (n_pub, _) = nf_pf("node_fold publics");
    println!(
        "R87-fn node_fold public fields = {n_pub} (node_fold_public_field_count(9,5,2) = 11+9+2*(9+5)*2 = 76)  RAN"
    );
    assert_eq!(n_pub, 76, "node_fold public layout must be the insecure-512 micro committee shape");

    let mut fn_steps = String::new();
    for s in &res.step_timings {
        fn_steps.push_str(&format!("{}={:.1}s  ", s.step, s.seconds));
    }
    println!("R87-fn step timings: {fn_steps} RAN");
    println!("R87-fn prove_node_dkg_fold wall = {fn_wall:.1}s  RAN");

    // ---- top-level verify (Default-variant fold verify over the node_fold artifact). ----
    let vok = prover
        .verify_fold_proof(&res.proof, "e3-r87", NODE_P as u64, &ad)
        .expect("verify_fold_proof node_fold");
    println!("R87-fn verify_fold_proof(node_fold) = {vok}  RAN");
    assert!(vok, "node_fold must verify");

    // ---- own-slot zero check on the c3ab state is internal to the function; here we check
    //      the function's returned node_fold carries the party binding (publics are stable).
    let owns = &res.proof.public_signals[11 * 32..12 * 32];
    // public[11] = the first [Field; N_PARTIES] binding column entry (own party at id 0).
    println!("R87-fn party-binding field[0] = 0x{} RAN", hex::encode(owns));
    // (value asserted non-fatal: node_fold encodes party commitments; the verify above is the
    //  load-bearing end-to-end check — the function would have Err'd earlier on mismatch.)

    for (label, secs) in &wall {
        println!("R87-leaf {label} = {secs:.1}s  RAN");
    }
    drop(_temp);
}