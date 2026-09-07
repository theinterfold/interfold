// SPDX-License-Identifier: LGPL-3.0-only
//
//! r119 - the C6 (threshold/share_decryption) fold-chain PRODUCTION-FIELD
//! soundness anchor: RAN at secure-8192/small (N=19/T=9/H=10, L=3) - the
//! production field where the C6 I14 gate cut (r115, commit 678d0fd4;
//! -13.943 %) and the C6 post-patch conformance (r117) both landed - rather
//! than at r117's InsecureThreshold512/Minimum (N=3/T=1) leg.
//!
//! Why this closes a real gap: r117's proof-level soundness anchor
//! (c6_fold_sequential_proves_and_verifies) hard-codes InsecureThreshold512/
//! Minimum. At the production field the C6 proof had only ever been COMPILED
//! (r115) and never once PROVED-and-verified end-to-end; and the C6
//! secure/small WITNESS layer at T=9/L=3 (the r97 witness-risk class de-risked
//! for C1/C2/C4, never C6) had never been RAN-exercised at the production
//! committee. This test is the box-1 mirror of the r117 leg at small:
//!   (1) 10 independent C6 samples at secure/small (fresh 19-party secrets, T=9),
//!   (2) 10 inner C6 proves (CircuitVariant::Recursive, into the r119-staged
//!       secure/small C6 leaf vk set - the r97-class witness anchor),
//!   (3) the full 10-slot c6_fold chain via the CANONICAL production API
//!       (generate_sequential_c6_fold: c6_fold_kernel genesis + c6_fold steps),
//!   (4) verify_fold_proof on the folded proof - r117's RED->GREEN anchor now
//!       RAN at the production field.
//!
//! Scope discipline: the FULL 19-NODE ceremony (c3 bulk + c7 + nodes tail,
//! hours-class) stays box-2 (r78, standing card). This is the C6-subtree
//! production-field leg: the two operations r117 RAN at min, replayed at small.
//! Box-1 RAM RAN-feasible: C6 2.56M g << the C2a-micro 4.28M g class that
//! peak-backed 7.09 GiB on this box (RAN r82); folds 1.45M g; serial chain so
//! peaks do not stack.
//!
//! Stage tree (produced by poc/r119/stage_c6_secure_small_r119.py):
//!     $E3_R119_STAGE_ROOT/secure-8192/small/
//!         recursive/threshold/share_decryption/{share_decryption.json, .vk, .vk_hash}
//!         default/recursive_aggregation/c6_fold/{c6_fold.json, .vk, .vk_hash}
//!         default/recursive_aggregation/c6_fold_kernel/{c6_fold_kernel.json, .vk, .vk_hash}
//!
//! Run:
//!     E3_R119_STAGE_ROOT=/home/dev/interfold-research/interfold/poc/r119/root \
//!         cargo test --release -p e3-zk-prover --test c6_fold_secure_small_r119 -- --nocapture

mod common;

use std::path::PathBuf;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::threshold::share_decryption::{
    ShareDecryptionCircuit, ShareDecryptionCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{generate_sequential_c6_fold, CircuitVariant, Provable, ZkProver};

const SLOTS: usize = 10; // small T=9 => T + 1 = 10 C6 slots

fn stage_root() -> PathBuf {
    match std::env::var("E3_R119_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R119_STAGE_ROOT unset - run poc/r119/stage_c6_secure_small_r119.py first"),
    }
}

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

/// Read total_slots (= T+1) from the STAGED c6_fold ABI: acc_public_inputs length
/// is 6 + 4 * total_slots (c6_accumulator.rs::c6_fold_public_input_field_count).
fn total_slots_from_staged_c6_fold(stage_root: &std::path::Path) -> usize {
    let p = stage_root
        .join("secure-8192/small/default/recursive_aggregation/c6_fold/c6_fold.json");
    let raw = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("read {}: {} (run poc/r119/stage_c6_secure_small_r119.py)", p.display(), e));
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", p.display(), e));
    let len = v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c6_fold.json: abi.parameters.acc_public_inputs.length") as usize;
    assert!(
        len >= 6 && (len - 6).is_multiple_of(4),
        "unexpected acc_public_inputs length {} (expected 6 + 4 * slots)",
        len
    );
    (len - 6) / 4
}

#[tokio::test]
async fn c6_secure_small_fold_chain_proves_and_verifies() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join("small");
    assert!(
        preset_tree.is_dir(),
        "stage tree {} missing - run poc/r119/stage_c6_secure_small_r119.py first",
        preset_tree.display()
    );

    let (backend, _temp) = setup_test_prover(&bb).await;
    copy_dir(&preset_tree, &backend.circuits_dir.join("secure-8192").join("small"))
        .await
        .expect("stage tree handoff to backend circuits_dir");

    let total_slots = total_slots_from_staged_c6_fold(&root);
    assert_eq!(
        total_slots, SLOTS,
        "total_slots from staged c6_fold ABI = {}, expected {} (small T=9 => T+1=10)",
        total_slots, SLOTS
    );

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    let ad = preset.artifacts_dir_for_committee("small");
    assert_eq!(ad, "secure-8192/small");
    let prover = ZkProver::new(&backend);

    let mut walls = Vec::new();

    // (1) SLOTS independent C6 samples at secure/small (fresh 19-party secrets, T=9).
    let mut samples = Vec::with_capacity(SLOTS);
    let t = Instant::now();
    for i in 0..SLOTS {
        let s = ShareDecryptionCircuitData::generate_sample(preset, committee.clone())
            .unwrap_or_else(|e| panic!("C6 sample #{} generation failed at secure/small: {:?}", i, e));
        samples.push(s);
    }
    let ds = t.elapsed().as_secs_f64();
    walls.push(("samples x10 (secure/small T=9, total)", ds));
    println!("10 C6 samples generated OK (total {:.2}s)", ds);

    // (2) SLOTS inner C6 PROVES at secure/small (CircuitVariant::Recursive).
    // r97-class witness anchor at the production committee: every quotient
    // range-check (BIT_R1/BIT_R2 vs the configured secure bounds), the ct
    // commitment bind, and the I14 payload class (ct limbs bound to the 1-field
    // public ct_commitment) all RAN-execute here at T=9/L=3 for the first time.
    let mut inners = Vec::with_capacity(SLOTS);
    let mut inner_total = 0.0f64;
    for i in 0..SLOTS {
        let e3 = format!("e3-r119-c6-inner-{}", i);
        let t = Instant::now();
        let inner = ShareDecryptionCircuit
            .prove_with_variant(&prover, &preset, &samples[i], &e3, CircuitVariant::Recursive, &ad)
            .unwrap_or_else(|e| {
                panic!(
                    "C6 inner prove #{} FAILED at secure/small (witness-layer breach, r97 \
                     class - the C6 secure/small witness does not satisfy the circuit at \
                     T=9/L=3; this is the RED 'witness exceeds committed bound' shape): {:?}",
                    i, e
                )
            });
        inner_total += t.elapsed().as_secs_f64();
        inners.push(inner);
        println!(
            "c6 inner #{}/{} PROVED secure/small T=9 ({:.2}s)",
            i + 1,
            SLOTS,
            t.elapsed().as_secs_f64()
        );
        prover.cleanup(&e3).unwrap();
    }
    walls.push(("c6 inner proves x10 total", inner_total));

    // (3) FULL 10-slot c6_fold chain via the CANONICAL production API (kernel
    // genesis step + 9 c6_fold steps) at the small stage tree.
    let slots_idx: Vec<u32> = (0..SLOTS as u32).collect();
    let t = Instant::now();
    let folded = generate_sequential_c6_fold(
        &prover,
        &inners,
        &slots_idx,
        total_slots,
        "e3-r119-c6fold",
        &ad,
    )
    .expect("c6_fold 10-slot chain at secure/small (canonical kernel-genesis + steps)");
    let fold_wall = t.elapsed().as_secs_f64();
    walls.push(("c6_fold_kernel genesis + 9 c6_fold steps (total)", fold_wall));
    assert_eq!(folded.circuit, CircuitName::C6Fold);
    assert!(!folded.data.is_empty(), "c6_fold proof data should be non-empty");
    assert!(!folded.public_signals.is_empty(), "c6_fold publics should be non-empty");

    // (4) PROOF-VERIFY the folded chain - the production-field soundness anchor
    // (r117's verify_fold_proof=true, RAN at insecure/min; now RAN at secure/small).
    let party_id = 1u64;
    let t = Instant::now();
    let ok = prover
        .verify_fold_proof(&folded, "e3-r119-c6fold", party_id, &ad)
        .expect("verify_fold_proof at secure/small");
    walls.push(("verify_fold_proof (production field)", t.elapsed().as_secs_f64()));
    assert!(
        ok,
        "verify_fold_proof == false at secure/small: the C6 I14-patched leaf + small fold \
         chain vk set is incoherent on the production field (r117 stale-vk class or \
         post-patch conformance gap at small)"
    );

    let total: f64 = walls.iter().map(|(_, s)| *s).sum();
    for (label, s) in &walls {
        println!("step: {:<56} {:>8.2} s", label, s);
    }
    println!(
        "c6 production-field anchor GREEN @secure-8192/small (N=19/T=9/H=10): total wall \
         {:.1}s = 10 C6 inner proves + 10-slot c6_fold chain (kernel genesis + 9 steps) + \
         verify_fold_proof=true",
        total
    );
}