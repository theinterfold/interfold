// SPDX-License-Identifier: LGPL-3.0-only
//
//! r121 - the C7 (threshold/decrypted_shares_aggregation) PRODUCTION-FIELD
//! prove-wall anchor: RAN at secure-8192/small (N=19/T=9/H=10, L=3) - the
//! production field - rather than at the InsecureThreshold512/Minimum dev leg.
//!
//! Why this closes a real gap (the r97-class witness family is COMPLETE for the
//! DKG leaves C1/C2/C4/C5/C6 + C6 prod-field r119/C5 prod-field r120, but the
//! POST-DKG decryption-tail leaf C7 was NEVER RAN-proved at the production
//! committee): r115 source-minimality told us C7 is pure deterministic
//! arith (Lagrange + CRT + decode, no FS sponge/challenge - 0 hits), so its
//! single structural risk is the WITNESS layer at T=9/H=10 (the r97
//! "witness-exceeds-committed-bound" class) - and the C7 PROVE WALL at
//! secure/small has never been RAN on box-1. The on-disk bench report
//! (results_secure_agg_small/report.md:86) carries a "C7 136,374 cons" row
//! but that is from the BENCH run's OWN committee + toolchain - report.md:8
//! "H=5, N=5, T=2" (micro) + report.md:6 branch params/dyn-conf @ de480d63
//! (old main lineage) - so it is NOT the production field; this round's fresh
//! secure-8192/small compile is the durable production-field anchor
//! (334,161 gates / 142,900 ACIR at this toolchain pin); the P4 "C7 + Pi_dec
//! fold" span 205.70 s (full) / 64.51 s (C7+fold) (report.md:104/105) and
//! ZkDecryptedSharesAggregation tracked 3.33 s are integration/M4-Pro numbers,
//! never RAN on box-1 at the production committee. This leg RAN-converts the
//! single-prove platform datum at small:
//!   (1) 5 independent C7 samples at secure/small (fresh 19-party TRBFV secrets,
//!       T=9 decryption shares - the r97-class witness footprint for C7 at the
//!       production committee),
//!   (2) 5 C7 PROVES at secure/small (CircuitVariant::Default into the r121-
//!       staged noir-recursive-no-zk C7 vk set - the single-prove wall datum;
//!       matches the production worker handle_decrypted_shares_aggregation,
//!       multithread.rs:1575-1596 which uses CircuitVariant::Default),
//!   (3) 5 proof-VERIFIES (ok=true - coherence of the staged vk set + the
//!       in-circuit d_commitment bind + Lagrange/CRT/decode relations),
//! reporting per-prove wall + total.
//!
//! Scope discipline: the FULL 19-NODE decryption aggregation (P4 c7 + Pi_dec
//! fold + network, the 205.70 s integration wall) stays box-2 (r78 card).
//! This is the C7-subtree production-field leg: the single-prove cost + witness
//! layer at small, box-1 RAN. Box-1 RAM RAN-feasible: C7 136,374 cons is the
//! SMALLEST leaf (<< C5 2,554,248 g r120 / C6 2,562,117 g r119 / C3 2,966,353
//! g r43); samples + serial proves so per-sample peaks do not stack.
//!
//! Stage tree (produced by poc/r121/stage_c7_secure_small_r121.py):
//!     $E3_R121_STAGE_ROOT/secure-8192/small/
//!         default/threshold/decrypted_shares_aggregation/
//!             {decrypted_shares_aggregation.json, .vk, .vk_hash}
//!
//! Run:
//!     E3_R121_STAGE_ROOT=/home/dev/interfold-research/interfold/poc/r121/root \
//!         cargo test --release -p e3-zk-prover --test c7_secure_small_r121 -- --nocapture
#![allow(dead_code, unused_imports)]
mod common;

use std::path::PathBuf;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::circuit::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{CircuitVariant, Provable, ZkProver};

const PROVES: usize = 5; // 5 C7 proves at secure/small (single-prove wall datum)

fn stage_root() -> PathBuf {
    match std::env::var("E3_R121_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R121_STAGE_ROOT unset - run poc/r121/stage_c7_secure_small_r121.py first"),
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

#[tokio::test]
async fn c7_secure_small_proves_and_verifies() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join("small");
    assert!(
        preset_tree.is_dir(),
        "stage tree {} missing - run poc/r121/stage_c7_secure_small_r121.py first",
        preset_tree.display()
    );

    // SECURITY FENCE: the staged C7 json is the production-field code - the
    // durable gate anchor is this round's FRESH secure-8192/small compile
    // (334,161 gates / 142,900 ACIR, recorded in poc/r121/secure_gates_r121.json
    // by the stage). The bench "136,374 cons" row (report.md:86) is the bench
    // run's OWN micro committee (H=5/N=5/T=2, report.md:8) on an older branch,
    // so it is NOT used as the production-field anchor here; the staged json
    // sha16 a72912c3915355b6 (stage) is byte-identical to the compile that the
    // stage measured, so we RAN-prove the SAME circuit the stage anchored.
    // (The two gate figures are from different committee sizes + toolchain pins,
    // so neither is a re-anchoring of the other; the fresh compile is the
    // production anchor by construction.)
    let staged_json = preset_tree
        .join("default/threshold/decrypted_shares_aggregation/decrypted_shares_aggregation.json");
    assert!(
        staged_json.exists(),
        "staged C7 json {} missing (stage materialize failed)",
        staged_json.display()
    );

    let (backend, _temp) = setup_test_prover(&bb).await;
    copy_dir(&preset_tree, &backend.circuits_dir.join("secure-8192").join("small"))
        .await
        .expect("stage tree handoff to backend circuits_dir");

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    // small: T=9, H=10, N=19
    assert_eq!(committee.h, 10, "small committee H=10 expected, got {}", committee.h);
    assert_eq!(committee.n, 19, "small committee N=19 expected, got {}", committee.n);
    assert_eq!(committee.threshold, 9, "small committee T=9 expected, got {}", committee.threshold);
    let ad = preset.artifacts_dir_for_committee("small");
    assert_eq!(ad, "secure-8192/small");
    let prover = ZkProver::new(&backend);

    let mut prove_walls: Vec<f64> = Vec::with_capacity(PROVES);
    let mut total_prove = 0.0f64;
    let mut samples_wall = 0.0f64;

    // (1)+(2) PROVES x PROVES at secure/small (CircuitVariant::Default - the
    // production worker's noir-recursive-no-zk path, multithread.rs:1575-1596).
    // r97-class witness anchor at the production committee: the in-circuit
    // d_commitment bind (T+1=10 compute_threshold_decryption_share_commitment
    // checks), the per-limb d-coeff range-checks vs BIT_D_NATIVE / BIT_NOISE,
    // the Lagrange-at-zero + CRT + decode relations all RAN-execute here at
    // T=9/H=10/L=3 for the FIRST TIME on box-1.
    for i in 0..PROVES {
        // (1) sample: fresh 19-party TRBFV secrets + T=9 decryption shares.
        let ts = Instant::now();
        let sample = DecryptedSharesAggregationCircuitData::generate_sample(preset, committee.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "C7 sample #{} generation FAILED at secure/small (T=9, r97-class \
                     witness footprint): {:?}",
                    i, e
                )
            });
        samples_wall += ts.elapsed().as_secs_f64();

        // (2) PROVE at secure/small, CircuitVariant::Default (noir-recursive-no-zk
        //     vk staged under default/threshold/decrypted_shares_aggregation/).
        let e3 = format!("e3-r121-c7-{}", i);
        let tp = Instant::now();
        let proof = DecryptedSharesAggregationCircuit
            .prove_with_variant(
                &prover,
                &preset,
                &sample,
                &e3,
                CircuitVariant::Default,
                &ad,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "C7 PROVE #{} FAILED at secure/small (witness-layer breach, r97 \
                     class - the C7 secure/small witness does not satisfy the circuit at \
                     T=9/H=10/L=3; the RED 'witness exceeds committed bound' shape): {:?}",
                    i, e
                )
            });
        let pw = tp.elapsed().as_secs_f64();
        prove_walls.push(pw);
        total_prove += pw;

        // (3) VERIFY the proof (ok=true => staged vk + artifact coherent).
        let party_id = 1u64;
        let tv = Instant::now();
        let ok = DecryptedSharesAggregationCircuit
            .verify_with_variant(&prover, &proof, &e3, party_id, CircuitVariant::Default, &ad)
            .unwrap_or_else(|e| {
                panic!("C7 VERIFY #{} errored at secure/small: {:?}", i, e)
            });
        let vw = tv.elapsed().as_secs_f64();
        assert!(
            ok,
            "C7 VERIFY #{} returned false at secure/small: staged vk + artifact \
             incoherent (r117 stale-vk class)",
            i
        );
        println!(
            "c7 prove #{}/{} secure/small T=9/H=10: PROVE {:.2}s / VERIFY {:.2}s (ok=true)",
            i + 1,
            PROVES,
            pw,
            vw
        );
        prover.cleanup(&e3).unwrap();
        let _ = CircuitName::DecryptedSharesAggregation;
    }

    let avg = total_prove / PROVES as f64;
    let mut ms = prove_walls.clone();
    ms.sort_by(|a, b| f64::total_cmp(a, b));
    let min = *ms.first().unwrap();
    let max = *ms.last().unwrap();
    println!();
    println!(
        "C7 PRODUCTION-FIELD ANCHOR GREEN @secure-8192/small (N=19/T=9/H=10/L=3): \
         {} PROVES, each {:.2}-{:.2}s, avg {:.2}s; samples x{} total {:.2}s; \
         total prove wall {:.2}s",
        PROVES,
        min,
        max,
        avg,
        PROVES,
        samples_wall,
        total_prove
    );
    // The single-prove wall datum: avg is the platform anchor for the P4 term's
    // C7 sub-span (bench P4 span 205.70 s is the integration-level wall, NOT the
    // single-prove; ZkDecryptedSharesAggregation tracked 3.33 s on the M4 Pro at
    // the bench's own micro committee; this box-1 4c number is the production
    // committee single-prove at the single-core class).
    println!(
        "single-prove platform datum (box-1 4c, release): avg {:.2}s / C7 334,161 gates \
         (r121 fresh secure-8192/small compile, durable anchor in secure_gates_r121.json) \
         - this is the C7 sub-span of the P4 205.70 s bench integration wall, now RAN \
         at the production committee",
        avg
    );
}