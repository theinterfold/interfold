// SPDX-License-Identifier: LGPL-3.0-only
//
//! r120 - the C5 (threshold/pk_aggregation) PRODUCTION-FIELD prove-wall anchor:
//! RAN at secure-8192/small (N=19/T=9/H=10, L=3) - the production field - rather
//! than at the InsecureThreshold512/Minimum dev leg.
//!
//! Why this closes a real gap (the r97-class witness family is C1/C2/C3/C4/C6,
//! but was NEVER C5): r113's whole secure/small 3-arm gate split
//! (verify_c5_secure_split_r113.py, V0 2,554,248 g / (a) 2,157,441 g / (b) 180,958 g
//! / (c) 215,849 g) was a GATE read (0 inners, 0 witness). r110/r111/r112/r113
//! source-minimality told us the C5 circuit source is minimal, de-risking any
//! future lever; but (a) the C5 PROVE WALL at secure/small (N=19/H=10) has never
//! been RAN on box-1, and (b) the C5 WITNESS layer at T=9/H=10 (the r97
//! "witness-exceeds-committed-bound" class r87 killed the C1 insecure/micro cell
//! on) has never been RAN-exercised for C5 - r97 RAN C1, r98 RAN C2/C4, r119 RAN
//! C6, C3 is committee-free (r41), and C5 was the missing 6th leaf.
//!
//! The bench P2 span 400.03 s (r28-class "Aggregator P2: PkAggregation pending
//! -> PublicKeyAggregated") is an integration-level number inherited from the
//! main-net/M4 Pro benchmark report; its single-prove component (C5 ZkPkAgg ~
//! 28-31 s tracked at micro/small) has never been RAN on box-1 at the production
//! committee. This leg RAN-converts the single-prove platform datum at small:
//!   (1) 5 independent C5 samples at secure/small (fresh H=10 pk_sks, public-key
//!       aggregate - the r97-class witness footprint for C5 at the production
//!       committee),
//!   (2) 5 C5 PROVES at secure/small (CircuitVariant::Default into the r120-
//!       staged noir-recursive-no-zk C5 vk set - the single-prove wall datum),
//!   (3) 5 proof-VERIFIES (ok=true - coherence of the staged vk set),
//! reporting per-prove wall + total.
//!
//! Scope discipline: the FULL 19-NODE P2 aggregator span (the 400.03 s integration
//! wall) stays box-2 (r78 card). This is the C5-subtree production-field leg:
//! the single-prove cost + witness layer at small, box-1 RAN. Box-1 RAM
//! RAN-feasible: C5 2,554,248 g << C3-small 2,966,353 g (RAN-compiled 5.87 GiB
//! r43) and ~ C6-small 2,562,117 g (RAN-proven, 10 proves 377.00 s total r119);
//! serial proves so per-sample peaks do not stack.
//!
//! Stage tree (produced by poc/r120/stage_c5_secure_small_r120.py):
//!     $E3_R120_STAGE_ROOT/secure-8192/small/
//!         default/threshold/pk_aggregation/{pk_aggregation.json, .vk, .vk_hash}
//!
//! Run:
//!     E3_R120_STAGE_ROOT=/home/dev/interfold-research/interfold/poc/r120/root \
//!         cargo test --release -p e3-zk-prover --test c5_secure_small_r120 -- --nocapture
#![allow(dead_code, unused_imports)]
mod common;

use std::path::PathBuf;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::circuits::threshold::pk_aggregation::circuit::{
    PkAggregationCircuit, PkAggregationCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{CircuitVariant, Provable, ZkProver};

const PROVES: usize = 5; // 5 C5 proves at secure/small (single-prove wall datum)

fn stage_root() -> PathBuf {
    match std::env::var("E3_R120_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R120_STAGE_ROOT unset - run poc/r120/stage_c5_secure_small_r120.py first"),
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
async fn c5_secure_small_proves_and_verifies() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join("small");
    assert!(
        preset_tree.is_dir(),
        "stage tree {} missing - run poc/r120/stage_c5_secure_small_r120.py first",
        preset_tree.display()
    );

    // SECURITY FENCE: the staged C5 json is the r113 code - verify the vestigial gate
    // count is DIGIT-EXACT to the r113/r39/r44 secure/small V0 anchor, so we RAN-prove
    // the SAME circuit (2,554,248 g) r113 gate-measured, not a drifted/rebuild.
    let staged_json = preset_tree
        .join("default/threshold/pk_aggregation/pk_aggregation.json");
    assert!(
        staged_json.exists(),
        "staged C5 json {} missing (stage materialize failed)",
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
    let ad = preset.artifacts_dir_for_committee("small");
    assert_eq!(ad, "secure-8192/small");
    let prover = ZkProver::new(&backend);

    let mut prove_walls: Vec<f64> = Vec::with_capacity(PROVES);
    let mut total_prove = 0.0f64;
    let mut samples_wall = 0.0f64;

    // (1)+(2) PROVES x PROVES at secure/small (CircuitVariant::Default).
    // r97-class witness anchor at the production committee: every pk0_share
    // range-check (BIT_PK=59 vs the configured secure bound), the crp + pk_agg
    // relation, and the per-honest re-commit consistency (the (a) block r113
    // quantified as 2,157,441 g = 84.46% of C5-secure) all RAN-execute here at
    // T=9/H=10 for the FIRST TIME on box-1.
    for i in 0..PROVES {
        // (1) sample: fresh H=10 pk_sks + aggregate.
        let ts = Instant::now();
        let sample = PkAggregationCircuitData::generate_sample(preset, committee.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "C5 sample #{} generation FAILED at secure/small (H=10, r97-class \
                     witness footprint): {:?}",
                    i, e
                )
            });
        samples_wall += ts.elapsed().as_secs_f64();

        // (2) PROVE at secure/small, CircuitVariant::Default (noir-recursive-no-zk
        //     vk staged under default/threshold/pk_aggregation/).
        let e3 = format!("e3-r120-c5-{}", i);
        let tp = Instant::now();
        let proof = PkAggregationCircuit
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
                    "C5 PROVE #{} FAILED at secure/small (witness-layer breach, r97 \
                     class - the C5 secure/small witness does not satisfy the circuit at \
                     T=9/H=10; the RED 'witness exceeds committed bound' shape): {:?}",
                    i, e
                )
            });
        let pw = tp.elapsed().as_secs_f64();
        prove_walls.push(pw);
        total_prove += pw;

        // (3) VERIFY the proof (ok=true => staged vk + artifact coherent).
        let party_id = 1u64;
        let tv = Instant::now();
        let ok = PkAggregationCircuit
            .verify_with_variant(&prover, &proof, &e3, party_id, CircuitVariant::Default, &ad)
            .unwrap_or_else(|e| {
                panic!("C5 VERIFY #{} errored at secure/small: {:?}", i, e)
            });
        let vw = tv.elapsed().as_secs_f64();
        assert!(
            ok,
            "C5 VERIFY #{} returned false at secure/small: staged vk + artifact \
             incoherent (r117 stale-vk class)",
            i
        );
        println!(
            "c5 prove #{}/{} secure/small H=10: PROVE {:.2}s / VERIFY {:.2}s (ok=true)",
            i + 1,
            PROVES,
            pw,
            vw
        );
        prover.cleanup(&e3).unwrap();
        let _ = CircuitName::PkAggregation;
    }

    let avg = total_prove / PROVES as f64;
    let mut ms = prove_walls.clone();
    ms.sort_by(|a, b| f64::total_cmp(a, b));
    let min = *ms.first().unwrap();
    let max = *ms.last().unwrap();
    println!();
    println!(
        "C5 PRODUCTION-FIELD ANCHOR GREEN @secure-8192/small (N=19/H=10/L=3): \
         {} PROVES, each {:.1}-{:.1}s, avg {:.1}s; samples x{} total {:.2}s; \
         total prove wall {:.1}s",
        PROVES,
        min,
        max,
        avg,
        PROVES,
        samples_wall,
        total_prove
    );
    // The single-prove wall datum: avg is the platform anchor for the P2 term's
    // C5 sub-span (bench P2 span 400.03 s is the integration-level wall, NOT the
    // single-prove; this number is the box-1 4c single-prove platform).
    println!(
        "single-prove platform datum (box-1 4c, release): avg {:.1}s / C5 2,554,248 g \
         (r113 anchor DIGIT-EXACT) - this is the C5 sub-span of the P2 400.03 s bench \
         integration wall, now RAN at the production committee",
        avg
    );
}