// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Machine-network tests for the C8-CKKS gate: a hybrid ceremony holds
//! every party's round-1 contribution until its `dnum` signed digit
//! proofs are (a) bound to the reassembled share — `digit`, shared
//! `s_commitment` == the party's C1-CKKS sk commitment, shared
//! `u_commitment`, `share_commitment` recomputed from the wire bytes —
//! and (b) Honk-verified (mocked here through the machine's verification
//! callback, the way the ShareVerificationActor reports back).

use super::machine::*;
use e3_events::{CircuitName, E3id, Proof, ProofPayload, ProofType, SignedProofPayload};
use e3_fhe::CkksFhe;
use e3_fhe_params::ckks_presets::{
    ckks_params_for_on_chain_param_set, relin_ceremony_plan_for_param_set,
};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::circuits::commitments::compute_share_computation_sk_commitment;
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks::CkksHybridRelinRound1Data;
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks_digit::compute_all_digit_inputs;
use e3_zk_helpers::threshold::pk_generation_ckks::{Bits as C1Bits, Bounds as C1Bounds};
use e3_zk_helpers::threshold::user_data_encryption_ckks::CkksPreset;
use e3_zk_helpers::Computation;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::trckks::{CkksCrp, CkksHybridRelinKeyShare, R1};
use fhe_traits::Serialize as FheSerialize;
use num_bigint::BigInt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

const N: usize = 3;
const T: usize = 1;
const SMUDGING_BITS: usize = 20;

fn be32(v: &BigInt) -> [u8; 32] {
    let (_, be) = v.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// The C1-CKKS sk commitment for a party's secret, EXACTLY as the C1
/// witness builder derives it (same fn, reversed layout, `sk_bit`).
fn c1_sk_commitment(preset: &CkksPreset, sk_coeffs: &[i64]) -> [u8; 32] {
    let bounds = C1Bounds::compute(preset.clone(), &()).unwrap();
    let bits = C1Bits::compute(preset.clone(), &bounds).unwrap();
    let mut c: Vec<BigInt> = sk_coeffs.iter().map(|&x| BigInt::from(x)).collect();
    c.reverse();
    be32(&compute_share_computation_sk_commitment(
        &e3_polynomial::Polynomial::new(c),
        bits.sk_bit,
    ))
}

/// Synthesize a party's signed digit-proof bundle from its witness: the
/// proof bytes are dummies (Honk is mocked), the PUBLIC SIGNALS are the
/// real ones (`[s_c, u_c, digit] ++ [share_c]`).
fn digit_bundle(
    e3_id: &E3id,
    preset: &CkksPreset,
    witness: &CkksC8Witness,
    crp_seed: [u8; 32],
) -> Vec<SignedProofPayload> {
    let params = &preset.params;
    let data = CkksHybridRelinRound1Data {
        crp: CkksCrp::vec_from_seed_qp(params, crp_seed).unwrap(),
        share: CkksHybridRelinKeyShare::<R1>::from_bytes(&witness.share, params).unwrap(),
        sk_coeffs: witness.sk_coeffs.clone(),
        u_coeffs: witness.u_coeffs.clone(),
        e0_coeffs: witness.e0_coeffs.clone(),
        e1_coeffs: witness.e1_coeffs.clone(),
    };
    let digits = compute_all_digit_inputs(preset, &data).unwrap();
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    digits
        .iter()
        .map(|d| {
            let mut signals = Vec::with_capacity(4 * 32);
            signals.extend_from_slice(&be32(&d.s_commitment));
            signals.extend_from_slice(&be32(&d.u_commitment));
            signals.extend_from_slice(&be32(&BigInt::from(d.digit as u64)));
            signals.extend_from_slice(&be32(&d.share_commitment));
            SignedProofPayload::sign(
                ProofPayload {
                    e3_id: e3_id.clone(),
                    proof_type: ProofType::C8RelinRound1,
                    proof: Proof::new(
                        CircuitName::RelinRound1HybridCkksDigit,
                        ArcBytes::from_bytes(&[1]),
                        ArcBytes::from_bytes(&signals),
                    ),
                },
                &signer,
            )
            .unwrap()
        })
        .collect()
}

struct Net {
    fhe: CkksFhe,
    preset: CkksPreset,
    seed: [u8; 32],
    machines: Vec<CkksKeyshareMachine>,
    /// party -> (chunks, witness)
    r1: BTreeMap<u64, (Vec<RelinShareChunk>, CkksC8Witness)>,
    /// party -> sk coefficients (for the C1 anchor)
    sk: BTreeMap<u64, Vec<i64>>,
}

/// Run the DKG on ParamSet 2 (hybrid) with the C8 gate REQUIRED, release
/// R1 on every machine, and return everything needed to drive the gate.
fn hybrid_network_through_r1() -> Net {
    let params = ckks_params_for_on_chain_param_set(2).unwrap();
    let plan = relin_ceremony_plan_for_param_set(2).unwrap();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N, T, shared_rng).unwrap();
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkgWide512).build_arc();
    let mut rng = rand::rng();
    let sk_bfv: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<ArcBytes> = sk_bfv
        .iter()
        .map(|sk| ArcBytes::from_bytes(&PublicKey::new(sk, &mut rng).to_bytes()))
        .collect();
    let mut machines: Vec<CkksKeyshareMachine> = (1..=N as u64)
        .map(|pid| {
            let m = CkksKeyshareMachine::with_relin_plan(pid, N, T, &plan, seed)
                .with_relin_proof_gate(RelinProofGate::Required);
            assert_eq!(m.relin_proof_gate, RelinProofGate::Required);
            m
        })
        .collect();

    let mut share_broadcasts = Vec::new();
    for m in machines.iter_mut() {
        for (j, pk) in pk_bfv.iter().enumerate() {
            for cmd in m
                .on_encryption_key(
                    (j + 1) as u64,
                    pk.clone(),
                    &fhe,
                    &enc_params,
                    params.moduli(),
                    SMUDGING_BITS,
                    &mut rng,
                )
                .unwrap()
            {
                if let CkksCommand::PublishThresholdShare { share } = cmd {
                    share_broadcasts.push(Arc::new(*share));
                }
            }
        }
    }
    let mut sk = BTreeMap::new();
    for (i, m) in machines.iter_mut().enumerate() {
        for share in &share_broadcasts {
            for cmd in m
                .on_threshold_share(share.clone(), &fhe, &sk_bfv[i], &enc_params)
                .unwrap()
            {
                if let CkksCommand::PublishKeyshareCreated { c1_witness, .. } = cmd {
                    sk.insert(m.party_id, c1_witness.sk_coeffs);
                }
            }
        }
    }
    let mut r1 = BTreeMap::new();
    for m in machines.iter_mut() {
        for cmd in m.on_public_key_aggregated(&fhe, &mut ()).unwrap() {
            if let CkksCommand::PublishRelinRound1 { chunks, c8_witness } = cmd {
                r1.insert(
                    m.party_id,
                    (
                        chunks,
                        c8_witness.expect("hybrid R1 carries the C8 witness"),
                    ),
                );
            }
        }
    }
    assert_eq!(r1.len(), N);
    Net {
        preset: CkksPreset {
            params: fhe.params.clone(),
            input_bound: 1.0,
        },
        fhe,
        seed,
        machines,
        r1,
        sk,
    }
}

fn install_anchors(net: &mut Net) {
    for m in net.machines.iter_mut() {
        for (pid, sk) in &net.sk {
            m.on_c1_sk_commitment(*pid, c1_sk_commitment(&net.preset, sk))
                .unwrap();
        }
    }
}

fn deliver_all_r1_chunks(net: &mut Net) {
    for m in net.machines.iter_mut() {
        for (pid, (chunks, _)) in &net.r1 {
            for c in chunks {
                for cmd in m.on_relin_round_1(*pid, c, &net.fhe, &mut ()).unwrap() {
                    assert!(
                        !matches!(cmd, CkksCommand::PublishRelinRound2 { .. }),
                        "R2 must not be emitted while the C8 gate is closed"
                    );
                }
            }
        }
        assert!(matches!(m.phase(), CkksPhase::RelinRound1 { .. }));
    }
}

/// Honest network: proofs bound + verified on every machine -> R2 flows
/// and the joint key is byte-identical everywhere.
#[test]
fn c8_gate_holds_r1_until_every_bundle_is_bound_and_verified() {
    let e3_id = E3id::new("42", 1);
    let mut net = hybrid_network_through_r1();
    install_anchors(&mut net);
    let bundles: BTreeMap<u64, Vec<SignedProofPayload>> = net
        .r1
        .iter()
        .map(|(pid, (_, w))| (*pid, digit_bundle(&e3_id, &net.preset, w, net.seed)))
        .collect();
    assert!(
        bundles.values().all(|b| b.len() == 13),
        "dnum = 13 digit proofs"
    );

    // Proofs arrive BEFORE any share: buffered, no dispatch yet.
    for m in net.machines.iter_mut() {
        for (pid, b) in &bundles {
            let cmds = m
                .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, b.clone(), &net.fhe)
                .unwrap();
            assert!(cmds.is_empty(), "no share reassembled yet");
        }
        // Identical re-delivery is idempotent; a different bundle bails.
        let (pid, b) = bundles.iter().next().unwrap();
        assert!(m
            .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, b.clone(), &net.fhe)
            .unwrap()
            .is_empty());
        let mut other = b.clone();
        other.truncate(12);
        let err = m
            .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, other, &net.fhe)
            .unwrap_err();
        assert!(err.to_string().contains("dnum"), "{err}");
    }

    // Shares land: the last one triggers binding of every bundle and the
    // verification dispatch; R2 is still held.
    let mut dispatched = 0;
    for m in net.machines.iter_mut() {
        for (pid, (chunks, _)) in &net.r1 {
            for c in chunks {
                for cmd in m.on_relin_round_1(*pid, c, &net.fhe, &mut ()).unwrap() {
                    match cmd {
                        CkksCommand::VerifyRelinRound1Proofs { bundles: b } => {
                            assert_eq!(b.len(), N);
                            dispatched += 1;
                        }
                        other => panic!("unexpected {other:?}"),
                    }
                }
            }
        }
        assert!(matches!(m.phase(), CkksPhase::RelinRound1 { .. }));
        assert!(m.relin_proofs.dispatched);
        assert_eq!(m.relin_proofs.bound.len(), N);
    }
    assert_eq!(dispatched, N, "exactly one dispatch per machine");

    // Honk round reports all honest: gate opens, R2 flows, keys agree.
    let mut r2 = Vec::new();
    for m in net.machines.iter_mut() {
        let cmds = m
            .on_relin_round_1_proofs_verified(&BTreeSet::new(), &net.fhe, &mut ())
            .unwrap();
        let mut got_r2 = false;
        for cmd in cmds {
            if let CkksCommand::PublishRelinRound2 { chunks } = cmd {
                r2.push((m.party_id, chunks));
                got_r2 = true;
            }
        }
        assert!(got_r2, "gate opened -> R2 emitted");
        assert!(matches!(m.phase(), CkksPhase::RelinRound2 { .. }));
        // Second completion is a no-op.
        assert!(m
            .on_relin_round_1_proofs_verified(&BTreeSet::new(), &net.fhe, &mut ())
            .unwrap()
            .is_empty());
    }
    let mut keys = Vec::new();
    for m in net.machines.iter_mut() {
        for (pid, chunks) in &r2 {
            for c in chunks {
                for cmd in m.on_relin_round_2(*pid, c, &net.fhe, &mut ()).unwrap() {
                    if let CkksCommand::RelinKeysReady { keys: k } = cmd {
                        keys.push(k);
                    }
                }
            }
        }
    }
    assert_eq!(keys.len(), N);
    assert!(keys[1..].iter().all(|k| k == &keys[0]));

    // The gate state survives a snapshot (small, persisted).
    let bytes = bincode::serialize(&net.machines[0]).unwrap();
    let reborn: CkksKeyshareMachine = bincode::deserialize(&bytes).unwrap();
    assert_eq!(reborn.relin_proof_gate, RelinProofGate::Required);
    assert!(reborn.relin_proofs.verified);
    assert_eq!(reborn.c1_sk_commitments.len(), N);
}

/// One party's digit proofs are inconsistent with its published share:
/// every honest machine fails the ceremony attributably (no R2, no key).
#[test]
fn c8_gate_rejects_an_inconsistent_digit_proof_attributably() {
    let e3_id = E3id::new("42", 1);
    let mut net = hybrid_network_through_r1();
    install_anchors(&mut net);
    let mut bundles: BTreeMap<u64, Vec<SignedProofPayload>> = net
        .r1
        .iter()
        .map(|(pid, (_, w))| (*pid, digit_bundle(&e3_id, &net.preset, w, net.seed)))
        .collect();
    // Party 3 proves a share whose digit 7 differs from what it published.
    let bad_pid = 3u64;
    {
        let b = bundles.get_mut(&bad_pid).unwrap();
        let mut signals = b[7].payload.proof.public_signals.to_vec();
        signals[3 * 32 + 5] ^= 0x01; // share_commitment
        b[7] = SignedProofPayload::sign(
            ProofPayload {
                e3_id: e3_id.clone(),
                proof_type: ProofType::C8RelinRound1,
                proof: Proof::new(
                    CircuitName::RelinRound1HybridCkksDigit,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&signals),
                ),
            },
            &"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse::<alloy::signers::local::PrivateKeySigner>()
                .unwrap(),
        )
        .unwrap();
    }
    deliver_all_r1_chunks(&mut net);
    for m in net.machines.iter_mut() {
        let mut failed = None;
        for (pid, b) in &bundles {
            for cmd in m
                .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, b.clone(), &net.fhe)
                .unwrap()
            {
                match cmd {
                    CkksCommand::RelinCeremonyFailed { party_id, reason } => {
                        failed = Some((party_id, reason))
                    }
                    CkksCommand::VerifyRelinRound1Proofs { .. } => {
                        panic!("must not dispatch with an unbound party")
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        let (party_id, reason) = failed.expect("attributable failure");
        assert_eq!(party_id, bad_pid);
        assert!(reason.contains("digit 7"), "{reason}");
        assert!(reason.contains("share_commitment"), "{reason}");
        assert!(!m.relin_proofs.dispatched);
        assert!(matches!(m.phase(), CkksPhase::RelinRound1 { .. }));
    }
}

/// The `s_commitment` must be the party's C1-CKKS sk commitment: a
/// bundle proven under a different secret (or with no anchor at all) is
/// rejected; a Honk failure reported by the verifier fails the ceremony.
#[test]
fn c8_gate_anchors_s_commitment_to_c1_and_fails_on_honk_rejection() {
    let e3_id = E3id::new("42", 1);
    let mut net = hybrid_network_through_r1();
    let bundles: BTreeMap<u64, Vec<SignedProofPayload>> = net
        .r1
        .iter()
        .map(|(pid, (_, w))| (*pid, digit_bundle(&e3_id, &net.preset, w, net.seed)))
        .collect();
    deliver_all_r1_chunks(&mut net);

    // No anchor recorded for anyone: the first bound attempt fails on
    // the missing C1 commitment.
    {
        let m = &mut net.machines[0];
        let (pid, b) = bundles.iter().next().unwrap();
        let cmds = m
            .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, b.clone(), &net.fhe)
            .unwrap();
        assert!(matches!(
            &cmds[..],
            [CkksCommand::RelinCeremonyFailed { party_id, reason }]
                if *party_id == *pid && reason.contains("no C1-CKKS sk commitment")
        ));
    }
    // Wrong anchor for party 2 (a different secret's commitment).
    {
        let m = &mut net.machines[1];
        for (pid, sk) in &net.sk {
            let anchor = if *pid == 2 {
                c1_sk_commitment(&net.preset, &net.sk[&1])
            } else {
                c1_sk_commitment(&net.preset, sk)
            };
            m.on_c1_sk_commitment(*pid, anchor).unwrap();
        }
        // Equivocating anchor is rejected.
        let err = m.on_c1_sk_commitment(1, [0xEE; 32]).unwrap_err();
        assert!(err.to_string().contains("equivocation"), "{err}");
        let mut failed = None;
        for (pid, b) in &bundles {
            for cmd in m
                .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, b.clone(), &net.fhe)
                .unwrap()
            {
                if let CkksCommand::RelinCeremonyFailed { party_id, reason } = cmd {
                    failed = Some((party_id, reason));
                }
            }
        }
        let (party_id, reason) = failed.expect("anchor mismatch is attributable");
        assert_eq!(party_id, 2);
        assert!(reason.contains("C1-CKKS sk commitment"), "{reason}");
    }
    // Correct anchors on machine 3, bindings pass, then the Honk round
    // rejects party 1: ceremony fails, gate stays closed.
    {
        let m = &mut net.machines[2];
        for (pid, sk) in &net.sk {
            m.on_c1_sk_commitment(*pid, c1_sk_commitment(&net.preset, sk))
                .unwrap();
        }
        let mut dispatched = false;
        for (pid, b) in &bundles {
            for cmd in m
                .on_relin_round_1_proofs(*pid, 1, HYBRID_RELIN_LEVEL, b.clone(), &net.fhe)
                .unwrap()
            {
                assert!(matches!(cmd, CkksCommand::VerifyRelinRound1Proofs { .. }));
                dispatched = true;
            }
        }
        assert!(dispatched);
        let cmds = m
            .on_relin_round_1_proofs_verified(&BTreeSet::from([1u64]), &net.fhe, &mut ())
            .unwrap();
        assert!(matches!(
            &cmds[..],
            [CkksCommand::RelinCeremonyFailed { party_id: 1, reason }] if reason.contains("Honk")
        ));
        assert!(!m.relin_proofs.verified);
        assert!(matches!(m.phase(), CkksPhase::RelinRound1 { .. }));
    }
}

/// Gate `Off` (per-level plans / explicit off-switch): bundles are
/// ignored and the ceremony runs verify-by-determinism as before.
#[test]
fn c8_gate_off_ignores_bundles() {
    let params = ckks_params_for_on_chain_param_set(3).unwrap();
    let plan = relin_ceremony_plan_for_param_set(3).unwrap();
    let m = CkksKeyshareMachine::with_relin_plan(1, N, T, &plan, [1u8; 32])
        .with_relin_proof_gate(RelinProofGate::Required);
    assert_eq!(
        m.relin_proof_gate,
        RelinProofGate::Off,
        "per-level plans never require digit proofs"
    );
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed([2u8; 32]),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), [1u8; 32], N, T, shared_rng).unwrap();
    let mut m = m;
    assert!(m
        .on_relin_round_1_proofs(1, 1, HYBRID_RELIN_LEVEL, vec![], &fhe)
        .unwrap()
        .is_empty());
}
