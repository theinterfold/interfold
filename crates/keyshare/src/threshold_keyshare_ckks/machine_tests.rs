// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! State-machine tests: five machines wired ONLY through each other's
//! emitted commands — a faithful message-passing simulation of the actor
//! network, ending in a threshold decryption of an auction-style masked
//! comparison.

use super::machine::*;
use e3_fhe::CkksFhe;
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParametersBuilder, CkksPublicKey};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::RngCore;
use std::sync::{Arc, Mutex};

const N: usize = 5;
const T: usize = 2;
const SMUDGING_BITS: usize = 20;

#[test]
fn machine_network_full_lifecycle() {
    // Committee setup (CKKS moduli within the DKG transport t — see
    // encrypted_dkg module docs).
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli(&[0xffffee001, 0xffffc4001])
        .set_scale(2f64.powi(26))
        .build_arc()
        .unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N, T, shared_rng).unwrap();
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
    let mut rng = rand::rng();

    // Per-node state: machine + ephemeral BFV keypair.
    let sk_bfv: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<ArcBytes> = sk_bfv
        .iter()
        .map(|sk| ArcBytes::from_bytes(&PublicKey::new(sk, &mut rng).to_bytes()))
        .collect();
    let mut machines: Vec<CkksKeyshareMachine> = (1..=N as u64)
        .map(|pid| CkksKeyshareMachine::new(pid, N, T))
        .collect();

    // ── Round 1: encryption-key broadcast. Every node feeds every key. ──
    let mut share_broadcasts = Vec::new();
    for m in machines.iter_mut() {
        for (j, pk) in pk_bfv.iter().enumerate() {
            let cmds = m
                .on_encryption_key(
                    (j + 1) as u64,
                    pk.clone(),
                    &fhe,
                    &enc_params,
                    params.moduli(),
                    SMUDGING_BITS,
                    &mut rng,
                )
                .unwrap();
            for cmd in cmds {
                match cmd {
                    CkksCommand::PublishThresholdShare { share } => {
                        share_broadcasts.push(Arc::new(*share))
                    }
                    other => panic!("unexpected command in round 1: {other:?}"),
                }
            }
        }
    }
    assert_eq!(share_broadcasts.len(), N, "every node must broadcast once");

    // ── Round 2: ThresholdShare broadcast delivery. ──
    // BFV-style: each converged machine announces its pk SHARE; the
    // aggregator sums them. Machines still hold the joint pk internally.
    let mut pk_shares = Vec::new();
    for (i, m) in machines.iter_mut().enumerate() {
        for share in &share_broadcasts {
            let cmds = m
                .on_threshold_share(share.clone(), &fhe, &sk_bfv[i], &enc_params)
                .unwrap();
            for cmd in cmds {
                match cmd {
                    CkksCommand::PublishKeyshareCreated { pk_share, .. } => {
                        pk_shares.push(pk_share)
                    }
                    other => panic!("unexpected command in round 2: {other:?}"),
                }
            }
        }
    }
    assert_eq!(pk_shares.len(), N);
    for share in &pk_shares[1..] {
        assert_ne!(share, &pk_shares[0], "pk shares must differ per node");
    }
    // Every machine's locally-aggregated joint pk agrees, and matches the
    // aggregator-style sum over the announced shares.
    let joint_pks: Vec<_> = machines
        .iter()
        .map(|m| m.joint_public_key().expect("converged").clone())
        .collect();
    for pk in &joint_pks[1..] {
        assert_eq!(pk, &joint_pks[0], "joint pk mismatch across nodes");
    }
    let summed = fhe
        .get_aggregate_public_key(e3_fhe::ckks_runtime::GetCkksAggregatePublicKey {
            keyshares: e3_events::OrderedSet::from(pk_shares.clone()),
        })
        .unwrap();
    assert_eq!(
        &summed[..],
        &joint_pks[0][..],
        "aggregator sum must equal machines' local aggregation"
    );

    // Idempotency: re-delivering a share emits nothing and breaks nothing.
    assert!(machines[0]
        .on_threshold_share(share_broadcasts[0].clone(), &fhe, &sk_bfv[0], &enc_params)
        .is_err()); // wrong phase now — rejected, not double-processed

    // ── E3 compute: auction-style masked difference of two bids. ──
    let pk = CkksPublicKey::from_bytes(&joint_pks[0], &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    // Values sized for the narrow (36-bit) transport-compatible moduli:
    // after rescale the ciphertext sits at one ~36-bit modulus, so
    // |result|*scale must stay under q/2 ~ 2^35 (result < ~500 at 2^26).
    let (bid_a, bid_b, mask) = (87.5f64, 31.25, 3.0);
    let ct_a = pk
        .try_encrypt(&encoder.encode(&[bid_a], 0).unwrap(), &mut rng)
        .unwrap();
    let ct_b = pk
        .try_encrypt(&encoder.encode(&[bid_b], 0).unwrap(), &mut rng)
        .unwrap();
    let diff = ct_a.try_sub(&ct_b).unwrap();
    // No rescale: with the narrow 36-bit transport-compatible moduli the
    // post-rescale scale (2^52 / 2^36 ~ 2^16.6) is too small to absorb the
    // committee's 20-bit smudging noise. Decrypting at scale 2^52 keeps
    // the flooding negligible; level-0 Q (~2^72) has ample headroom.
    let output: CkksCiphertext = diff
        .try_mul_plaintext(&encoder.encode(&[mask], 0).unwrap())
        .unwrap();
    let out_bytes = output.to_bytes();

    // ── Round 3: ciphertext output -> decryption shares from t+1 nodes. ──
    let reconstructing = [1u64, 3, 5];
    let mut dec_shares = Vec::new();
    for &pid in &reconstructing {
        let cmds = machines[(pid - 1) as usize]
            .on_ciphertext_output(&out_bytes, &fhe)
            .unwrap();
        for cmd in cmds {
            match cmd {
                CkksCommand::PublishDecryptionShare { share, .. } => dec_shares.push((pid, share)),
                other => panic!("unexpected command in round 3: {other:?}"),
            }
        }
    }
    // SINGLE-USE smudging guard: the same ciphertext re-served is
    // idempotent (deterministic share, event replay safe)...
    let again = machines[0].on_ciphertext_output(&out_bytes, &fhe).unwrap();
    assert_eq!(again.len(), 1, "same-ct re-serve must succeed");
    // ...but a DIFFERENT ciphertext must be refused — the dealt e_sm has
    // already flooded one opening (IND-CPA-D reuse channel).
    let other_ct = ct_a.to_bytes();
    let err = machines[0]
        .on_ciphertext_output(&other_ct, &fhe)
        .unwrap_err();
    assert!(
        err.to_string().contains("single-use"),
        "wrong refusal: {err}"
    );

    let values = super::workflow::aggregate_plaintext(&fhe, dec_shares, &out_bytes).unwrap();
    let expected = (bid_a - bid_b) * mask;
    assert!(
        (values[0] - expected).abs() < 0.5,
        "decrypted {} vs {expected}",
        values[0]
    );
    assert!(values[0] > 0.0, "sign must reveal the higher bid");

    // ── Completion. ──
    for &pid in &reconstructing {
        machines[(pid - 1) as usize]
            .on_plaintext_aggregated()
            .unwrap();
    }

    // Machine state survives serde (the recovery path).
    let bytes = bincode::serialize(&machines[0]).unwrap();
    let restored: CkksKeyshareMachine = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(restored.phase, CkksPhase::Completed));
}

#[test]
fn machine_network_relin_ceremony() {
    // Transport-compatible moduli (both <= t_dkg). MULTIPARTY relin
    // noise is ~n x the single-key case (~2^56 here, vs 2^48), so delta
    // must be 2^30 for the noise to land ~2^-4 below the delta^2 = 2^60
    // product scale (2^26 fails: error ~17 on a product of 9). Message
    // headroom: 9 * 2^60 = 2^63 < Q/2 = 2^71. Decrypted at delta^2
    // without rescale, like the masked-difference lifecycle test.
    //
    // CHUNKED TRANSPORT: parties 1-2 keep the production chunk budget
    // (demo-size shares -> exactly ONE chunk: the unchunked path);
    // parties 3-5 get a tiny test budget that FORCES multi-chunk
    // broadcasts. Every machine ingests both shapes, and all five must
    // derive byte-identical joint keys — proving chunking is pure
    // transport with no effect on the ceremony output.
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli(&[0xffffee001, 0xffffc4001])
        .set_scale(2f64.powi(30))
        .build_arc()
        .unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N, T, shared_rng).unwrap();
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
    let mut rng = rand::rng();

    let sk_bfv: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<ArcBytes> = sk_bfv
        .iter()
        .map(|sk| ArcBytes::from_bytes(&PublicKey::new(sk, &mut rng).to_bytes()))
        .collect();
    // Ceremony for one multiplication level (level 0). Tiny chunk budget
    // on parties 3..=5 forces the multi-chunk path.
    const TINY_CHUNK: usize = 3000;
    let mut machines: Vec<CkksKeyshareMachine> = (1..=N as u64)
        .map(|pid| {
            let m = CkksKeyshareMachine::with_relin_levels(pid, N, T, vec![0], seed);
            if pid >= 3 {
                m.with_relin_chunk_bytes(TINY_CHUNK)
            } else {
                m
            }
        })
        .collect();

    // DKG rounds (same as the lifecycle test, condensed).
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

    // ThresholdShare delivery: the LAST delivery flips each machine into
    // the ceremony. R1 chunks are HELD until pk consensus is confirmed —
    // the DKG phase emits ONLY KeyshareCreated.
    for (i, m) in machines.iter_mut().enumerate() {
        for share in &share_broadcasts {
            for cmd in m
                .on_threshold_share(share.clone(), &fhe, &sk_bfv[i], &enc_params)
                .unwrap()
            {
                match cmd {
                    CkksCommand::PublishKeyshareCreated { .. } => {}
                    other => panic!("unexpected command after DKG: {other:?}"),
                }
            }
        }
        assert!(matches!(m.phase(), CkksPhase::RelinRound1 { .. }));
    }

    // PublicKeyAggregated confirmation releases every machine's held R1
    // chunks (the live-stack ordering: ceremony bulk must not compete
    // with DKG documents on the DHT). Idempotent on re-delivery.
    let mut r1_broadcasts: Vec<(u64, Vec<RelinShareChunk>)> = Vec::new();
    for m in machines.iter_mut() {
        for cmd in m.on_public_key_aggregated(&fhe, &mut ()).unwrap() {
            match cmd {
                CkksCommand::PublishRelinRound1 { chunks, .. } => {
                    r1_broadcasts.push((m.party_id, chunks));
                }
                other => panic!("unexpected command on pk confirmation: {other:?}"),
            }
        }
        assert!(
            m.on_public_key_aggregated(&fhe, &mut ())
                .unwrap()
                .is_empty(),
            "second pk confirmation must be a no-op"
        );
    }
    assert_eq!(r1_broadcasts.len(), N, "every node emits round 1");
    // Chunk-shape assertions: default budget = exactly 1 chunk (no
    // regression for demo shapes); tiny budget = FORCED multi-chunk.
    for (pid, chunks) in &r1_broadcasts {
        if *pid < 3 {
            assert_eq!(chunks.len(), 1, "party {pid}: demo share must be 1 chunk");
            assert_eq!(chunks[0].chunk_count, 1);
        } else {
            assert!(
                chunks.len() > 1,
                "party {pid}: tiny budget must force multi-chunk (got {})",
                chunks.len()
            );
            for c in chunks {
                assert!(c.bytes.size() <= TINY_CHUNK, "chunk over budget");
                assert_eq!(c.chunk_count as usize, chunks.len());
            }
        }
    }

    // ── Chunk-integrity rejections (on a machine still in RelinRound1,
    // against a party whose share it has NOT completed). ──
    let (corrupt_pid, corrupt_chunks) = r1_broadcasts
        .iter()
        .find(|(pid, _)| *pid >= 3)
        .cloned()
        .unwrap();
    let victim = machines
        .iter_mut()
        .find(|m| m.party_id != corrupt_pid)
        .unwrap();
    // (a) corrupted chunk bytes: reassembly keccak mismatch must bail on
    // the FINAL chunk of the set (attributable to the sender).
    let mut tampered = corrupt_chunks.clone();
    let last = tampered.len() - 1;
    let mut bad_bytes = tampered[last].bytes.to_vec();
    bad_bytes[0] ^= 0xff;
    tampered[last].bytes = ArcBytes::from_bytes(&bad_bytes);
    for c in &tampered[..last] {
        assert!(victim
            .on_relin_round_1(corrupt_pid, c, &fhe, &mut ())
            .unwrap()
            .is_empty());
    }
    let err = victim
        .on_relin_round_1(corrupt_pid, &tampered[last], &fhe, &mut ())
        .unwrap_err();
    assert!(
        err.to_string().contains("failed integrity"),
        "wrong rejection: {err}"
    );
    // (b) inconsistent chunk_count from the same party bails attributably.
    let mut wrong_count = corrupt_chunks[0].clone();
    wrong_count.chunk_count += 1;
    // The poisoned buffer was dropped on the integrity failure, so seed a
    // fresh buffer with the honest first chunk, then conflict against it.
    assert!(victim
        .on_relin_round_1(corrupt_pid, &corrupt_chunks[0], &fhe, &mut ())
        .unwrap()
        .is_empty());
    let err = victim
        .on_relin_round_1(corrupt_pid, &wrong_count, &fhe, &mut ())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("inconsistent relin chunk metadata"),
        "wrong rejection: {err}"
    );
    // (b') a CONFLICTING keccak for the same (round, level) from the
    // same party: same chunk_count, different advertised payload hash —
    // equivocation on the commitment, rejected attributably.
    let mut wrong_keccak = corrupt_chunks[0].clone();
    wrong_keccak.payload_keccak[0] ^= 0x01;
    let err = victim
        .on_relin_round_1(corrupt_pid, &wrong_keccak, &fhe, &mut ())
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!("party {corrupt_pid}"))
            && err.to_string().contains("differing payload keccak"),
        "wrong rejection: {err}"
    );
    // (b'') an absurd chunk_count is rejected BEFORE any buffer grows
    // when parameter-derived bounds are installed.
    {
        let mut bounded = CkksKeyshareMachine::with_relin_levels(9, N, T, vec![0], seed)
            .with_relin_bounds(RelinChunkBounds::for_params(&params, TINY_CHUNK));
        let mut huge = corrupt_chunks[0].clone();
        huge.chunk_count = u32::MAX;
        let err = bounded
            .on_relin_round_1(corrupt_pid, &huge, &fhe, &mut ())
            .unwrap_err();
        assert!(
            err.to_string().contains("needs more than"),
            "wrong rejection: {err}"
        );
        // The honest chunk count fits the parameter-derived cap.
        assert!(bounded
            .on_relin_round_1(corrupt_pid, &corrupt_chunks[0], &fhe, &mut ())
            .unwrap()
            .is_empty());
        // A chunk over the wire cap is rejected too.
        let mut fat = corrupt_chunks[0].clone();
        fat.bytes = ArcBytes::from_bytes(&vec![0u8; CKKS_RELIN_CHUNK_BYTES + 1]);
        let err = bounded
            .on_relin_round_1(corrupt_pid, &fat, &fhe, &mut ())
            .unwrap_err();
        assert!(
            err.to_string().contains("wire cap"),
            "wrong rejection: {err}"
        );
    }
    // (c) duplicate chunk re-delivery is idempotent: Ok(vec![]).
    assert!(victim
        .on_relin_round_1(corrupt_pid, &corrupt_chunks[0], &fhe, &mut ())
        .unwrap()
        .is_empty());

    // R1 delivery to every machine (the tampered party's HONEST chunks
    // still land — the poisoned buffer was dropped); completion emits R2.
    let mut r2_broadcasts: Vec<(u64, Vec<RelinShareChunk>)> = Vec::new();
    for m in machines.iter_mut() {
        for (pid, chunks) in &r1_broadcasts {
            for chunk in chunks {
                for cmd in m.on_relin_round_1(*pid, chunk, &fhe, &mut ()).unwrap() {
                    match cmd {
                        CkksCommand::PublishRelinRound2 { chunks } => {
                            r2_broadcasts.push((m.party_id, chunks));
                        }
                        other => panic!("unexpected command in round 1: {other:?}"),
                    }
                }
            }
        }
    }
    assert_eq!(r2_broadcasts.len(), N, "every node emits round 2");

    // R2 delivery; completion emits the joint keys and lands in
    // ReadyForDecryption. Machine 1 is SNAPSHOT mid-round-2 (after a
    // partial R2 delivery) and RESTORED: the serde(skip) chunk buffers
    // are gone, so re-feeding every party's R2 chunks (the shell's
    // recovery replays them from the event log) must still reach the
    // same joint keys — the restart-mid-ceremony contract.
    let mut key_sets: Vec<Vec<(usize, ArcBytes)>> = Vec::new();
    let mut progress: Vec<CkksProgress> = Vec::new();
    for (i, m) in machines.iter_mut().enumerate() {
        let mut restored_once = false;
        for (pid, chunks) in &r2_broadcasts {
            if i == 0 && !restored_once && *pid == 3 {
                // Crash + restore before party 3's chunks land.
                let bytes = bincode::serialize(&*m).unwrap();
                let mut reborn: CkksKeyshareMachine = bincode::deserialize(&bytes).unwrap();
                assert!(matches!(reborn.phase(), CkksPhase::RelinRound2 { .. }));
                assert_eq!(
                    reborn.relin_complete_counts(),
                    (0, 0),
                    "buffers not snapshot"
                );
                // The shell replays ALL recorded chunks: round 1 first (the
                // R1 aggregation cache is not snapshot either — it is
                // rebuilt from these), then round 2 (parties 1-2 again,
                // then 3-5); duplicates of already-complete payloads are
                // idempotent. Nothing may complete before R2 is full.
                for (rpid, rchunks) in &r1_broadcasts {
                    for chunk in rchunks {
                        assert!(reborn
                            .on_relin_round_1(*rpid, chunk, &fhe, &mut ())
                            .unwrap()
                            .is_empty());
                    }
                }
                for (rpid, rchunks) in r2_broadcasts.iter().filter(|(p, _)| *p < 3) {
                    for chunk in rchunks {
                        assert!(reborn
                            .on_relin_round_2(*rpid, chunk, &fhe, &mut ())
                            .unwrap()
                            .is_empty());
                    }
                }
                *m = reborn;
                restored_once = true;
            }
            for chunk in chunks {
                let mut observe = |p: CkksProgress| progress.push(p);
                for cmd in m.on_relin_round_2(*pid, chunk, &fhe, &mut observe).unwrap() {
                    match cmd {
                        CkksCommand::RelinKeysReady { keys } => key_sets.push(keys),
                        other => panic!("unexpected command in round 2: {other:?}"),
                    }
                }
            }
        }
        assert!(matches!(m.phase(), CkksPhase::ReadyForDecryption(_)));
    }
    assert_eq!(key_sets.len(), N);
    // The observer saw one R2-complete fact per (machine, level).
    assert_eq!(
        progress
            .iter()
            .filter(|p| matches!(p, CkksProgress::RelinRound2LevelComplete { level: 0 }))
            .count(),
        N
    );
    // Byte-identical joint keys across the single-chunk (parties 1-2,
    // the unchunked path) AND multi-chunk (parties 3-5) machines.
    for keys in &key_sets[1..] {
        assert_eq!(keys, &key_sets[0], "all parties must derive the same key");
    }

    // The derived joint key actually relinearizes a product under the
    // committee's joint pk: encrypt, square, relinearize, threshold-open
    // via the machines' aggregated shares.
    let joint_pk_bytes = machines[0].joint_public_key().unwrap().to_vec();
    let pk = CkksPublicKey::from_bytes(&joint_pk_bytes, &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    let rlk = fhe::ckks::CkksRelinearizationKey::from_bytes(&key_sets[0][0].1, &params).unwrap();
    let x = vec![3.0f64, -1.5];
    let ct = pk
        .try_encrypt(&encoder.encode(&x, 0).unwrap(), &mut rng)
        .unwrap();
    let mut sq = ct.try_mul(&ct).unwrap();
    rlk.relinearizes(&mut sq).unwrap();
    // No rescale: decrypt at delta^2 (smudging headroom; see above).
    let sq_bytes = sq.to_bytes();

    let mut dec_shares = Vec::new();
    for m in machines.iter_mut().take(T + 1) {
        for cmd in m.on_ciphertext_output(&sq_bytes, &fhe).unwrap() {
            if let CkksCommand::PublishDecryptionShare { share, .. } = cmd {
                dec_shares.push((m.party_id, share));
            }
        }
    }
    let values = super::workflow::aggregate_plaintext(&fhe, dec_shares, &sq_bytes).unwrap();
    for (i, xi) in x.iter().enumerate() {
        assert!(
            (values[i] - xi * xi).abs() < 0.5,
            "slot {i}: {} vs {}",
            values[i],
            xi * xi
        );
    }
}

/// The WIDE DKG transport preset carries the sign-extraction modulus
/// ladder (45-bit base + 40-bit rescale limbs): full DKG + ceremony over
/// `InsecureDkgWide512`, then a leveled circuit — pack (rescale to level
/// 1), square + relinearize with the ceremony's LEVEL-1 key, rescale —
/// threshold-decrypted at level 2. This is the exact dataflow of one
/// sign-extraction iteration.
#[test]
fn machine_network_sign_extraction_ladder_transport() {
    // sign_extraction_params(1)-shaped ladder: delta = 2^40 over
    // [45, 40, 40, 40]. Every limb <= t_dkg = 0x3fffffff6401 (46-bit).
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 40, 40, 40])
        .set_scale(2f64.powi(40))
        .build_arc()
        .unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N, T, shared_rng).unwrap();
    // WIDE preset: the standard InsecureDkg512 transport (t = 0xffffee001,
    // 36-bit) rejects this ladder's 45-bit base.
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkgWide512).build_arc();
    let mut rng = rand::rng();

    let sk_bfv: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<ArcBytes> = sk_bfv
        .iter()
        .map(|sk| ArcBytes::from_bytes(&PublicKey::new(sk, &mut rng).to_bytes()))
        .collect();
    // Ceremony for the first sign-extraction multiplication level.
    let mut machines: Vec<CkksKeyshareMachine> = (1..=N as u64)
        .map(|pid| CkksKeyshareMachine::with_relin_levels(pid, N, T, vec![1], seed))
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
    for (i, m) in machines.iter_mut().enumerate() {
        for share in &share_broadcasts {
            m.on_threshold_share(share.clone(), &fhe, &sk_bfv[i], &enc_params)
                .unwrap();
        }
    }
    // pk-consensus confirmation releases the held R1 chunks.
    let mut r1_broadcasts: Vec<(u64, Vec<RelinShareChunk>)> = Vec::new();
    for m in machines.iter_mut() {
        for cmd in m.on_public_key_aggregated(&fhe, &mut ()).unwrap() {
            if let CkksCommand::PublishRelinRound1 { chunks, .. } = cmd {
                r1_broadcasts.push((m.party_id, chunks));
            }
        }
    }
    let mut r2_broadcasts: Vec<(u64, Vec<RelinShareChunk>)> = Vec::new();
    for m in machines.iter_mut() {
        for (pid, chunks) in &r1_broadcasts {
            for chunk in chunks {
                for cmd in m.on_relin_round_1(*pid, chunk, &fhe, &mut ()).unwrap() {
                    if let CkksCommand::PublishRelinRound2 { chunks } = cmd {
                        r2_broadcasts.push((m.party_id, chunks));
                    }
                }
            }
        }
    }
    let mut key_sets: Vec<Vec<(usize, ArcBytes)>> = Vec::new();
    for m in machines.iter_mut() {
        for (pid, chunks) in &r2_broadcasts {
            for chunk in chunks {
                for cmd in m.on_relin_round_2(*pid, chunk, &fhe, &mut ()).unwrap() {
                    if let CkksCommand::RelinKeysReady { keys } = cmd {
                        key_sets.push(keys);
                    }
                }
            }
        }
    }
    assert_eq!(key_sets.len(), N);
    for keys in &key_sets[1..] {
        assert_eq!(keys, &key_sets[0], "joint keys must agree");
    }

    // One sign-extraction-shaped iteration: pack -> rescale -> square ->
    // relin (level 1) -> rescale -> threshold decrypt at level 2.
    let joint_pk_bytes = machines[0].joint_public_key().unwrap().to_vec();
    let pk = CkksPublicKey::from_bytes(&joint_pk_bytes, &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    let rlk = fhe::ckks::CkksRelinearizationKey::from_bytes(&key_sets[0][0].1, &params).unwrap();
    assert_eq!(rlk.level(), 1);

    let x = 0.6f64;
    let slots = params.degree() / 2;
    let ct = pk
        .try_encrypt(&encoder.encode(&vec![x; slots], 0).unwrap(), &mut rng)
        .unwrap();
    // pack: normalize by 1/B via plaintext mask, rescale to level 1.
    let bound = 1.0;
    let mut y = ct
        .try_mul_plaintext(
            &encoder
                .encode_with_scale(&vec![1.0 / bound; slots], 0, params.scale())
                .unwrap(),
        )
        .unwrap();
    y.rescale().unwrap();
    assert_eq!(y.level, 1);
    // square + relin at level 1 + rescale.
    let mut sq = y.try_mul(&y).unwrap();
    rlk.relinearizes(&mut sq).unwrap();
    sq.rescale().unwrap();
    assert_eq!(sq.level, 2);
    let sq_bytes = sq.to_bytes();

    let mut dec_shares = Vec::new();
    for m in machines.iter_mut().take(T + 1) {
        for cmd in m.on_ciphertext_output(&sq_bytes, &fhe).unwrap() {
            if let CkksCommand::PublishDecryptionShare { share, .. } = cmd {
                dec_shares.push((m.party_id, share));
            }
        }
    }
    let values = super::workflow::aggregate_plaintext(&fhe, dec_shares, &sq_bytes).unwrap();
    assert!(
        (values[0] - x * x).abs() < 0.05,
        "slot 0: {} vs {}",
        values[0],
        x * x
    );
}

#[test]
fn machine_rejects_out_of_order_events() {
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli(&[0xffffee001, 0xffffc4001])
        .set_scale(2f64.powi(26))
        .build_arc()
        .unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N, T, shared_rng).unwrap();
    let mut m = CkksKeyshareMachine::new(1, N, T);

    // Ciphertext output before DKG completes: rejected.
    assert!(m.on_ciphertext_output(&[0u8; 8], &fhe).is_err());
    // Completion before decryption: rejected.
    assert!(m.on_plaintext_aggregated().is_err());
    // Out-of-range party id: rejected.
    let mut rng = rand::rng();
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
    assert!(m
        .on_encryption_key(
            99,
            ArcBytes::from_bytes(&[]),
            &fhe,
            &enc_params,
            params.moduli(),
            SMUDGING_BITS,
            &mut rng,
        )
        .is_err());
}

/// HYBRID ceremony over the REAL ParamSet-2 ladder (38 limbs + 3 special
/// primes, wide transport): full DKG + ONE two-round hybrid ceremony —
/// exactly one `(round, HYBRID_RELIN_LEVEL)` payload per party per
/// round — with parties 3..=5 on a tiny chunk budget (forced
/// multi-chunk), a corrupted-chunk rejection, and machine 1 SNAPSHOT +
/// RESTORED mid-round-2 (the recovery replay contract). All five must
/// derive the byte-identical `CkksHybridRelinKey`, which then
/// relinearizes a real product at a DEEP level (one sign-iteration shape
/// at level 1 AND a second square at level 4 under the SAME key) that
/// the committee threshold-decrypts.
#[test]
fn machine_network_hybrid_ceremony_ladder() {
    use e3_fhe_params::ckks_presets::{
        ckks_params_for_on_chain_param_set, relin_ceremony_plan_for_param_set, RelinCeremonyPlan,
    };
    let params = ckks_params_for_on_chain_param_set(2).unwrap();
    assert!(params.hybrid_enabled());
    let plan = relin_ceremony_plan_for_param_set(2).unwrap();
    assert_eq!(plan, RelinCeremonyPlan::Hybrid);

    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe = CkksFhe::from_encoded(&params.to_bytes(), seed, N, T, shared_rng).unwrap();
    assert!(fhe.hybrid_enabled());
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkgWide512).build_arc();
    let mut rng = rand::rng();

    let sk_bfv: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<ArcBytes> = sk_bfv
        .iter()
        .map(|sk| ArcBytes::from_bytes(&PublicKey::new(sk, &mut rng).to_bytes()))
        .collect();

    // Parties 3..=5: tiny budget forces multi-chunk hybrid shares (a
    // hybrid share here is ~2.7 MiB: 13 digits × 41 limbs × 2 polys).
    // Every receiver installs parameter-derived bounds at the tiny budget,
    // which exercises the hybrid share-size estimate behind
    // `max_chunk_count` (an honest 7-chunk share must fit it).
    const TINY_CHUNK: usize = 400_000;
    let bounds = RelinChunkBounds::for_params(&params, TINY_CHUNK);
    assert!(
        max_relin_share_bytes(&params, HYBRID_RELIN_LEVEL) > 2_700_000,
        "hybrid share estimate covers the real share"
    );
    let mut machines: Vec<CkksKeyshareMachine> = (1..=N as u64)
        .map(|pid| {
            let m = CkksKeyshareMachine::with_relin_plan(pid, N, T, &plan, seed);
            assert!(m.relin_is_hybrid());
            assert_eq!(m.relin_plan(), RelinCeremonyPlan::Hybrid);
            if pid >= 3 {
                m.with_relin_bounds(bounds)
            } else {
                // Production chunk budget, unbounded count (a receiver's
                // count cap is derived from ITS budget; peers on the tiny
                // test budget legitimately send more chunks).
                m
            }
        })
        .collect();

    // DKG.
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
    for (i, m) in machines.iter_mut().enumerate() {
        for share in &share_broadcasts {
            for cmd in m
                .on_threshold_share(share.clone(), &fhe, &sk_bfv[i], &enc_params)
                .unwrap()
            {
                assert!(matches!(cmd, CkksCommand::PublishKeyshareCreated { .. }));
            }
        }
        assert!(matches!(m.phase(), CkksPhase::RelinRound1 { .. }));
    }

    // pk confirmation releases ONE hybrid R1 payload per party.
    let mut r1_broadcasts: Vec<(u64, Vec<RelinShareChunk>)> = Vec::new();
    for m in machines.iter_mut() {
        for cmd in m.on_public_key_aggregated(&fhe, &mut ()).unwrap() {
            if let CkksCommand::PublishRelinRound1 { chunks, .. } = cmd {
                r1_broadcasts.push((m.party_id, chunks));
            }
        }
    }
    assert_eq!(r1_broadcasts.len(), N);
    for (pid, chunks) in &r1_broadcasts {
        assert!(chunks.iter().all(|c| c.level == HYBRID_RELIN_LEVEL));
        let payload: usize = chunks.iter().map(|c| c.bytes.size()).sum();
        // ONE payload per round, ~2.7 MiB (vs ~96 MB for 24 per-level shares).
        assert!(
            (2_000_000..4_000_000).contains(&payload),
            "party {pid}: hybrid R1 share is {payload} bytes"
        );
        if *pid < 3 {
            assert_eq!(chunks.len(), 1, "production budget: one chunk");
        } else {
            assert!(chunks.len() > 1, "tiny budget must force multi-chunk");
        }
    }

    // A per-level chunk (real level) is rejected by a hybrid machine at
    // the envelope: the sentinel is the ONLY slot.
    {
        let mut stray = r1_broadcasts[0].1[0].clone();
        stray.level = 1;
        let err = machines[1]
            .on_relin_round_1(r1_broadcasts[0].0, &stray, &fhe, &mut ())
            .unwrap_err();
        assert!(err.to_string().contains("not a ceremony level"), "{err}");
    }
    // Corrupted final chunk of a multi-chunk hybrid share: keccak
    // mismatch bails attributably; the honest re-send still lands.
    {
        let (pid, chunks) = r1_broadcasts.iter().find(|(p, _)| *p >= 3).unwrap();
        let victim = machines.iter_mut().find(|m| m.party_id != *pid).unwrap();
        let mut tampered = chunks.clone();
        let last = tampered.len() - 1;
        let mut bad = tampered[last].bytes.to_vec();
        bad[7] ^= 0x5a;
        tampered[last].bytes = ArcBytes::from_bytes(&bad);
        for c in &tampered[..last] {
            assert!(victim
                .on_relin_round_1(*pid, c, &fhe, &mut ())
                .unwrap()
                .is_empty());
        }
        let err = victim
            .on_relin_round_1(*pid, &tampered[last], &fhe, &mut ())
            .unwrap_err();
        assert!(err.to_string().contains("failed integrity"), "{err}");
    }

    // R1 delivery -> R2 emission.
    let mut r2_broadcasts: Vec<(u64, Vec<RelinShareChunk>)> = Vec::new();
    for m in machines.iter_mut() {
        for (pid, chunks) in &r1_broadcasts {
            for chunk in chunks {
                for cmd in m.on_relin_round_1(*pid, chunk, &fhe, &mut ()).unwrap() {
                    if let CkksCommand::PublishRelinRound2 { chunks } = cmd {
                        r2_broadcasts.push((m.party_id, chunks));
                    }
                }
            }
        }
    }
    assert_eq!(r2_broadcasts.len(), N);

    // R2 delivery with machine 1 crashed + restored mid-round (buffers
    // and the R1 aggregation are not snapshot; the shell replays every
    // logged chunk, R1 then R2).
    let mut key_sets: Vec<Vec<(usize, ArcBytes)>> = Vec::new();
    let mut progress: Vec<CkksProgress> = Vec::new();
    for (i, m) in machines.iter_mut().enumerate() {
        let mut restored = false;
        for (pid, chunks) in &r2_broadcasts {
            if i == 0 && !restored && *pid == 3 {
                let bytes = bincode::serialize(&*m).unwrap();
                let mut reborn: CkksKeyshareMachine = bincode::deserialize(&bytes).unwrap();
                assert!(matches!(reborn.phase(), CkksPhase::RelinRound2 { .. }));
                assert_eq!(reborn.relin_complete_counts(), (0, 0));
                assert!(reborn.relin_is_hybrid(), "plan survives the snapshot");
                for (rpid, rchunks) in &r1_broadcasts {
                    for chunk in rchunks {
                        assert!(reborn
                            .on_relin_round_1(*rpid, chunk, &fhe, &mut ())
                            .unwrap()
                            .is_empty());
                    }
                }
                for (rpid, rchunks) in r2_broadcasts.iter().filter(|(p, _)| *p < 3) {
                    for chunk in rchunks {
                        assert!(reborn
                            .on_relin_round_2(*rpid, chunk, &fhe, &mut ())
                            .unwrap()
                            .is_empty());
                    }
                }
                *m = reborn;
                restored = true;
            }
            for chunk in chunks {
                let mut observe = |p: CkksProgress| progress.push(p);
                for cmd in m.on_relin_round_2(*pid, chunk, &fhe, &mut observe).unwrap() {
                    if let CkksCommand::RelinKeysReady { keys } = cmd {
                        key_sets.push(keys);
                    }
                }
            }
        }
        assert!(matches!(m.phase(), CkksPhase::ReadyForDecryption(_)));
    }
    assert_eq!(key_sets.len(), N);
    for keys in &key_sets {
        assert_eq!(keys.len(), 1, "ONE joint key");
        assert_eq!(keys[0].0, HYBRID_RELIN_LEVEL);
    }
    for keys in &key_sets[1..] {
        assert_eq!(
            keys, &key_sets[0],
            "byte-identical hybrid key on every party"
        );
    }
    assert_eq!(
        progress
            .iter()
            .filter(|p| matches!(
                p,
                CkksProgress::RelinRound2LevelComplete {
                    level: HYBRID_RELIN_LEVEL
                }
            ))
            .count(),
        N
    );

    // The ONE key relinearizes at several levels: one sign-iteration
    // shape (square at level 1) then another square at level 4, all
    // under the same key, then threshold-decrypt at level 5.
    let rlk = fhe::ckks::CkksHybridRelinKey::from_bytes(&key_sets[0][0].1, &params).unwrap();
    assert_eq!(rlk.dnum(), 13);
    let joint_pk_bytes = machines[0].joint_public_key().unwrap().to_vec();
    let pk = CkksPublicKey::from_bytes(&joint_pk_bytes, &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    let x = 0.6f64;
    let slots = params.degree() / 2;
    let ct = pk
        .try_encrypt(&encoder.encode(&vec![x; slots], 0).unwrap(), &mut rng)
        .unwrap();
    let mut y = ct
        .try_mul_plaintext(
            &encoder
                .encode_with_scale(&vec![1.0; slots], 0, params.scale())
                .unwrap(),
        )
        .unwrap();
    y.rescale().unwrap();
    assert_eq!(y.level, 1);
    let mut sq = y.try_mul(&y).unwrap();
    rlk.relinearizes(&mut sq).unwrap();
    sq.rescale().unwrap();
    assert_eq!(sq.level, 2);
    // Drop to level 4 (mod-switch), square AGAIN under the same key.
    sq.mod_switch_to_level(4).unwrap();
    let mut quad = sq.try_mul(&sq).unwrap();
    rlk.relinearizes(&mut quad).unwrap();
    quad.rescale().unwrap();
    assert_eq!(quad.level, 5);
    let out_bytes = quad.to_bytes();

    let mut dec_shares = Vec::new();
    for m in machines.iter_mut().take(T + 1) {
        for cmd in m.on_ciphertext_output(&out_bytes, &fhe).unwrap() {
            if let CkksCommand::PublishDecryptionShare { share, .. } = cmd {
                dec_shares.push((m.party_id, share));
            }
        }
    }
    let values = super::workflow::aggregate_plaintext(&fhe, dec_shares, &out_bytes).unwrap();
    let expected = x.powi(4);
    assert!(
        (values[0] - expected).abs() < 0.01,
        "slot 0: {} vs {expected}",
        values[0]
    );
}
