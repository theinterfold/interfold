// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The CKKS rogue-key gate: CKKS pk shares go through the C1 round, the
//! `pk_commitment` twin cross-checks the received bytes, and only honest
//! shares are summed.

use super::*;
use e3_events::{E3Failed, PublicKeyAggregated, SignedProofFailed};
use e3_fhe::ckks_runtime::CkksFhe;
use e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set;
use e3_zk_helpers::circuits::threshold::pk_generation_ckks::{
    compute_ckks_pk_commitment_from_share_bytes, compute_pk_share, sample_pk_share_error,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::CkksPreset;
use fhe::ckks::CkksSecretKey;
use fhe_traits::Serialize as _;

const CRP_SEED: [u8; 32] = [5u8; 32];

fn ckks_runtime(n: usize, t: usize) -> Result<Arc<CkksFhe>> {
    let params = ckks_params_for_on_chain_param_set(0)?;
    let rng = Arc::new(std::sync::Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed([1u8; 32]),
    ));
    Ok(Arc::new(CkksFhe::from_encoded(
        &params.to_bytes(),
        CRP_SEED,
        n,
        t,
        rng,
    )?))
}

fn c1_ckks_proof(e3_id: &E3id, pk_commitment: [u8; 32]) -> SignedProofPayload {
    let mut signals = vec![0u8; 96];
    signals[32..64].copy_from_slice(&pk_commitment);
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .expect("test signer");
    SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C1PkGeneration,
            proof: Proof::new(
                CircuitName::PkGenerationCkksPs0,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&signals),
            ),
        },
        &signer,
    )
    .expect("sign")
}

/// A real CKKS pk share (bytes as `KeyshareCreated.pubkey` carries them)
/// and its honest C1-CKKS `pk_commitment`.
fn real_share(ckks: &CkksFhe) -> Result<(ArcBytes, [u8; 32])> {
    let mut rng = rand::rng();
    let sk = CkksSecretKey::random(&ckks.params, &mut rng);
    let e = sample_pk_share_error(&ckks.params, &mut rng);
    let share = compute_pk_share(&ckks.params, &ckks.crp, sk.coeffs.as_ref(), &e)?;
    let bytes = ArcBytes::from_bytes(&share.p0_to_bytes());
    let preset = CkksPreset {
        params: ckks.params.clone(),
        input_bound: 1.0,
    };
    let commitment = compute_ckks_pk_commitment_from_share_bytes(&preset, &ckks.crp, &bytes)?;
    Ok((bytes, commitment))
}

async fn build_ckks_aggregator(
    state: PublicKeyAggregatorState,
    ckks: Arc<CkksFhe>,
) -> Result<(
    PublicKeyAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: None,
            ckks: Some(ckks),
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(state),
    );
    Ok((aggregator, history, e3_id))
}

/// Committee of 3 (t = 1): party 0/1 honest, party 2 per `bad`.
enum Bad {
    None,
    MissingProof,
    WrongCommitment,
}

fn verifying_c1_state(ckks: &CkksFhe, e3_id: &E3id, bad: Bad) -> Result<PublicKeyAggregatorState> {
    let mut submission_order = Vec::new();
    let mut c1_proofs = Vec::new();
    let mut canonical_party_nodes = HashMap::new();
    for party_id in 0..3u64 {
        let node = format!("0x{:040x}", party_id + 1);
        canonical_party_nodes.insert(party_id, node.clone());
        let (bytes, commitment) = real_share(ckks)?;
        submission_order.push((party_id, node, bytes));
        let proof = match (&bad, party_id) {
            (Bad::MissingProof, 2) => None,
            (Bad::WrongCommitment, 2) => Some(c1_ckks_proof(e3_id, [0xAB; 32])),
            _ => Some(c1_ckks_proof(e3_id, commitment)),
        };
        c1_proofs.push(proof);
    }
    Ok(PublicKeyAggregatorState::VerifyingC1 {
        submission_order,
        threshold_m: 1,
        circuit_committee_n: 3,
        circuit_committee_h: 3,
        c1_proofs,
        no_proof_parties: vec![],
        canonical_party_nodes,
    })
}

fn complete(e3_id: &E3id, dishonest: BTreeSet<u64>) -> TypedEvent<ShareVerificationComplete> {
    let v = ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::PkGenerationProofs,
        dishonest_parties: dishonest,
    };
    TypedEvent::new(v.clone(), test_ctx(v))
}

/// CKKS shares are DISPATCHED for C1 verification (no more bypass), with
/// the proof-less party pre-marked dishonest.
#[actix::test]
async fn ckks_dispatches_c1_verification_instead_of_summing() -> Result<()> {
    let ckks = ckks_runtime(3, 1)?;
    let e3_id = E3id::new("42", 1);
    let state = verifying_c1_state(&ckks, &e3_id, Bad::MissingProof)?;
    let (mut aggregator, history, _) = build_ckks_aggregator(state, ckks).await?;
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    let event = next_event(&history).await?;
    let InterfoldEventData::ShareVerificationDispatched(data) = event.into_data() else {
        panic!("expected ShareVerificationDispatched, CKKS must not bypass C1");
    };
    assert_eq!(data.kind, VerificationKind::PkGenerationProofs);
    assert_eq!(data.share_proofs.len(), 2);
    assert_eq!(data.pre_dishonest, BTreeSet::from([2]));
    assert_eq!(
        data.share_proofs[0].signed_proofs[0].payload.proof.circuit,
        CircuitName::PkGenerationCkksPs0
    );
    Ok(())
}

/// Honest proofs → joint key over ALL three shares.
#[actix::test]
async fn ckks_good_proofs_aggregate_all_shares() -> Result<()> {
    let ckks = ckks_runtime(3, 1)?;
    let e3_id = E3id::new("42", 1);
    let state = verifying_c1_state(&ckks, &e3_id, Bad::None)?;
    let (mut aggregator, history, _) = build_ckks_aggregator(state, ckks).await?;
    aggregator.handle_c1_verification_complete(complete(&e3_id, BTreeSet::new()))?;
    let event = next_event(&history).await?;
    let InterfoldEventData::PublicKeyAggregated(PublicKeyAggregated { nodes, .. }) =
        event.into_data()
    else {
        panic!("expected PublicKeyAggregated");
    };
    assert_eq!(nodes.len(), 3);
    Ok(())
}

/// A share whose proof commits to DIFFERENT bytes → SignedProofFailed
/// (attributable) and E3Failed: CKKS machines aggregate the dealt secret
/// over every dealer, so no subset key is published.
#[actix::test]
async fn ckks_commitment_mismatch_is_reported_and_fails_e3() -> Result<()> {
    let ckks = ckks_runtime(3, 1)?;
    let e3_id = E3id::new("42", 1);
    let state = verifying_c1_state(&ckks, &e3_id, Bad::WrongCommitment)?;
    let (mut aggregator, history, _) = build_ckks_aggregator(state, ckks).await?;
    aggregator.handle_c1_verification_complete(complete(&e3_id, BTreeSet::new()))?;
    let events = history
        .send(TakeEvents::<InterfoldEvent>::new(2))
        .await?
        .events;
    let mut failed = None;
    let mut e3_failed = false;
    for e in events {
        match e.into_data() {
            InterfoldEventData::SignedProofFailed(f) => failed = Some(f),
            InterfoldEventData::E3Failed(E3Failed {
                reason: FailureReason::DKGInvalidShares,
                ..
            }) => e3_failed = true,
            InterfoldEventData::PublicKeyAggregated(_) => {
                panic!("no joint key may be published over a rejected share")
            }
            _ => {}
        }
    }
    let SignedProofFailed { proof_type, .. } = failed.expect("SignedProofFailed");
    assert_eq!(proof_type, ProofType::C1PkGeneration);
    assert!(e3_failed, "E3Failed expected");
    Ok(())
}

/// Verifier-rejected + missing proofs leaving ≤ t honest → E3Failed, no
/// key published.
#[actix::test]
async fn ckks_too_few_honest_after_c1_fails_e3() -> Result<()> {
    let ckks = ckks_runtime(3, 1)?;
    let e3_id = E3id::new("42", 1);
    let state = verifying_c1_state(&ckks, &e3_id, Bad::MissingProof)?;
    let (mut aggregator, history, _) = build_ckks_aggregator(state, ckks).await?;
    // The verifier also rejected party 1's proof; party 2 has none.
    aggregator.handle_c1_verification_complete(complete(&e3_id, BTreeSet::from([1, 2])))?;
    let events = history
        .send(TakeEvents::<InterfoldEvent>::new(1))
        .await?
        .events;
    assert!(events.iter().any(|e| matches!(
        e.get_data(),
        InterfoldEventData::E3Failed(E3Failed {
            reason: FailureReason::DKGInvalidShares,
            ..
        })
    )));
    assert!(!events
        .iter()
        .any(|e| matches!(e.get_data(), InterfoldEventData::PublicKeyAggregated(_))));
    Ok(())
}
