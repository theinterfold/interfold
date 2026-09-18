// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Actor;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{ensure, Result};
use e3_ciphernode_builder::EventSystem;
use e3_crypto::SensitiveBytes;
use e3_data::{CommitLogEventLog, DataStore, InMemStore};
use e3_events::{
    AggregateConfig, AggregateId, ComputeRequestKind, E3id, Event, EventConstructorWithTimestamp,
    EventLog, EventSource, EventSubscriber, EventType, GetEvents, HistoryCollector, InterfoldEvent,
    InterfoldEventData, PkGenerationProofRequest, ShareComputationProofRequest,
    ShareEncryptionProofRequest, ThresholdShare, ThresholdSharePending, TypedEvent, Unsequenced,
};
use e3_fhe_params::BfvPreset;
use e3_keyshare::{ThresholdKeyshareRecoveryPayloads, ThresholdKeyshareRecoveryState};
use e3_trbfv::shares::BfvEncryptedShares;
use e3_utils::ArcBytes;
use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};
use e3_zk_prover::ProofRequestActor;
use std::{collections::HashMap, sync::Arc, time::Duration};

fn pending_small_work_plan() -> ThresholdSharePending {
    let committee = CiphernodesCommitteeSize::Small;
    let n = committee.values().n;
    let preset = BfvPreset::SecureThreshold8192;
    let empty = SensitiveBytes::from_encrypted(&[]);
    let proof_request = PkGenerationProofRequest {
        pk0_share: ArcBytes::from_bytes(&[]),
        sk: empty.clone(),
        eek: empty.clone(),
        e_sm: empty.clone(),
        params_preset: preset,
        committee_size: committee,
    };
    let computation = |kind| ShareComputationProofRequest {
        secret_raw: empty.clone(),
        secret_sss_raw: empty.clone(),
        dkg_input_type: kind,
        params_preset: preset,
        committee_size: committee,
    };

    // Small has 18 external recipients and three secure-8192 modulus rows.
    // Each recipient has C3a and C3b work, for 108 C3 requests plus C1/C2a/C2b.
    // The payload bytes are synthetic; this test checks durable transport and dispatch,
    // not BFV witness validity or proof generation.
    let large_ciphertext = ArcBytes::from_bytes(&vec![0x5a; 1_130_000]);
    let encryption_request = |party_id, row_index, kind| ShareEncryptionProofRequest {
        share_row_raw: empty.clone(),
        ciphertext_raw: large_ciphertext.clone(),
        recipient_pk_raw: ArcBytes::from_bytes(&[]),
        u_rns_raw: empty.clone(),
        e0_rns_raw: empty.clone(),
        e1_rns_raw: empty.clone(),
        dkg_input_type: kind,
        params_preset: preset,
        committee_size: committee,
        recipient_party_id: party_id,
        row_index,
        esi_index: 0,
    };
    let mut sk_requests = Vec::new();
    let mut esm_requests = Vec::new();
    for party_id in 1..n {
        for row_index in 0..3 {
            sk_requests.push(encryption_request(
                party_id,
                row_index,
                DkgInputType::SecretKey,
            ));
            esm_requests.push(encryption_request(
                party_id,
                row_index,
                DkgInputType::SmudgingNoise,
            ));
        }
    }
    assert_eq!(sk_requests.len() + esm_requests.len() + 3, 111);

    ThresholdSharePending {
        e3_id: E3id::new("7", 1),
        full_share: Arc::new(ThresholdShare {
            party_id: 0,
            pk_share: ArcBytes::from_bytes(&[]),
            sk_sss: BfvEncryptedShares::default(),
            esi_sss: vec![],
        }),
        proof_request,
        sk_share_computation_request: computation(DkgInputType::SecretKey),
        e_sm_share_computation_request: computation(DkgInputType::SmudgingNoise),
        sk_share_encryption_requests: sk_requests,
        e_sm_share_encryption_requests: esm_requests,
        recipient_party_ids: (0..n as u64).collect(),
    }
}

async fn dispatch_work_plan(event: InterfoldEvent<Unsequenced>) -> Result<Vec<ComputeRequestKind>> {
    let system = EventSystem::in_mem()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            AggregateId::new(1),
            Duration::ZERO,
        )])));
    let bus = system.handle()?.enable("proof-recovery-test");
    let history = HistoryCollector::<InterfoldEvent>::new().start();
    bus.subscribe(EventType::ComputeRequest, history.clone().recipient());
    let _actor = ProofRequestActor::setup(&bus, PrivateKeySigner::random(), false);
    bus.naked_dispatch_async(event).await?;

    let mut requests = Vec::new();
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
            requests = events
                .into_iter()
                .filter_map(|event| match event.into_data() {
                    InterfoldEventData::ComputeRequest(request) => Some(request.request),
                    _ => None,
                })
                .collect();
            if requests.len() >= 111 {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    ensure!(requests.len() == 111, "unexpected proof request count");
    Ok(requests)
}

#[actix::test]
async fn large_small_work_plan_survives_reopen_and_fresh_proof_dispatch() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        pending_small_work_plan().into(),
        None,
        123,
        None,
        EventSource::Local,
    );
    let encoded_len = bincode::serialized_size(&event)?;
    ensure!(encoded_len > 122_000_000, "work plan fixture is too small");

    let sequenced = event.clone().into_sequenced(1);
    let ec = sequenced.get_ctx().clone();
    let InterfoldEventData::ThresholdSharePending(pending) = sequenced.into_data() else {
        unreachable!("fixture is a threshold-share work plan")
    };
    let typed = TypedEvent::new(pending, ec.clone());
    let payload_store = InMemStore::new(false).start();
    let data = DataStore::from_in_mem(&payload_store);
    let payloads = ThresholdKeyshareRecoveryPayloads::new(data.clone());
    let reference = payloads.write_pending(&typed, &ec)?;
    let root = ThresholdKeyshareRecoveryState {
        threshold_share_pending_ref: Some(reference),
        ..Default::default()
    };
    ensure!(
        bincode::serialized_size(&root)? < 4_096,
        "large work plan leaked into the mutable recovery root"
    );
    let loaded = ThresholdKeyshareRecoveryPayloads::load(data, &root).await?;
    ensure!(loaded.pending() == Some(&typed), "split work plan changed");

    let mut log = CommitLogEventLog::new(directory.path())?;
    ensure!(log.append(&event)? == 1, "unexpected event sequence");
    log.flush()?;
    drop(log);

    let reopened = CommitLogEventLog::new(directory.path())?;
    let mut events = reopened.read_from_checked(1)?;
    ensure!(events.len() == 1, "expected one recovered work plan");
    let recovered = events.pop().expect("checked length").1;
    ensure!(recovered == event, "work plan changed during recovery");

    let first = dispatch_work_plan(recovered.clone()).await?;
    let second = dispatch_work_plan(recovered).await?;
    ensure!(first == second, "proof work changed after fresh dispatch");
    Ok(())
}
