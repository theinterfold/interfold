// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_crypto::SensitiveBytes;
use e3_events::*;
use e3_fhe_params::{constants::secure_8192, BfvPreset};
use e3_trbfv::shares::BfvEncryptedShares;
use e3_utils::AsBytesSerde;
use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};

const MIB: usize = 1024 * 1024;
const N: usize = 19;
const H: usize = 14;
const LIMBS: usize = secure_8192::threshold::MODULI.len();
const ROW: usize = secure_8192::DEGREE * 8;
const THRESHOLD_POLY: usize = LIMBS * ROW;
const DKG_POLY: usize = secure_8192::dkg::MODULI.len() * ROW;
const PRESET: BfvPreset = BfvPreset::SecureThreshold8192;
const COMMITTEE: CiphernodesCommitteeSize = CiphernodesCommitteeSize::Small;

// Each call owns new, nonzero storage. The extra 64 bytes cover encoding and AEAD headers.
// These are size fixtures for the router, not cryptographic proof fixtures.
fn bytes(len: usize) -> ArcBytes {
    ArcBytes::try_from_bytes(vec![0x5a; len + 64]).unwrap()
}

fn sensitive(len: usize) -> SensitiveBytes {
    SensitiveBytes::from_encrypted(&bytes(len))
}

fn encrypted_shares(targets: &[usize]) -> BfvEncryptedShares {
    let rows: Vec<_> = (0..N)
        .map(|party| {
            targets
                .contains(&party)
                .then(|| (0..LIMBS).map(|_| bytes(2 * DKG_POLY)).collect::<Vec<_>>())
        })
        .collect();
    // The opaque share container has no constructor except encryption. Decode its row layout.
    bincode::deserialize(&bincode::serialize(&rows).unwrap()).unwrap()
}

fn threshold_share(party_id: u64, targets: &[usize]) -> Arc<ThresholdShare> {
    Arc::new(ThresholdShare {
        party_id,
        pk_share: bytes(THRESHOLD_POLY),
        sk_sss: encrypted_shares(targets),
        esi_sss: vec![encrypted_shares(targets)],
    })
}

fn c1() -> PkGenerationProofRequest {
    PkGenerationProofRequest::new(
        bytes(THRESHOLD_POLY),
        sensitive(THRESHOLD_POLY),
        sensitive(THRESHOLD_POLY),
        sensitive(THRESHOLD_POLY),
        PRESET,
        COMMITTEE,
    )
}

fn c2(dkg_input_type: DkgInputType) -> ShareComputationProofRequest {
    ShareComputationProofRequest {
        secret_raw: sensitive(THRESHOLD_POLY),
        secret_sss_raw: sensitive(N * THRESHOLD_POLY + 1024),
        dkg_input_type,
        params_preset: PRESET,
        committee_size: COMMITTEE,
    }
}

fn c3(kind: DkgInputType, party: usize, row: usize) -> ShareEncryptionProofRequest {
    ShareEncryptionProofRequest {
        share_row_raw: sensitive(ROW),
        ciphertext_raw: bytes(2 * DKG_POLY),
        recipient_pk_raw: bytes(2 * DKG_POLY),
        u_rns_raw: sensitive(DKG_POLY),
        e0_rns_raw: sensitive(DKG_POLY),
        e1_rns_raw: sensitive(DKG_POLY),
        dkg_input_type: kind,
        params_preset: PRESET,
        committee_size: COMMITTEE,
        recipient_party_id: party,
        row_index: row,
        esi_index: 0,
    }
}

fn c3_batch(kind: DkgInputType) -> Vec<ShareEncryptionProofRequest> {
    (1..N)
        .flat_map(|party| (0..LIMBS).map(move |row| c3(kind, party, row)))
        .collect()
}

fn c4(kind: DkgInputType) -> DkgShareDecryptionProofRequest {
    DkgShareDecryptionProofRequest {
        sk_bfv: sensitive(DKG_POLY),
        honest_ciphertexts_raw: (0..H * LIMBS).map(|_| bytes(2 * DKG_POLY)).collect(),
        num_honest_parties: H,
        num_moduli: LIMBS,
        own_plaintext_idx: None,
        recipient_party_id: 0,
        own_share_raw: None,
        dkg_input_type: kind,
        params_preset: PRESET,
        committee_size: COMMITTEE,
    }
}

fn compute_failure(id: &E3id, request: ZkRequest) -> ComputeRequestError {
    ComputeRequestError::new(
        ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("worker unavailable".into())),
        ComputeRequest::zk(request, CorrelationId::new(), id.clone()),
    )
}

fn proof(circuit: CircuitName) -> Proof {
    Proof::new(circuit, bytes(16 * 1024), bytes(256))
}

fn signed(id: &E3id, kind: ProofType, circuit: CircuitName) -> SignedProofPayload {
    SignedProofPayload {
        payload: ProofPayload {
            e3_id: id.clone(),
            proof_type: kind,
            proof: proof(circuit),
        },
        signature: ArcBytes::from_bytes(&[0x5a; 65]),
    }
}

fn peer_share(id: &E3id, party: usize, external: bool) -> ThresholdShareCreated {
    ThresholdShareCreated {
        e3_id: id.clone(),
        share: threshold_share(
            if external { party as u64 } else { 0 },
            &[if external { 0 } else { party }],
        ),
        target_party_id: if external { 0 } else { party as u64 },
        external,
        signed_c2a_proof: Some(signed(
            id,
            ProofType::C2aSkShareComputation,
            CircuitName::SkShareComputation,
        )),
        signed_c2b_proof: Some(signed(
            id,
            ProofType::C2bESmShareComputation,
            CircuitName::ESmShareComputation,
        )),
        signed_c3a_proofs: (0..LIMBS)
            .map(|_| {
                signed(
                    id,
                    ProofType::C3aSkShareEncryption,
                    CircuitName::ShareEncryption,
                )
            })
            .collect(),
        signed_c3b_proofs: (0..LIMBS)
            .map(|_| {
                signed(
                    id,
                    ProofType::C3bESmShareEncryption,
                    CircuitName::ShareEncryption,
                )
            })
            .collect(),
        signature: ArcBytes::from_bytes(&[0x5a; 65]),
    }
}

async fn send_data(
    router: &Addr<E3Router>,
    sequence: &mut u64,
    data: impl Into<InterfoldEventData>,
) -> usize {
    *sequence += 1;
    let event = InterfoldEvent::<Sequenced>::test_event("capacity")
        .data(data)
        .seq(*sequence)
        .build();
    let size = charged_bytes(&event);
    route(router, event).await;
    size
}

async fn send_documented(
    router: &Addr<E3Router>,
    id: &E3id,
    sequence: &mut u64,
    data: impl Into<InterfoldEventData>,
    external: bool,
) -> usize {
    let data = data.into();
    let value = ArcBytes::try_from_bytes(bincode::serialize(&data).unwrap()).unwrap();
    let meta = DocumentMeta::new(id.clone(), DocumentKind::TrBFV, vec![], None);
    let envelope: InterfoldEventData = if external {
        DocumentReceived { meta, value }.into()
    } else {
        PublishDocumentRequested { meta, value }.into()
    };
    let size = send_data(router, sequence, envelope).await;
    size + send_data(router, sequence, data).await
}

async fn secure_history(router: &Addr<E3Router>, id: &E3id) -> Result<()> {
    use DkgInputType::{SecretKey, SmudgingNoise};
    let mut late_bytes = charged_bytes(&admission(id));
    route(router, admission(id)).await;
    let mut sequence = 1;
    let committee: Vec<_> = (0..N).map(|party| format!("0x{party:040x}")).collect();
    late_bytes += send_data(
        router,
        &mut sequence,
        CommitteeFinalized {
            e3_id: id.clone(),
            committee: committee.clone(),
            scores: vec![],
            chain_id: 1,
        },
    )
    .await;

    // Peer contributions can precede local selection. Both local DKG recipients are still absent.
    let mut early_bytes = 0;
    for party in 1..N {
        early_bytes += send_documented(
            router,
            id,
            &mut sequence,
            EncryptionKeyCreated {
                e3_id: id.clone(),
                key: Arc::new(
                    EncryptionKey::new(party as u64, bytes(2 * DKG_POLY))
                        .with_proof(proof(CircuitName::PkBfv)),
                ),
                external: true,
            },
            true,
        )
        .await;
        early_bytes +=
            send_documented(router, id, &mut sequence, peer_share(id, party, true), true).await;
    }
    assert!(early_bytes < 80 * MIB);
    late_bytes += send_data(
        router,
        &mut sequence,
        CiphernodeSelected {
            e3_id: id.clone(),
            threshold_m: 9,
            threshold_n: N,
            params_preset: PRESET,
            committee,
            ..Default::default()
        },
    )
    .await;

    late_bytes += early_bytes;
    late_bytes += send_data(
        router,
        &mut sequence,
        ThresholdSharePending {
            e3_id: id.clone(),
            full_share: threshold_share(0, &(1..N).collect::<Vec<_>>()),
            proof_request: c1(),
            sk_share_computation_request: c2(SecretKey),
            e_sm_share_computation_request: c2(SmudgingNoise),
            sk_share_encryption_requests: c3_batch(SecretKey),
            e_sm_share_encryption_requests: c3_batch(SmudgingNoise),
            recipient_party_ids: (0..N as u64).collect(),
        },
    )
    .await;
    // A compute failure routes its full request again. Keep those witnesses independently allocated.
    for request in [
        ZkRequest::PkGeneration(c1()),
        ZkRequest::ShareComputation(c2(SecretKey)),
        ZkRequest::ShareComputation(c2(SmudgingNoise)),
    ] {
        late_bytes += send_data(router, &mut sequence, compute_failure(id, request)).await;
    }
    for kind in [SecretKey, SmudgingNoise] {
        for party in 1..N {
            for row in 0..LIMBS {
                late_bytes += send_data(
                    router,
                    &mut sequence,
                    compute_failure(id, ZkRequest::ShareEncryption(c3(kind, party, row))),
                )
                .await;
            }
        }
    }
    for party in 1..N {
        late_bytes += send_documented(
            router,
            id,
            &mut sequence,
            peer_share(id, party, false),
            false,
        )
        .await;
    }
    late_bytes += send_data(
        router,
        &mut sequence,
        DecryptionShareProofsPending {
            e3_id: id.clone(),
            party_id: 0,
            node: format!("0x{:040x}", 0),
            sk_request: c4(SecretKey),
            esm_requests: vec![c4(SmudgingNoise)],
        },
    )
    .await;
    for kind in [SecretKey, SmudgingNoise] {
        late_bytes += send_data(
            router,
            &mut sequence,
            compute_failure(id, ZkRequest::DkgShareDecryption(c4(kind))),
        )
        .await;
    }
    for party in 0..N {
        late_bytes += send_documented(
            router,
            id,
            &mut sequence,
            DecryptionshareCreated {
                e3_id: id.clone(),
                party_id: party as u64,
                node: format!("0x{party:040x}"),
                decryption_share: vec![bytes(THRESHOLD_POLY)],
                signed_decryption_proofs: vec![signed(
                    id,
                    ProofType::C6ThresholdShareDecryption,
                    CircuitName::ThresholdShareDecryption,
                )],
            },
            true,
        )
        .await;
    }
    // Pad proof results and control traffic to the documented 1,536-record envelope.
    while sequence < 1_536 {
        late_bytes += send_data(
            router,
            &mut sequence,
            ComputeResponse::zk(
                ZkResponse::PkGeneration(PkGenerationProofResponse {
                    proof: proof(CircuitName::PkGeneration),
                }),
                CorrelationId::new(),
                id.clone(),
            ),
        )
        .await;
    }
    assert!(late_bytes < 512 * MIB, "secure history: {late_bytes} bytes");
    println!("secure history {id}: {sequence} records, {late_bytes} late bytes, {early_bytes} bytes before local selection");
    Ok(())
}

async fn drain_history(
    router: &Addr<E3Router>,
    recorders: &[Addr<Recorder>],
    id: &E3id,
) -> Result<()> {
    send_data(
        router,
        &mut 1_536,
        CiphertextOutputPublished {
            e3_id: id.clone(),
            ciphertext_output: vec![bytes(2 * THRESHOLD_POLY)],
            ciphertext_commitment: [0; 32],
        },
    )
    .await;
    for recorder in recorders {
        assert_eq!(
            recorder.send(Recorded(id.clone())).await?,
            (1..=1_537).collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn memory_bytes(field: &str) -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(field).map(|rest| {
                rest.split_whitespace()
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
                    * 1024
            })
        })
        .expect("Linux reports resident memory")
}

#[actix::test]
async fn allocated_histories_fit_and_default_bytes_isolate_overflow() -> Result<()> {
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let recorders: Vec<_> = (0..5).map(|_| Recorder::default().start()).collect();
    let router = E3Router::from_params(router_params(&store, &recorders)).start();
    #[cfg(target_os = "linux")]
    let baseline = memory_bytes("VmRSS:");
    let ids: Vec<_> = (51..55).map(|id| E3id::new(id.to_string(), 1)).collect();
    for id in &ids {
        secure_history(&router, id).await?;
    }
    #[cfg(target_os = "linux")]
    {
        let resident = memory_bytes("VmRSS:").saturating_sub(baseline);
        println!("four secure histories: {resident} resident bytes above baseline");
        assert!(
            resident > 1024 * MIB,
            "capacity histories must own distinct resident payloads"
        );
        assert!(
            resident < 2560 * MIB,
            "four legitimate histories need memory margin"
        );
    }
    for id in &ids {
        drain_history(&router, &recorders, id).await?;
    }

    // Exercise the shipped byte budgets, with one missing recipient and independently allocated data.
    // Four queues reach the global budget while every individual queue stays below its own budget.
    for (queues, entries, overflowed) in [(1, 64, 0), (4, 47, 3)] {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let recorder = Recorder::default().start();
        let router =
            E3Router::from_params(router_params(&store, std::slice::from_ref(&recorder))).start();
        let ids: Vec<_> = (0..queues)
            .map(|id| E3id::new((id + 61).to_string(), 1))
            .collect();
        for id in &ids {
            route(&router, admission(id)).await;
            for sequence in 2..=entries + 1 {
                route(
                    &router,
                    InterfoldEvent::<Sequenced>::test_event("capacity")
                        .data(DecryptionshareCreated {
                            e3_id: id.clone(),
                            party_id: 0,
                            node: "member".into(),
                            decryption_share: vec![bytes(16 * MIB)],
                            signed_decryption_proofs: vec![],
                        })
                        .seq(sequence)
                        .build(),
                )
                .await;
            }
        }
        #[cfg(target_os = "linux")]
        {
            let resident = memory_bytes("VmRSS:").saturating_sub(baseline);
            println!("{queues} saturated queues: {resident} resident bytes above baseline");
            if queues == 4 {
                assert!(
                    resident > 2816 * MIB,
                    "saturation must use distinct resident payloads"
                );
            }
            assert!(
                memory_bytes("VmHWM:").saturating_sub(baseline) < 4608 * MIB,
                "router memory must leave headroom on an 8 GiB node"
            );
        }
        let failed = &ids[overflowed];
        // Four more payloads cross the shared limit while staying below the per-E3 limit.
        for extra in 0..if queues == 4 { 4 } else { 0 } {
            route(
                &router,
                InterfoldEvent::<Sequenced>::test_event("capacity")
                    .data(DecryptionshareCreated {
                        e3_id: failed.clone(),
                        party_id: 0,
                        node: "member".into(),
                        decryption_share: vec![bytes(16 * MIB)],
                        signed_decryption_proofs: vec![],
                    })
                    .seq(entries + 2 + extra)
                    .build(),
            )
            .await;
        }
        route(&router, attach(failed, entries + 6)).await;
        route(&router, share(failed, entries + 7)).await;
        assert_eq!(
            recorder.send(Recorded(failed.clone())).await?,
            [entries + 6, entries + 7],
            "default byte limit must discard only the failed backlog"
        );
        for healthy in ids.iter().filter(|id| *id != failed) {
            route(&router, attach(healthy, entries + 2)).await;
            assert_eq!(
                recorder.send(Recorded(healthy.clone())).await?,
                (1..=entries + 2).collect::<Vec<_>>()
            );
        }
    }

    // Small independent allocations must consume the byte budget before the item budget.
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let recorder = Recorder::default().start();
    let router =
        E3Router::from_params(router_params(&store, std::slice::from_ref(&recorder))).start();
    let failed = E3id::new("71", 1);
    let healthy = E3id::new("72", 1);
    route(&router, admission(&failed)).await;
    let mut encoded_bytes = 0;
    for sequence in 2..=65 {
        let event = InterfoldEvent::<Sequenced>::test_event("capacity")
            .data(DecryptionshareCreated {
                e3_id: failed.clone(),
                party_id: 0,
                node: "member".into(),
                decryption_share: (0..131_072).map(|_| ArcBytes::from_bytes(&[])).collect(),
                signed_decryption_proofs: vec![],
            })
            .seq(sequence)
            .build();
        encoded_bytes += bincode::serialized_size(&event)?;
        route(&router, event).await;
    }
    assert!(encoded_bytes < 128 * MIB as u64);
    route(&router, admission(&healthy)).await;
    route(&router, share(&healthy, 2)).await;
    route(&router, attach(&healthy, 3)).await;
    assert_eq!(recorder.send(Recorded(healthy)).await?, [1, 2, 3]);
    route(&router, attach(&failed, 66)).await;
    route(&router, share(&failed, 67)).await;
    assert_eq!(
        recorder.send(Recorded(failed)).await?,
        [66, 67],
        "nested allocations must fail only their deferred queue"
    );
    #[cfg(target_os = "linux")]
    {
        let peak = memory_bytes("VmHWM:").saturating_sub(baseline);
        println!("peak resident growth including overflow and draining: {peak} bytes");
        assert!(
            peak < 4608 * MIB,
            "router memory must leave headroom on an 8 GiB node"
        );
    }
    Ok(())
}

#[actix::test]
async fn deferred_share_collections_release_spare_capacity() -> Result<()> {
    #[derive(Default)]
    struct CapacityRecorder(Vec<usize>);

    impl Actor for CapacityRecorder {
        type Context = Context<Self>;
    }

    impl Handler<InterfoldEvent> for CapacityRecorder {
        type Result = ();

        fn handle(&mut self, event: InterfoldEvent, _: &mut Self::Context) {
            let share = match event.get_data() {
                InterfoldEventData::ThresholdShareCreated(data) => &data.share,
                InterfoldEventData::ThresholdSharePending(data) => &data.full_share,
                _ => return,
            };
            assert_eq!(share.esi_sss.len(), 1);
            self.0.push(share.esi_sss.capacity());
        }
    }

    #[derive(Message)]
    #[rtype(result = "Vec<usize>")]
    struct Capacities;

    impl Handler<Capacities> for CapacityRecorder {
        type Result = Vec<usize>;

        fn handle(&mut self, _: Capacities, _: &mut Self::Context) -> Self::Result {
            self.0.clone()
        }
    }

    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let recorder = CapacityRecorder::default().start();
    let router = E3Router::builder(&super::super::test_bus(), store)
        .with_recipient(
            "plaintext",
            Box::new(LateRecipient {
                key: "plaintext",
                recipient: recorder.clone().recipient(),
            }),
        )
        .build()
        .await?;
    let id = E3id::new("81", 1);
    route(&router, admission(&id)).await;
    let mut share = threshold_share(0, &[]);
    Arc::make_mut(&mut share).esi_sss.reserve(4096);
    assert!(share.esi_sss.capacity() > 4096);
    let mut sequence = 1;
    send_data(
        &router,
        &mut sequence,
        ThresholdShareCreated {
            share: share.clone(),
            ..peer_share(&id, 1, false)
        },
    )
    .await;
    send_data(
        &router,
        &mut sequence,
        ThresholdSharePending {
            e3_id: id.clone(),
            full_share: share,
            proof_request: c1(),
            sk_share_computation_request: c2(DkgInputType::SecretKey),
            e_sm_share_computation_request: c2(DkgInputType::SmudgingNoise),
            sk_share_encryption_requests: vec![],
            e_sm_share_encryption_requests: vec![],
            recipient_party_ids: vec![],
        },
    )
    .await;
    route(&router, attach(&id, 4)).await;
    assert_eq!(recorder.send(Capacities).await?, [1, 1]);
    Ok(())
}
