// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{
    CommitmentConsistencyCheckComplete, Committee, Die, EventBusBarrier, PartyVerificationResult,
    ResetHistory, VerifyShareDecryptionProofsResponse, VerifyShareProofsResponse, ZkRequest,
    ZkResponse,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::ShareVerificationActor;

fn signed_proof(e3_id: &E3id, party: u64, proof_type: ProofType) -> SignedProofPayload {
    SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof: Proof::new(
                proof_type.circuit_names()[0],
                ArcBytes::from_bytes(&[party as u8, proof_type as u8]),
                ArcBytes::from_bytes(&[7; 64]),
            ),
        },
        &dealer_signer(party),
    )
    .unwrap()
}

fn authenticated_share(e3_id: &E3id, party: u64) -> ThresholdShareCreated {
    let rows = BfvPreset::InsecureThreshold512.metadata().num_moduli;
    ThresholdShareCreated {
        signed_c2a_proof: Some(signed_proof(e3_id, party, ProofType::C2aSkShareComputation)),
        signed_c2b_proof: Some(signed_proof(
            e3_id,
            party,
            ProofType::C2bESmShareComputation,
        )),
        signed_c3a_proofs: vec![signed_proof(e3_id, party, ProofType::C3aSkShareEncryption); rows],
        signed_c3b_proofs: vec![signed_proof(e3_id, party, ProofType::C3bESmShareEncryption); rows],
        share: Arc::new(ThresholdShare {
            esi_sss: vec![Default::default()],
            ..(*peer_share(e3_id, party).share).clone()
        }),
        ..peer_share(e3_id, party)
    }
    .sign(&dealer_signer(party))
    .unwrap()
}

struct AdmissionHarness {
    e3_id: E3id,
    bus: BusHandle,
    history: Addr<HistoryCollector<InterfoldEvent>>,
    state: Repository<ThresholdKeyshareState>,
    recovery: Repository<ThresholdKeyshareRecoveryState>,
    payloads: DataStore,
    bfv_keys: DurableIntent<BfvKeyIntent>,
    cipher: Arc<Cipher>,
}

impl AdmissionHarness {
    async fn new(cutoff_passed: bool) -> Result<(Self, ThresholdKeyshare)> {
        Self::with_committee(cutoff_passed, CiphernodesCommitteeSize::Minimum).await
    }

    async fn with_committee(
        cutoff_passed: bool,
        committee_size: CiphernodesCommitteeSize,
    ) -> Result<(Self, ThresholdKeyshare)> {
        let e3_id = E3id::new("91", 1);
        let committee = committee_size.values();
        let selected = CiphernodeSelected {
            committee: (0..committee.n as u64)
                .map(|party| dealer_signer(party).address().to_string())
                .collect(),
            threshold_m: committee.threshold,
            threshold_n: committee.n,
            ..selection(&e3_id)
        };
        let (bus, history) = test_bus();
        let cipher = Arc::new(Cipher::from_password("test-password").await?);
        let rows = vec![vec![1u64]; BfvPreset::InsecureThreshold512.metadata().num_moduli];
        let rows = SensitiveBytes::new(bincode::serialize(&rows)?, &cipher)?;
        let current = AggregatingDecryptionKey {
            own_sk_share_raw: rows.clone(),
            own_esi_shares_raw: vec![rows],
            signed_sk_share_computation_proof: Some(signed_proof(
                &e3_id,
                0,
                ProofType::C2aSkShareComputation,
            )),
            signed_e_sm_share_computation_proof: Some(signed_proof(
                &e3_id,
                0,
                ProofType::C2bESmShareComputation,
            )),
            ..aggregating_decryption_key_for_roster_test()
        };
        let (mut state, state_repo) =
            test_state(&e3_id, KeyshareState::AggregatingDecryptionKey(current));
        state.try_mutate_without_context(|mut state| {
            state.threshold_m = committee.threshold as u64;
            state.threshold_n = committee.n as u64;
            state.params = insecure_threshold_params();
            Ok(state)
        })?;
        if cutoff_passed {
            state.try_mutate_without_context(|mut state| {
                state.dkg_deadline_unix_secs =
                    Some(crate::domain::timeout_policy::now_unix_secs() + 1_800);
                state.dkg_window_secs = Some(14_400);
                Ok(state)
            })?;
        }
        let (mut recovery, recovery_repo) = test_recovery_with_repo();
        recovery.try_mutate_without_context(|mut recovery| {
            recovery.ciphernode_selected = Some(TypedEvent::new(selected.clone(), test_ec(0)));
            recovery.encryption_keys.insert(
                0,
                TypedEvent::new(
                    EncryptionKeyCreated {
                        e3_id: e3_id.clone(),
                        key: Arc::new(
                            EncryptionKey::new(0, ArcBytes::default())
                                .with_signed_payload(signed_proof(&e3_id, 0, ProofType::C0PkBfv)),
                        ),
                        external: false,
                    },
                    test_ec(0),
                ),
            );
            Ok(recovery)
        })?;
        let store = InMemStore::new(false).start();
        let harness = Self {
            e3_id: e3_id.clone(),
            bus,
            history,
            state: state_repo,
            recovery: recovery_repo,
            payloads: DataStore::from_in_mem(&store),
            bfv_keys: test_bfv_key_in(&store),
            cipher,
        };
        let actor = harness.actor(
            state,
            recovery,
            ThresholdKeyshareRecoveryPayloads::new(harness.payloads.clone()),
        );
        ShareVerificationActor::setup(
            &harness.bus,
            HashMap::from([(e3_id, Committee::new(selected.committee))]),
        );
        Ok((harness, actor))
    }

    fn actor(
        &self,
        state: Persistable<ThresholdKeyshareState>,
        recovery: Persistable<ThresholdKeyshareRecoveryState>,
        recovery_payloads: ThresholdKeyshareRecoveryPayloads,
    ) -> ThresholdKeyshare {
        ThresholdKeyshare::new(ThresholdKeyshareParams {
            bus: self.bus.clone(),
            cipher: self.cipher.clone(),
            state,
            share_enc_preset: BfvPreset::InsecureDkg512,
            interfold_address: Address::ZERO,
            signer: dealer_signer(0),
            effects_enabled: true,
            recovery,
            recovery_payloads,
            bfv_key: self.bfv_keys.clone(),
            dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
        })
    }

    async fn start(&self, actor: ThresholdKeyshare) -> Result<Addr<ThresholdKeyshare>> {
        let actor = actor.start();
        for event_type in [
            EventType::ThresholdShareCreated,
            EventType::DecryptionKeyShared,
            EventType::ShareVerificationDispatched,
            EventType::ShareVerificationComplete,
        ] {
            self.bus.subscribe(event_type, actor.clone().into());
        }
        self.bus.event_bus().send(EventBusBarrier).await?;
        Ok(actor)
    }

    async fn restart(&self, actor: Addr<ThresholdKeyshare>) -> Result<Addr<ThresholdKeyshare>> {
        actor.send(Die).await?;
        let recovery = self.recovery.load().await?;
        let payloads =
            ThresholdKeyshareRecoveryPayloads::load(self.payloads.clone(), &recovery.try_get()?)
                .await?;
        let actor = self
            .start(self.actor(self.state.load().await?, recovery, payloads))
            .await?;
        actor
            .send(keyshare_event(
                EffectsEnabled::new(),
                100,
                EventSource::Local,
            ))
            .await?;
        Ok(actor)
    }

    async fn event(&self, matches: impl Fn(&InterfoldEventData) -> bool) -> Result<InterfoldEvent> {
        actix::clock::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(event) = self
                    .history
                    .send(GetEvents::<InterfoldEvent>::new())
                    .await?
                    .into_iter()
                    .find(|event| matches(event.get_data()))
                {
                    return Ok::<_, anyhow::Error>(event);
                }
                actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await?
    }

    async fn verify_collected_shares(&self, expected: &[u64]) -> Result<()> {
        let check = self
            .event(|data| {
                matches!(
                    data,
                    InterfoldEventData::CommitmentConsistencyCheckRequested(_)
                )
            })
            .await?;
        let InterfoldEventData::CommitmentConsistencyCheckRequested(check) = check.into_data()
        else {
            unreachable!()
        };
        assert_eq!(
            check
                .party_proofs
                .iter()
                .map(|party| party.party_id)
                .collect::<BTreeSet<_>>(),
            expected.iter().copied().collect()
        );
        self.bus
            .publish_without_context(CommitmentConsistencyCheckComplete {
                e3_id: self.e3_id.clone(),
                correlation_id: check.correlation_id,
                kind: check.kind.clone(),
                inconsistent_parties: BTreeSet::new(),
            })?;
        let request = self
            .event(|data| matches!(data, InterfoldEventData::ComputeRequest(_)))
            .await?;
        let InterfoldEventData::ComputeRequest(request) = request.into_data() else {
            unreachable!()
        };
        let party_results = expected
            .iter()
            .map(|&party| PartyVerificationResult {
                sender_party_id: party,
                all_verified: true,
                failed_signed_payload: None,
                recovered_address: Some(dealer_signer(party).address()),
            })
            .collect();
        let (parties, response): (BTreeSet<_>, _) = match request.request {
            ComputeRequestKind::Zk(ZkRequest::VerifyShareProofs(proofs)) => (
                proofs
                    .party_proofs
                    .iter()
                    .map(|party| party.sender_party_id)
                    .collect(),
                ZkResponse::VerifyShareProofs(VerifyShareProofsResponse { party_results }),
            ),
            ComputeRequestKind::Zk(ZkRequest::VerifyShareDecryptionProofs(proofs)) => (
                proofs
                    .party_proofs
                    .iter()
                    .map(|party| party.sender_party_id)
                    .collect(),
                ZkResponse::VerifyShareDecryptionProofs(VerifyShareDecryptionProofsResponse {
                    party_results,
                }),
            ),
            _ => panic!("expected share verification"),
        };
        assert_eq!(parties, expected.iter().copied().collect());
        // The worker response supplies only ZK results. Admission, signature checks, dispatch,
        // and durable result application run through the production actors.
        self.bus.publish_without_context(ComputeResponse::zk(
            response,
            request.correlation_id,
            self.e3_id.clone(),
        ))?;
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        wait_for_record(&self.recovery, |recovery| {
            if check.kind == VerificationKind::DecryptionProofs {
                recovery
                    .decryption_verification_complete
                    .as_ref()
                    .is_some_and(|result| result.dishonest_parties.is_empty())
            } else {
                recovery.verified_dealer_ids.as_ref() == Some(&expected)
            }
        })
        .await?;
        let events = self
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?;
        assert!(
            events.iter().all(|event| !matches!(
                event.get_data(),
                InterfoldEventData::ProofVerificationFailed(_)
                    | InterfoldEventData::SignedProofFailed(_)
                    | InterfoldEventData::ProofFailureAccusation(_)
            )),
            "unauthenticated input caused fault attribution"
        );
        Ok(())
    }
}

#[actix::test]
async fn forged_threshold_share_cannot_reserve_dealer_slot() -> Result<()> {
    for forgery in [
        "no proofs",
        "wrong signer",
        "unrecoverable",
        "share bytes",
        "proof bytes",
        "recipient",
        "dealer",
        "E3",
    ] {
        let (h, actor) = AdmissionHarness::new(false).await?;
        let genuine = authenticated_share(&h.e3_id, 1);
        let mut forged = genuine.clone();
        match forgery {
            "no proofs" => {
                forged.signed_c2a_proof = None;
                forged.signed_c2b_proof = None;
                forged.signed_c3a_proofs.clear();
                forged.signed_c3b_proofs.clear();
            }
            "wrong signer" => forged = forged.sign(&dealer_signer(2))?,
            "unrecoverable" => forged.signature = ArcBytes::from_bytes(&[0; 65]),
            "share bytes" => Arc::make_mut(&mut forged.share).pk_share = ArcBytes::from_bytes(&[9]),
            "proof bytes" => {
                forged.signed_c3a_proofs[0].payload.proof.data = ArcBytes::from_bytes(&[9])
            }
            "recipient" => {
                forged.target_party_id = 2;
                forged = forged.sign(&dealer_signer(1))?;
                forged.target_party_id = 0;
            }
            "dealer" => {
                Arc::make_mut(&mut forged.share).party_id = 2;
                forged = forged.sign(&dealer_signer(1))?;
                Arc::make_mut(&mut forged.share).party_id = 1;
            }
            "E3" => {
                forged.e3_id = E3id::new("92", 1);
                forged = forged.sign(&dealer_signer(1))?;
                forged.e3_id = h.e3_id.clone();
            }
            _ => unreachable!(),
        }
        let actor = h.start(actor).await?;
        actor
            .send(keyshare_event(forged, 0, EventSource::Net))
            .await?;
        assert!(
            h.recovery
                .read()
                .await?
                .unwrap()
                .threshold_share_refs
                .is_empty(),
            "{forgery} reserved a slot"
        );
        h.bus.publish_without_context(genuine.clone())?;
        h.bus
            .publish_without_context(authenticated_share(&h.e3_id, 2))?;
        h.verify_collected_shares(&[1, 2]).await?;
        let recovery = h.recovery.read().await?.unwrap();
        let saved = ThresholdKeyshareRecoveryPayloads::load(h.payloads.clone(), &recovery).await?;
        assert_eq!(**saved.share(1).unwrap(), genuine);
        actor.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn forged_c4_share_cannot_reserve_dealer_slot() -> Result<()> {
    for forgery in [
        "no proofs",
        "wrong signer",
        "unrecoverable",
        "proof bytes",
        "node",
    ] {
        let (h, mut actor) = AdmissionHarness::new(false).await?;
        actor.state.try_mutate_without_context(|mut state| {
            state.state = KeyshareState::ReadyForDecryption(ready_for_c4_test());
            state.honest_parties = Some(BTreeSet::from([0, 1]));
            Ok(state)
        })?;
        let event = peer_c4_event(&h.e3_id, 0);
        let InterfoldEventData::DecryptionKeyShared(genuine) = event.into_data() else {
            unreachable!()
        };
        let mut forged = genuine.clone();
        match forgery {
            "no proofs" => forged.signed_e_sm_decryption_proofs.clear(),
            "wrong signer" => forged = forged.sign(&dealer_signer(2))?,
            "unrecoverable" => forged.signature = ArcBytes::from_bytes(&[0; 65]),
            "proof bytes" => {
                forged.signed_sk_decryption_proof.payload.proof.data = ArcBytes::from_bytes(&[9])
            }
            "node" => forged.node = dealer_signer(2).address().to_string(),
            _ => unreachable!(),
        }
        let actor = h.start(actor).await?;
        actor
            .send(keyshare_event(forged, 0, EventSource::Net))
            .await?;
        assert!(
            h.recovery
                .read()
                .await?
                .unwrap()
                .decryption_key_shares
                .is_empty(),
            "{forgery} reserved a C4 slot"
        );
        h.bus.publish_without_context(genuine.clone())?;
        let event = h
            .event(|data| matches!(data, InterfoldEventData::ShareVerificationDispatched(_)))
            .await?;
        let InterfoldEventData::ShareVerificationDispatched(dispatch) = event.into_data() else {
            unreachable!()
        };
        assert_eq!(dispatch.decryption_proofs.len(), 1);
        assert_eq!(
            dispatch.decryption_proofs[0].signed_sk_decryption_proof,
            genuine.signed_sk_decryption_proof
        );
        h.verify_collected_shares(&[1]).await?;
        assert_eq!(
            h.recovery.read().await?.unwrap().decryption_key_shares[&1]
                .clone()
                .into_inner(),
            genuine
        );
        actor.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn empty_precheck_batch_completes_and_accepts_growth_after_restart() -> Result<()> {
    for restart in [false, true] {
        let (h, actor) = AdmissionHarness::new(true).await?;
        let mut actor = h.start(actor).await?;
        // This dealer authenticates an incomplete contribution. It can occupy only its own slot.
        h.bus.publish_without_context(peer_share(&h.e3_id, 1))?;
        let outcome = wait_for_record(&h.recovery, |recovery| {
            recovery.share_verification_complete.is_some()
        })
        .await?;
        assert_eq!(
            outcome
                .share_verification_complete
                .unwrap()
                .dishonest_parties,
            BTreeSet::from([1])
        );
        assert_eq!(outcome.verified_dealer_ids, Some(BTreeSet::new()));
        if restart {
            actor = h.restart(actor).await?;
        }
        h.bus
            .publish_without_context(authenticated_share(&h.e3_id, 2))?;
        h.verify_collected_shares(&[2]).await?;
        assert_eq!(
            h.recovery
                .read()
                .await?
                .unwrap()
                .collected_threshold_share_ids,
            Some(BTreeSet::from([1, 2]))
        );
        actor.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn restarted_micro_batch_survives_its_original_deadline() -> Result<()> {
    use e3_trbfv::{
        calculate_decryption_key::calculate_decryption_key, shares::BfvEncryptedShares,
    };
    use fhe::bfv::PublicKey;
    use fhe_traits::DeserializeParametrized;
    use ndarray::Array2;
    use std::time::Duration;

    // Cover both a node waiting for its roster and one that has finished local DKG.
    for finish_dkg in [true, false] {
        let (h, mut actor) =
            AdmissionHarness::with_committee(true, CiphernodesCommitteeSize::Micro).await?;
        let params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
        let key = generate_bfv_keypair(&BfvPreset::InsecureDkg512, &h.cipher)?;
        let pk = PublicKey::from_bytes(&key.pk_bfv, &params)?;
        let num_moduli = BfvPreset::InsecureThreshold512.metadata().num_moduli;
        let rows = vec![vec![1u64; params.degree()]; num_moduli];
        let own_rows = SensitiveBytes::new(bincode::serialize(&rows)?, &h.cipher)?;
        let secret =
            SharedSecret::new(vec![Array2::from_elem((1, params.degree()), 1); num_moduli]);
        let (encrypted, _) = BfvEncryptedShares::encrypt_all_extended_for_share_indices(
            &secret,
            &[pk],
            &[0],
            &params,
            &mut rand_core::UnwrapErr(rand::rngs::OsRng),
            None,
        )?;
        let share = |party| -> Result<ThresholdShareCreated> {
            let mut event = authenticated_share(&h.e3_id, party);
            let payload = Arc::make_mut(&mut event.share);
            payload.sk_sss = encrypted.clone();
            payload.esi_sss = vec![encrypted.clone()];
            event.sign(&dealer_signer(party))
        };
        let deadline = crate::domain::timeout_policy::now_unix_secs() + 12;
        actor.state.try_mutate_without_context(|mut state| {
            state.dkg_deadline_unix_secs = Some(deadline);
            state.dkg_window_secs = Some(60);
            let KeyshareState::AggregatingDecryptionKey(current) = &mut state.state else {
                unreachable!()
            };
            current.sk_bfv = key.sk_bfv;
            current.own_sk_share_raw = own_rows.clone();
            current.own_esi_shares_raw = vec![own_rows];
            current.signed_pk_generation_proof =
                Some(signed_proof(&h.e3_id, 0, ProofType::C1PkGeneration));
            Ok(state)
        })?;
        let actor = h.start(actor).await?;
        for party in 1..=3 {
            h.bus.publish_without_context(share(party)?)?;
        }
        h.bus.publish_without_context(peer_share(&h.e3_id, 4))?;
        h.verify_collected_shares(&[1, 2, 3]).await?;
        let saved = h.recovery.read().await?.unwrap();
        assert_eq!(
            saved.share_verification_complete.unwrap().dishonest_parties,
            BTreeSet::from([4])
        );
        assert!(
            saved.dkg_ready.is_none(),
            "three external dealers are below H - 1"
        );

        let actor = h.restart(actor).await?;
        assert_eq!(
            h.state.read().await?.unwrap().dkg_deadline_unix_secs,
            Some(deadline)
        );
        h.history.send(ResetHistory).await?;
        h.bus.publish_without_context(share(5)?)?;
        h.verify_collected_shares(&[1, 2, 3, 5]).await?;
        let ready = wait_for_record(&h.recovery, |recovery| recovery.dkg_ready.is_some())
            .await?
            .dkg_ready
            .unwrap();
        assert_eq!(
            ready
                .dealers
                .iter()
                .map(|dealer| dealer.party_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1, 2, 3, 5])
        );

        if finish_dkg {
            actor
                .send(keyshare_event(
                    AggregatorChanged {
                        e3_id: h.e3_id.clone(),
                        is_aggregator: false,
                        active_party_id: Some(1),
                    },
                    101,
                    EventSource::Local,
                ))
                .await?;
            for (seq, kind) in [
                (102, DkgCoordinationKind::Ready),
                (103, DkgCoordinationKind::Roster),
            ] {
                let message = DkgCoordination::sign(
                    h.e3_id.clone(),
                    Address::ZERO,
                    1,
                    kind,
                    ready.dealers.clone(),
                    &dealer_signer(1),
                )?;
                actor
                    .send(keyshare_event(message, seq, EventSource::Net))
                    .await?;
            }
            let calculation = h.event(|data| matches!(data,
                InterfoldEventData::ComputeRequest(request)
                    if matches!(request.request, ComputeRequestKind::TrBFV(TrBFVRequest::CalculateDecryptionKey(_)))
            )).await?;
            // Starting the calculation fixes the roster, also for a later restart.
            wait_for_record(&h.state, |state| state.dkg_roster_fixed).await?;
            let InterfoldEventData::ComputeRequest(request) = calculation.into_data() else {
                unreachable!()
            };
            let ComputeRequestKind::TrBFV(TrBFVRequest::CalculateDecryptionKey(input)) =
                request.request
            else {
                unreachable!()
            };
            let output = calculate_decryption_key(&h.cipher, input)?;
            actor
                .send(keyshare_event(
                    ComputeResponse::trbfv(
                        TrBFVResponse::CalculateDecryptionKey(output),
                        request.correlation_id,
                        h.e3_id.clone(),
                    ),
                    104,
                    EventSource::Local,
                ))
                .await?;
            wait_for_keyshare_state(&h.state, |state| {
                matches!(state, KeyshareState::ReadyForDecryption(_))
            })
            .await?;
            h.history.send(ResetHistory).await?;
            for party in [1, 2, 3, 5] {
                h.bus.publish_without_context(
                    DecryptionKeyShared {
                        signature: Default::default(),
                        e3_id: h.e3_id.clone(),
                        party_id: party,
                        node: dealer_signer(party).address().to_string(),
                        signed_sk_decryption_proof: signed_proof(
                            &h.e3_id,
                            party,
                            ProofType::C4aSkShareDecryption,
                        ),
                        signed_e_sm_decryption_proofs: vec![signed_proof(
                            &h.e3_id,
                            party,
                            ProofType::C4bESmShareDecryption,
                        )],
                        external: true,
                    }
                    .sign(&dealer_signer(party))?,
                )?;
            }
            h.verify_collected_shares(&[1, 2, 3, 5]).await?;
            wait_for_record(&h.state, |state| state.keyshare_published).await?;
            h.event(|data| matches!(data, InterfoldEventData::KeyshareCreated(_)))
                .await?;
        }

        actix::clock::sleep(Duration::from_secs(
            deadline.saturating_sub(crate::domain::timeout_policy::now_unix_secs()) + 2,
        ))
        .await;
        let state = h.state.read().await?.unwrap();
        assert!(
            if finish_dkg {
                matches!(state.state, KeyshareState::ReadyForDecryption(_))
                    && state.keyshare_published
            } else {
                matches!(state.state, KeyshareState::AggregatingDecryptionKey(_))
            },
            "the original collection deadline changed the DKG outcome: {:?}",
            state.state
        );
        let recovery = h.recovery.read().await?.unwrap();
        assert_eq!(
            recovery.verified_dealer_ids,
            Some(BTreeSet::from([1, 2, 3, 5]))
        );
        assert_eq!(
            recovery.collected_threshold_share_ids,
            (!finish_dkg).then(|| BTreeSet::from([1, 2, 3, 4, 5])),
            "a retired collector must not restore a completed verification batch"
        );
        let events = h.history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert!(events.iter().all(|event| !matches!(
            event.get_data(),
            InterfoldEventData::ThresholdShareCollectionFailed(_) | InterfoldEventData::E3Failed(_)
        )));
        actor.send(Die).await?;
    }
    Ok(())
}
