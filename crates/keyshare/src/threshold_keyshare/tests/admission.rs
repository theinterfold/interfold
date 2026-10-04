// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{
    CommitmentConsistencyCheckComplete, Committee, Die, EventBusBarrier, PartyVerificationResult,
    VerifyShareDecryptionProofsResponse, VerifyShareProofsResponse, ZkRequest, ZkResponse,
};
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
    cipher: Arc<Cipher>,
}

impl AdmissionHarness {
    async fn new(cutoff_passed: bool) -> Result<(Self, ThresholdKeyshare)> {
        let e3_id = E3id::new("91", 1);
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
            recovery.ciphernode_selected = Some(TypedEvent::new(selection(&e3_id), test_ec(0)));
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
            cipher,
        };
        let actor = harness.actor(
            state,
            recovery,
            ThresholdKeyshareRecoveryPayloads::new(harness.payloads.clone()),
        );
        ShareVerificationActor::setup(
            &harness.bus,
            HashMap::from([(e3_id, Committee::new(selection(&harness.e3_id).committee))]),
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
