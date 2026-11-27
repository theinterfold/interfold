// SPDX-License-Identifier: LGPL-3.0-only

//! Definition-level collection/flush tests deliberately enter below disabled runtime admission.
//! Synthetic proof bytes exercise routing, not cryptographic acceptance.

use super::*;
use actix::{Actor, ActorContext, Handler, Message};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_data::RepositoriesFactory;
use e3_event_system::{test_support::EventFixture, EventSystem};
use e3_events::*;
use e3_fhe_params::BfvProfile;
use e3_sync::SyncRepositoryFactory;
use e3_trbfv::synchronized::{PrfKey, SealedPrfKeys};
use e3_utils::ArcBytes;
use e3_zk_config::{synchronized::Configs, CircuitName, DkgInputType};
use fhe::bfv::{PublicKey, SecretKey};
use fhe_traits::Serialize as _;

fn ec(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(data.into()).sequence(1)
}

fn request(id: E3id, profile: BfvProfile) -> Result<E3Requested> {
    let size = CiphernodesCommitteeSize::Minimum;
    let params = e3_fhe_params::BfvParamSet::from(profile.threshold_preset()).build();
    Ok(E3Requested {
        e3_id: id,
        threshold_m: size.values().threshold,
        threshold_n: size.values().n,
        params_profile: profile,
        crypto_config_id: profile.crypto_config_id(size)?.into(),
        params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&params)),
        ..Default::default()
    })
}

#[test]
fn synchronized_dealer_initial_collection_excludes_ss_authority() -> Result<()> {
    let sync_id = E3id::new("2459", 1);
    let ss_id = E3id::new("2460", 1);
    let sync_meta = E3Meta::from(&request(sync_id.clone(), BfvProfile::SyncDecInsecure64)?);
    let ss_meta = E3Meta::from(&request(ss_id.clone(), BfvProfile::SsInsecure64)?);
    sync_meta.validate_identity()?;
    ss_meta.validate_identity()?;
    let committee = Committee::new(vec![Address::repeat_byte(1).to_string()]);
    let collection = DealerCollection::new(
        HashMap::from([
            (sync_id.clone(), sync_meta.clone()),
            (ss_id.clone(), ss_meta),
        ]),
        HashMap::from([
            (sync_id.clone(), committee.clone()),
            (ss_id.clone(), committee.clone()),
        ]),
        HashSet::from([sync_id.clone(), ss_id]),
        HashMap::new(),
        DealerRecovery::default(),
    );
    assert_eq!(
        collection.metadata,
        HashMap::from([(sync_id.clone(), sync_meta)])
    );
    assert_eq!(
        collection.committees,
        HashMap::from([(sync_id.clone(), committee)])
    );
    assert!(collection.ended.contains(&sync_id));
    Ok(())
}

#[derive(Message)]
#[rtype(result = "(bool, bool)")]
struct InspectAuthority(E3id);

impl Handler<InspectAuthority> for NodeProofAggregator {
    type Result = actix::MessageResult<InspectAuthority>;
    fn handle(&mut self, msg: InspectAuthority, _: &mut Context<Self>) -> Self::Result {
        actix::MessageResult((
            self.dealer.metadata.contains_key(&msg.0),
            self.dealer.committees.contains_key(&msg.0),
        ))
    }
}

#[actix::test]
async fn synchronized_dealer_live_routing_does_not_retain_ss_authority() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, _, _) = fixture(&bus).await?;
    actor.dealer = DealerCollection::default();
    let addr = actor.start();
    for (id, profile, retained) in [
        (E3id::new("2460", 1), BfvProfile::SsInsecure64, false),
        (E3id::new("2459", 1), BfvProfile::SyncDecInsecure64, true),
    ] {
        for data in [
            InterfoldEventData::from(request(id.clone(), profile)?),
            CommitteeFinalized {
                e3_id: id.clone(),
                committee: vec![Address::repeat_byte(1).to_string()],
                scores: vec![],
                chain_id: 1,
            }
            .into(),
        ] {
            addr.send(
                InterfoldEvent::new_with_timestamp(data, None, 1, None, EventSource::Evm)
                    .into_sequenced(1),
            )
            .await?;
        }
        assert_eq!(
            addr.send(InspectAuthority(id)).await?,
            (retained, retained),
            "{profile}"
        );
    }
    Ok(())
}

async fn fixture(
    bus: &BusHandle,
) -> Result<(NodeProofAggregator, ThresholdSharePending, DealerPlan)> {
    let profile = BfvProfile::SyncDecInsecure64;
    let size = CiphernodesCommitteeSize::Minimum;
    let signer: alloy::signers::local::PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let mut members = vec![
        Address::repeat_byte(1),
        Address::repeat_byte(2),
        signer.address(),
    ];
    members.sort();
    let owner = members
        .iter()
        .position(|member| member == &signer.address())
        .unwrap() as u32;
    let context = SynchronizedProofContext {
        party_id: owner,
        setup: e3_committee_hash::DkgSetupContext {
            interfold_address: Address::repeat_byte(3),
            committee_hash: e3_committee_hash::hash_committee_addresses(&members),
            crypto_config_id: profile.crypto_config_id(size)?,
        },
    };
    let id = E3id::new("2459", 1);
    let config = Configs::for_profile(profile, size)?;
    let binding = crate::synchronized::request_binding(&config, &context, &id)?;
    let cipher = Cipher::from_password("dealer-test").await?;
    let keys = (0..size.values().n)
        .map(|_| PrfKey::from_bytes(profile, [0; 32]))
        .collect::<Result<Vec<_>>>()?;
    let sensitive = || SensitiveBytes::from_encrypted(&[]);
    let mut rng = rand::rng();
    let transport_keys: Vec<_> = members
        .iter()
        .map(|_| {
            let secret = SecretKey::random(&config.transport, &mut rng);
            ArcBytes::from_bytes(&PublicKey::new(&secret, &mut rng).to_bytes())
        })
        .collect();
    let c3 = (0..size.values().n)
        .filter(|&party| party != owner as usize)
        .flat_map(|party| (0..config.threshold.moduli().len()).map(move |row| (party, row)))
        .map(|(party, row)| ShareEncryptionProofRequest {
            share_row_raw: sensitive(),
            ciphertext_raw: ArcBytes::from_bytes(&[]),
            recipient_pk_raw: transport_keys[party].clone(),
            u_rns_raw: sensitive(),
            e0_rns_raw: sensitive(),
            e1_rns_raw: sensitive(),
            dkg_input_type: DkgInputType::SecretKey,
            params_profile: profile,
            committee_size: size,
            recipient_party_id: party,
            row_index: row,
            esi_index: 0,
        })
        .collect();
    let input = ThresholdSharePending {
        e3_id: id.clone(),
        full_share: std::sync::Arc::new(ThresholdShare {
            party_id: owner.into(),
            pk_share: ArcBytes::from_bytes(&[]),
            sk_sss: Default::default(),
            esi_sss: vec![],
        }),
        proof_request: PkGenerationProofRequest {
            pk0_share: ArcBytes::from_bytes(&[]),
            sk: sensitive(),
            eek: sensitive(),
            e_sm: None,
            params_profile: profile,
            committee_size: size,
            synchronized: Some(context.clone()),
        },
        sk_share_computation_request: ShareComputationProofRequest {
            secret_raw: sensitive(),
            secret_sss_raw: sensitive(),
            dkg_input_type: DkgInputType::SecretKey,
            params_profile: profile,
            committee_size: size,
            synchronized: Some(SynchronizedShareComputation {
                context: context.clone(),
                outgoing_keys: SealedPrfKeys::seal(profile, binding, owner, &keys, &cipher)?,
            }),
        },
        e_sm_share_computation_request: None,
        sk_share_encryption_requests: c3,
        e_sm_share_encryption_requests: vec![],
        recipient_party_ids: vec![0, 1, 2],
        own_sk_share_raw: sensitive(),
        own_esi_shares_raw: vec![],
    };
    let plan = DealerPlan::from_pending(&input)?;
    let mut actor = NodeProofAggregator::new(bus, signer, HashMap::new(), HashMap::new(), true);
    actor.dealer = DealerCollection::new(
        HashMap::from([(
            id.clone(),
            E3Meta {
                threshold_m: size.values().threshold,
                threshold_n: size.values().n,
                seed: Seed([0; 32]),
                params_profile: profile,
                crypto_config_id: context.setup.crypto_config_id.into(),
                params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&config.threshold)),
                error_size: ArcBytes::from_bytes(&[]),
            },
        )]),
        HashMap::from([(
            id,
            Committee::new(members.iter().map(ToString::to_string).collect()),
        )]),
        HashSet::new(),
        HashMap::from([(1, context.setup.interfold_address)]),
        DealerRecovery::default(),
    );
    actor.recovery_repositories = Some(Repositories::in_mem());
    Ok((actor, input, plan))
}

fn proof(plan: &DealerPlan, id: &E3id, circuit: CircuitName) -> Proof {
    let config = Configs::for_profile(plan.profile, plan.committee).unwrap();
    let mut fields = vec![
        [0; 32];
        config.public_inputs(circuit).unwrap()
            + config.public_outputs(circuit).unwrap()
    ];
    if circuit != CircuitName::ShareEncryption {
        let binding = crate::synchronized::request_binding(&config, &plan.context, id).unwrap();
        fields[0][16..].copy_from_slice(&binding[0].to_be_bytes());
        fields[1][16..].copy_from_slice(&binding[1].to_be_bytes());
        fields[2][28..].copy_from_slice(&plan.context.party_id.to_be_bytes());
    }
    if circuit == CircuitName::NodeFold {
        let first_key = 6 + plan.committee.values().n * config.threshold.moduli().len();
        for (field, key) in fields[first_key..].iter_mut().zip(&plan.recipient_keys) {
            *field = key.unwrap_or_default();
        }
    }
    Proof::new(
        circuit,
        ArcBytes::from_bytes(&[7]),
        ArcBytes::from_bytes(&fields.concat()),
    )
}

fn leaves(plan: &DealerPlan, id: &E3id) -> Vec<DKGInnerProofReady> {
    let config = plan.config().unwrap();
    plan.circuits
        .iter()
        .enumerate()
        .map(|(index, &circuit)| {
            let seq = index + 1;
            let mut proof = proof(plan, id, circuit);
            if circuit == CircuitName::ShareEncryption {
                let (party, _) = plan.c3_slot(&config, seq).unwrap();
                let mut public = proof.public_signals.to_vec();
                public[..32].copy_from_slice(&plan.recipient_keys[party].unwrap());
                proof.public_signals = ArcBytes::from_bytes(&public);
            }
            DKGInnerProofReady {
                e3_id: id.clone(),
                party_id: plan.context.party_id.into(),
                seq,
                proof,
            }
        })
        .collect()
}

fn change_public_field(leaf: &mut DKGInnerProofReady, field: usize) {
    let mut bytes = leaf.proof.public_signals.to_vec();
    bytes[field * 32 + 31] ^= 1;
    leaf.proof.public_signals = ArcBytes::from_bytes(&bytes);
}

fn collect(
    actor: &mut NodeProofAggregator,
    input: &ThresholdSharePending,
    plan: &DealerPlan,
) -> Result<()> {
    let leaves = leaves(plan, &input.e3_id);
    // Prefix before plan and tail after plan exercise both recovery orders.
    actor.accept_dealer_input(&leaves[0].clone().into(), &ec(leaves[0].clone()))?;
    actor.accept_dealer_input(&input.clone().into(), &ec(input.clone()))?;
    for leaf in leaves.into_iter().skip(1) {
        actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf))?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_c3_stays_provisional_until_plan_and_coherent_sharing() -> Result<()> {
    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [2, 0, 1]] {
        let EventFixture { bus, .. } = EventFixture::new()?;
        let (mut actor, input, plan) = fixture(&bus).await?;
        let id = input.e3_id.clone();
        let valid = leaves(&plan, &id);
        let mut wrong = valid[2].clone();
        let mut public = wrong.proof.public_signals.to_vec();
        public[63] = 1; // C3 message, while the corresponding C2 slot is zero.
        wrong.proof.public_signals = ArcBytes::from_bytes(&public);
        let events = [
            InterfoldEventData::from(wrong.clone()),
            input.clone().into(),
            valid[1].clone().into(),
        ];
        for index in order {
            actor.accept_dealer_input(&events[index], &ec(events[index].clone()))?;
            if index == 0 {
                // Both candidates arrive while the slot is still provisional. The correct
                // candidate is journaled only once; no redelivery will rescue a lost slot.
                actor.accept_dealer_input(&valid[2].clone().into(), &ec(valid[2].clone()))?;
                assert!(!actor.dealer.inner_proofs().contains_key(&id));
            }
        }
        assert!(!actor.dealer.inner_proofs().contains_key(&id));
        actor.accept_dealer_input(&valid[0].clone().into(), &ec(valid[0].clone()))?;
        for leaf in valid.iter().filter(|leaf| leaf.seq != 3) {
            actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf.clone()))?;
        }
        assert!(plan
            .request(&id, &actor.dealer.records[&id].proofs)?
            .is_some());
        assert_eq!(actor.dealer.inner_proofs()[&id][&3], valid[2].proof);
        assert!(actor
            .accept_dealer_input(&wrong.clone().into(), &ec(wrong))
            .is_err());
        let mut reproved = valid[2].clone();
        reproved.proof.data = ArcBytes::from_bytes(&[99]);
        actor.accept_dealer_input(&reproved.clone().into(), &ec(reproved))?;
        assert_eq!(actor.dealer.records[&id].proofs[&3], valid[2]);
    }
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_uses_controller_independent_of_both_local_requests() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, canonical, _) = fixture(&bus).await?;
    let mut wrong = canonical.clone();
    wrong
        .proof_request
        .synchronized
        .as_mut()
        .unwrap()
        .setup
        .interfold_address = Address::repeat_byte(4);
    wrong
        .sk_share_computation_request
        .synchronized
        .as_mut()
        .unwrap()
        .context = wrong.proof_request.synchronized.clone().unwrap();
    assert!(actor
        .accept_dealer_input(&wrong.clone().into(), &ec(wrong))
        .is_err());
    assert!(actor.dealer.records.is_empty());
    assert!(actor.accept_dealer_input(&canonical.clone().into(), &ec(canonical))?);
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_keeps_inconsistent_secret_pair_repairable_before_dispatch(
) -> Result<()> {
    for bad_slot in [0, 1] {
        let EventFixture { bus, .. } = EventFixture::new()?;
        let (mut actor, input, plan) = fixture(&bus).await?;
        let id = input.e3_id.clone();
        let valid = leaves(&plan, &id);
        actor.accept_dealer_input(&input.clone().into(), &ec(input))?;
        let mut candidates = valid.clone();
        change_public_field(&mut candidates[bad_slot], 3);
        if bad_slot == 1 {
            // A C2 candidate that disagrees on the secret must not discard an earlier valid C3.
            let (party, row) = plan.c3_slot(&plan.config()?, 3)?;
            let l = plan.config()?.threshold.moduli().len();
            change_public_field(&mut candidates[1], 4 + party * l + row);
        }
        for leaf in candidates {
            actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf))?;
        }
        actor.dealer.effects = true;
        actor.publish_dealer_work(&id);
        assert!(!actor.dealer.in_flight.contains_key(&id));
        let corrected = valid[bad_slot].clone();
        assert!(actor.accept_dealer_input(&corrected.clone().into(), &ec(corrected))?);
        actor.publish_dealer_work(&id);
        assert!(actor.dealer.in_flight.contains_key(&id));
        assert_eq!(actor.dealer.records[&id].proofs[&1], valid[0]);
        assert_eq!(actor.dealer.records[&id].proofs[&2], valid[1]);
        assert_eq!(actor.dealer.records[&id].proofs[&3], valid[2]);
    }
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_keeps_c2_repairable_until_all_c3_match() -> Result<()> {
    for c2_first in [false, true] {
        let EventFixture { bus, .. } = EventFixture::new()?;
        let (mut actor, input, plan) = fixture(&bus).await?;
        let id = input.e3_id.clone();
        let mut valid = leaves(&plan, &id);
        valid[1].proof.data = ArcBytes::from_bytes(&[87]);
        let config = plan.config()?;
        let (party, row) = plan.c3_slot(&config, 3)?;
        let mut wrong = valid[1].clone();
        change_public_field(
            &mut wrong,
            4 + party * config.threshold.moduli().len() + row,
        );
        actor.accept_dealer_input(&input.clone().into(), &ec(input))?;
        for leaf in [&valid[0], &wrong] {
            actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf.clone()))?;
        }
        if c2_first {
            actor.accept_dealer_input(&valid[1].clone().into(), &ec(valid[1].clone()))?;
            let mut reproved = valid[1].clone();
            reproved.proof.data = ArcBytes::from_bytes(&[88]);
            actor.accept_dealer_input(&reproved.clone().into(), &ec(reproved))?;
        }
        for leaf in &valid[2..valid.len() - 1] {
            actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf.clone()))?;
        }
        actor.dealer.effects = true;
        actor.publish_dealer_work(&id);
        assert!(!actor.dealer.in_flight.contains_key(&id));
        assert!(!actor.dealer.inner_proofs().contains_key(&id));
        let last = valid.last().unwrap().clone();
        actor.accept_dealer_input(&last.clone().into(), &ec(last))?;
        if !c2_first {
            actor.publish_dealer_work(&id);
            assert!(!actor.dealer.in_flight.contains_key(&id));
            actor.accept_dealer_input(&valid[1].clone().into(), &ec(valid[1].clone()))?;
        }
        actor.publish_dealer_work(&id);
        assert!(actor.dealer.in_flight.contains_key(&id));
        assert_eq!(actor.dealer.records[&id].proofs[&2], valid[1]);
        assert_eq!(actor.dealer.records[&id].proofs[&3], valid[2]);
        assert!(actor
            .accept_dealer_input(&wrong.clone().into(), &ec(wrong))
            .is_err());
    }
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_requires_the_native_recipient_key_in_every_crt_row() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    let id = input.e3_id.clone();
    let valid = leaves(&plan, &id);
    actor.accept_dealer_input(&input.clone().into(), &ec(input))?;
    for leaf in &valid[..3] {
        actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf.clone()))?;
    }
    let mut wrong = valid[3].clone();
    let l = plan.config()?.threshold.moduli().len();
    let mut public = wrong.proof.public_signals.to_vec();
    public[..32].copy_from_slice(&valid[2 + l].proof.public_signals[..32]);
    wrong.proof.public_signals = ArcBytes::from_bytes(&public);
    assert!(actor
        .accept_dealer_input(&wrong.clone().into(), &ec(wrong))
        .is_err());
    for leaf in &valid[3..] {
        actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf.clone()))?;
    }
    assert!(plan
        .request(&id, &actor.dealer.records[&id].proofs)?
        .is_some());
    assert_eq!(actor.dealer.records[&id].proofs[&4], valid[3]);
    Ok(())
}

#[test]
fn synchronized_dealer_restores_alternates_from_the_disk_prefix() -> Result<()> {
    let aggregate = AggregateId::new(1);
    for (saved_plan, saved_c2_alternate) in [(false, false), (true, false), (true, true)] {
        let root = tempfile::tempdir()?;
        let system = |enable_chain: bool| {
            EventSystem::persisted(root.path().join("log"), root.path().join("sled"))
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(
                    enable_chain
                        .then_some((aggregate, Duration::ZERO))
                        .into_iter()
                        .collect(),
                ))
        };
        let (native, valid) = actix::System::new().block_on(async {
            let system = system(true);
            let bus = system.handle()?.enable("dealer-prefix");
            let store = system.store()?;
            let repositories = store.repositories();
            e3_sync::preflight_schema_version(
                &repositories,
                &system.aggregate_config(),
                &system.eventstore_reader()?.seq(),
            )
            .await?;
            let (mut actor, input, plan) = fixture(&bus).await?;
            let mut valid = leaves(&plan, &input.e3_id);
            valid[1].proof.data = ArcBytes::from_bytes(&[87]);
            valid[2].proof.data = ArcBytes::from_bytes(&[89]);
            let mut wrong = valid[2].clone();
            change_public_field(&mut wrong, 1);
            let mut events = Vec::new();
            if saved_plan {
                events.push(input.clone().into());
            }
            if saved_c2_alternate {
                let config = plan.config()?;
                // No C3 for this incorrect C2 at sequence 4 is ever emitted.
                let (party, row) = plan.c3_slot(&config, 4)?;
                let mut wrong_c2 = valid[1].clone();
                change_public_field(
                    &mut wrong_c2,
                    4 + party * config.threshold.moduli().len() + row,
                );
                events.extend([InterfoldEventData::from(wrong_c2), valid[1].clone().into()]);
            }
            events.extend([InterfoldEventData::from(wrong), valid[2].clone().into()]);
            let last_seq = events.len() as u64;
            for data in events {
                bus.publish_without_context(data.clone())?;
                actor.accept_dealer_input(&data, &ec(data.clone()))?;
            }
            bus.flush_event_pipeline().await?;
            repository(&repositories, &input.e3_id)
                .write_sync(&actor.dealer.records[&input.e3_id])
                .await?;
            system.buffer()?.send(FlushPendingSnapshots).await??;
            let cursor = repositories.aggregate_seq(aggregate).read().await?;
            assert!(cursor.is_some_and(|seq| seq >= last_seq));
            store.shutdown().await?;
            Ok::<_, anyhow::Error>((input, valid))
        })?;
        e3_data::SledDb::close_connection(&root.path().join("sled"));

        // Neither early C3 nor any previously journaled C2 is redelivered.
        actix::System::new().block_on(async {
            let reopened = system(true);
            let bus = reopened.handle()?.enable("dealer-prefix-restored");
            let (mut actor, _, _) = fixture(&bus).await?;
            let id = &native.e3_id;
            let store = reopened.store()?;
            let record = repository(&store.repositories(), id).read().await?.unwrap();
            let recovery = DealerRecovery {
                records: HashMap::from([(id.clone(), record)]),
                ..Default::default()
            };
            let reader = reopened.eventstore_reader()?.seq();
            if saved_plan {
                let disabled = system(false);
                let aggregates = disabled
                    .aggregate_config()
                    .indexed_ids()
                    .into_iter()
                    .map(AggregateId::new)
                    .collect::<Vec<_>>();
                let error = recovery
                    .clone()
                    .restore(
                        &actor.dealer.metadata,
                        &actor.dealer.controllers,
                        &disabled.eventstore_reader()?.seq(),
                        &aggregates,
                    )
                    .await
                    .expect_err("a chain with saved dealer work cannot lose its journal");
                assert!(error
                    .to_string()
                    .contains("no configured journal aggregate"));
                let mut wrong = recovery.clone();
                wrong
                    .records
                    .get_mut(id)
                    .unwrap()
                    .plan
                    .as_mut()
                    .unwrap()
                    .context
                    .setup
                    .interfold_address = Address::repeat_byte(4);
                let error = wrong
                    .restore(
                        &actor.dealer.metadata,
                        &actor.dealer.controllers,
                        &reader,
                        &[aggregate],
                    )
                    .await
                    .expect_err("a saved plan cannot authenticate its own controller");
                assert!(error
                    .to_string()
                    .contains("configured Interfold controller"));
            }
            let restored = recovery
                .restore(
                    &actor.dealer.metadata,
                    &actor.dealer.controllers,
                    &reader,
                    &[aggregate],
                )
                .await?;
            actor.dealer.records = restored.records;
            actor.dealer.alternates = restored.alternates;
            if !saved_plan {
                actor.accept_dealer_input(&native.clone().into(), &ec(native.clone()))?;
            }
            for leaf in valid
                .iter()
                .filter(|leaf| leaf.seq != 3 && !(saved_c2_alternate && leaf.seq == 2))
            {
                actor.accept_dealer_input(&leaf.clone().into(), &ec(leaf.clone()))?;
            }
            let record = &actor.dealer.records[id];
            assert_eq!(record.proofs[&2], valid[1]);
            assert_eq!(record.proofs[&3], valid[2]);
            assert!(record
                .plan
                .as_ref()
                .unwrap()
                .request(id, &record.proofs)?
                .is_some());
            store.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        })?;
        e3_data::SledDb::close_connection(&root.path().join("sled"));
    }
    Ok(())
}

#[derive(Message)]
#[rtype(result = "()")]
struct ReplaceDealerBus(BusHandle);
impl Handler<ReplaceDealerBus> for NodeProofAggregator {
    type Result = ();
    fn handle(&mut self, msg: ReplaceDealerBus, _: &mut Context<Self>) {
        self.bus = msg.0;
    }
}

#[derive(Message)]
#[rtype(result = "Result<InterfoldEventData>")]
struct SaturateDealerPublication(E3id);
impl Handler<SaturateDealerPublication> for NodeProofAggregator {
    type Result = Result<InterfoldEventData>;
    fn handle(&mut self, msg: SaturateDealerPublication, ctx: &mut Context<Self>) -> Self::Result {
        for _ in 0..e3_utils::MAILBOX_LIMIT_LARGE {
            self.bus.publish_without_context(EffectsEnabled::new())?;
        }
        self.drive_dealer_publication(&msg.0, ctx);
        let expected = self.dealer.pending[&msg.0].events[0].clone();
        self.drive_dealer_publication(&msg.0, ctx);
        assert_eq!(self.dealer.pending[&msg.0].events[0], expected);
        assert_eq!(self.dealer.pending[&msg.0].failures, 1);
        assert_eq!(self.dealer.publication_retries.len(), 1);
        Ok(expected)
    }
}

#[actix::test]
async fn synchronized_dealer_saturation_preserves_correlation_and_retirement_cancels_retry(
) -> Result<()> {
    tokio::time::pause();
    for retire in [false, true] {
        let EventFixture { bus, history, .. } = EventFixture::new()?;
        let (mut actor, input, plan) = fixture(&bus).await?;
        collect(&mut actor, &input, &plan)?;
        let id = input.e3_id.clone();
        repository(actor.recovery_repositories.as_ref().unwrap(), &id)
            .write_sync(&actor.dealer.records[&id])
            .await?;
        actor.dealer.effects = true;
        let addr = actor.start();
        let expected = addr.send(SaturateDealerPublication(id.clone())).await??;
        bus.flush_event_pipeline().await?;
        if retire {
            addr.send(
                InterfoldEvent::new_with_timestamp(
                    E3StageChanged {
                        e3_id: id.clone(),
                        previous_stage: E3Stage::CommitteeFinalized,
                        new_stage: E3Stage::KeyPublished,
                    }
                    .into(),
                    None,
                    3,
                    None,
                    EventSource::Evm,
                )
                .into_sequenced(3),
            )
            .await?;
            assert_eq!(addr.send(Inspect(id.clone())).await?, (false, true, false));
        }
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        addr.send(Inspect(id)).await?;
        bus.flush_event_pipeline().await?;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert_eq!(
            events
                .iter()
                .filter(|event| event.get_data() == &expected)
                .count(),
            usize::from(!retire)
        );
        addr.send(StopDefinition).await?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_refused_publications_retry_without_new_input() -> Result<()> {
    tokio::time::pause();
    for completed in [false, true] {
        let EventFixture { bus, .. } = EventFixture::new()?;
        let (mut actor, input, plan) = fixture(&bus).await?;
        collect(&mut actor, &input, &plan)?;
        let id = input.e3_id.clone();
        actor.dealer.effects = true;
        if completed {
            actor.publish_dealer_work(&id);
            let request = actor.dealer.in_flight[&id].clone();
            let response = ComputeResponse::zk(
                ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Dealer {
                    proof: proof(&plan, &id, CircuitName::NodeFold),
                }),
                request.correlation_id,
                id.clone(),
            );
            actor.accept_dealer_input(&response.clone().into(), &ec(response))?;
        }
        bus.flush_event_pipeline().await?;
        bus.fail_event_pipeline("injected dealer publication refusal");
        let addr = actor.start();
        addr.send(FlushDefinition(id.clone())).await?;
        addr.send(Inspect(id.clone())).await?;
        // Test-only bus substitution isolates retry from fatal node-health shutdown policy.
        let EventFixture {
            bus: healthy,
            history,
            ..
        } = EventFixture::new()?;
        addr.send(ReplaceDealerBus(healthy.clone())).await?;
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        addr.send(Inspect(id)).await?;
        healthy.flush_event_pipeline().await?;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert_eq!(
            events.len(),
            if completed { 2 } else { 1 },
            "flushed publication must retry"
        );
        assert!(
            matches!(events[0].get_data(),
                InterfoldEventData::SynchronizedDealerProofReady(_) if completed
            ) || matches!(events[0].get_data(), InterfoldEventData::ComputeRequest(_) if !completed)
        );
        addr.send(StopDefinition).await?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_partial_output_retry_only_admits_the_remaining_signed_effect(
) -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    collect(&mut actor, &input, &plan)?;
    let id = input.e3_id.clone();
    actor.dealer.effects = true;
    assert!(actor.publish_dealer_work(&id));
    let request = actor.dealer.in_flight[&id].clone();
    let response = ComputeResponse::zk(
        ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Dealer {
            proof: proof(&plan, &id, CircuitName::NodeFold),
        }),
        request.correlation_id,
        id.clone(),
    );
    actor.accept_dealer_input(&response.clone().into(), &ec(response))?;
    bus.flush_event_pipeline().await?;
    for _ in 0..e3_utils::MAILBOX_LIMIT_LARGE - 1 {
        bus.publish_without_context(EffectsEnabled::new())?;
    }
    assert!(!actor.publish_dealer_work(&id));
    let pending = &actor.dealer.pending[&id];
    assert_eq!(pending.events.len(), 1);
    assert!(matches!(
        pending.events[0],
        InterfoldEventData::SynchronizedDkgProofPublished(_)
    ));
    let expected = pending.events[0].clone();
    bus.flush_event_pipeline().await?;
    for _ in 0..e3_utils::MAILBOX_LIMIT_LARGE - 1 {
        bus.publish_without_context(EffectsEnabled::new())?;
    }
    assert!(
        actor.publish_dealer_work(&id),
        "retry must not spend its single admission slot on the local output again"
    );
    bus.flush_event_pipeline().await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.get_data() == &expected)
            .count(),
        1
    );
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_plan_requires_canonical_fanout_and_no_ss_lane() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (_, input, plan) = fixture(&bus).await?;
    assert_eq!(plan.circuits.len(), 8); // N=3, threshold L=3; no self C3 or ESM.
    let mut invalid = input.clone();
    invalid.sk_share_encryption_requests.swap(0, 1);
    assert!(DealerPlan::from_pending(&invalid).is_err());
    let mut invalid = input.clone();
    invalid.sk_share_encryption_requests.pop();
    assert!(DealerPlan::from_pending(&invalid).is_err());
    let mut invalid = input.clone();
    invalid.proof_request.e_sm = Some(SensitiveBytes::from_encrypted(&[]));
    assert!(DealerPlan::from_pending(&invalid).is_err());
    let mut invalid = input;
    invalid
        .sk_share_computation_request
        .synchronized
        .as_mut()
        .unwrap()
        .context
        .party_id = 0;
    assert!(DealerPlan::from_pending(&invalid).is_err());
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_rejects_unowned_inputs_without_consuming_valid_slots() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    let leaf = leaves(&plan, &input.e3_id).remove(0);
    let peer = ec(leaf.clone()).with_source(EventSource::Net);
    assert!(actor
        .accept_dealer_input(&leaf.clone().into(), &peer)
        .is_err());
    assert!(actor.dealer.records.is_empty());
    let mut wrong = leaf.clone();
    wrong.party_id = 0;
    assert!(actor
        .accept_dealer_input(&wrong.clone().into(), &ec(wrong))
        .is_err());
    assert!(actor.dealer.records.is_empty());
    collect(&mut actor, &input, &plan)?;
    let original = actor.dealer.records[&input.e3_id].proofs[&1].clone();
    let mut reproved = original.clone();
    reproved.proof.data = ArcBytes::from_bytes(&[9]);
    actor.accept_dealer_input(&reproved.clone().into(), &ec(reproved))?;
    assert_eq!(actor.dealer.records[&input.e3_id].proofs[&1], original);
    let mut wrong_plan = plan;
    wrong_plan.context.setup.committee_hash = [8; 32].into();
    assert!(actor
        .validate_dealer_authority(&input.e3_id, &wrong_plan)
        .is_err());
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_correlates_exact_response_and_retains_retry_request() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    collect(&mut actor, &input, &plan)?;
    actor.dealer.effects = true;
    // Isolated definition dispatch below the runtime admission guard.
    actor.publish_dealer_work(&input.e3_id);
    let request = actor.dealer.in_flight[&input.e3_id].clone();
    let error = ComputeRequestError::new(
        ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("missing VK".into())),
        request.clone(),
    );
    actor.accept_dealer_input(&error.clone().into(), &ec(error))?;
    assert_eq!(actor.dealer.in_flight[&input.e3_id], request);
    let mut substituted = request.clone();
    let ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)) = &mut substituted.request else {
        panic!("expected synchronized dealer request");
    };
    work.context.party_id = 0;
    let error = ComputeRequestError::new(
        ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("different work".into())),
        substituted,
    );
    assert!(actor
        .accept_dealer_input(&error.clone().into(), &ec(error))
        .is_err());
    let output = proof(&plan, &input.e3_id, CircuitName::NodeFold);
    let response = ComputeResponse::zk(
        ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Dealer { proof: output }),
        request.correlation_id,
        input.e3_id.clone(),
    );
    let mut stale = response.clone();
    stale.correlation_id = CorrelationId::new();
    assert!(actor
        .accept_dealer_input(&stale.clone().into(), &ec(stale))
        .is_err());
    let mut wrong_e3 = response.clone();
    wrong_e3.e3_id = E3id::new("2460", 1);
    actor.accept_dealer_input(&wrong_e3.clone().into(), &ec(wrong_e3))?;
    assert!(actor.dealer.records[&input.e3_id].completed.is_none());
    assert!(actor
        .accept_dealer_input(
            &response.clone().into(),
            &ec(response.clone()).with_source(EventSource::Net)
        )
        .is_err());
    let mut wrong_plan = plan.clone();
    wrong_plan.context.party_id = 0;
    let wrong_result = ComputeResponse::zk(
        ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Dealer {
            proof: proof(&wrong_plan, &input.e3_id, CircuitName::NodeFold),
        }),
        request.correlation_id,
        input.e3_id.clone(),
    );
    assert!(actor
        .accept_dealer_input(&wrong_result.clone().into(), &ec(wrong_result))
        .is_err());
    assert_eq!(actor.dealer.in_flight[&input.e3_id], request);
    actor.accept_dealer_input(&response.clone().into(), &ec(response))?;
    assert!(actor.dealer.records[&input.e3_id].completed.is_some());
    assert!(!actor.dealer.in_flight.contains_key(&input.e3_id));
    Ok(())
}

#[derive(Message)]
#[rtype(result = "()")]
struct FlushDefinition(E3id);

#[derive(Message)]
#[rtype(result = "(bool, bool, bool)")]
struct Inspect(E3id);

#[derive(Message)]
#[rtype(result = "()")]
struct StopDefinition;

impl Handler<StopDefinition> for NodeProofAggregator {
    type Result = ();
    fn handle(&mut self, _: StopDefinition, ctx: &mut Context<Self>) {
        ctx.stop();
    }
}

impl Handler<Inspect> for NodeProofAggregator {
    type Result = actix::MessageResult<Inspect>;
    fn handle(&mut self, msg: Inspect, _: &mut Context<Self>) -> Self::Result {
        actix::MessageResult((
            self.dealer.records.contains_key(&msg.0),
            self.dealer.ended.contains(&msg.0),
            self.dealer.in_flight.contains_key(&msg.0),
        ))
    }
}

impl Handler<FlushDefinition> for NodeProofAggregator {
    type Result = ();
    fn handle(&mut self, msg: FlushDefinition, ctx: &mut Context<Self>) {
        let record = self.dealer.records[&msg.0].clone();
        self.flush_dealer_record(&msg.0, record, ctx);
    }
}

#[actix::test]
async fn synchronized_dealer_plan_prunes_unbound_early_leaves_after_disk_reopen() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    let id = input.e3_id.clone();
    let directory = tempfile::tempdir()?;
    let store = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let repositories = Repositories::new(store.clone());
    let valid = leaves(&plan, &id);
    let mut wrong = valid[0].clone();
    let mut public = wrong.proof.public_signals.to_vec();
    public[31] ^= 1;
    wrong.proof.public_signals = ArcBytes::from_bytes(&public);
    actor.accept_dealer_input(&wrong.clone().into(), &ec(wrong.clone()))?;
    actor.accept_dealer_input(&valid[1].clone().into(), &ec(valid[1].clone()))?;
    repository(&repositories, &id)
        .write_sync(&actor.dealer.records[&id])
        .await?;
    drop(actor);
    drop(repositories);
    store.shutdown().await?;
    drop(store);
    e3_data::SledDb::close_connection(directory.path());

    let reopened = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let record = repository(&Repositories::new(reopened.clone()), &id)
        .read()
        .await?
        .unwrap();
    let (mut restarted, _, _) = fixture(&bus).await?;
    record.validate(&id, &restarted.dealer.metadata[&id])?;
    restarted.dealer.records.insert(id.clone(), record);
    restarted.accept_dealer_input(&input.clone().into(), &ec(input.clone()))?;
    assert_eq!(restarted.dealer.records[&id].proofs.len(), 1);
    assert_eq!(restarted.dealer.records[&id].proofs[&2], valid[1]);
    // Once the native plan is fixed, the same incompatible leaf is still rejected.
    assert!(restarted
        .accept_dealer_input(&wrong.clone().into(), &ec(wrong))
        .unwrap_err()
        .to_string()
        .contains("dealer leaf identity differs"));
    for leaf in valid {
        restarted.accept_dealer_input(&leaf.clone().into(), &ec(leaf))?;
    }
    assert!(plan
        .request(&id, &restarted.dealer.records[&id].proofs)?
        .is_some());
    reopened.shutdown().await?;
    e3_data::SledDb::close_connection(directory.path());
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_flush_restart_reissues_only_unfinished_work() -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    let directory = tempfile::tempdir()?;
    let store = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    actor.recovery_repositories = Some(Repositories::new(store.clone()));
    collect(&mut actor, &input, &plan)?;
    actor.dealer.effects = true;
    let repositories = actor.recovery_repositories.clone().unwrap();
    let meta = actor.dealer.metadata[&input.e3_id].clone();
    let addr = actor.start();
    addr.send(FlushDefinition(input.e3_id.clone())).await?;
    // A second mailbox message waits for the first record's flush/dispatch acknowledgment.
    addr.send(FlushDefinition(input.e3_id.clone())).await?;
    bus.flush_event_pipeline().await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let requests: Vec<_> = events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::ComputeRequest(request) => Some(request.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 1);
    addr.send(StopDefinition).await?;
    store.shutdown().await?;
    drop(repositories);
    e3_data::SledDb::close_connection(directory.path());
    let reopened = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let mut record = repository(&Repositories::new(reopened.clone()), &input.e3_id)
        .read()
        .await?
        .unwrap();
    assert!(record
        .plan
        .as_mut()
        .unwrap()
        .restore_recipient_keys(plan.clone()));
    record.validate(&input.e3_id, &meta)?;
    let (mut restarted, _, _) = fixture(&bus).await?;
    restarted.dealer.records.insert(input.e3_id.clone(), record);
    restarted.dealer.effects = true;
    restarted.publish_dealer_work(&input.e3_id);
    let new_request = &restarted.dealer.in_flight[&input.e3_id];
    assert_ne!(new_request.correlation_id, requests[0].correlation_id);
    assert_eq!(new_request.request, requests[0].request);
    let stale = ComputeResponse::zk(
        ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Dealer {
            proof: proof(&plan, &input.e3_id, CircuitName::NodeFold),
        }),
        requests[0].correlation_id,
        input.e3_id.clone(),
    );
    assert!(restarted
        .accept_dealer_input(&stale.clone().into(), &ec(stale))
        .is_err());
    reopened.shutdown().await?;
    e3_data::SledDb::close_connection(directory.path());
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_runtime_stays_disabled_and_terminal_history_cannot_resurrect(
) -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    // Even a previously complete definition record cannot bypass runtime admission.
    collect(&mut actor, &input, &plan)?;
    let repositories = actor.recovery_repositories.clone().unwrap();
    let id = input.e3_id.clone();
    let meta = actor.dealer.metadata.clone();
    let record = actor.dealer.records[&id].clone();
    let controllers = actor.dealer.controllers.clone();
    let eventstore = EventSystem::in_mem()
        .with_fresh_bus()
        .eventstore_reader()?
        .seq();
    repository(&repositories, &id).write_sync(&record).await?;
    let error = recover(
        &repositories,
        &meta,
        &HashSet::new(),
        &controllers,
        &eventstore,
        &[],
    )
    .await
    .expect_err("the production recovery path must reject the disabled profile");
    assert!(matches!(
        error.downcast_ref::<e3_fhe_params::BfvProfileError>(),
        Some(e3_fhe_params::BfvProfileError::AdmissionDisabled(profile))
            if *profile == meta[&id].params_profile.name()
    ));
    let addr = actor.start();
    let effects: InterfoldEventData = EffectsEnabled::new().into();
    addr.send(
        InterfoldEvent::new_with_timestamp(effects, None, 1, None, EventSource::Local)
            .into_sequenced(1),
    )
    .await?;
    bus.flush_event_pipeline().await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    let terminal: InterfoldEventData = E3StageChanged {
        e3_id: id.clone(),
        previous_stage: E3Stage::Requested,
        new_stage: E3Stage::KeyPublished,
    }
    .into();
    addr.send(
        InterfoldEvent::new_with_timestamp(terminal.clone(), None, 2, None, EventSource::Net)
            .into_sequenced(2),
    )
    .await?;
    assert_eq!(addr.send(Inspect(id.clone())).await?, (true, false, false));
    addr.send(
        InterfoldEvent::new_with_timestamp(terminal, None, 3, None, EventSource::Evm)
            .into_sequenced(3),
    )
    .await?;
    assert_eq!(addr.send(Inspect(id.clone())).await?, (false, true, false));
    addr.send(
        InterfoldEvent::new_with_timestamp(input.into(), None, 4, None, EventSource::Local)
            .into_sequenced(4),
    )
    .await?;
    assert_eq!(addr.send(Inspect(id.clone())).await?, (false, true, false));
    assert!(repository(&repositories, &id).read().await?.is_none());
    // A stale disk record is also removed from the independent confirmed startup projection.
    repository(&repositories, &id).write_sync(&record).await?;
    recover(
        &repositories,
        &meta,
        &HashSet::from([id.clone()]),
        &controllers,
        &eventstore,
        &[],
    )
    .await?;
    assert!(repository(&repositories, &id).read().await?.is_none());
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_completed_result_is_flushed_before_republication() -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    collect(&mut actor, &input, &plan)?;
    let request = ComputeRequest::zk(
        ZkRequest::SynchronizedDkg(Box::new(
            plan.request(&input.e3_id, &actor.dealer.records[&input.e3_id].proofs)?
                .unwrap(),
        )),
        CorrelationId::new(),
        input.e3_id.clone(),
    );
    actor
        .dealer
        .in_flight
        .insert(input.e3_id.clone(), request.clone());
    let response = ComputeResponse::zk(
        ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Dealer {
            proof: proof(&plan, &input.e3_id, CircuitName::NodeFold),
        }),
        request.correlation_id,
        input.e3_id.clone(),
    );
    actor.accept_dealer_input(&response.clone().into(), &ec(response))?;
    let repositories = actor.recovery_repositories.clone().unwrap();
    let expected = actor.dealer.records[&input.e3_id]
        .completed
        .clone()
        .unwrap();
    actor.dealer.effects = true;
    let addr = actor.start();
    addr.send(FlushDefinition(input.e3_id.clone())).await?;
    addr.send(Inspect(input.e3_id.clone())).await?;
    let record = repository(&repositories, &input.e3_id)
        .read()
        .await?
        .unwrap();
    assert_eq!(record.completed.as_ref(), Some(&expected));
    let EventFixture {
        bus: resumed_bus,
        history: resumed_history,
        ..
    } = EventFixture::new()?;
    let (mut restarted, _, _) = fixture(&resumed_bus).await?;
    restarted.dealer.records.insert(input.e3_id.clone(), record);
    restarted.publish_dealer_work(&input.e3_id);
    resumed_bus.flush_event_pipeline().await?;
    assert!(resumed_history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    restarted.dealer.effects = true;
    restarted.publish_dealer_work(&input.e3_id);
    restarted.publish_dealer_work(&input.e3_id);
    resumed_bus.flush_event_pipeline().await?;
    let events = resumed_history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].get_data(), &InterfoldEventData::from(expected));
    let InterfoldEventData::SynchronizedDkgProofPublished(signed) = events[1].get_data() else {
        panic!("missing authenticated dealer output");
    };
    assert_eq!(signed.recover_address()?, restarted.signer.address());
    assert_eq!(signed.role, SynchronizedDkgProofRole::Dealer);
    bus.flush_event_pipeline().await?;
    assert_eq!(
        history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .len(),
        2
    );
    Ok(())
}

struct FailedFlush;
impl Actor for FailedFlush {
    type Context = Context<Self>;
}
impl Handler<Flush> for FailedFlush {
    type Result = Result<()>;
    fn handle(&mut self, _: Flush, _: &mut Context<Self>) -> Self::Result {
        anyhow::bail!("injected flush failure")
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct DriveDealerDefinition(InterfoldEventData);

impl Handler<DriveDealerDefinition> for NodeProofAggregator {
    type Result = Result<()>;

    fn handle(&mut self, msg: DriveDealerDefinition, ctx: &mut Context<Self>) -> Self::Result {
        self.drive_dealer_input(&msg.0, &ec(msg.0.clone()), ctx)
    }
}

struct CountDealerFlush(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Actor for CountDealerFlush {
    type Context = Context<Self>;
}

impl Handler<Flush> for CountDealerFlush {
    type Result = Result<()>;

    fn handle(&mut self, _: Flush, _: &mut Context<Self>) -> Self::Result {
        let old = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ensure!(old != 0, "first flush fails");
        Ok(())
    }
}

#[actix::test]
async fn synchronized_dealer_only_flushes_progress_or_an_unacknowledged_write() -> Result<()> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let EventFixture { bus, .. } = EventFixture::new()?;
    let (mut actor, input, _) = fixture(&bus).await?;
    let id = input.e3_id.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let repositories = actor.recovery_repositories.take().unwrap();
    actor.recovery_repositories =
        Some(Repositories::new(repositories.store.with_flush_recipient(
            CountDealerFlush(count.clone()).start().recipient(),
        )));
    actor.dealer.effects = true;
    let node = actor.start();
    for expected in [1, 2, 2] {
        node.send(DriveDealerDefinition(input.clone().into()))
            .await??;
        node.send(Inspect(id.clone())).await?;
        assert_eq!(count.load(Ordering::SeqCst), expected);
    }
    node.send(StopDefinition).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_dealer_failed_flush_withholds_dispatch_and_keeps_inputs() -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let (mut actor, input, plan) = fixture(&bus).await?;
    collect(&mut actor, &input, &plan)?;
    let repositories = actor.recovery_repositories.take().unwrap();
    actor.recovery_repositories = Some(Repositories::new(
        repositories
            .store
            .with_flush_recipient(FailedFlush.start().recipient()),
    ));
    actor.dealer.effects = true;
    let addr = actor.start();
    addr.send(FlushDefinition(input.e3_id.clone())).await?;
    assert_eq!(addr.send(Inspect(input.e3_id)).await?, (true, false, false));
    bus.flush_event_pipeline().await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    Ok(())
}
