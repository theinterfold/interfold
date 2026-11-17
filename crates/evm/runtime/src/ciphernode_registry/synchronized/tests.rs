// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    transports::mock::Asserter,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_committee_hash::{hash_committee_addresses, DkgSetupContext};
use e3_event_system::test_support::EventFixture;
use e3_events::*;
use e3_fhe_params::BfvProfile;
use e3_request::canonical_key::SynchronizedDkgSelection;

fn fixture() -> Result<(CanonicalPublicKeys, SynchronizedDkgPublicationReady)> {
    let profile = BfvProfile::SyncDecInsecure64;
    let size = CiphernodesCommitteeSize::Minimum;
    let mut signers = (1..=3)
        .map(|id| format!("{id:064x}").parse())
        .collect::<Result<Vec<PrivateKeySigner>, _>>()?;
    signers.sort_by_key(|s| s.address());
    let committee: Vec<_> = signers.iter().map(|s| s.address()).collect();
    let id = E3id::new("2459", 1);
    let config_id = profile.crypto_config_id(size)?.0;
    let setup = DkgSetupContext {
        interfold_address: Address::repeat_byte(4),
        committee_hash: hash_committee_addresses(&committee),
        crypto_config_id: config_id.into(),
    };
    let binding = setup.hash(1, id.clone().try_into()?).0;
    let context = SynchronizedDkgContext {
        registry: Address::repeat_byte(5),
        verifying_contract: Address::repeat_byte(6),
        crypto_config_id: config_id,
    };
    let (params, _) = profile.build_pair()?;
    let bytes = e3_bfv_client::client::generate_public_key(
        params.degree(),
        params.plaintext(),
        params.moduli().to_vec(),
    )?;
    let commitment = e3_bfv_client::compute_pk_commitment(
        bytes.clone(),
        params.degree(),
        params.plaintext(),
        params.moduli().to_vec(),
    )?;
    let expected = SynchronizedPublicationExpectation {
        dealers: vec![0, 2],
        threshold_keys: vec![[1; 32], [2; 32]],
        dealer_batch: [3; 32],
        sk_commitments: vec![[4; 32], [5; 32]],
        key_bundles: vec![[6; 32], [7; 32]],
        public_key: ArcBytes::from_bytes(&bytes),
    };
    let mut fields = vec![
        [1; 32],
        [2; 32],
        U256::from_be_slice(&binding[..16]).to_be_bytes::<32>(),
        U256::from_be_slice(&binding[16..]).to_be_bytes::<32>(),
        [0; 32],
        U256::from(2).to_be_bytes::<32>(),
        expected.dealer_batch,
    ];
    fields.extend(&expected.threshold_keys);
    fields.extend(&expected.sk_commitments);
    fields.extend(&expected.key_bundles);
    fields.push(commitment);
    let consents = expected
        .dealers
        .iter()
        .enumerate()
        .map(|(slot, &party)| {
            SignedSynchronizedDkgAttestation::sign(
                SynchronizedDkgAttestationPayload {
                    e3_id: id.clone(),
                    context,
                    setup_binding: binding,
                    roster_hash: synchronized_dkg_roster_hash(&expected.dealers),
                    dealer_batch: expected.dealer_batch,
                    pk_commitment: commitment,
                    party_id: party,
                    sk_agg_commit: expected.sk_commitments[slot],
                    key_bundle_commit: expected.key_bundles[slot],
                },
                &signers[party as usize],
            )
        })
        .collect::<Result<_>>()?;
    let intent = SynchronizedDkgPublicationReady {
        e3_id: id.clone(),
        params_profile: profile,
        committee_size: size,
        context: SynchronizedProofContext { setup, party_id: 0 },
        expected,
        proof: Proof::new(
            e3_zk_config::CircuitName::DkgAggregator,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&fields.concat()),
        ),
        consents,
    };
    let keys = CanonicalPublicKeys::default();
    keys.remember_synchronized_context(id.clone(), context)?;
    keys.remember_synchronized_selection(
        id,
        SynchronizedDkgSelection {
            params_profile: profile,
            committee_size: size,
            interfold_address: setup.interfold_address,
            committee,
        },
    )?;
    Ok((keys, intent))
}

fn event(data: impl Into<InterfoldEventData>, source: EventSource) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(data.into(), None, 1, None, source)
        .into_sequenced(1)
}

#[derive(Message)]
#[rtype(result = "usize")]
struct Pending;
impl<P: Provider + WalletProvider + Clone + 'static> Handler<Pending>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = usize;
    fn handle(&mut self, _: Pending, _: &mut Self::Context) -> usize {
        self.synchronized_publication.pending_keys().len()
    }
}

#[derive(Message)]
#[rtype(result = "usize")]
struct PendingSs;
impl<P: Provider + WalletProvider + Clone + 'static> Handler<PendingSs>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = usize;
    fn handle(&mut self, _: PendingSs, _: &mut Self::Context) -> usize {
        self.publication.pending_keys().len()
    }
}

#[actix::test]
async fn synchronized_terminal_retirement_preserves_ss_failure_behavior() -> Result<()> {
    let (keys, intent) = fixture()?;
    let EventFixture { bus, .. } = EventFixture::new()?;
    let asserter = Asserter::new();
    asserter.push_success(&"0x1");
    let provider = EthProvider::new(
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_mocked_client(asserter),
    )
    .await?;
    let writer = CiphernodeRegistrySolWriter::new_with_recovery(
        &bus,
        provider,
        Address::repeat_byte(99),
        HashMap::new(),
        HashMap::new(),
        keys,
        vec![intent.clone()],
    )?
    .start();
    let ss_id = E3id::new("2460", 1);
    for id in [&intent.e3_id, &ss_id] {
        writer
            .send(
                InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    E3Failed {
                        e3_id: id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::DKGTimeout,
                    }
                    .into(),
                    None,
                    1,
                    Some(3),
                    EventSource::Evm,
                )
                .into_sequenced(1),
            )
            .await?;
    }
    writer.send(AcceptDefinition(intent)).await??;
    assert_eq!(writer.send(Pending).await?, 0);
    // The SS writer historically retains these intents until its completion/publication boundary.
    writer
        .send(PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
            e3_id: ss_id,
            nodes: e3_utils::OrderedSet::from(vec![]),
            committee_addresses: vec![],
            honest_committee_addresses: vec![],
            pk_commitment: [7; 32],
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        })
        .await?;
    assert_eq!(writer.send(PendingSs).await?, 1);
    writer.send(Shutdown).await?;
    Ok(())
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct AcceptDefinition(SynchronizedDkgPublicationReady);
impl<P: Provider + WalletProvider + Clone + 'static> Handler<AcceptDefinition>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = Result<()>;
    fn handle(&mut self, msg: AcceptDefinition, _: &mut Self::Context) -> Self::Result {
        self.accept_synchronized_definition(msg.0)
    }
}

#[actix::test]
async fn local_intent_validation_precedes_dedup_and_terminal_history_wins() -> Result<()> {
    let (keys, intent) = fixture()?;
    let EventFixture { bus, .. } = EventFixture::new()?;
    let asserter = Asserter::new();
    asserter.push_success(&"0x1");
    let provider = EthProvider::new(
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_mocked_client(asserter),
    )
    .await?;
    let writer = CiphernodeRegistrySolWriter::new_with_recovery(
        &bus,
        provider,
        Address::repeat_byte(99),
        HashMap::new(),
        HashMap::new(),
        keys,
        Vec::new(),
    )?
    .start();
    for source in [EventSource::Net, EventSource::Evm, EventSource::Local] {
        writer.send(event(intent.clone(), source)).await?;
        assert_eq!(writer.send(Pending).await?, 0); // Admission is still disabled, even locally.
    }
    for mutation in 0..6 {
        let mut changed = intent.clone();
        match mutation {
            0 => {
                changed.consents.pop();
            }
            1 => changed.consents.swap(0, 1),
            2 => changed.expected.public_key = ArcBytes::from_bytes(&[1]),
            3 => changed.context.setup.interfold_address = Address::repeat_byte(10),
            4 => changed.expected.key_bundles[0][31] ^= 1,
            _ => changed.consents[0] = changed.consents[1].clone(),
        }
        assert!(writer.send(AcceptDefinition(changed)).await?.is_err());
        assert_eq!(writer.send(Pending).await?, 0);
    }
    writer.send(AcceptDefinition(intent.clone())).await??;
    writer.send(AcceptDefinition(intent.clone())).await??;
    assert_eq!(writer.send(Pending).await?, 1);
    writer
        .send(event(
            E3RequestComplete {
                e3_id: intent.e3_id.clone(),
            },
            EventSource::Net,
        ))
        .await?;
    assert_eq!(writer.send(Pending).await?, 1);
    writer
        .send(event(
            E3RequestComplete {
                e3_id: intent.e3_id.clone(),
            },
            EventSource::Local,
        ))
        .await?;
    writer.send(AcceptDefinition(intent)).await??;
    writer
        .send(event(EffectsEnabled::new(), EventSource::Local))
        .await?;
    assert_eq!(writer.send(Pending).await?, 0);
    writer.send(Shutdown {}).await?;
    Ok(())
}

#[actix::test]
async fn preflight_compares_complete_authority_not_only_the_pk() -> Result<()> {
    use alloy::sol_types::SolValue;
    let (keys, intent) = fixture()?;
    let candidate = keys
        .synchronized_selection(&intent.e3_id)
        .unwrap()
        .validate_publication(keys.synchronized_context(&intent.e3_id).unwrap(), &intent)?;
    let (_, mut on_chain) = effects::authority(&candidate)?;
    // The PK matches but one setup anchor differs. No send may follow this view.
    on_chain.keyBundleCommits[0] = B256::repeat_byte(9);
    let asserter = Asserter::new();
    asserter.push_success(&"0x1");
    asserter.push_success(&Bytes::from(on_chain.abi_encode()));
    let provider = EthProvider::new(
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_mocked_client(asserter),
    )
    .await?;
    let error = publish_synchronized_committee_definition(provider, &keys, &intent)
        .await
        .unwrap_err();
    assert!(effects::is_terminal(&error), "{error:#}");
    assert!(keys.get(&intent.e3_id).is_none());
    Ok(())
}

#[actix::test]
async fn transient_preflight_failure_retains_the_local_intent() -> Result<()> {
    let (keys, intent) = fixture()?;
    let EventFixture { bus, .. } = EventFixture::new()?;
    let asserter = Asserter::new();
    asserter.push_success(&"0x1");
    asserter.push_failure_msg("connection reset");
    let provider = EthProvider::new(
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_mocked_client(asserter),
    )
    .await?;
    let mut writer = CiphernodeRegistrySolWriter::new_with_recovery(
        &bus,
        provider,
        Address::repeat_byte(99),
        HashMap::new(),
        HashMap::new(),
        keys,
        vec![intent.clone()],
    )?;
    assert!(writer
        .synchronized_publication
        .start(&intent.e3_id)
        .is_none());
    writer.effects_enabled = true;
    writer.synchronized_publication.enable_effects();
    let started = writer
        .synchronized_publication
        .start(&intent.e3_id)
        .unwrap();
    assert_eq!(started, intent);
    assert!(writer
        .synchronized_publication
        .start(&intent.e3_id)
        .is_none());
    let writer = writer.start();
    writer.send(SubmitSynchronizedPublication(started)).await?;
    assert_eq!(writer.send(Pending).await?, 1);
    writer.send(Shutdown).await?;
    Ok(())
}

#[actix::test]
async fn recovery_ignores_peer_intents_and_prunes_closed_history_before_validation() -> Result<()> {
    use e3_data::{InMemEventLog, InMemSequenceIndex};
    let (keys, intent) = fixture()?;
    for (source, terminal, expected) in [
        (EventSource::Net, false, 0),
        (EventSource::Local, false, 1),
        (EventSource::Local, true, 0),
    ] {
        let mut store = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())?;
        store.store_event(InterfoldEvent::<Unsequenced>::new_with_timestamp(
            intent.clone().into(),
            None,
            1,
            None,
            source,
        ))?;
        if terminal {
            store.store_event(InterfoldEvent::<Unsequenced>::new_with_timestamp(
                E3RequestComplete {
                    e3_id: intent.e3_id.clone(),
                }
                .into(),
                None,
                2,
                Some(5),
                EventSource::Evm,
            ))?;
        }
        let reader = EventStoreRouter::new(HashMap::from([(1, store.start())]))
            .start()
            .recipient();
        let empty = CanonicalPublicKeys::default();
        let restored =
            recover_synchronized_publications(&reader, 1, if terminal { &empty } else { &keys })
                .await?;
        assert_eq!(restored.len(), expected);
        if expected == 1 {
            assert_eq!(restored[0], intent);
        }
    }
    Ok(())
}
