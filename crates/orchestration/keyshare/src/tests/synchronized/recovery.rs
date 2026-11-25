// SPDX-License-Identifier: LGPL-3.0-only

//! Physical Sled reopen and real actor mailboxes/effects, below disabled profile admission.
//! Checkpoints come from production native planning. No production enable switch, chain reader,
//! network transport or ProofRequestActor is simulated as present. The replay child separately
//! drives startup sync from a durable log; the real-proof child joins reopened artifacts to C5.

use super::*;
use actix::{ActorContext, ActorFutureExt, Message, ResponseActFuture, WrapFuture};
use e3_data::{SledDb, SledStore};
use e3_events::ComputeRequestKind;
use e3_trbfv::{
    calculate_decryption_key::{CalculateDecryptionKeyRequest, CalculateDecryptionKeyResponse},
    shares::DecryptVec,
};
use e3_zk_prover::{synchronized as adapters, ZkProver};
use std::path::Path;

#[path = "recovery/chain.rs"]
mod chain;
#[path = "recovery/publication.rs"]
mod publication;
#[path = "recovery/replay.rs"]
mod replay;

// These are this crate's only Sled fixtures. Close all three stores before evicting the process
// cache; serialize the variants so one cannot evict the other's still-open database handles.
pub(super) static DISK_RECOVERY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn cipher(owner: usize) -> Result<Arc<Cipher>> {
    Ok(Arc::new(
        Cipher::from_password(&format!("sync-disk-owner-{owner}")).await?,
    ))
}

fn sign_proof(
    setup: &Setup,
    owner: usize,
    kind: ProofType,
    proof: Proof,
) -> Result<SignedProofPayload> {
    SignedProofPayload::sign(
        ProofPayload {
            e3_id: setup.selected[owner].e3_id.clone(),
            proof_type: kind,
            proof,
        },
        &setup.signers[owner],
    )
}

struct Artifacts {
    keys: Vec<EncryptionKeyCreated>,
    c1: Vec<SignedProofPayload>,
    messages: BTreeMap<(usize, usize), ThresholdShareCreated>,
}

async fn artifacts(setup: &mut Setup, prover: Option<&ZkProver>) -> Result<Artifacts> {
    let mut keys = Vec::new();
    let mut c1 = Vec::new();
    for owner in 0..3 {
        let e3 = &setup.selected[owner].e3_id;
        let public = PublicKey::from_bytes(
            &setup.encryption_keys[owner].pk_bfv,
            &setup.config.transport,
        )?;
        let inputs = e3_zk_witness::dkg::pk::Inputs::compute(&setup.config.pk, &public)?;
        let c0 = match prover {
            Some(prover) => sign_proof(
                setup,
                owner,
                ProofType::C0PkBfv,
                prove_prepared(
                    &e3_zk_prover::PkCircuit,
                    prover,
                    &setup.config.pk,
                    &public,
                    owner as u64,
                )?,
            )?,
            None => signed(
                setup,
                owner,
                ProofType::C0PkBfv,
                vec![commitment_field(
                    &e3_zk_witness::compute_dkg_pk_commitment(
                        &inputs.pk0is,
                        &inputs.pk1is,
                        setup.config.pk.pk_bit,
                    ),
                )?],
            )?,
        };
        let mut key = (*setup.encryption_keys[owner]).clone();
        key.signed_payload = Some(c0);
        keys.push(EncryptionKeyCreated {
            e3_id: e3.clone(),
            key: Arc::new(key),
            external: true,
        });
        let generation = prepare_pk_generation(
            &setup.config,
            &setup.pending[owner].proof_request,
            e3,
            &setup.ciphers[owner],
        )?;
        let binding = setup_binding(&setup.material[owner].context, e3)?;
        c1.push(match prover {
            Some(prover) => sign_proof(
                setup,
                owner,
                ProofType::C1PkGeneration,
                prove_prepared(
                    &adapters::PkGenerationCircuit,
                    prover,
                    &setup.config,
                    &generation,
                    owner as u64,
                )?,
            )?,
            None => signed(
                setup,
                owner,
                ProofType::C1PkGeneration,
                vec![
                    scalar(binding[0])?,
                    scalar(binding[1])?,
                    scalar(owner)?,
                    commitment_field(&e3_zk_witness::compute_share_computation_sk_commitment(
                        &generation.sk,
                        setup.config.pk_generation.bits.sk_bit,
                    ))?,
                    commitment_field(&e3_zk_witness::compute_threshold_pk_commitment(
                        &generation.pk0is,
                        setup.config.pk_generation.bits.pk_bit,
                    ))?,
                ],
            )?,
        });
        if let Some(prover) = prover {
            let input = prepare_share_computation(
                &setup.config,
                &setup.pending[owner].sk_share_computation_request,
                e3,
                &setup.ciphers[owner],
            )?;
            let proof = prove_prepared(
                &adapters::ShareComputationCircuit,
                prover,
                &setup.config,
                &input,
                owner as u64,
            )?;
            ensure!(proof.public_signals == setup.c2[&(owner as u64)].payload.proof.public_signals);
            let proof = sign_proof(setup, owner, ProofType::C2aSkShareComputation, proof)?;
            setup.c2.insert(owner as u64, proof);
        }
    }
    let mut messages = BTreeMap::new();
    for dealer in 0..3 {
        for recipient in (0..3).filter(|&id| id != dealer) {
            let mut message = setup.message(dealer, recipient)?;
            if let Some(prover) = prover {
                let mut proofs = Vec::new();
                for request in setup.pending[dealer]
                    .sk_share_encryption_requests
                    .iter()
                    .filter(|request| request.recipient_party_id == recipient)
                {
                    let proof = prove_prepared(
                        &e3_zk_prover::ShareEncryptionCircuit,
                        prover,
                        &setup.config.share_encryption,
                        &setup.c3_data(dealer, request)?,
                        dealer as u64,
                    )?;
                    proofs.push(sign_proof(
                        setup,
                        dealer,
                        ProofType::C3aSkShareEncryption,
                        proof,
                    )?);
                }
                message.signed_c3a_proofs = proofs;
                message = message.sign(&setup.signers[dealer])?;
            }
            messages.insert((dealer, recipient), message);
        }
    }
    Ok(Artifacts { keys, c1, messages })
}

#[derive(Clone)]
struct Calculation {
    native_request: CalculateDecryptionKeyRequest,
    response: CalculateDecryptionKeyResponse,
    request: DkgShareDecryptionProofRequest,
    material: SynchronizedDkgRecovery,
}

fn calculations(setup: &Setup) -> Result<Vec<Calculation>> {
    (0..3)
        .map(|owner| {
            let DecryptionKeyPlan::Proceed {
                calc_request,
                sk_request,
                esm_requests,
                synchronized: Some(material),
                honest_party_ids,
            } = setup.plan(owner)?
            else {
                anyhow::bail!("missing synchronized calculation");
            };
            ensure!(esm_requests.is_empty() && honest_party_ids == DEALERS.into());
            Ok(Calculation {
                response: calculate_decryption_key(&setup.ciphers[owner], calc_request.clone())?,
                native_request: calc_request,
                request: sk_request,
                material,
            })
        })
        .collect()
}

fn c4_message(
    setup: &Setup,
    owner: usize,
    proof: SignedProofPayload,
) -> Result<DecryptionKeyShared> {
    DecryptionKeyShared {
        e3_id: setup.selected[owner].e3_id.clone(),
        party_id: owner as u64,
        node: setup.signers[owner].address().to_string(),
        signed_sk_decryption_proof: proof,
        signed_e_sm_decryption_proofs: vec![],
        external: true,
        signature: Default::default(),
    }
    .sign(&setup.signers[owner])
}

fn provisional_c4(
    setup: &Setup,
    owner: usize,
    calculation: &Calculation,
) -> Result<DecryptionKeyShared> {
    let mut fields = c4_fields(
        &calculation.request,
        &calculation.material,
        &setup.selected[owner].e3_id,
    )?;
    fields[6][31] ^= 1; // Authenticated but unrelated opening, before the recipient has C2 anchors.
    c4_message(
        setup,
        owner,
        signed(setup, owner, ProofType::C4aSkShareDecryption, fields)?,
    )
}

// Qualification supplies the verified C2/C3 verdict and native worker result below admission.
// Production readiness, roster acceptance, planning and plan persistence own the asserted state.
#[derive(Message)]
#[rtype(result = "Result<()>")]
struct CompleteQualifiedCalculation {
    calculation: Calculation,
    roster: DkgCoordination,
    shares: Vec<ThresholdShareCreated>,
}

impl Handler<CompleteQualifiedCalculation> for ThresholdKeyshare {
    type Result = Result<()>;
    fn handle(
        &mut self,
        input: CompleteQualifiedCalculation,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let ec = test_ec(500);
        let enabled = self.effects_enabled;
        self.effects_enabled = false;
        let owner = self.state.try_get()?.party_id;
        for share in &input.shares {
            self.handle_threshold_share_created(
                TypedEvent::new(share.clone(), ec.clone()),
                ctx.address(),
            )?;
        }
        let verified: BTreeSet<_> = input
            .shares
            .iter()
            .map(|share| share.share.party_id)
            .collect();
        let e3_id = self.state.try_get()?.e3_id;
        self.recovery.try_mutate(&ec, |mut saved| {
            saved.collected_threshold_share_ids = Some(verified.clone());
            saved.verified_dealer_ids = Some(verified);
            saved.share_verification_complete = Some(share_proofs_verified(&e3_id));
            Ok(saved)
        })?;
        self.maybe_publish_dkg_ready(ec.clone())?;
        self.accept_dkg_roster(input.roster, ec.clone())?;
        ensure!(!self.state.try_get()?.dkg_roster_fixed);
        let plan = self.decryption_key_plan(None)?;
        let DecryptionKeyPlan::Proceed {
            ref honest_party_ids,
            ref sk_request,
            ..
        } = plan
        else {
            anyhow::bail!("restored authenticated contributions cannot produce C4 for {owner}");
        };
        ensure!(honest_party_ids == &DEALERS.into());
        ensure!(sk_request == &input.calculation.request);
        self.apply_decryption_key_plan(plan, ec.clone())?;
        self.effects_enabled = enabled;
        let response = ComputeResponse::trbfv(
            TrBFVResponse::CalculateDecryptionKey(input.calculation.response),
            CorrelationId::new(),
            self.state.try_get()?.e3_id,
        );
        self.handle_calculate_decryption_key_response(TypedEvent::new(response, ec), ctx.address())
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct AssertReplayQuiescent;

impl Handler<AssertReplayQuiescent> for ThresholdKeyshare {
    type Result = Result<()>;
    fn handle(&mut self, _: AssertReplayQuiescent, _: &mut Self::Context) -> Self::Result {
        ensure!(!self.effects_enabled);
        ensure!(self.encryption_key_collector.is_none());
        ensure!(self.decryption_key_collector.is_none());
        ensure!(self.decryption_key_shared_collector.is_none());
        ensure!(self.bfv_key.is_some());
        Ok(())
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct StopForReopen;

impl Handler<StopForReopen> for EncryptionKeyCollector {
    type Result = Result<()>;
    fn handle(&mut self, _: StopForReopen, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

impl Handler<StopForReopen> for DecryptionKeySharedCollector {
    type Result = Result<()>;
    fn handle(&mut self, _: StopForReopen, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

impl Handler<StopForReopen> for ThresholdShareCollector {
    type Result = Result<()>;
    fn handle(&mut self, _: StopForReopen, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

fn stopped(result: std::result::Result<Result<()>, actix::MailboxError>) -> Result<()> {
    match result {
        Ok(result) => result,
        Err(actix::MailboxError::Closed) => Ok(()), // Completed collectors have already stopped.
        Err(error) => Err(error.into()),
    }
}

impl Handler<StopForReopen> for ThresholdKeyshare {
    type Result = ResponseActFuture<Self, Result<()>>;
    fn handle(&mut self, _: StopForReopen, _: &mut Self::Context) -> Self::Result {
        let c0 = self.encryption_key_collector.take();
        let shares = self.decryption_key_collector.take();
        let c4 = self.decryption_key_shared_collector.take();
        Box::pin(
            async move {
                if let Some(actor) = c0 {
                    stopped(actor.send(StopForReopen).await)?;
                }
                if let Some(actor) = shares {
                    stopped(actor.send(StopForReopen).await)?;
                }
                if let Some(actor) = c4 {
                    stopped(actor.send(StopForReopen).await)?;
                }
                Ok(())
            }
            .into_actor(self)
            .map(|result, _, ctx| {
                ctx.stop();
                result
            }),
        )
    }
}

struct Node {
    store: DataStore,
    repositories: Repositories,
    actor: Addr<ThresholdKeyshare>,
    history: Addr<HistoryCollector<InterfoldEvent>>,
}

impl Node {
    async fn open(
        path: &Path,
        owner: usize,
        setup: &Setup,
        seed: Option<&Artifacts>,
    ) -> Result<Self> {
        let (bus, history) = test_bus();
        let store = DataStore::from_sled_store(&SledStore::new(&bus, &path.to_path_buf())?);
        let repositories = store.repositories();
        let selection = &setup.selected[owner];
        let e3 = &selection.e3_id;
        let root_repo = repositories.threshold_keyshare_recovery(e3);
        let state_repo = repositories.threshold_keyshare(e3);
        let bfv_key = repositories.threshold_keyshare_bfv_key(e3);
        let expected_key = BfvKeyIntent {
            sk_bfv: setup.sk_bfv[owner].clone(),
            pk_bfv: setup.encryption_keys[owner].pk_bfv.clone(),
        };
        if let Some(seed) = seed {
            bfv_key.record(&expected_key).await?;
            let pending = TypedEvent::new(setup.pending[owner].clone(), test_ec(10));
            let payloads = ThresholdKeyshareRecoveryPayloads::new(
                repositories.threshold_keyshare_recovery_payloads(e3),
            );
            let reference = payloads.write_pending(&pending, pending.get_ctx())?;
            store.flush_sync().await?;
            let state = AggregatingDecryptionKey {
                pk_share: pending.full_share.pk_share.clone(),
                sk_bfv: setup.sk_bfv[owner].clone(),
                own_sk_share_raw: pending.own_sk_share_raw.clone(),
                own_esi_shares_raw: vec![],
                signed_pk_generation_proof: Some(seed.c1[owner].clone()),
                signed_sk_share_computation_proof: Some(setup.c2[&(owner as u64)].clone()),
                signed_e_sm_share_computation_proof: None,
                signed_sk_share_encryption_proofs: seed
                    .messages
                    .iter()
                    .filter(|((dealer, _), _)| *dealer == owner)
                    .flat_map(|(_, message)| message.signed_c3a_proofs.clone())
                    .collect(),
                signed_e_sm_share_encryption_proofs: vec![],
            };
            let mut state = ThresholdKeyshareState::new(
                e3.clone(),
                owner as u64,
                KeyshareState::AggregatingDecryptionKey(state),
                1,
                3,
                selection.params.clone(),
                setup.signers[owner].address().to_string(),
            );
            state.dkg_deadline_unix_secs =
                Some(crate::domain::timeout_policy::now_unix_secs() + 7200);
            state.dkg_window_secs = Some(7200);
            state_repo.write_sync(&state).await?;
            root_repo
                .write_sync(&ThresholdKeyshareRecoveryState {
                    ciphernode_selected: Some(TypedEvent::new(selection.clone(), test_ec(0))),
                    synchronized: Some(setup.material[owner].clone()),
                    threshold_share_pending_ref: Some(reference),
                    last_ec: Some(test_ec(10)),
                    encryption_keys: seed
                        .keys
                        .iter()
                        .enumerate()
                        .map(|(id, key)| (id as u64, TypedEvent::new(key.clone(), test_ec(1))))
                        .collect(),
                    ..Default::default()
                })
                .await?;
        }
        Self::restore(store, bus, history, owner, setup).await
    }

    async fn restore(
        store: DataStore,
        bus: BusHandle,
        history: Addr<HistoryCollector<InterfoldEvent>>,
        owner: usize,
        setup: &Setup,
    ) -> Result<Self> {
        let repositories = store.repositories();
        let selection = &setup.selected[owner];
        let e3 = &selection.e3_id;
        let root_repo = repositories.threshold_keyshare_recovery(e3);
        let state_repo = repositories.threshold_keyshare(e3);
        let bfv_key = repositories.threshold_keyshare_bfv_key(e3);
        let expected_key = BfvKeyIntent {
            sk_bfv: setup.sk_bfv[owner].clone(),
            pk_bfv: setup.encryption_keys[owner].pk_bfv.clone(),
        };
        let recovery = root_repo.load().await?;
        let payloads = ThresholdKeyshareRecoveryPayloads::load(
            repositories.threshold_keyshare_recovery_payloads(e3),
            &recovery.try_get()?,
        )
        .await?;
        ensure!(bfv_key.restore().await?.as_ref() == Some(&expected_key));
        // A new password-derived cipher on every boot, not an in-memory retained secret key.
        let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
            state: state_repo.load().await?,
            recovery,
            recovery_payloads: payloads,
            bus,
            cipher: cipher(owner).await?,
            params_profile: PROFILE,
            interfold_address: setup.interfold,
            signer: setup.signers[owner].clone(),
            bfv_key,
            effects_enabled: false,
            dkg_timing_reader: Arc::new(|_| {
                Box::pin(async { anyhow::bail!("timing must be recovered") })
            }),
        })
        .start();
        actor.send(AssertReplayQuiescent).await??;
        Ok(Self {
            store,
            repositories,
            actor,
            history,
        })
    }

    async fn root(&self, e3: &E3id) -> Result<ThresholdKeyshareRecoveryState> {
        self.store.flush_sync().await?;
        self.repositories
            .threshold_keyshare_recovery(e3)
            .read()
            .await?
            .context("missing root")
    }

    async fn stop(self) -> Result<()> {
        self.actor.send(StopForReopen).await??;
        self.store.shutdown().await
    }

    async fn enable(&self, seq: u64) -> Result<()> {
        self.actor
            .send(keyshare_event(
                EffectsEnabled::new(),
                seq,
                EventSource::Local,
            ))
            .await?;
        Ok(())
    }
}

async fn stop(nodes: Vec<Node>) -> Result<()> {
    for node in nodes {
        node.stop().await?;
    }
    // Sled's process cache otherwise retains an open Db even after the store actor drops its Tree.
    SledDb::close_all_connections();
    Ok(())
}

async fn open(root: &Path, setup: &Setup) -> Result<Vec<Node>> {
    let mut nodes = Vec::new();
    for owner in 0..3 {
        nodes.push(Node::open(&root.join(owner.to_string()), owner, setup, None).await?);
    }
    Ok(nodes)
}

async fn exercise(prover: Option<&ZkProver>) -> Result<()> {
    let _exclusive = DISK_RECOVERY.lock().await;
    let mut ciphers = Vec::new();
    for owner in 0..3 {
        ciphers.push(cipher(owner).await?);
    }
    let chain = if prover.is_some() {
        Some(chain::Chain::start().await?)
    } else {
        None
    };
    let mut setup = Setup::with_ciphers_at(
        ciphers,
        chain
            .as_ref()
            .map_or(Address::repeat_byte(0x11), |chain| chain.controller),
    )
    .await?;
    let artifacts = artifacts(&mut setup, prover).await?;
    let mut plans = calculations(&setup)?;
    let mut successful = plans.clone();
    let provisional = plans
        .iter()
        .enumerate()
        .map(|(owner, plan)| provisional_c4(&setup, owner, plan))
        .collect::<Result<Vec<_>>>()?;
    let temp = tempfile::tempdir()?;
    let e3 = &setup.selected[0].e3_id;
    let peers = [2, 0, 0];
    let mut nodes = Vec::new();
    for owner in 0..3 {
        let node = Node::open(
            &temp.path().join(owner.to_string()),
            owner,
            &setup,
            Some(&artifacts),
        )
        .await?;
        let mut forged = artifacts.messages[&(peers[owner], owner)].clone();
        forged.signature = Default::default();
        node.actor
            .send(keyshare_event(forged, 100, EventSource::Net))
            .await?;
        ensure!(node.root(e3).await?.threshold_share_refs.is_empty());
        node.actor
            .send(keyshare_event(
                artifacts.messages[&(peers[owner], owner)].clone(),
                101,
                EventSource::Net,
            ))
            .await?;
        // This first boot cannot yet compare C4 against the incoming C2 batch.
        node.actor
            .send(keyshare_event(
                provisional[peers[owner]].clone(),
                102,
                EventSource::Net,
            ))
            .await?;
        ensure!(node
            .root(e3)
            .await?
            .decryption_key_shares
            .contains_key(&(peers[owner] as u64)));
        node.actor.send(AssertReplayQuiescent).await??;
        ensure!(node
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        nodes.push(node);
    }
    stop(nodes).await?;

    let dealers = DEALERS
        .iter()
        .map(|&id| {
            crate::domain::dealer_identity_for_profile(
                PROFILE,
                e3,
                id,
                &setup.pending[id as usize].full_share.pk_share,
                &setup.c2[&id],
                None,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let roster = DkgCoordination::sign(
        e3.clone(),
        setup.interfold,
        0,
        DkgCoordinationKind::Roster,
        dealers,
        &setup.signers[0],
    )?;
    let nodes = open(temp.path(), &setup).await?;
    for (owner, node) in nodes.iter().enumerate() {
        ensure!(node
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        let root = node.root(e3).await?;
        let payloads = ThresholdKeyshareRecoveryPayloads::load(
            node.repositories.threshold_keyshare_recovery_payloads(e3),
            &root,
        )
        .await?;
        ensure!(**payloads.pending().context("missing plan")? == setup.pending[owner]);
        ensure!(
            **payloads
                .share(peers[owner] as u64)
                .context("missing saved share")?
                == artifacts.messages[&(peers[owner], owner)]
        );
        ensure!(root.synchronized == Some(setup.material[owner].clone()));
        let state = node
            .repositories
            .threshold_keyshare(e3)
            .read()
            .await?
            .context("lost aggregation state")?;
        let KeyshareState::AggregatingDecryptionKey(state) = state.state else {
            anyhow::bail!("reopen changed the saved DKG phase");
        };
        ensure!(state.sk_bfv == setup.sk_bfv[owner]);
        ensure!(state.own_sk_share_raw == setup.pending[owner].own_sk_share_raw);
        ensure!(state.signed_pk_generation_proof.as_ref() == Some(&artifacts.c1[owner]));
        ensure!(
            state.signed_sk_share_computation_proof.as_ref() == Some(&setup.c2[&(owner as u64)])
        );
        node.enable(200).await?;
        let event = next_event(&node.history).await?;
        let InterfoldEventData::ThresholdSharePending(pending) = event.into_data() else {
            anyhow::bail!("expected recovered threshold work");
        };
        ensure!(bincode::serialize(&pending)? == bincode::serialize(&setup.pending[owner])?);
        // Move, rather than recompute, the already successful native calculation.
        let calculation = plans.remove(0);
        node.actor
            .send(CompleteQualifiedCalculation {
                calculation,
                roster: roster.clone(),
                shares: DEALERS
                    .iter()
                    .filter(|&&dealer| dealer != owner as u64)
                    .map(|&dealer| artifacts.messages[&(dealer as usize, owner)].clone())
                    .collect(),
            })
            .await??;
        let events = next_events(&node.history, 3).await?;
        ensure!(matches!(
            events[0].get_data(),
            InterfoldEventData::CommitmentRosterSelected(_)
        ));
        let InterfoldEventData::ComputeRequest(request) = events[1].get_data() else {
            anyhow::bail!("expected recovered calculation work");
        };
        let ComputeRequestKind::TrBFV(TrBFVRequest::CalculateDecryptionKey(actual)) =
            &request.request
        else {
            anyhow::bail!("recovery dispatched another calculation kind");
        };
        let expected = &successful[owner].native_request;
        ensure!(request.e3_id == *e3 && actual.trbfv_config == expected.trbfv_config);
        ensure!(actual.esi_sss_collected.is_empty() && expected.esi_sss_collected.is_empty());
        // Replanning seals with fresh AEAD randomness; compare every ordered native share value.
        ensure!(
            actual
                .sk_sss_collected
                .clone()
                .decrypt(&setup.ciphers[owner])?
                == expected
                    .sk_sss_collected
                    .clone()
                    .decrypt(&setup.ciphers[owner])?,
            "recovered calculation inputs differ from the successful native request"
        );
        ensure!(matches!(
            events[2].get_data(),
            InterfoldEventData::DecryptionShareProofsPending(_)
        ));
        let root = node.root(e3).await?;
        let material = root
            .synchronized
            .as_ref()
            .context("production planning lost setup")?;
        let mut expected = successful[owner].material.clone();
        // Planning seals the same keys with fresh local AEAD randomness. Check the independent
        // native anchors now, then require these exact production bytes across each reopen.
        expected.incoming_keys = material.incoming_keys.clone();
        ensure!(material == &expected);
        successful[owner].material = material.clone();
        ensure!(
            root.decryption_key_shares.is_empty(),
            "provisional C4 retained a dealer slot"
        );
        ensure!(root.decryption_share_proofs_pending.is_some());
    }
    stop(nodes).await?;

    let nodes = open(temp.path(), &setup).await?;
    let mut accepted_c4 = Vec::new();
    for (owner, node) in nodes.iter().enumerate() {
        let saved = node.root(e3).await?;
        ensure!(saved.dkg_roster.as_ref() == Some(&roster));
        ensure!(saved.encryption_keys.len() == 3);
        ensure!(saved
            .encryption_keys
            .iter()
            .all(|(&id, key)| **key == artifacts.keys[id as usize]));
        let material = saved.synchronized.as_ref().context("lost material")?;
        ensure!(material == &successful[owner].material);
        ensure!(material.dealer_ids == DEALERS.iter().map(|&id| id as u32).collect::<Vec<_>>());
        material.validate(
            &setup.selected[owner],
            setup.interfold,
            &*cipher(owner).await?,
        )?;
        ensure!(material
            .validate(
                &setup.selected[owner],
                setup.interfold,
                &*cipher((owner + 1) % 3).await?
            )
            .is_err());
        let pending = saved
            .decryption_share_proofs_pending
            .as_ref()
            .context("lost C4 intent")?;
        ensure!(pending.esm_requests.is_empty());
        ensure!(pending.sk_request == successful[owner].request);
        ensure!(pending.sk_request.own_plaintext_idx == [Some(0), None, Some(1)][owner]);
        ensure!(node
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        node.actor
            .send(keyshare_event(
                provisional[peers[owner]].clone(),
                600,
                EventSource::Net,
            ))
            .await?;
        ensure!(node.root(e3).await?.decryption_key_shares.is_empty());
        node.actor.send(AssertReplayQuiescent).await??;
        node.enable(601).await?;
        let mut replayed = Vec::new();
        for _ in 0..2 {
            replayed.push(next_event(&node.history).await?.into_data());
        }
        ensure!(replayed.iter().any(
            |data| matches!(data, InterfoldEventData::ThresholdSharePending(value)
            if value == &setup.pending[owner])
        ));
        let request = replayed
            .into_iter()
            .find_map(|data| match data {
                InterfoldEventData::DecryptionShareProofsPending(value) => Some(value),
                _ => None,
            })
            .context("C4 intent was not resumed")?;
        ensure!(bincode::serialize(&request)? == bincode::serialize(&**pending)?);
        let input = prepare_share_decryption(
            &setup.config,
            &request.sk_request,
            e3,
            &*cipher(owner).await?,
        )?;
        let proof = match prover {
            Some(prover) => sign_proof(
                &setup,
                owner,
                ProofType::C4aSkShareDecryption,
                prove_prepared(
                    &adapters::ShareDecryptionCircuit,
                    prover,
                    &setup.config,
                    &input,
                    owner as u64,
                )?,
            )?,
            None => signed(
                &setup,
                owner,
                ProofType::C4aSkShareDecryption,
                c4_fields(&request.sk_request, material, e3)?,
            )?,
        };
        material.validate_c4(&setup.config, e3, owner as u32, &proof)?;
        accepted_c4.push(c4_message(&setup, owner, proof)?);
    }
    for (owner, node) in nodes.iter().enumerate() {
        let valid = accepted_c4[peers[owner]].clone();
        let mut forged = valid.clone();
        forged.signature = Default::default();
        node.actor
            .send(keyshare_event(forged, 700, EventSource::Net))
            .await?;
        ensure!(node.root(e3).await?.decryption_key_shares.is_empty());
        node.actor
            .send(keyshare_event(valid.clone(), 701, EventSource::Net))
            .await?;
        ensure!(node
            .root(e3)
            .await?
            .decryption_key_shares
            .get(&(peers[owner] as u64))
            .is_some_and(|saved| **saved == valid));
    }
    stop(nodes).await?;

    let nodes = open(temp.path(), &setup).await?;
    let mut recovered = Vec::new();
    let mut recovered_pending = Vec::new();
    for (owner, node) in nodes.iter().enumerate() {
        let saved = node.root(e3).await?;
        ensure!(saved.dkg_roster.as_ref() == Some(&roster));
        ensure!(saved
            .decryption_key_shares
            .get(&(peers[owner] as u64))
            .is_some_and(|value| **value == accepted_c4[peers[owner]]));
        let material = saved
            .synchronized
            .as_ref()
            .context("lost C4 key material")?;
        ensure!(material == &successful[owner].material);
        let binding = setup_binding(&material.context, e3)?;
        let incoming = material
            .incoming_keys
            .as_ref()
            .context("lost incoming keys")?
            .open(PROFILE, binding, owner as u32, 2, &*cipher(owner).await?)?;
        for (row, &dealer) in DEALERS.iter().enumerate() {
            let outgoing = setup.material[dealer as usize].outgoing_keys.open(
                PROFILE,
                binding,
                dealer as u32,
                3,
                &*cipher(dealer as usize).await?,
            )?;
            ensure!(
                incoming[row].as_bytes() == outgoing[owner].as_bytes(),
                "restored directed keys disagree for dealer {dealer}, recipient {owner}"
            );
        }
        let state = node
            .repositories
            .threshold_keyshare(e3)
            .read()
            .await?
            .context("lost state")?;
        ensure!(state.honest_parties == Some(DEALERS.into()) && state.dkg_roster_fixed);
        ensure!(!state.keyshare_published);
        let KeyshareState::ReadyForDecryption(state) = state.state else {
            anyhow::bail!("reopen lost the completed native calculation");
        };
        ensure!(state.sk_poly_sum == successful[owner].response.sk_poly_sum);
        ensure!(state.es_poly_sum.is_empty());
        ensure!(state.pk_share == setup.pending[owner].full_share.pk_share);
        ensure!(state.signed_pk_generation_proof.as_ref() == Some(&artifacts.c1[owner]));
        ensure!(
            state.signed_sk_share_computation_proof.as_ref() == Some(&setup.c2[&(owner as u64)])
        );
        let expected_c3: Vec<_> = artifacts
            .messages
            .iter()
            .filter(|((dealer, _), _)| *dealer == owner)
            .flat_map(|(_, message)| message.signed_c3a_proofs.clone())
            .collect();
        ensure!(state.signed_sk_share_encryption_proofs == expected_c3);
        ensure!(state.signed_e_sm_share_computation_proof.is_none());
        ensure!(state.signed_e_sm_share_encryption_proofs.is_empty());
        ensure!(node
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        let payloads = ThresholdKeyshareRecoveryPayloads::load(
            node.repositories.threshold_keyshare_recovery_payloads(e3),
            &saved,
        )
        .await?;
        recovered_pending.push((**payloads.pending().context("lost dealer proof plan")?).clone());
        recovered.push((saved, state));
    }
    let qualified = match prover {
        Some(prover) => {
            publication::qualify(
                &recovered,
                &recovered_pending,
                &accepted_c4,
                prover,
                temp.path(),
                chain.as_ref().context("missing qualification chain")?,
                &setup.signers,
            )
            .await
        }
        None => Ok(()),
    };
    let stopped = stop(nodes).await;
    if let Err(error) = qualified {
        let evidence = temp.keep();
        let error = error.context(format!(
            "Recovered publication fixture retained at {}",
            evidence.display(),
        ));
        return Err(match stopped {
            Ok(()) => error,
            Err(stop_error) => {
                error.context(format!("fixture shutdown also failed: {stop_error:#}"))
            }
        });
    }
    stopped?;
    ensure!(!PROFILE.admission_enabled());
    Ok(())
}

#[actix::test]
async fn synchronized_disk_reopen_restores_actor_work_and_releases_rejected_slots() -> Result<()> {
    exercise(None).await
}

#[actix::test]
#[ignore = "requires pinned nargo/bb, solc 0.8.28, Anvil, pnpm and built contract artifacts; restored setup through DKG and plaintext publication"]
async fn synchronized_disk_reopen_uses_real_proofs_and_restored_private_inputs() -> Result<()> {
    let mut circuits = CircuitName::SYNCHRONIZED_DKG.to_vec();
    circuits.extend([
        CircuitName::ThresholdShareDecryption,
        CircuitName::DecryptedSharesAggregation,
        CircuitName::DecryptionAggregator,
    ]);
    let (directory, prover) = real_prover(&circuits)?;
    if let Err(error) = exercise(Some(&prover)).await {
        let evidence = directory.keep();
        return Err(error.context(format!(
            "Proof artifacts retained at {}",
            evidence.display()
        )));
    }
    Ok(())
}
