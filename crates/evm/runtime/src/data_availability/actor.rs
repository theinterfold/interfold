// SPDX-License-Identifier: LGPL-3.0-only

//! Recovery-safe assembly and retrieval for large protocol objects.

use actix::{
    Actor, ActorContext, ActorFutureExt, AsyncContext, Context, Handler, Message, WrapFuture,
};
use alloy::primitives::keccak256;
use e3_bfv_client::validate_pk_commitment;
use e3_config::chain_config::{DataAvailabilityConfig, DataAvailabilityMode};
use e3_data::Repository;
use e3_data_availability::{
    public_key::{self, ChunkLayout},
    AvailReader, DataAvailabilityReader, DataReference, HttpObjectReader,
};
use e3_events::{
    prelude::*, BusHandle, CiphertextOutputPublished, CiphertextOutputReferencePublished,
    CommitteePublicKeyChunkPublished, CommitteePublished, E3id, EType, EventContext,
    EventPublisher, EventType, InterfoldEvent, InterfoldEventData, Sequenced,
};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_utils::{ArcBytes, MAILBOX_LIMIT};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tracing::{info, warn};

const OUTPUT_RETRY_DELAY: Duration = Duration::from_secs(30);
pub const DATA_AVAILABILITY_RECOVERY_SCHEMA_VERSION: u32 = 2;

type CandidateKey = (E3id, String, [u8; 32]);

fn validate_committee_public_key(
    public_key: &[u8],
    expected_commitment: [u8; 32],
    preset: BfvPreset,
) -> anyhow::Result<()> {
    // The final committee key uses threshold parameters. DKG parameters apply only to temporary
    // share-transport keys.
    let params = BfvParamSet::from(preset);
    validate_pk_commitment(
        public_key,
        expected_commitment,
        params.degree,
        params.plaintext_modulus,
        params.moduli.to_vec(),
    )
}

fn is_late_fact_for_terminal_e3(event: &InterfoldEventData, terminal_e3s: &HashSet<E3id>) -> bool {
    event
        .get_e3_id()
        .is_some_and(|e3_id| terminal_e3s.contains(&e3_id))
        && !matches!(
            event,
            InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::E3Failed(_)
        )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OutputReference {
    event: CiphertextOutputReferencePublished,
    cause: EventContext<Sequenced>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct KeyAssembly {
    nodes: Vec<String>,
    pk_commitment: [u8; 32],
    total_length: u32,
    chunks: Vec<Option<ArcBytes>>,
}

/// Durable transport projection used when the EVM replay begins after a snapshot boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataAvailabilityRecoveryState {
    pub schema_version: u32,
    presets: HashMap<E3id, BfvPreset>,
    assemblies: HashMap<CandidateKey, KeyAssembly>,
    selected_candidates: HashMap<(E3id, String), [u8; 32]>,
    invalid_candidates: HashSet<CandidateKey>,
    published_keys: HashSet<E3id>,
    pending_outputs: HashMap<E3id, OutputReference>,
    resolved_outputs: HashSet<E3id>,
    terminal_e3s: HashSet<E3id>,
}

impl Default for DataAvailabilityRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: DATA_AVAILABILITY_RECOVERY_SCHEMA_VERSION,
            presets: HashMap::new(),
            assemblies: HashMap::new(),
            selected_candidates: HashMap::new(),
            invalid_candidates: HashSet::new(),
            published_keys: HashSet::new(),
            pending_outputs: HashMap::new(),
            resolved_outputs: HashSet::new(),
            terminal_e3s: HashSet::new(),
        }
    }
}

impl KeyAssembly {
    pub(crate) fn event_shape_is_valid(event: &CommitteePublicKeyChunkPublished) -> bool {
        ChunkLayout::new(event.total_length as usize).is_ok_and(|layout| {
            layout.accepts(event.chunk_index, event.chunk_count, event.chunk.len())
        })
    }

    pub(crate) fn new(event: &CommitteePublicKeyChunkPublished) -> Self {
        Self {
            nodes: event.nodes.clone(),
            pk_commitment: event.pk_commitment,
            total_length: event.total_length,
            chunks: vec![None; usize::from(event.chunk_count)],
        }
    }

    fn metadata_matches(&self, event: &CommitteePublicKeyChunkPublished) -> bool {
        self.nodes == event.nodes
            && self.pk_commitment == event.pk_commitment
            && self.total_length == event.total_length
            && self.chunks.len() == usize::from(event.chunk_count)
    }

    pub(crate) fn insert(&mut self, event: &CommitteePublicKeyChunkPublished) -> bool {
        if !self.metadata_matches(event) {
            return false;
        }
        public_key::insert_chunk(&mut self.chunks, event.chunk_index, &event.chunk, || {
            event.chunk.clone()
        })
    }

    pub(crate) fn validated_bytes(
        &self,
        candidate_hash: [u8; 32],
        preset: BfvPreset,
    ) -> Option<Vec<u8>> {
        let bytes = self.bytes()?;
        if keccak256(&bytes).0 != candidate_hash
            || validate_committee_public_key(&bytes, self.pk_commitment, preset).is_err()
        {
            return None;
        }
        Some(bytes)
    }

    pub(crate) fn matches_authority(
        &self,
        nodes: &[alloy::primitives::Address],
        commitment: [u8; 32],
    ) -> bool {
        self.pk_commitment == commitment
            && self
                .nodes
                .iter()
                .map(|node| node.parse())
                .collect::<Result<Vec<alloy::primitives::Address>, _>>()
                .as_deref()
                == Ok(nodes)
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        public_key::assemble_chunks(self.total_length, &self.chunks)
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct RetrieveOutput(E3id);

/// Converts durable transport facts into the existing in-memory protocol events.
///
/// Historical replay performs no network I/O and emits no derived events. Once
/// `EffectsEnabled` arrives, complete key assemblies and unresolved DA references resume, except
/// for the E3s that startup reports as finished.
pub struct DataAvailabilityCoordinator {
    chain_id: u64,
    bus: BusHandle,
    reader: Option<Arc<dyn DataAvailabilityReader>>,
    effects_enabled: bool,
    presets: HashMap<E3id, BfvPreset>,
    assemblies: HashMap<CandidateKey, KeyAssembly>,
    selected_candidates: HashMap<(E3id, String), [u8; 32]>,
    invalid_candidates: HashSet<CandidateKey>,
    published_keys: HashSet<E3id>,
    publishing_keys: HashSet<E3id>,
    pending_outputs: HashMap<E3id, OutputReference>,
    resolved_outputs: HashSet<E3id>,
    retrieving_outputs: HashSet<E3id>,
    terminal_e3s: HashSet<E3id>,
    recovery: Repository<DataAvailabilityRecoveryState>,
}

impl DataAvailabilityCoordinator {
    /// Start the coordinator for one chain from its recovery state.
    ///
    /// `finished` holds the E3s whose work ends at startup: those whose local lifecycle stage is
    /// terminal, and failed E3s that keep their contexts only for accusation or slashing work.
    /// Their restored work is dropped before `EffectsEnabled`, and later facts for them are
    /// ignored.
    pub async fn attach(
        bus: &BusHandle,
        chain_id: u64,
        config: Option<&DataAvailabilityConfig>,
        recovery: Repository<DataAvailabilityRecoveryState>,
        finished: &HashSet<E3id>,
    ) -> anyhow::Result<()> {
        let reader: Option<Arc<dyn DataAvailabilityReader>> = match config {
            Some(config) => Some(match config.mode {
                DataAvailabilityMode::Avail => Arc::new(AvailReader::new(&config.rpc_url)?),
                DataAvailabilityMode::MockHttp => Arc::new(HttpObjectReader::new(&config.rpc_url)?),
            }),
            None => None,
        };
        let recovered = recovery.read().await?.unwrap_or_default();
        anyhow::ensure!(
            recovered.schema_version == DATA_AVAILABILITY_RECOVERY_SCHEMA_VERSION,
            "unsupported data-availability recovery schema {} for chain {}",
            recovered.schema_version,
            chain_id
        );
        let mut coordinator = Self {
            chain_id,
            bus: bus.clone(),
            reader,
            effects_enabled: false,
            presets: recovered.presets,
            assemblies: recovered.assemblies,
            selected_candidates: recovered.selected_candidates,
            invalid_candidates: recovered.invalid_candidates,
            published_keys: recovered.published_keys,
            publishing_keys: HashSet::new(),
            pending_outputs: recovered.pending_outputs,
            resolved_outputs: recovered.resolved_outputs,
            retrieving_outputs: HashSet::new(),
            terminal_e3s: recovered.terminal_e3s,
            recovery,
        };
        // The next recovery write stores this, at the latest at `EffectsEnabled`. Until then, the
        // lifecycle store gives the same set on every start.
        for e3_id in finished.iter().filter(|e3_id| e3_id.chain_id() == chain_id) {
            coordinator.complete(e3_id);
        }
        let addr = coordinator.start();
        bus.subscribe_all(
            &[
                EventType::E3Requested,
                EventType::CommitteePublicKeyChunkPublished,
                EventType::CommitteePublished,
                EventType::CiphertextOutputReferencePublished,
                EventType::CiphertextOutputPublished,
                EventType::EffectsEnabled,
                EventType::E3RequestComplete,
                EventType::E3Failed,
                EventType::Shutdown,
            ],
            addr.into(),
        );
        Ok(())
    }

    fn recovery_state(&self) -> DataAvailabilityRecoveryState {
        DataAvailabilityRecoveryState {
            schema_version: DATA_AVAILABILITY_RECOVERY_SCHEMA_VERSION,
            presets: self.presets.clone(),
            assemblies: self.assemblies.clone(),
            selected_candidates: self.selected_candidates.clone(),
            invalid_candidates: self.invalid_candidates.clone(),
            published_keys: self.published_keys.clone(),
            pending_outputs: self.pending_outputs.clone(),
            resolved_outputs: self.resolved_outputs.clone(),
            terminal_e3s: self.terminal_e3s.clone(),
        }
    }

    fn persist(&self, cause: &EventContext<Sequenced>) -> anyhow::Result<()> {
        self.recovery
            .write_with_context(&self.recovery_state(), cause)
    }

    fn try_publish_keys(&mut self) {
        if !self.effects_enabled {
            return;
        }
        let keys: Vec<CandidateKey> = self.assemblies.keys().cloned().collect();
        for key in keys {
            if self.invalid_candidates.contains(&key)
                || self.published_keys.contains(&key.0)
                || self.publishing_keys.contains(&key.0)
            {
                continue;
            }
            let Some(preset) = self.presets.get(&key.0).copied() else {
                continue;
            };
            let Some(assembly) = self.assemblies.get(&key) else {
                continue;
            };
            let Some(bytes) = assembly.bytes() else {
                continue;
            };
            if assembly.validated_bytes(key.2, preset).is_none() {
                warn!(e3_id = %key.0, publisher = %key.1, "Rejecting public-key chunks that do not match the candidate hash or key commitment");
                self.invalid_candidates.insert(key);
                continue;
            }

            let event = CommitteePublished {
                e3_id: key.0.clone(),
                nodes: assembly.nodes.clone(),
                public_key: ArcBytes::from_bytes(&bytes),
                proof: ArcBytes::from_bytes(&[]),
            };
            self.publishing_keys.insert(key.0.clone());
            if let Err(error) = self.bus.publish_without_context(event) {
                warn!(e3_id = %key.0, %error, "Could not publish the assembled committee public key");
                self.publishing_keys.remove(&key.0);
            } else {
                info!(e3_id = %key.0, bytes = bytes.len(), "Verified and assembled the chunked committee public key");
            }
        }
    }

    fn start_output(&mut self, e3_id: &E3id, ctx: &mut Context<Self>) {
        if !self.effects_enabled
            || self.reader.is_none()
            || self.terminal_e3s.contains(e3_id)
            || self.resolved_outputs.contains(e3_id)
            || !self.pending_outputs.contains_key(e3_id)
            || !self.retrieving_outputs.insert(e3_id.clone())
        {
            return;
        }
        ctx.notify(RetrieveOutput(e3_id.clone()));
    }

    /// Make the E3 terminal and drop its work, so that later facts cannot recreate it.
    fn complete(&mut self, e3_id: &E3id) {
        self.terminal_e3s.insert(e3_id.clone());
        self.cleanup(e3_id);
    }

    fn cleanup(&mut self, e3_id: &E3id) {
        self.presets.remove(e3_id);
        self.pending_outputs.remove(e3_id);
        self.retrieving_outputs.remove(e3_id);
        self.published_keys.remove(e3_id);
        self.publishing_keys.remove(e3_id);
        self.resolved_outputs.remove(e3_id);
        self.assemblies.retain(|key, _| &key.0 != e3_id);
        self.selected_candidates.retain(|key, _| &key.0 != e3_id);
        self.invalid_candidates.retain(|key| &key.0 != e3_id);
    }
}

impl Actor for DataAvailabilityCoordinator {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for DataAvailabilityCoordinator {
    type Result = ();

    fn handle(&mut self, message: InterfoldEvent, ctx: &mut Self::Context) {
        let (event, cause) = message.into_components();
        if event
            .get_e3_id()
            .is_some_and(|e3_id| e3_id.chain_id() != self.chain_id)
        {
            return;
        }
        if is_late_fact_for_terminal_e3(&event, &self.terminal_e3s) {
            return;
        }
        let persists_recovery = matches!(
            &event,
            InterfoldEventData::E3Requested(_)
                | InterfoldEventData::CommitteePublicKeyChunkPublished(_)
                | InterfoldEventData::CommitteePublished(_)
                | InterfoldEventData::CiphertextOutputReferencePublished(_)
                | InterfoldEventData::CiphertextOutputPublished(_)
                | InterfoldEventData::EffectsEnabled(_)
                | InterfoldEventData::E3RequestComplete(_)
        );
        match event {
            InterfoldEventData::E3Requested(event) => {
                self.presets.insert(event.e3_id, event.params_preset);
                self.try_publish_keys();
            }
            InterfoldEventData::CommitteePublicKeyChunkPublished(event) => {
                if !KeyAssembly::event_shape_is_valid(&event) {
                    warn!(e3_id = %event.e3_id, publisher = %event.publisher, "Ignoring a malformed public-key chunk");
                    return;
                }
                let publisher_key = (event.e3_id.clone(), event.publisher.clone());
                let selected = self
                    .selected_candidates
                    .entry(publisher_key)
                    .or_insert(event.candidate_hash);
                if *selected != event.candidate_hash {
                    warn!(e3_id = %event.e3_id, publisher = %event.publisher, "Ignoring a second public-key candidate from one committee member");
                    return;
                }
                let key = (
                    event.e3_id.clone(),
                    event.publisher.clone(),
                    event.candidate_hash,
                );
                if self.invalid_candidates.contains(&key) {
                    return;
                }
                let assembly = self
                    .assemblies
                    .entry(key.clone())
                    .or_insert_with(|| KeyAssembly::new(&event));
                if !assembly.insert(&event) {
                    warn!(e3_id = %event.e3_id, publisher = %event.publisher, "Rejecting inconsistent public-key chunks");
                    self.invalid_candidates.insert(key);
                }
                self.try_publish_keys();
            }
            // A locally derived publication is durable. Replaying it prevents the coordinator
            // from appending the same derived event on every restart.
            InterfoldEventData::CommitteePublished(event) => {
                self.publishing_keys.remove(&event.e3_id);
                self.published_keys.insert(event.e3_id.clone());
                self.assemblies.retain(|key, _| key.0 != event.e3_id);
                self.selected_candidates
                    .retain(|key, _| key.0 != event.e3_id);
                self.invalid_candidates.retain(|key| key.0 != event.e3_id);
            }
            InterfoldEventData::CiphertextOutputReferencePublished(event) => {
                let e3_id = event.e3_id.clone();
                self.pending_outputs.insert(
                    e3_id.clone(),
                    OutputReference {
                        event,
                        cause: cause.clone(),
                    },
                );
                if self.reader.is_none() && self.effects_enabled {
                    warn!(%e3_id, "Cannot retrieve a ciphertext output because data availability is not configured");
                }
                self.start_output(&e3_id, ctx);
            }
            InterfoldEventData::CiphertextOutputPublished(event) => {
                self.resolved_outputs.insert(event.e3_id.clone());
                self.pending_outputs.remove(&event.e3_id);
                self.retrieving_outputs.remove(&event.e3_id);
            }
            InterfoldEventData::EffectsEnabled(_) => {
                self.effects_enabled = true;
                self.try_publish_keys();
                for e3_id in self.pending_outputs.keys().cloned().collect::<Vec<_>>() {
                    self.start_output(&e3_id, ctx);
                }
            }
            InterfoldEventData::E3RequestComplete(event) => self.complete(&event.e3_id),
            // `E3Failed` can be a local failure proposal which the chain has not accepted yet.
            // `E3RequestComplete` is the router's durable teardown fact, so only that event makes
            // this projection terminal and prevents later chain events from recreating state.
            InterfoldEventData::E3Failed(_) => {}
            InterfoldEventData::Shutdown(_) => ctx.stop(),
            _ => {}
        }
        if persists_recovery {
            if let Err(error) = self.persist(&cause) {
                self.bus.with_ec(&cause).err(EType::Evm, error);
            }
        }
    }
}

impl Handler<RetrieveOutput> for DataAvailabilityCoordinator {
    type Result = actix::ResponseActFuture<Self, ()>;

    fn handle(&mut self, message: RetrieveOutput, _: &mut Self::Context) -> Self::Result {
        let e3_id = message.0;
        let Some(reader) = self.reader.clone() else {
            self.retrieving_outputs.remove(&e3_id);
            return Box::pin(async {}.into_actor(self));
        };
        let Some(pending) = self.pending_outputs.get(&e3_id).cloned() else {
            self.retrieving_outputs.remove(&e3_id);
            return Box::pin(async {}.into_actor(self));
        };
        let reference = DataReference {
            content_hash: pending.event.content_hash,
            block_number: pending.event.availability_block,
            leaf_index: pending.event.availability_leaf_index,
        };

        Box::pin(
            async move { reader.retrieve(reference).await }
                .into_actor(self)
                .map(move |result, actor, ctx| match result {
                    Ok(bytes) => {
                        if actor.terminal_e3s.contains(&e3_id) {
                            actor.retrieving_outputs.remove(&e3_id);
                            return;
                        }
                        let event = CiphertextOutputPublished {
                            e3_id: e3_id.clone(),
                            ciphertext_output: vec![ArcBytes::from_bytes(&bytes)],
                            ciphertext_commitment: pending.event.ciphertext_commitment,
                        };
                        actor.retrieving_outputs.remove(&e3_id);
                        if let Err(error) = actor.bus.publish(event, pending.cause) {
                            warn!(%e3_id, %error, "Could not publish the retrieved ciphertext output");
                            ctx.run_later(OUTPUT_RETRY_DELAY, move |actor, ctx| {
                                actor.start_output(&e3_id, ctx);
                            });
                        }
                    }
                    Err(error) => {
                        warn!(%e3_id, %error, "Ciphertext output is not retrievable yet; retrying");
                        actor.retrieving_outputs.remove(&e3_id);
                        ctx.run_later(OUTPUT_RETRY_DELAY, move |actor, ctx| {
                            actor.start_output(&e3_id, ctx);
                        });
                    }
                }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_bfv_client::{client::generate_public_key, compute_pk_commitment};
    use e3_data_availability::public_key::PUBLIC_KEY_CHUNK_BYTES;

    fn chunk_event(bytes: &[u8], chunk_index: u16) -> CommitteePublicKeyChunkPublished {
        let layout = ChunkLayout::new(bytes.len()).unwrap();
        CommitteePublicKeyChunkPublished {
            e3_id: E3id::new("7", 1),
            publisher: "0x0000000000000000000000000000000000000001".to_owned(),
            candidate_hash: keccak256(bytes).0,
            nodes: vec!["0x0000000000000000000000000000000000000001".to_owned()],
            pk_commitment: [9; 32],
            chunk_index,
            chunk_count: layout.chunk_count(),
            total_length: layout.total_length(),
            chunk: ArcBytes::from_bytes(&bytes[layout.range(chunk_index).unwrap()]),
        }
    }

    #[test]
    fn deterministic_chunks_reassemble_in_index_order() {
        let bytes = (0..(3 * PUBLIC_KEY_CHUNK_BYTES + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut events = (0..ChunkLayout::new(bytes.len()).unwrap().chunk_count())
            .map(|index| chunk_event(&bytes, index))
            .collect::<Vec<_>>();
        let mut assembly = KeyAssembly::new(&events[0]);

        events.reverse();
        for event in &events {
            assert!(KeyAssembly::event_shape_is_valid(event));
            assert!(assembly.insert(event));
        }

        assert_eq!(assembly.bytes().as_deref(), Some(bytes.as_slice()));
    }

    #[test]
    fn malformed_or_conflicting_chunks_are_rejected() {
        let bytes = vec![3; PUBLIC_KEY_CHUNK_BYTES + 1];
        let first = chunk_event(&bytes, 0);
        let mut malformed = first.clone();
        malformed.chunk = ArcBytes::from_bytes(&[3; 16]);
        assert!(!KeyAssembly::event_shape_is_valid(&malformed));

        let mut assembly = KeyAssembly::new(&first);
        assert!(assembly.insert(&first));
        let mut conflicting = first;
        conflicting.chunk = ArcBytes::from_bytes(&vec![4; PUBLIC_KEY_CHUNK_BYTES]);
        assert!(!assembly.insert(&conflicting));
    }

    #[test]
    fn terminal_e3_rejects_late_transport_facts() {
        let bytes = vec![3; PUBLIC_KEY_CHUNK_BYTES + 1];
        let event = chunk_event(&bytes, 0);
        let terminal_e3s = HashSet::from([event.e3_id.clone()]);

        assert!(is_late_fact_for_terminal_e3(
            &InterfoldEventData::CommitteePublicKeyChunkPublished(event),
            &terminal_e3s,
        ));
    }

    #[test]
    fn partial_assembly_survives_the_repository_encoding() {
        let bytes = vec![3; PUBLIC_KEY_CHUNK_BYTES + 1];
        let first = chunk_event(&bytes, 0);
        let key = (
            first.e3_id.clone(),
            first.publisher.clone(),
            first.candidate_hash,
        );
        let mut assembly = KeyAssembly::new(&first);
        assert!(assembly.insert(&first));
        let mut state = DataAvailabilityRecoveryState::default();
        state.assemblies.insert(key.clone(), assembly);
        state
            .selected_candidates
            .insert((first.e3_id, first.publisher), first.candidate_hash);
        state.terminal_e3s.insert(E3id::new("8", 1));

        let encoded = bincode::serialize(&state).expect("encode recovery state");
        let recovered: DataAvailabilityRecoveryState =
            bincode::deserialize(&encoded).expect("decode recovery state");

        assert!(recovered.assemblies.contains_key(&key));
        assert!(recovered.assemblies[&key].bytes().is_none());
        assert!(recovered.terminal_e3s.contains(&E3id::new("8", 1)));
    }

    #[test]
    fn legacy_key_assembly_encoding_stays_readable() {
        let bytes = vec![3; 92_161];
        let last = chunk_event(&bytes, 1);
        let mut assembly = KeyAssembly::new(&last);
        assert!(assembly.insert(&last));
        // Captured before extracting transport mechanics; never regenerate from the new helper.
        let frozen = hex::decode("01000000000000002a0000000000000030783030303030303030303030303030303030303030303030303030303030303030303030303030303109090909090909090909090909090909090909090909090909090909090909090168010002000000000000000001010000000000000003").unwrap();
        assert_eq!(bincode::serialize(&assembly).unwrap(), frozen);
        let mut recovered: KeyAssembly = bincode::deserialize(&frozen).unwrap();
        assert!(recovered.bytes().is_none());
        assert!(recovered.insert(&chunk_event(&bytes, 0)));
        assert_eq!(recovered.bytes().unwrap(), bytes);
    }

    fn test_bus() -> BusHandle {
        use e3_data::{InMemEventLog, InMemSequenceIndex};
        use e3_events::{hlc_factory::HlcFactory, EventBus, EventStore, Sequencer};

        let event_bus = EventBus::<InterfoldEvent>::default().start();
        let store = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())
            .expect("in-memory EventStore")
            .start();
        let sequencer =
            Sequencer::new_with_flush(&event_bus, store.clone().recipient(), store.recipient())
                .start();
        BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("data-availability-test")
    }

    /// Store a complete, valid committee key assembly for each E3.
    fn complete_assemblies(e3_ids: &[&E3id], preset: BfvPreset) -> DataAvailabilityRecoveryState {
        let params = BfvParamSet::from(preset);
        let public_key = generate_public_key(
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )
        .expect("generate threshold public key");
        let pk_commitment = compute_pk_commitment(
            public_key.clone(),
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )
        .expect("compute C5 commitment");
        let mut state = DataAvailabilityRecoveryState::default();
        for e3_id in e3_ids {
            let chunk_count = ChunkLayout::new(public_key.len()).unwrap().chunk_count();
            let mut assembly = None;
            for chunk_index in 0..chunk_count {
                let event = CommitteePublicKeyChunkPublished {
                    e3_id: (*e3_id).clone(),
                    pk_commitment,
                    ..chunk_event(&public_key, chunk_index)
                };
                let assembly = assembly.get_or_insert_with(|| KeyAssembly::new(&event));
                assert!(assembly.insert(&event));
            }
            let key = (
                (*e3_id).clone(),
                "0x0000000000000000000000000000000000000001".to_owned(),
                keccak256(&public_key).0,
            );
            state.presets.insert((*e3_id).clone(), preset);
            state
                .selected_candidates
                .insert((key.0.clone(), key.1.clone()), key.2);
            state
                .assemblies
                .insert(key, assembly.expect("at least one chunk"));
        }
        state
    }

    #[actix::test]
    async fn finished_e3s_resume_no_work_at_effects_enabled() -> anyhow::Result<()> {
        use crate::DataAvailabilityRepositoryFactory;
        use e3_data::{DataStore, InMemStore, RepositoriesFactory};
        use e3_events::GetEvents;

        let (active, finished, other_chain) =
            (E3id::new("7", 1), E3id::new("8", 1), E3id::new("8", 2));
        let recovery = DataStore::from_in_mem(&InMemStore::new(false).start())
            .repositories()
            .data_availability_recovery(1);
        recovery
            .write_sync(&complete_assemblies(
                &[&active, &finished],
                BfvPreset::InsecureThreshold64,
            ))
            .await?;
        let bus = test_bus();
        let history = bus.history();

        DataAvailabilityCoordinator::attach(
            &bus,
            1,
            None,
            recovery.clone(),
            &HashSet::from([finished.clone(), other_chain.clone()]),
        )
        .await?;
        // A fact for the finished E3 that the replay delivers after startup.
        bus.publish_without_context(CiphertextOutputReferencePublished {
            e3_id: finished.clone(),
            content_hash: [1; 32],
            ciphertext_commitment: [2; 32],
            availability_block: 3,
            availability_leaf_index: 4,
        })?;
        bus.publish_without_context(e3_events::EffectsEnabled::new())?;
        bus.flush_event_pipeline().await?;
        actix::clock::sleep(Duration::from_millis(100)).await;

        let published: Vec<E3id> = history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .into_iter()
            .filter_map(|event| match event.get_data() {
                InterfoldEventData::CommitteePublished(event) => Some(event.e3_id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(published, vec![active.clone()]);
        let state = recovery.read().await?.expect("recovery state");
        assert!(state.terminal_e3s.contains(&finished));
        assert!(!state.terminal_e3s.contains(&active));
        assert!(!state.terminal_e3s.contains(&other_chain));
        assert!(state.assemblies.keys().all(|key| key.0 == active));
        assert!(!state.presets.contains_key(&finished));
        assert!(state.pending_outputs.is_empty());
        Ok(())
    }

    #[actix::test]
    async fn restart_keeps_selected_and_invalid_candidates_separate() -> anyhow::Result<()> {
        use crate::DataAvailabilityRepositoryFactory;
        use e3_data::{DataStore, InMemStore, RepositoriesFactory};
        use e3_events::GetEvents;

        async fn recovered_when(
            recovery: &Repository<DataAvailabilityRecoveryState>,
            ready: impl Fn(&DataAvailabilityRecoveryState) -> bool,
        ) -> anyhow::Result<DataAvailabilityRecoveryState> {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(state) = recovery.read().await? {
                        if ready(&state) {
                            return Ok(state);
                        }
                    }
                    actix::clock::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?
        }

        let e3_id = E3id::new("7", 1);
        let mut seed = complete_assemblies(&[&e3_id], BfvPreset::SecureThreshold8192);
        let (key, assembly) = seed.assemblies.iter().next().unwrap();
        let key = key.clone();
        let bytes = assembly.bytes().unwrap();
        let commitment = assembly.pk_commitment;
        let layout = ChunkLayout::new(bytes.len())?;
        assert!(layout.chunk_count() > 1);
        let event = |index| CommitteePublicKeyChunkPublished {
            pk_commitment: commitment,
            ..chunk_event(&bytes, index)
        };
        seed.assemblies.clear();
        seed.selected_candidates.clear();
        let recovery = DataStore::from_in_mem(&InMemStore::new(false).start())
            .repositories()
            .data_availability_recovery(1);
        recovery.write_sync(&seed).await?;
        let bus = test_bus();
        DataAvailabilityCoordinator::attach(&bus, 1, None, recovery.clone(), &HashSet::new())
            .await?;
        let last = layout.chunk_count() - 1;
        let mut malformed = event(last);
        malformed.candidate_hash = [0; 32];
        malformed.chunk = ArcBytes::from_bytes(&[]);
        bus.publish_without_context(malformed)?;
        bus.publish_without_context(event(last))?;
        bus.publish_without_context(event(last))?;
        bus.flush_event_pipeline().await?;
        let partial =
            recovered_when(&recovery, |state| state.assemblies.contains_key(&key)).await?;
        assert_eq!(
            partial.selected_candidates[&(key.0.clone(), key.1.clone())],
            key.2
        );
        assert!(partial.assemblies[&key].bytes().is_none());
        bus.publish_shutdown_and_wait().await?;
        bus.flush_event_pipeline().await?;

        let bus = test_bus();
        DataAvailabilityCoordinator::attach(&bus, 1, None, recovery.clone(), &HashSet::new())
            .await?;
        let mut second_candidate = event(0);
        second_candidate.candidate_hash = [0x55; 32];
        bus.publish_without_context(second_candidate)?;
        let mut changed_metadata = event(last);
        changed_metadata.pk_commitment = [0; 32];
        bus.publish_without_context(changed_metadata)?;
        // Neither the original bytes nor another hash from that publisher revives the candidate.
        for index in 0..layout.chunk_count() {
            bus.publish_without_context(event(index))?;
        }
        bus.flush_event_pipeline().await?;
        let invalid =
            recovered_when(&recovery, |state| state.invalid_candidates.contains(&key)).await?;
        assert_eq!(invalid.assemblies.len(), 1);
        bus.publish_shutdown_and_wait().await?;
        bus.flush_event_pipeline().await?;

        let bus = test_bus();
        let history = bus.history();
        DataAvailabilityCoordinator::attach(&bus, 1, None, recovery.clone(), &HashSet::new())
            .await?;
        bus.publish_without_context(event(last))?;
        let good_publisher = "0x0000000000000000000000000000000000000002".to_owned();
        let good_key = (key.0.clone(), good_publisher.clone(), key.2);
        for index in (0..layout.chunk_count()).rev() {
            bus.publish_without_context(CommitteePublicKeyChunkPublished {
                publisher: good_publisher.clone(),
                ..event(index)
            })?;
        }
        bus.flush_event_pipeline().await?;
        let restored = recovered_when(&recovery, |state| {
            state
                .assemblies
                .get(&good_key)
                .is_some_and(|assembly| assembly.bytes().is_some())
        })
        .await?;
        assert!(restored.invalid_candidates.contains(&key));
        assert!(!restored.invalid_candidates.contains(&good_key));
        assert_eq!(restored.assemblies.len(), 2);
        assert_eq!(restored.selected_candidates.len(), 2);
        assert_eq!(restored.assemblies[&good_key].bytes(), Some(bytes.clone()));
        assert!(history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .iter()
            .all(|event| !matches!(event.get_data(), InterfoldEventData::CommitteePublished(_))));

        bus.publish_without_context(e3_events::EffectsEnabled::new())?;
        bus.flush_event_pipeline().await?;
        let published = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                // A derived event is appended after the input handler has run.
                bus.flush_event_pipeline().await?;
                let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
                if let Some(publication) = events.iter().find_map(|event| match event.get_data() {
                    InterfoldEventData::CommitteePublished(event) => Some(event.clone()),
                    _ => None,
                }) {
                    return Ok::<_, anyhow::Error>(publication);
                }
                actix::clock::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        assert_eq!(&published.public_key[..], bytes.as_slice());
        assert_eq!(published.e3_id, e3_id);
        bus.publish_shutdown_and_wait().await?;
        Ok(())
    }

    #[test]
    fn threshold_public_key_is_validated_with_threshold_parameters() {
        let preset = BfvPreset::InsecureThreshold64;
        let params = BfvParamSet::from(preset);
        let public_key = generate_public_key(
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )
        .expect("generate threshold public key");
        let commitment = compute_pk_commitment(
            public_key.clone(),
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )
        .expect("compute C5 commitment");

        validate_committee_public_key(&public_key, commitment, preset)
            .expect("validate threshold public key");
        assert!(validate_committee_public_key(&public_key, [0x55; 32], preset).is_err());
    }
}
