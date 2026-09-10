// SPDX-License-Identifier: LGPL-3.0-only

//! Recovery-safe assembly and retrieval for large protocol objects.

use actix::{
    Actor, ActorContext, ActorFutureExt, AsyncContext, Context, Handler, Message, WrapFuture,
};
use alloy::primitives::keccak256;
use e3_bfv_client::validate_pk_commitment;
use e3_config::chain_config::{DataAvailabilityConfig, DataAvailabilityMode};
use e3_data::Repository;
use e3_data_availability::{AvailReader, DataAvailabilityReader, DataReference, HttpObjectReader};
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
const MAX_PUBLIC_KEY_BYTES: usize = 512 * 1024;
const PUBLIC_KEY_CHUNK_BYTES: usize = 90 * 1024;
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
struct KeyAssembly {
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
    fn event_shape_is_valid(event: &CommitteePublicKeyChunkPublished) -> bool {
        let total_length = event.total_length as usize;
        if total_length == 0 || total_length > MAX_PUBLIC_KEY_BYTES {
            return false;
        }
        let expected_count = total_length.div_ceil(PUBLIC_KEY_CHUNK_BYTES);
        if expected_count != usize::from(event.chunk_count)
            || usize::from(event.chunk_index) >= expected_count
        {
            return false;
        }
        let offset = usize::from(event.chunk_index) * PUBLIC_KEY_CHUNK_BYTES;
        let expected_length = (total_length - offset).min(PUBLIC_KEY_CHUNK_BYTES);
        event.chunk.len() == expected_length
    }

    fn new(event: &CommitteePublicKeyChunkPublished) -> Self {
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

    fn insert(&mut self, event: &CommitteePublicKeyChunkPublished) -> bool {
        if !self.metadata_matches(event) {
            return false;
        }
        let Some(slot) = self.chunks.get_mut(usize::from(event.chunk_index)) else {
            return false;
        };
        if let Some(existing) = slot {
            return existing[..] == event.chunk[..];
        }
        *slot = Some(event.chunk.clone());
        true
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.total_length as usize);
        for chunk in &self.chunks {
            bytes.extend_from_slice(chunk.as_ref()?.as_ref());
        }
        (bytes.len() == self.total_length as usize).then_some(bytes)
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct RetrieveOutput(E3id);

/// Converts durable transport facts into the existing in-memory protocol events.
///
/// Historical replay performs no network I/O and emits no derived events. Once
/// `EffectsEnabled` arrives, complete key assemblies and unresolved DA references resume.
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
    pub async fn attach(
        bus: &BusHandle,
        chain_id: u64,
        config: Option<&DataAvailabilityConfig>,
        recovery: Repository<DataAvailabilityRecoveryState>,
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
        let addr = Self {
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
        }
        .start();
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
            if keccak256(&bytes).0 != key.2 {
                warn!(e3_id = %key.0, publisher = %key.1, "Rejecting public-key chunks with a mismatched candidate hash");
                self.invalid_candidates.insert(key);
                continue;
            }
            if let Err(error) =
                validate_committee_public_key(&bytes, assembly.pk_commitment, preset)
            {
                warn!(e3_id = %key.0, publisher = %key.1, %error, "Rejecting a committee public key that does not match its proven C5 commitment");
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
            InterfoldEventData::E3RequestComplete(event) => {
                self.terminal_e3s.insert(event.e3_id.clone());
                self.cleanup(&event.e3_id);
            }
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

    fn chunk_event(bytes: &[u8], chunk_index: u16) -> CommitteePublicKeyChunkPublished {
        let chunk_count = bytes.len().div_ceil(PUBLIC_KEY_CHUNK_BYTES) as u16;
        let offset = usize::from(chunk_index) * PUBLIC_KEY_CHUNK_BYTES;
        let end = (offset + PUBLIC_KEY_CHUNK_BYTES).min(bytes.len());
        CommitteePublicKeyChunkPublished {
            e3_id: E3id::new("7", 1),
            publisher: "0x0000000000000000000000000000000000000001".to_owned(),
            candidate_hash: keccak256(bytes).0,
            nodes: vec!["0x0000000000000000000000000000000000000001".to_owned()],
            pk_commitment: [9; 32],
            chunk_index,
            chunk_count,
            total_length: bytes.len() as u32,
            chunk: ArcBytes::from_bytes(&bytes[offset..end]),
        }
    }

    #[test]
    fn deterministic_chunks_reassemble_in_index_order() {
        let bytes = (0..(3 * PUBLIC_KEY_CHUNK_BYTES + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut events = (0..bytes.len().div_ceil(PUBLIC_KEY_CHUNK_BYTES) as u16)
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
    fn threshold_public_key_is_validated_with_threshold_parameters() {
        let preset = BfvPreset::InsecureThreshold512;
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
