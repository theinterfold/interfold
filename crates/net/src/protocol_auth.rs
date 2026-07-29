// SPDX-License-Identifier: LGPL-3.0-only

//! EVM-authenticated protocol gossip admission.

use alloy::{
    primitives::{keccak256, Address, Signature},
    signers::{local::PrivateKeySigner, SignerSync},
};
use anyhow::{anyhow, ensure, Context, Result};
use e3_events::{
    Committee, E3id, Event, InterfoldEvent, InterfoldEventData, Sequenced, Unsequenced,
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROTOCOL_GOSSIP_VERSION: u8 = 1;
pub const PROTOCOL_GOSSIP_REPLAY_WINDOW_SECS: u64 = 5 * 60;
pub const PROTOCOL_GOSSIP_RATE_WINDOW_SECS: u64 = 60;
pub const MAX_PROTOCOL_EVENTS_PER_PEER_WINDOW: usize = 512;
pub const MAX_PROTOCOL_EVENTS_PER_PEER_E3_WINDOW: usize = 256;
pub const MAX_PROTOCOL_BYTES_PER_PEER_WINDOW: usize = 128 * 1024 * 1024;
pub const MAX_PROTOCOL_BYTES_PER_PEER_E3_WINDOW: usize = 64 * 1024 * 1024;
const INVALID_EVENTS_BEFORE_QUARANTINE: u32 = 8;
const GOSSIP_DOMAIN: &[u8] = b"interfold/protocol-gossip/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedProtocolEvent {
    pub version: u8,
    pub peer_id: Vec<u8>,
    pub issued_at: u64,
    pub event: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AuthenticatedProtocolEvent {
    fn digest(&self) -> [u8; 32] {
        let mut bytes =
            Vec::with_capacity(GOSSIP_DOMAIN.len() + self.peer_id.len() + self.event.len() + 32);
        bytes.extend_from_slice(GOSSIP_DOMAIN);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&(self.peer_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.peer_id);
        bytes.extend_from_slice(&(self.event.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.event);
        keccak256(bytes).into()
    }

    pub fn recover_address(&self) -> Result<Address> {
        let signature = Signature::try_from(self.signature.as_slice())
            .context("invalid protocol-gossip ECDSA signature")?;
        signature
            .recover_address_from_prehash(&self.digest().into())
            .context("could not recover protocol-gossip signer")
    }
}

#[derive(Clone)]
pub struct ProtocolSigner {
    signer: PrivateKeySigner,
    peer_id: PeerId,
}

impl ProtocolSigner {
    pub fn new(signer: PrivateKeySigner, peer_id: PeerId) -> Self {
        Self { signer, peer_id }
    }

    pub fn address(&self) -> Address {
        self.signer.address()
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn sign_event(
        &self,
        event: InterfoldEvent<Sequenced>,
    ) -> Result<AuthenticatedProtocolEvent> {
        self.sign_event_at(event, unix_time_secs()?)
    }

    pub(crate) fn sign_event_at(
        &self,
        event: InterfoldEvent<Sequenced>,
        issued_at: u64,
    ) -> Result<AuthenticatedProtocolEvent> {
        let mut envelope = AuthenticatedProtocolEvent {
            version: PROTOCOL_GOSSIP_VERSION,
            peer_id: self.peer_id.to_bytes(),
            issued_at,
            event: event
                .clone_unsequenced()
                .to_bytes()
                .context("could not serialize protocol event")?,
            signature: Vec::new(),
        };
        let signature = self
            .signer
            .sign_hash_sync(&envelope.digest().into())
            .context("could not sign protocol-gossip envelope")?;
        envelope.signature = signature.as_bytes().to_vec();
        Ok(envelope)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NetworkAuthorizationState {
    committees: HashMap<E3id, Committee>,
    expelled: HashMap<E3id, HashSet<u64>>,
}

impl NetworkAuthorizationState {
    pub fn new(committees: HashMap<E3id, Committee>, expelled: HashMap<E3id, Vec<u64>>) -> Self {
        Self {
            committees,
            expelled: expelled
                .into_iter()
                .map(|(e3_id, parties)| (e3_id, parties.into_iter().collect()))
                .collect(),
        }
    }

    pub fn observe(&mut self, event: &InterfoldEvent) {
        match event.get_data() {
            InterfoldEventData::CommitteeFinalized(event) => {
                let mut committee = event.clone();
                committee.sort_by_address();
                self.committees
                    .insert(event.e3_id.clone(), Committee::new(committee.committee));
            }
            InterfoldEventData::CommitteeMemberExpelled(event) => {
                if let Some(party_id) = event.party_id {
                    self.expelled
                        .entry(event.e3_id.clone())
                        .or_default()
                        .insert(party_id);
                }
            }
            InterfoldEventData::E3RequestComplete(event) => {
                self.committees.remove(&event.e3_id);
                self.expelled.remove(&event.e3_id);
            }
            _ => {}
        }
    }

    fn authorize(&self, signer: Address, event: &InterfoldEvent<Unsequenced>) -> Result<E3id> {
        let e3_id = event
            .get_e3_id()
            .ok_or_else(|| anyhow!("protocol event has no E3 identity"))?;
        let committee = self
            .committees
            .get(&e3_id)
            .ok_or_else(|| anyhow!("no current finalized committee for {e3_id}"))?;
        let signer_string = signer.to_string();
        let party_id = committee
            .party_id_for(&signer_string)
            .ok_or_else(|| anyhow!("signer is not a committee member for {e3_id}"))?;
        ensure!(
            !self
                .expelled
                .get(&e3_id)
                .is_some_and(|parties| parties.contains(&party_id)),
            "signer is expelled from committee for {e3_id}"
        );

        match event.get_data() {
            InterfoldEventData::KeyshareCreated(data) => {
                ensure_declared_party(committee, signer, &data.node, data.party_id)?;
            }
            InterfoldEventData::DecryptionshareCreated(data) => {
                ensure_declared_party(committee, signer, &data.node, data.party_id)?;
            }
            InterfoldEventData::DKGRecursiveAggregationComplete(data) => {
                ensure!(
                    data.party_id == party_id,
                    "DKG fold party does not match envelope signer"
                );
            }
            InterfoldEventData::ProofFailureAccusation(data) => {
                ensure!(
                    data.accuser == signer,
                    "accuser does not match envelope signer"
                );
            }
            InterfoldEventData::AccusationVote(data) => {
                ensure!(data.voter == signer, "voter does not match envelope signer");
            }
            InterfoldEventData::PublicKeyAggregated(_)
            | InterfoldEventData::PlaintextAggregated(_) => {
                // Aggregator liveness is local and deadline-driven. Any current, non-expelled
                // committee member may carry the aggregator artifact; downstream role/proof and
                // contract single-shot checks still decide whether it can take effect.
            }
            _ => return Err(anyhow!("event type is not protocol-gossip admissible")),
        }
        Ok(e3_id)
    }
}

fn ensure_declared_party(
    committee: &Committee,
    signer: Address,
    declared_node: &str,
    declared_party_id: u64,
) -> Result<()> {
    let declared: Address = declared_node
        .parse()
        .context("declared node is not an EVM address")?;
    ensure!(
        declared == signer,
        "declared node does not match envelope signer"
    );
    ensure!(
        committee.party_id_for(declared_node) == Some(declared_party_id),
        "declared party does not match canonical committee slot"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct WindowMeter {
    started_at: u64,
    events: usize,
    bytes: usize,
}

impl WindowMeter {
    fn admit(&mut self, now: u64, bytes: usize, max_events: usize, max_bytes: usize) -> Result<()> {
        if now.saturating_sub(self.started_at) >= PROTOCOL_GOSSIP_RATE_WINDOW_SECS {
            *self = Self {
                started_at: now,
                events: 0,
                bytes: 0,
            };
        }
        ensure!(self.events < max_events, "protocol event rate exceeded");
        ensure!(
            self.bytes.saturating_add(bytes) <= max_bytes,
            "protocol byte rate exceeded"
        );
        self.events += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }
}

#[derive(Debug)]
pub struct AdmissionRejection {
    pub reason: String,
    pub quarantine: bool,
}

impl std::fmt::Display for AdmissionRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

#[derive(Debug)]
pub struct AuthorizedProtocolEvent {
    pub signer: Address,
    pub e3_id: E3id,
    pub event: InterfoldEvent<Unsequenced>,
}

#[derive(Default)]
pub struct ProtocolAdmission {
    authorization: NetworkAuthorizationState,
    peer_bindings: HashMap<PeerId, Address>,
    peer_windows: HashMap<PeerId, WindowMeter>,
    e3_windows: HashMap<(PeerId, E3id), WindowMeter>,
    invalid_events: HashMap<PeerId, u32>,
    quarantined: HashSet<PeerId>,
}

impl ProtocolAdmission {
    pub fn new(authorization: NetworkAuthorizationState) -> Self {
        Self {
            authorization,
            ..Self::default()
        }
    }

    pub fn observe(&mut self, event: &InterfoldEvent) {
        self.authorization.observe(event);
    }

    pub fn authorize_local_event(
        &self,
        signer: Address,
        event: &InterfoldEvent<Sequenced>,
    ) -> Result<()> {
        let unsequenced = event.clone().clone_unsequenced();
        self.authorization.authorize(signer, &unsequenced)?;
        Ok(())
    }

    pub fn authorize(
        &mut self,
        author: PeerId,
        envelope: AuthenticatedProtocolEvent,
        now: u64,
    ) -> std::result::Result<AuthorizedProtocolEvent, AdmissionRejection> {
        if self.quarantined.contains(&author) {
            return Err(AdmissionRejection {
                reason: "peer is quarantined".to_owned(),
                quarantine: false,
            });
        }
        self.try_authorize(author, envelope, now)
            .map_err(|error| self.reject(author, error.to_string()))
    }

    fn try_authorize(
        &mut self,
        author: PeerId,
        envelope: AuthenticatedProtocolEvent,
        now: u64,
    ) -> Result<AuthorizedProtocolEvent> {
        ensure!(
            envelope.version == PROTOCOL_GOSSIP_VERSION,
            "unsupported protocol-gossip version"
        );
        ensure!(
            envelope.peer_id == author.to_bytes(),
            "envelope peer does not match signed gossipsub author"
        );
        ensure!(
            now.abs_diff(envelope.issued_at) <= PROTOCOL_GOSSIP_REPLAY_WINDOW_SECS,
            "protocol-gossip envelope is outside the replay window"
        );
        let signer = envelope.recover_address()?;
        if let Some(bound) = self.peer_bindings.get(&author) {
            ensure!(
                *bound == signer,
                "libp2p peer attempted to change its bound EVM address"
            );
        }
        let event = InterfoldEvent::from_bytes(&envelope.event)
            .context("could not decode authenticated protocol event")?;
        let e3_id = self.authorization.authorize(signer, &event)?;
        let bytes = envelope.event.len();
        self.peer_windows.entry(author).or_default().admit(
            now,
            bytes,
            MAX_PROTOCOL_EVENTS_PER_PEER_WINDOW,
            MAX_PROTOCOL_BYTES_PER_PEER_WINDOW,
        )?;
        self.e3_windows
            .entry((author, e3_id.clone()))
            .or_default()
            .admit(
                now,
                bytes,
                MAX_PROTOCOL_EVENTS_PER_PEER_E3_WINDOW,
                MAX_PROTOCOL_BYTES_PER_PEER_E3_WINDOW,
            )?;
        self.peer_bindings.entry(author).or_insert(signer);
        Ok(AuthorizedProtocolEvent {
            signer,
            e3_id,
            event,
        })
    }

    fn reject(&mut self, author: PeerId, reason: String) -> AdmissionRejection {
        let failures = self.invalid_events.entry(author).or_default();
        *failures = failures.saturating_add(1);
        let quarantine = *failures == INVALID_EVENTS_BEFORE_QUARANTINE;
        if quarantine {
            self.quarantined.insert(author);
        }
        AdmissionRejection { reason, quarantine }
    }
}

pub fn unix_time_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        AccusationVote, DKGRecursiveAggregationComplete, DecryptionshareCreated,
        EventConstructorWithTimestamp, EventSource, KeyshareCreated, PlaintextAggregated,
        ProofFailureAccusation, ProofType, PublicKeyAggregated,
    };
    use e3_utils::ArcBytes;

    const NOW: u64 = 10_000;

    fn event(e3_id: E3id, entropy: u64) -> InterfoldEvent<Sequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            PlaintextAggregated {
                e3_id,
                decrypted_output: vec![ArcBytes::from_bytes(&entropy.to_be_bytes())],
                decryption_aggregator_proofs: vec![],
            }
            .into(),
            None,
            u128::from(entropy),
            None,
            EventSource::Local,
        )
        .into_sequenced(entropy)
    }

    fn every_forwardable_event(e3_id: &E3id, signer: Address) -> Vec<InterfoldEvent<Sequenced>> {
        let node = signer.to_string();
        let events: Vec<InterfoldEventData> = vec![
            KeyshareCreated {
                pubkey: ArcBytes::from_bytes(&[1]),
                e3_id: e3_id.clone(),
                node: node.clone(),
                party_id: 0,
                signed_pk_generation_proof: None,
            }
            .into(),
            DecryptionshareCreated {
                party_id: 0,
                decryption_share: vec![ArcBytes::from_bytes(&[2])],
                e3_id: e3_id.clone(),
                node,
                signed_decryption_proofs: vec![],
            }
            .into(),
            DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id: 0,
                aggregated_proof: None,
                fold_attestation: None,
            }
            .into(),
            PublicKeyAggregated {
                pubkey: ArcBytes::from_bytes(&[3]),
                e3_id: e3_id.clone(),
                nodes: vec![signer.to_string()].into(),
                committee_addresses: vec![signer],
                honest_committee_addresses: vec![signer],
                pk_commitment: [0; 32],
                dkg_aggregator_proof: None,
                dkg_attestation_bundle: None,
            }
            .into(),
            PlaintextAggregated {
                e3_id: e3_id.clone(),
                decrypted_output: vec![ArcBytes::from_bytes(&[4])],
                decryption_aggregator_proofs: vec![],
            }
            .into(),
            ProofFailureAccusation {
                e3_id: e3_id.clone(),
                accuser: signer,
                accused: Address::repeat_byte(0x44),
                accused_party_id: 1,
                proof_type: ProofType::C0PkBfv,
                data_hash: [5; 32],
                deadline: NOW + 1,
                signed_payload: None,
                signature: ArcBytes::from_bytes(&[6]),
            }
            .into(),
            AccusationVote {
                e3_id: e3_id.clone(),
                accusation_id: [7; 32],
                voter: signer,
                data_hash: [8; 32],
                deadline: NOW + 1,
                signature: ArcBytes::from_bytes(&[9]),
            }
            .into(),
        ];
        events
            .into_iter()
            .enumerate()
            .map(|(index, data)| {
                InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    data,
                    None,
                    index as u128,
                    None,
                    EventSource::Local,
                )
                .into_sequenced(index as u64)
            })
            .collect()
    }

    fn fixture(expelled: bool) -> (ProtocolSigner, E3id, NetworkAuthorizationState) {
        let e3_id = E3id::new("7", 31_337);
        let signer = PrivateKeySigner::random();
        let protocol_signer = ProtocolSigner::new(signer.clone(), PeerId::random());
        let committee = Committee::new(vec![signer.address().to_string()]);
        let expelled = if expelled {
            HashMap::from([(e3_id.clone(), vec![0])])
        } else {
            HashMap::new()
        };
        (
            protocol_signer,
            e3_id.clone(),
            NetworkAuthorizationState::new(HashMap::from([(e3_id, committee)]), expelled),
        )
    }

    #[test]
    fn valid_current_committee_peer_is_admitted() {
        let (signer, e3_id, authorization) = fixture(false);
        let envelope = signer.sign_event_at(event(e3_id.clone(), 1), NOW).unwrap();
        let admitted = ProtocolAdmission::new(authorization)
            .authorize(signer.peer_id(), envelope, NOW)
            .unwrap();
        assert_eq!(admitted.signer, signer.address());
        assert_eq!(admitted.e3_id, e3_id);
    }

    #[test]
    fn only_current_members_can_send_every_forwardable_event_type() {
        let (member, e3_id, authorization) = fixture(false);
        let mut member_admission = ProtocolAdmission::new(authorization);
        for event in every_forwardable_event(&e3_id, member.address()) {
            let envelope = member.sign_event_at(event, NOW).unwrap();
            member_admission
                .authorize(member.peer_id(), envelope, NOW)
                .unwrap();
        }

        let outsider = ProtocolSigner::new(PrivateKeySigner::random(), PeerId::random());
        let mut outsider_admission = ProtocolAdmission::new(NetworkAuthorizationState::default());
        for event in every_forwardable_event(&e3_id, outsider.address()) {
            let envelope = outsider.sign_event_at(event, NOW).unwrap();
            assert!(outsider_admission
                .authorize(outsider.peer_id(), envelope, NOW)
                .is_err());
        }
    }

    #[test]
    fn unregistered_unique_flood_never_crosses_admission_and_quarantines_once() {
        let (signer, e3_id, _) = fixture(false);
        let mut admission = ProtocolAdmission::new(NetworkAuthorizationState::default());
        let mut quarantine_transitions = 0;
        for entropy in 0..10_001 {
            let envelope = signer
                .sign_event_at(event(e3_id.clone(), entropy), NOW)
                .unwrap();
            let rejection = admission
                .authorize(signer.peer_id(), envelope, NOW)
                .unwrap_err();
            quarantine_transitions += usize::from(rejection.quarantine);
        }
        assert_eq!(quarantine_transitions, 1);
    }

    #[test]
    fn expelled_stale_and_wrong_peer_events_are_rejected() {
        let (expelled_signer, e3_id, expelled_authorization) = fixture(true);
        let expelled = expelled_signer
            .sign_event_at(event(e3_id.clone(), 1), NOW)
            .unwrap();
        assert!(ProtocolAdmission::new(expelled_authorization)
            .authorize(expelled_signer.peer_id(), expelled, NOW)
            .unwrap_err()
            .reason
            .contains("expelled"));

        let (signer, e3_id, authorization) = fixture(false);
        let stale = signer
            .sign_event_at(
                event(e3_id.clone(), 2),
                NOW - PROTOCOL_GOSSIP_REPLAY_WINDOW_SECS - 1,
            )
            .unwrap();
        assert!(ProtocolAdmission::new(authorization.clone())
            .authorize(signer.peer_id(), stale, NOW)
            .unwrap_err()
            .reason
            .contains("replay window"));

        let wrong_peer = signer.sign_event_at(event(e3_id, 3), NOW).unwrap();
        assert!(ProtocolAdmission::new(authorization)
            .authorize(PeerId::random(), wrong_peer, NOW)
            .unwrap_err()
            .reason
            .contains("gossipsub author"));

        let (signer, e3_id, authorization) = fixture(false);
        let wrong_chain = signer
            .sign_event_at(
                event(E3id::new(e3_id.e3_id(), e3_id.chain_id() + 1), 4),
                NOW,
            )
            .unwrap();
        assert!(ProtocolAdmission::new(authorization)
            .authorize(signer.peer_id(), wrong_chain, NOW)
            .unwrap_err()
            .reason
            .contains("no current finalized committee"));
    }

    #[test]
    fn declared_party_must_match_envelope_signer_and_canonical_slot() {
        let (signer, e3_id, authorization) = fixture(false);
        let forged = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            KeyshareCreated {
                pubkey: ArcBytes::from_bytes(&[1]),
                e3_id,
                node: Address::repeat_byte(0x44).to_string(),
                party_id: 0,
                signed_pk_generation_proof: None,
            }
            .into(),
            None,
            1,
            None,
            EventSource::Local,
        )
        .into_sequenced(1);
        let envelope = signer.sign_event_at(forged, NOW).unwrap();
        assert!(ProtocolAdmission::new(authorization)
            .authorize(signer.peer_id(), envelope, NOW)
            .unwrap_err()
            .reason
            .contains("declared node"));
    }

    #[test]
    fn per_e3_rate_is_bounded_before_persistence() {
        let (signer, e3_id, authorization) = fixture(false);
        let mut admission = ProtocolAdmission::new(authorization);
        for entropy in 0..MAX_PROTOCOL_EVENTS_PER_PEER_E3_WINDOW {
            let envelope = signer
                .sign_event_at(event(e3_id.clone(), entropy as u64), NOW)
                .unwrap();
            admission
                .authorize(signer.peer_id(), envelope, NOW)
                .unwrap();
        }
        let over_limit = signer.sign_event_at(event(e3_id, u64::MAX), NOW).unwrap();
        assert!(admission
            .authorize(signer.peer_id(), over_limit, NOW)
            .unwrap_err()
            .reason
            .contains("rate exceeded"));
    }
}
