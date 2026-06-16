// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Off-chain accusation quorum protocol for fault attribution.
//!
//! When a node detects a ZK proof failure from another committee member, it
//! broadcasts a [`ProofFailureAccusation`] over gossip. Other committee members
//! independently check the same proof and respond with [`AccusationVote`]s.
//! Once a quorum of M (the cryptographic threshold) votes is reached, the
//! actor emits [`AccusationQuorumReached`] for downstream consumers (aggregator
//! exclusion, on-chain slash submission).
//!
//! ## Architecture
//!
//! This file is a **thin actix shell**. All protocol logic lives in the plain,
//! synchronous [`AccusationVoting`] service ([`crate::accusation_voting`]). The
//! actor's only job is to translate inbound [`InterfoldEvent`]s into service
//! calls and to perform the I/O ([`VoteAction`]s) the service returns —
//! publishing gossip events, dispatching ZK requests, and managing vote
//! timeouts.
//!
//! ## Proof-type-specific behavior
//!
//! | Proof   | Attestation                | Notes                                      |
//! |---------|----------------------------|--------------------------------------------|
//! | C0      | All nodes independently    | Everyone receives via DHT                  |
//! | C1      | All nodes independently    | Bundled in ThresholdShareCreated            |
//! | C2a/C2b | All nodes independently    | Same proof bytes for all recipients         |
//! | C3a/C3b | Forwarding required        | Per-recipient; accuser forwards payload     |
//! | C4      | All nodes independently    | Broadcast via gossip                        |
//! | C5      | Committee attests          | Aggregator-generated; nodes verify off-chain|
//! | C6      | All nodes independently    | Broadcast via gossip                        |
//! | C7      | On-chain verification      | Not handled here (on-chain verifier)        |

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use actix::{Actor, Addr, AsyncContext, Context, Handler, SpawnHandle};
use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    AccusationVote, BusHandle, CommitmentConsistencyViolation, ComputeRequestError,
    ComputeResponse, E3id, EventPublisher, EventSubscriber, EventType, InterfoldEvent,
    InterfoldEventData, ProofFailureAccusation, ProofType, ProofVerificationFailed,
    ProofVerificationPassed, TypedEvent,
};
use e3_utils::NotifySync;
use tracing::error;

use crate::domain::accusation_voting::{AccusationVoting, VoteAction};

/// Abstraction over wall-clock time so the deadline-stamping logic is
/// deterministically testable. Production uses [`SystemClock`], which reads
/// `SystemTime::now()`; tests can inject a mock clock that returns fixed
/// timestamps.
pub trait Clock: Send + Sync + 'static {
    /// Current Unix time in seconds. Returns `0` if the platform clock is
    /// pre-`UNIX_EPOCH` (a broken clock should not silently produce
    /// signatures that look valid forever — the on-chain check will then
    /// reject the resulting deadline immediately).
    fn unix_now_secs(&self) -> u64;
}

/// Production clock backed by `SystemTime::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Thin actix shell around the [`AccusationVoting`] domain service.
///
/// **Lifecycle**: One instance per E3 computation. Created by
/// [`AccusationManagerExtension`] when [`CommitteeFinalized`] fires and
/// destroyed when the E3 completes or the node shuts down. All protocol state
/// lives inside the owned [`AccusationVoting`] service and is therefore
/// naturally scoped to a single E3.
///
/// **Ephemeral**: This actor does *not* persist state across restarts.
/// In-flight accusations are lost on node restart (accepted trade-off:
/// they would have timed out within the vote timeout anyway).
///
/// Subscribes to:
/// - [`ProofVerificationFailed`] — local proof failure detection
/// - [`ProofVerificationPassed`] — cache successful verification for voting
/// - [`ProofFailureAccusation`] — incoming accusations from other nodes via gossip
/// - [`AccusationVote`] — incoming votes from other nodes via gossip
/// - [`SlashExecuted`] — on-chain slash confirmation for committee updates
///
/// Publishes:
/// - [`ProofFailureAccusation`] — broadcast own accusations via gossip
/// - [`AccusationVote`] — broadcast own votes via gossip
/// - [`AccusationQuorumReached`] — quorum decision for downstream consumers
///
/// [`AccusationManagerExtension`]: crate::accusation_manager_ext::AccusationManagerExtension
/// [`CommitteeFinalized`]: e3_events::CommitteeFinalized
/// [`AccusationQuorumReached`]: e3_events::AccusationQuorumReached
/// [`SlashExecuted`]: e3_events::SlashExecuted
pub struct AccusationManager {
    bus: BusHandle,
    /// Plain, synchronous protocol core. Owns all accusation/vote state.
    voting: AccusationVoting,
    /// Active vote-collection timeouts keyed by accusation_id. Managed entirely
    /// by the actor — the service only signals start/cancel via [`VoteAction`].
    timeout_handles: HashMap<[u8; 32], SpawnHandle>,
}

impl AccusationManager {
    /// Construct an actor with the production [`SystemClock`]. Use
    /// [`AccusationManager::new_with_clock`] in tests that need deterministic
    /// timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        threshold_m: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
    ) -> Self {
        Self::new_with_clock(
            bus,
            e3_id,
            signer,
            slashing_manager,
            committee,
            threshold_m,
            vote_validity_secs,
            accusation_deadline_skew_secs,
            params_preset,
            Arc::new(SystemClock),
        )
    }

    /// Construct an actor with an explicit [`Clock`]. Allows unit tests to
    /// drive deadline computation without touching wall-clock time.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_clock(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        threshold_m: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            voting: AccusationVoting::new(
                e3_id,
                signer,
                slashing_manager,
                committee,
                threshold_m,
                vote_validity_secs,
                accusation_deadline_skew_secs,
                params_preset,
                clock,
            ),
            timeout_handles: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        threshold_m: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
    ) -> Addr<Self> {
        let addr = Self::new(
            bus,
            e3_id,
            signer,
            slashing_manager,
            committee,
            threshold_m,
            vote_validity_secs,
            accusation_deadline_skew_secs,
            params_preset,
        )
        .start();
        bus.subscribe(EventType::ProofVerificationFailed, addr.clone().into());
        bus.subscribe(EventType::ProofVerificationPassed, addr.clone().into());
        bus.subscribe(EventType::ProofFailureAccusation, addr.clone().into());
        bus.subscribe(EventType::AccusationVote, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        bus.subscribe(EventType::SlashExecuted, addr.clone().into());
        bus.subscribe(
            EventType::CommitmentConsistencyViolation,
            addr.clone().into(),
        );
        addr
    }

    /// Canonical EIP-712 typed-data hash for a vote.
    ///
    /// Delegates to [`AccusationVoting::vote_digest`]. Exposed `pub` so the
    /// Anvil parity test in
    /// `crates/zk-prover/tests/slashing_integration_tests.rs` can sign votes
    /// through the **same** code path the production actor uses.
    pub fn vote_digest(vote: &AccusationVote, verifying_contract: Address) -> [u8; 32] {
        AccusationVoting::vote_digest(vote, verifying_contract)
    }

    /// Cache a successful proof verification result for a specific
    /// (accused, proof_type). Allows the node to vote on accusations from
    /// other nodes.
    pub fn cache_verification_result(
        &mut self,
        accused: Address,
        proof_type: ProofType,
        data_hash: [u8; 32],
        passed: bool,
        evidence: Bytes,
    ) {
        self.voting
            .cache_verification_result(accused, proof_type, data_hash, passed, evidence);
    }

    /// Perform the I/O the [`AccusationVoting`] service requested.
    ///
    /// This is the *only* place the actor publishes events or touches timers —
    /// keeping all protocol decisions in the pure service.
    fn apply_actions(&mut self, actions: Vec<VoteAction>, ctx: &mut Context<Self>) {
        for action in actions {
            match action {
                VoteAction::PublishAccusation {
                    accusation,
                    ec,
                    dedup_key,
                } => {
                    if let Err(err) = self.bus.publish(accusation, ec) {
                        error!("Failed to broadcast ProofFailureAccusation: {err}");
                        // Preserve the original rollback: re-allow this
                        // (accused, proof_type) accusation on a dead bus.
                        self.voting.rollback_initiation(&dedup_key);
                    }
                }
                VoteAction::PublishVote { vote, ec } => {
                    if let Err(err) = self.bus.publish(vote, ec) {
                        error!("Failed to broadcast AccusationVote: {err}");
                    }
                }
                VoteAction::PublishQuorum { quorum, ec } => {
                    if let Err(err) = self.bus.publish(quorum, ec) {
                        error!("Failed to publish AccusationQuorumReached: {err}");
                    }
                }
                VoteAction::DispatchZk {
                    request,
                    ec,
                    correlation_id,
                } => {
                    if let Err(err) = self.bus.publish(request, ec) {
                        error!("Failed to dispatch C3a/C3b ZK re-verification: {err}");
                        self.voting.discard_reverification(&correlation_id);
                    }
                }
                VoteAction::StartTimeout(accusation_id) => {
                    let timeout = self.voting.vote_timeout();
                    let handle = ctx.run_later(timeout, move |act, _ctx| {
                        act.timeout_handles.remove(&accusation_id);
                        if let Some((quorum, ec)) = act.voting.on_vote_timeout(accusation_id) {
                            if let Err(err) = act.bus.publish(quorum, ec) {
                                error!(
                                    "Failed to publish AccusationQuorumReached on timeout: {err}"
                                );
                            }
                        }
                    });
                    self.timeout_handles.insert(accusation_id, handle);
                }
                VoteAction::CancelTimeout(accusation_id) => {
                    if let Some(handle) = self.timeout_handles.remove(&accusation_id) {
                        ctx.cancel_future(handle);
                    }
                }
            }
        }
    }
}

impl Actor for AccusationManager {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for AccusationManager {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::ProofVerificationFailed(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ProofVerificationPassed(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ProofFailureAccusation(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AccusationVote(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::SlashExecuted(data) => {
                self.voting.on_slash_executed(data);
            }
            InterfoldEventData::CommitmentConsistencyViolation(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<ProofVerificationFailed>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofVerificationFailed>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_local_proof_failure(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<ProofVerificationPassed>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofVerificationPassed>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, _ec) = msg.into_components();
        self.voting.on_proof_verification_passed(data);
    }
}

impl Handler<TypedEvent<ProofFailureAccusation>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ProofFailureAccusation>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_accusation_received(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<AccusationVote>> for AccusationManager {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<AccusationVote>, ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_vote_received(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<ComputeResponse>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let actions = self.voting.handle_reverification_response(msg);
        self.apply_actions(actions, ctx);
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.voting.handle_reverification_error(msg);
    }
}

impl Handler<TypedEvent<CommitmentConsistencyViolation>> for AccusationManager {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyViolation>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        let actions = self.voting.on_consistency_violation(data, &ec);
        self.apply_actions(actions, ctx);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════
//
// These tests pin the actor's public EIP-712 digest computation (delegated to
// `AccusationVoting`) to the exact bytes that off-chain test helpers (and
// ultimately the on-chain `SlashingManager._verifyVotes`) expect.

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{keccak256, FixedBytes, U256};
    use alloy::signers::SignerSync;
    use alloy::sol_types::SolValue;
    use e3_events::{VOTE_DOMAIN_NAME, VOTE_DOMAIN_VERSION, VOTE_TYPEHASH_STR};
    use e3_utils::ArcBytes;

    /// Default clock-skew allowance when validating peer-stamped accusation
    /// deadlines (mirrors the production extension default).
    const DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS: u64 = 30;

    /// Independent re-derivation of the EIP-712 vote digest, mirroring exactly
    /// what `SlashingManager._verifyVotes` computes on chain.
    fn reference_vote_digest(
        chain_id: u64,
        verifying_contract: Address,
        e3_id: u64,
        accusation_id: [u8; 32],
        voter: Address,
        data_hash: [u8; 32],
        deadline: u64,
    ) -> [u8; 32] {
        let domain_typehash: [u8; 32] = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .into();
        let name_hash: [u8; 32] = keccak256(VOTE_DOMAIN_NAME).into();
        let version_hash: [u8; 32] = keccak256(VOTE_DOMAIN_VERSION).into();
        let domain_separator: [u8; 32] = keccak256(
            (
                domain_typehash,
                name_hash,
                version_hash,
                U256::from(chain_id),
                verifying_contract,
            )
                .abi_encode(),
        )
        .into();

        let typehash: [u8; 32] = keccak256(VOTE_TYPEHASH_STR).into();
        let struct_hash: [u8; 32] = keccak256(
            (
                typehash,
                U256::from(e3_id),
                FixedBytes::<32>::from(accusation_id),
                voter,
                FixedBytes::<32>::from(data_hash),
                U256::from(deadline),
            )
                .abi_encode(),
        )
        .into();

        let mut buf = Vec::with_capacity(2 + 32 + 32);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(&domain_separator);
        buf.extend_from_slice(&struct_hash);
        keccak256(&buf).into()
    }

    /// The actor's `vote_digest` must equal the reference digest byte-for-byte.
    #[test]
    fn vote_digest_matches_reference() {
        let chain_id = 31337u64;
        let verifying_contract: Address = "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap();
        let voter: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let accusation_id = [0xab; 32];
        let data_hash = [0xcd; 32];
        let deadline: u64 = 1_700_000_000;

        let vote = AccusationVote {
            e3_id: E3id::new("42", chain_id),
            accusation_id,
            voter,
            data_hash,
            deadline,
            signature: ArcBytes::default(),
        };

        let actor = AccusationManager::vote_digest(&vote, verifying_contract);
        let reference = reference_vote_digest(
            chain_id,
            verifying_contract,
            42,
            accusation_id,
            voter,
            data_hash,
            deadline,
        );

        assert_eq!(
            actor, reference,
            "AccusationManager::vote_digest drifted from the reference EIP-712 \
             computation. Check VOTE_TYPEHASH_STR / VOTE_DOMAIN_NAME against \
             SlashingManager.sol — these MUST stay byte-equal across crates."
        );
    }

    /// Sign-and-recover round-trip using the actor's digest.
    #[test]
    fn actor_signature_recovers_to_voter() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let voter = signer.address();
        let verifying_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 31337u64;

        let vote = AccusationVote {
            e3_id: E3id::new("12345", chain_id),
            accusation_id: [0x07; 32],
            voter,
            data_hash: [0x08; 32],
            deadline: 1_700_000_000,
            signature: ArcBytes::default(),
        };

        let digest = AccusationManager::vote_digest(&vote, verifying_contract);
        let sig = signer
            .sign_hash_sync(&FixedBytes::<32>::from(digest))
            .unwrap();
        let recovered = sig
            .recover_address_from_prehash(&FixedBytes::<32>::from(digest))
            .expect("recover");
        assert_eq!(
            recovered, voter,
            "signing the actor's digest and recovering must yield the voter"
        );
    }

    /// The accusation digest must include `deadline`.
    #[test]
    fn accusation_digest_binds_deadline() {
        let make = |deadline: u64| ProofFailureAccusation {
            e3_id: E3id::new("9", 31337),
            accuser: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
            accused: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
            accused_party_id: 1,
            proof_type: ProofType::C1PkGeneration,
            data_hash: [0x42; 32],
            deadline,
            signed_payload: None,
            signature: ArcBytes::default(),
        };
        let a = AccusationVoting::accusation_digest(&make(1_700_000_000));
        let b = AccusationVoting::accusation_digest(&make(1_700_000_001));
        assert_ne!(a, b, "deadline must be part of the accusation digest");
    }

    #[test]
    fn peer_deadline_acceptance_enforces_local_window() {
        let now = 1_700_000_000u64;
        let validity = 1_800u64;
        let skew = DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS;
        let max_ok = now + validity + skew;

        assert!(
            !AccusationVoting::is_peer_deadline_acceptable(now, now, validity, skew),
            "deadline equal to now must be rejected"
        );
        assert!(
            !AccusationVoting::is_peer_deadline_acceptable(now - 1, now, validity, skew),
            "expired deadline must be rejected"
        );
        assert!(
            AccusationVoting::is_peer_deadline_acceptable(max_ok, now, validity, skew),
            "deadline at upper bound must be accepted"
        );
        assert!(
            !AccusationVoting::is_peer_deadline_acceptable(max_ok + 1, now, validity, skew),
            "far-future deadline must be rejected"
        );
        assert!(
            !AccusationVoting::is_peer_deadline_acceptable(now + 10, now, 0, skew),
            "vote_validity_secs=0 must reject peer accusations"
        );
    }
}
