// SPDX-License-Identifier: LGPL-3.0-only

//! Construction, subscription, digest compatibility, and verifier-cache entry points.

use super::*;

impl AccusationManager {
    pub(in crate::actors::accusation_manager) fn canonical_vote_quorum(
        circuit_threshold_t: usize,
        committee_n: usize,
    ) -> usize {
        match CiphernodesCommitteeSize::from_threshold(circuit_threshold_t, committee_n) {
            Ok(size) => size.values().h,
            Err(err) => {
                // Preserve the historical constructor behavior for external callers with a
                // non-canonical test committee. Production creation is validated by the
                // extension and uses `setup_with_quorum` below.
                warn!(
                    circuit_threshold_t,
                    committee_n,
                    error = %err,
                    "Unknown committee size; falling back to the supplied threshold as vote quorum"
                );
                circuit_threshold_t
            }
        }
    }

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
        circuit_threshold_t: usize,
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
            circuit_threshold_t,
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
        circuit_threshold_t: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let vote_quorum_h = Self::canonical_vote_quorum(circuit_threshold_t, committee.len());
        Self::new_with_clock_and_quorum(
            bus,
            e3_id,
            signer,
            slashing_manager,
            committee,
            circuit_threshold_t,
            vote_quorum_h,
            vote_validity_secs,
            accusation_deadline_skew_secs,
            params_preset,
            clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::actors::accusation_manager) fn new_with_clock_and_quorum(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        circuit_threshold_t: usize,
        vote_quorum_h: usize,
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
                circuit_threshold_t,
                vote_quorum_h,
                vote_validity_secs,
                accusation_deadline_skew_secs,
                params_preset,
                clock,
            ),
            timeout_handles: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_quorum(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        circuit_threshold_t: usize,
        vote_quorum_h: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
    ) -> Self {
        Self::new_with_clock_and_quorum(
            bus,
            e3_id,
            signer,
            slashing_manager,
            committee,
            circuit_threshold_t,
            vote_quorum_h,
            vote_validity_secs,
            accusation_deadline_skew_secs,
            params_preset,
            Arc::new(SystemClock),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        circuit_threshold_t: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
    ) -> Addr<Self> {
        let vote_quorum_h = Self::canonical_vote_quorum(circuit_threshold_t, committee.len());
        Self::setup_with_quorum(
            bus,
            e3_id,
            signer,
            slashing_manager,
            committee,
            circuit_threshold_t,
            vote_quorum_h,
            vote_validity_secs,
            accusation_deadline_skew_secs,
            params_preset,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn setup_with_quorum(
        bus: &BusHandle,
        e3_id: E3id,
        signer: PrivateKeySigner,
        slashing_manager: Address,
        committee: Vec<Address>,
        circuit_threshold_t: usize,
        vote_quorum_h: usize,
        vote_validity_secs: u64,
        accusation_deadline_skew_secs: u64,
        params_preset: e3_fhe_params::BfvPreset,
    ) -> Addr<Self> {
        let addr = Self::new_with_quorum(
            bus,
            e3_id,
            signer,
            slashing_manager,
            committee,
            circuit_threshold_t,
            vote_quorum_h,
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
        proof_instance: u32,
        data_hash: [u8; 32],
        passed: bool,
        evidence: Bytes,
    ) {
        self.voting.cache_verification_result(
            accused,
            proof_type,
            proof_instance,
            data_hash,
            passed,
            evidence,
        );
    }
}
