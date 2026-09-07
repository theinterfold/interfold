// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded wait for honest-party DKG node proofs.
//!
//! The aggregator enters `GeneratingC5Proof` and then waits for one `NodeDkgFold` proof from
//! every honest party. That wait had no bound: a single member that could never finish its
//! fold (Round 14, cn3 stuck at 13/14 inner proofs) held the whole E3 open indefinitely. The
//! sortition failover only rotates the *aggregator role* — every standby inherits the same
//! missing proof, so its budgets drain one after another and the E3 stalls until the canonical
//! deadline.
//!
//! Excluding the late party is not available here: C5 is signed *before* the fold completes
//! and binds exactly the H honest keyshares (`PkAggregationProofRequest.keyshare_bytes` +
//! `aggregated_pk_bytes`), so dropping a party after C5 would invalidate the proof that has
//! already been published. The correct bounded outcome is therefore an explicit, attributable
//! failure rather than a silent hang.

use std::time::Duration;

/// Environment override for the honest-node-proof collection budget.
pub(crate) const DKG_NODE_PROOF_TIMEOUT_ENV: &str = "E3_DKG_NODE_PROOF_TIMEOUT_SECS";

/// Default budget for collecting every honest party's NodeDkgFold proof.
///
/// Matches the DKG window (`E3_DKG_WINDOW_SECS`, 7200 s), for the same reason the `bb` cap does:
/// a node proof that arrives after the window cannot be used by the E3 it belongs to, because
/// `Interfold.onCommitteePublished` rejects a key published after `dkgDeadline`. Failing earlier
/// than the window only converts a recoverable delay into a lost E3.
///
/// A shorter budget is unsafe at production parameters. Measured `ZkNodeDkgFold` at the
/// `secure-8192` preset (`circuits/benchmarks/results_secure_*`) is 132 s at N=3, 380 s at N=5,
/// and 904 s at N=9, which extrapolates to about 2180 s at N=19, the largest supported committee.
/// A member that restarts mid-DKG must also re-prove its inner circuits before it can fold again,
/// which measures about 5500 s per node at N=9. The earlier 1800 s default was therefore below
/// the honest completion time for a restarted member at N=9 and would have failed healthy E3s.
///
/// Operators who want a tighter bound must measure a node fold at their own preset and committee
/// size first, then set `E3_DKG_NODE_PROOF_TIMEOUT_SECS` above the restart-inclusive worst case.
pub(crate) const DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS: u64 = 7200;

/// Resolve the collection budget, honouring the environment override.
pub(crate) fn dkg_node_proof_timeout() -> Duration {
    let secs = std::env::var(DKG_NODE_PROOF_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `E3_DKG_NODE_PROOF_TIMEOUT_SECS` is process-global, so the default and override cases
    /// share one test rather than racing each other under the threaded test harness.
    #[test]
    fn budget_resolution_prefers_a_valid_override_and_falls_back_otherwise() {
        let default = Duration::from_secs(DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS);

        std::env::remove_var(DKG_NODE_PROOF_TIMEOUT_ENV);
        assert_eq!(dkg_node_proof_timeout(), default);

        std::env::set_var(DKG_NODE_PROOF_TIMEOUT_ENV, "42");
        assert_eq!(dkg_node_proof_timeout(), Duration::from_secs(42));

        // A zero or unparseable budget would disable the bound entirely — fall back.
        std::env::set_var(DKG_NODE_PROOF_TIMEOUT_ENV, "0");
        assert_eq!(dkg_node_proof_timeout(), default);

        std::env::set_var(DKG_NODE_PROOF_TIMEOUT_ENV, "not-a-number");
        assert_eq!(dkg_node_proof_timeout(), default);

        std::env::remove_var(DKG_NODE_PROOF_TIMEOUT_ENV);
    }

    /// The budget must not drop below the honest completion time at production parameters.
    ///
    /// Measured `ZkNodeDkgFold` at `secure-8192` is 904 s per node at N=9, and a member that
    /// restarts mid-DKG re-proves about 5500 s of inner circuits before it can fold again. A
    /// budget under that sum fails healthy E3s, which is worse than the stall it replaces. The
    /// DKG window is the natural bound: a proof that lands later cannot be used by its E3.
    #[test]
    fn default_budget_covers_a_restarted_member_at_secure_parameters() {
        const DKG_WINDOW_SECS: u64 = 7200;
        const MEASURED_RESTART_WORST_CASE_SECS: u64 = 6414;

        assert_eq!(
            DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS, DKG_WINDOW_SECS,
            "the budget must track the DKG window; work finishing later cannot be used"
        );
        assert!(
            DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS > MEASURED_RESTART_WORST_CASE_SECS,
            "budget {DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS} s would fail a healthy restarted \
             member that needs {MEASURED_RESTART_WORST_CASE_SECS} s at N=9"
        );
    }
}
