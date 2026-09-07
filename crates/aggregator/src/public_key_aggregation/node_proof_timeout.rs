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
/// A node fold is the most expensive job in the DKG and its cost grows with the ring degree.
/// Measured at the insecure test preset (degree 512) across five folds: 135 s, 137 s, 147 s,
/// 214 s, 214 s. A restarted member must also re-prove C1–C4 before it can start folding
/// (~40 s more). 30 minutes is ~8x the slowest measured fold, which bounds the stall well
/// below the two-hour DKG window while leaving room for a slow or once-restarted member.
///
/// CAUTION — this default is calibrated against insecure test params and has NOT been measured
/// at secure params. Secure operation uses degree 32768 (64x this ring), and if fold cost grows
/// even linearly in the degree the honest fold alone would exceed this budget, so every E3 would
/// fail with `DKGTimeout` on healthy nodes. Measure the fold at the deployment preset and raise
/// this default (or set `E3_DKG_NODE_PROOF_TIMEOUT_SECS`) before running at secure N.
pub(crate) const DEFAULT_DKG_NODE_PROOF_TIMEOUT_SECS: u64 = 1800;

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
}
