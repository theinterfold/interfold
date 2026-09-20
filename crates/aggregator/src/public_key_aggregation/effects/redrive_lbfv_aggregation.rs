// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Periodic redrive of secure-16384 aggregation requests whose response never arrived.
//!
//! Every l-BFV aggregation request is correlated by an in-flight correlation ID.
//! The normal chain advances only on responses: a row response dispatches the
//! next fold step, a fold completion dispatches the final aggregation. When a
//! response is dropped between the worker and the actor — the worker heartbeat
//! stops but no `ComputeResponse` or `ComputeRequestError` reaches the event
//! bus — no later event re-dispatches the missing request and key publication
//! stalls without an error. Restart recovery clears in-flight correlations and
//! re-dispatches, which is why the stall survives only until a restart.
//!
//! This redrive is the in-process equivalent of that recovery step: a periodic
//! tick clears a correlation older than its timeout and publishes the request
//! again. Clearing one correlation never touches the others, so a slow job on
//! another row keeps running. A response for a cleared correlation arrives too
//! late and is rejected by the usual correlation check; the re-dispatched
//! request produces the accepted response.

use super::super::*;
use std::collections::HashSet;
use std::time::Duration;

/// How often the actor scans l-BFV aggregation correlations for stalls.
pub(in crate::actors::publickey_aggregator) const LBFV_AGGREGATION_REDRIVE_INTERVAL_SECS: u64 = 60;

/// A row or streaming fold-step request older than this is re-published. The
/// value must comfortably exceed the slowest legitimate row job, and exceed the
/// compute effect gate's 300 s stale-entry threshold, so the gate evicts the
/// outcome-less entry and re-forwards the retry instead of parking it behind
/// the lost outcome.
pub(in crate::actors::publickey_aggregator) const LBFV_ROW_CORRELATION_TIMEOUT_SECS: u64 = 900;

/// The final DKG aggregation is the largest circuit of the family, so its
/// correlation gets a longer timeout before the request is re-published.
pub(in crate::actors::publickey_aggregator) const LBFV_FINAL_CORRELATION_TIMEOUT_SECS: u64 = 1800;

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn arm_lbfv_aggregation_redrive_timer(
        &mut self,
        ctx: &mut Context<Self>,
    ) {
        if self.lbfv_aggregation_redrive_timer.is_some() {
            return;
        }
        if !self.is_lbfv() {
            return;
        }
        let handle = ctx.run_interval(
            Duration::from_secs(LBFV_AGGREGATION_REDRIVE_INTERVAL_SECS),
            |actor, _| {
                if let Err(error) = actor.redrive_lbfv_aggregation() {
                    actor.bus.err(EType::PublickeyAggregation, error);
                }
            },
        );
        self.lbfv_aggregation_redrive_timer = Some(handle);
    }

    /// Record when an l-BFV aggregation or fold-step request was published so
    /// the redrive tick can age its correlation.
    pub(in crate::actors::publickey_aggregator) fn note_lbfv_aggregation_dispatch(
        &mut self,
        correlation: CorrelationId,
        ec: &EventContext<Sequenced>,
    ) {
        self.lbfv_aggregation_dispatch_at.insert(
            correlation,
            AggregationDispatch {
                at: self.lbfv_retry_clock.now_unix_secs(),
                ec: ec.clone(),
            },
        );
    }

    /// Clear every l-BFV aggregation correlation older than its timeout and
    /// publish the missing requests again. Rows, fold steps, and the final
    /// aggregation are independent: only timed-out correlations are cleared.
    pub(in crate::actors::publickey_aggregator) fn redrive_lbfv_aggregation(
        &mut self,
    ) -> Result<()> {
        if !self.is_lbfv() || !self.can_run_aggregation_effects() {
            return Ok(());
        }
        if !matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
        ) {
            return Ok(());
        }
        let Some(mut aggregation) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        if aggregation.is_failed() {
            return Ok(());
        }
        let row_count = aggregation.row_count()?;
        let now = self.lbfv_retry_clock.now_unix_secs();
        // Causal context for a correlation that was dispatched without
        // bookkeeping: prefer the sidecar's own last context, then the
        // recovery snapshot. Entering GeneratingC5Proof always records a
        // context, so this is only empty before any event was processed.
        let fallback_ec = self
            .lbfv_aggregation
            .as_ref()
            .and_then(|sidecar| sidecar.get_ctx())
            .or_else(|| {
                self.recovery
                    .get()
                    .and_then(|recovery| recovery.last_ec.clone())
            });

        let mut live = HashSet::new();
        let mut timed_out: Vec<(CorrelationId, EventContext<Sequenced>)> = Vec::new();
        let mut check = |correlation: Option<CorrelationId>, timeout: u64| {
            if let Some(correlation) = correlation {
                live.insert(correlation);
                if let Some(dispatch) = self.lbfv_aggregation_dispatch_at.get(&correlation) {
                    if now.saturating_sub(dispatch.at) > timeout
                        && !timed_out.iter().any(|(c, _)| c == &correlation)
                    {
                        timed_out.push((correlation, dispatch.ec.clone()));
                    }
                } else if let Some(ec) = fallback_ec.clone() {
                    // Dispatched without bookkeeping: age it from now instead
                    // of clearing a correlation that may belong to a running job.
                    self.lbfv_aggregation_dispatch_at
                        .insert(correlation, AggregationDispatch { at: now, ec });
                }
            }
        };
        for row in 0..row_count {
            check(
                aggregation.public_key_aggregation_correlations[row],
                LBFV_ROW_CORRELATION_TIMEOUT_SECS,
            );
            check(
                aggregation.rlk_aggregation_correlations[row],
                LBFV_ROW_CORRELATION_TIMEOUT_SECS,
            );
        }
        check(
            aggregation.aggregation_fold_correlation,
            LBFV_ROW_CORRELATION_TIMEOUT_SECS,
        );
        check(
            aggregation.dkg_aggregation_correlation,
            LBFV_FINAL_CORRELATION_TIMEOUT_SECS,
        );
        let nodes_fold_step = match self.state.get() {
            Some(PublicKeyAggregatorState::GeneratingC5Proof {
                nodes_fold_step_correlation,
                ..
            }) => nodes_fold_step_correlation,
            _ => None,
        };
        check(nodes_fold_step, LBFV_ROW_CORRELATION_TIMEOUT_SECS);

        self.lbfv_aggregation_dispatch_at
            .retain(|correlation, _| live.contains(correlation));

        if timed_out.is_empty() {
            return Ok(());
        }
        let (_, ec) = &timed_out[0];
        let ec = ec.clone();
        let mut cleared_sidecar = false;
        for (correlation, _) in &timed_out {
            let mut cleared = false;
            for row in 0..row_count as u32 {
                if aggregation.public_key_aggregation_correlations[row as usize]
                    == Some(*correlation)
                {
                    aggregation.clear_public_key_correlation(row, *correlation)?;
                    cleared = true;
                }
                if aggregation.rlk_aggregation_correlations[row as usize] == Some(*correlation) {
                    aggregation.clear_rlk_correlation(row, *correlation)?;
                    cleared = true;
                }
            }
            if aggregation.aggregation_fold_correlation == Some(*correlation) {
                aggregation.clear_fold_correlation(*correlation)?;
                cleared = true;
            }
            if aggregation.dkg_aggregation_correlation == Some(*correlation) {
                aggregation.clear_dkg_correlation(*correlation)?;
                cleared = true;
            }
            if cleared {
                cleared_sidecar = true;
            }
        }
        if cleared_sidecar {
            self.set_lbfv_aggregation(aggregation, &ec)?;
        }
        let nodes_fold_timed_out = timed_out.iter().any(|(c, _)| Some(*c) == nodes_fold_step);
        if nodes_fold_timed_out {
            self.state.try_mutate(&ec, |state| {
                let PublicKeyAggregatorState::GeneratingC5Proof {
                    public_key,
                    keyshare_bytes,
                    nodes,
                    party_nodes,
                    dkg_node_proofs,
                    dkg_fold_attestations,
                    honest_party_ids,
                    dishonest_parties,
                    circuit_committee_n,
                    circuit_committee_h,
                    dkg_aggregation_correlation,
                    dkg_aggregated_proof,
                    c5_proof_pending,
                    last_ec,
                    nodes_fold_accumulator,
                    nodes_fold_completed_slots,
                    nodes_fold_step_correlation: _,
                } = state
                else {
                    return Ok(state);
                };
                Ok(PublicKeyAggregatorState::GeneratingC5Proof {
                    public_key,
                    keyshare_bytes,
                    nodes,
                    party_nodes,
                    dkg_node_proofs,
                    dkg_fold_attestations,
                    honest_party_ids,
                    dishonest_parties,
                    circuit_committee_n,
                    circuit_committee_h,
                    dkg_aggregation_correlation,
                    dkg_aggregated_proof,
                    c5_proof_pending,
                    last_ec,
                    nodes_fold_accumulator,
                    nodes_fold_completed_slots,
                    nodes_fold_step_correlation: None,
                })
            })?;
            // The tick-time prune above already dropped the cleared correlation
            // from the dispatch map; the re-dispatch below records the new one.
        }
        warn!(
            e3_id = %self.e3_id,
            timed_out = timed_out.len(),
            "Re-publishing l-BFV aggregation requests with timed-out correlations"
        );
        self.try_dispatch_lbfv_aggregation_rows(&ec)?;
        self.try_dispatch_lbfv_aggregation_fold(&ec)?;
        self.try_dispatch_nodes_fold_step(&ec)?;
        self.try_dispatch_dkg_aggregation(&ec)
    }
}
