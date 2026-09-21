// SPDX-License-Identifier: LGPL-3.0-only

//! Correlate worker failures to the affected proof workflow.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_compute_request_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) {
        let (msg, _ec) = msg.into_components();

        // Every actor that dispatches compute work receives every `ComputeRequestError`, so a
        // correlation that no map below owns belongs to a different actor. Match on the
        // correlation first and report the error kind through `Display`: a failure that this
        // actor owns is a local infrastructure failure. Keep the pending inputs so EventStore
        // replay can safely retry them after a restart. A local prover failure is not evidence
        // that the committee supplied invalid cryptographic data.
        if let Some(pending) = self.pending.get(msg.correlation_id()) {
            error!(
                "C0 proof request failed locally for E3 {}: {msg}; pending work is preserved for restart",
                pending.e3_id
            );
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.threshold_correlation.get(msg.correlation_id()) {
            error!(
                "DKG {:?} proof request failed locally for E3 {}: {msg}; pending work is preserved for restart",
                kind, e3_id
            );
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.decryption_correlation.get(msg.correlation_id()) {
            error!(
                "C4 {:?} proof request failed locally for E3 {}: {msg}; pending work is preserved for restart",
                kind, e3_id
            );
            return;
        }

        if let Some(e3_id) = self.share_decryption_correlation.get(msg.correlation_id()) {
            error!(
                "C6 proof request failed locally for E3 {}: {msg}; pending work is preserved for restart",
                e3_id
            );
            return;
        }

        if let Some(e3_id) = self.pk_aggregation_correlation.get(msg.correlation_id()) {
            error!(
                "C5 proof request failed locally for E3 {}: {msg}; pending work is preserved for restart",
                e3_id
            );
            return;
        }

        if let Some(e3_id) = self.aggregation_correlation.get(msg.correlation_id()) {
            error!(
                "C7 proof request failed locally for E3 {}: {msg}; pending work is preserved for restart",
                e3_id
            );
            return;
        }

        debug!(
            "ProofRequestActor: ignored compute error for correlation {:?} held by another actor: {msg}",
            msg.correlation_id()
        );
    }
}
