// SPDX-License-Identifier: LGPL-3.0-only

//! Correlate worker failures to the affected proof workflow.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_compute_request_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) {
        let (msg, ec) = msg.into_components();

        // Every actor that dispatches compute work receives every `ComputeRequestError`, so a
        // correlation that no map below owns belongs to a different actor. Match on the
        // correlation first and report the error kind through `Display`: a failure that this
        // actor owns must fail its round, whether the worker reported a ZK or a TrBFV error.
        if let Some(pending) = self.pending.remove(msg.correlation_id()) {
            error!(
                "C0 proof request failed for E3 {}: {msg} — key will not be published without proof",
                pending.e3_id
            );
            self.fail_dkg_round(pending.e3_id, &ec, "C0 proof request error");
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.threshold_correlation.remove(msg.correlation_id()) {
            error!(
                "DKG {:?} proof request failed for E3 {}: {msg} — threshold share will not be published without proof",
                kind, e3_id
            );
            self.threshold_correlation
                .retain(|_, (eid, _, _)| *eid != e3_id);
            self.pending_threshold.remove(&e3_id);
            self.fail_dkg_round(e3_id, &ec, "DKG threshold proof request error");
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.decryption_correlation.remove(msg.correlation_id())
        {
            error!(
                "C4 {:?} proof request failed for E3 {}: {msg} — DecryptionKeyShared will not be published",
                kind, e3_id
            );
            self.decryption_correlation
                .retain(|_, (eid, _, _)| *eid != e3_id);
            self.pending_decryption.remove(&e3_id);
            self.fail_dkg_round(e3_id, &ec, "C4 proof request error");
            return;
        }

        if let Some(e3_id) = self
            .share_decryption_correlation
            .remove(msg.correlation_id())
        {
            error!(
                "C6 proof request failed for E3 {}: {msg} — DecryptionshareCreated will not be published",
                e3_id
            );
            self.pending_share_decryption.remove(&e3_id);
            self.fail_decryption_round(e3_id, &ec, "C6 proof request error");
            return;
        }

        if let Some(e3_id) = self.pk_aggregation_correlation.remove(msg.correlation_id()) {
            error!(
                "C5 proof request failed for E3 {}: {msg} — PkAggregationProofSigned will not be published",
                e3_id
            );
            self.pending_pk_aggregation.remove(&e3_id);

            self.fail_dkg_round(e3_id, &ec, "C5 proof request error");
            return;
        }

        if let Some(e3_id) = self.aggregation_correlation.remove(msg.correlation_id()) {
            error!(
                "C7 proof request failed for E3 {}: {msg} — AggregationProofSigned will not be published",
                e3_id
            );
            self.pending_aggregation.remove(&e3_id);
            self.fail_decryption_round(e3_id, &ec, "C7 proof request error");
            return;
        }

        debug!(
            "ProofRequestActor: ignored compute error for correlation {:?} held by another actor: {msg}",
            msg.correlation_id()
        );
    }
}
