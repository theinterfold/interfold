// SPDX-License-Identifier: LGPL-3.0-only

//! Correlate worker failures to the affected proof workflow.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_compute_request_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) {
        let (msg, ec) = msg.into_components();
        let ComputeRequestErrorKind::Zk(err) = msg.get_err() else {
            return;
        };

        if let Some(pending) = self.pending.remove(msg.correlation_id()) {
            error!(
                "C0 proof request failed for E3 {}: {err} — key will not be published without proof",
                pending.e3_id
            );
            self.fail_dkg_round(pending.e3_id, &ec, "C0 proof request error");
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.threshold_correlation.remove(msg.correlation_id()) {
            error!(
                "DKG {:?} proof request failed for E3 {}: {err} — threshold share will not be published without proof",
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
                "C4 {:?} proof request failed for E3 {}: {err} — DecryptionKeyShared will not be published",
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
                "C6 proof request failed for E3 {}: {err} — DecryptionshareCreated will not be published",
                e3_id
            );
            self.pending_share_decryption.remove(&e3_id);
            self.fail_decryption_round(e3_id, &ec, "C6 proof request error");
            return;
        }

        if let Some(e3_id) = self.pk_aggregation_correlation.remove(msg.correlation_id()) {
            error!(
                "C5 proof request failed for E3 {}: {err} — PkAggregationProofSigned will not be published",
                e3_id
            );
            self.pending_pk_aggregation.remove(&e3_id);

            self.fail_dkg_round(e3_id, &ec, "C5 proof request error");
            return;
        }

        if let Some(e3_id) = self
            .pk_generation_ckks_correlation
            .remove(msg.correlation_id())
        {
            error!(
                "C1-CKKS proof request failed for E3 {}: {err} — KeyshareCreated will not be \
                 published without proof",
                e3_id
            );
            self.pending_pk_generation_ckks.remove(&e3_id);
            self.fail_dkg_round(e3_id, &ec, "C1-CKKS proof request error");
            return;
        }

        if let Some(e3_id) = self.relin_round1_correlation.remove(msg.correlation_id()) {
            error!(
                "C8-CKKS proof request failed for E3 {}: {err} — RelinCeremonyProofSigned will \
                 not be published; the ceremony cannot complete with this party",
                e3_id
            );
            self.pending_relin_round1.remove(&e3_id);
            self.fail_dkg_round(e3_id, &ec, "C8-CKKS proof request error");
            return;
        }

        if let Some(e3_id) = self.aggregation_correlation.remove(msg.correlation_id()) {
            error!(
                "C7 proof request failed for E3 {}: {err} — AggregationProofSigned will not be published",
                e3_id
            );
            self.pending_aggregation.remove(&e3_id);
            self.fail_decryption_round(e3_id, &ec, "C7 proof request error");
        }
    }
}
