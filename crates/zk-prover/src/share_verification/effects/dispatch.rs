// SPDX-License-Identifier: LGPL-3.0-only

//! Select the verification workflow for an incoming proof bundle.

use super::*;

impl ShareVerificationActor {
    pub(in crate::actors::share_verification) fn handle_share_verification_dispatched(
        &mut self,
        msg: TypedEvent<ShareVerificationDispatched>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        info!(
            "handling ShareVerificationDispatched {:?}, {:?}",
            e3_id, msg.kind
        );

        let params_preset = msg.params_preset;
        let committee_size = msg.committee_size;
        let dkg_roster = msg.dkg_roster.clone();
        match msg.kind {
            VerificationKind::ShareProofs
            | VerificationKind::ThresholdDecryptionProofs
            | VerificationKind::PkGenerationProofs => {
                let kind = msg.kind.clone();
                self.verify_proofs(
                    e3_id,
                    kind.clone(),
                    msg.share_proofs,
                    msg.pre_dishonest,
                    ec,
                    params_preset,
                    committee_size,
                    dkg_roster,
                    |pending, passed| {
                        pending.ecdsa_passed_share_proofs = passed;
                    },
                );
            }
            VerificationKind::DecryptionProofs => {
                self.verify_proofs(
                    e3_id,
                    VerificationKind::DecryptionProofs,
                    msg.decryption_proofs,
                    msg.pre_dishonest,
                    ec,
                    params_preset,
                    committee_size,
                    dkg_roster,
                    |pending, passed| {
                        pending.ecdsa_passed_decryption_proofs = passed;
                    },
                );
            }
        }
    }
}
