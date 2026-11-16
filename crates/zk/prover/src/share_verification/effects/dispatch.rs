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
        // A profile that this build cannot verify is a local fault. The node abstains: it keeps no
        // pending work, publishes no verdict and blames no peer.
        if let Err(error) = msg
            .params_profile
            .ensure_admission_enabled()
            .and_then(|()| msg.params_profile.validate_committee(msg.committee_size))
        {
            self.bus.with_ec(&ec).err(
                EType::Computation,
                anyhow!(
                    "Skipping {:?} verification for E3 {e3_id}: {error}",
                    msg.kind
                ),
            );
            return;
        }

        info!(
            "handling ShareVerificationDispatched {:?}, {:?}",
            e3_id, msg.kind
        );

        let params_profile = msg.params_profile;
        let committee_size = msg.committee_size;
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
                    params_profile,
                    committee_size,
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
                    params_profile,
                    committee_size,
                    |pending, passed| {
                        pending.ecdsa_passed_decryption_proofs = passed;
                    },
                );
            }
        }
    }
}
