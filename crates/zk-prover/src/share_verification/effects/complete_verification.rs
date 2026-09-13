// SPDX-License-Identifier: LGPL-3.0-only

//! Publish the terminal verification decision.

use super::*;

impl ShareVerificationActor {
    pub(in crate::actors::share_verification) fn publish_complete(
        &self,
        e3_id: E3id,
        kind: VerificationKind,
        verification_id: Option<B256>,
        dishonest_parties: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
    ) {
        if let Err(err) = self.bus.publish(
            ShareVerificationComplete {
                e3_id,
                kind,
                verification_id,
                dishonest_parties,
            },
            ec,
        ) {
            error!("Failed to publish ShareVerificationComplete: {err}");
        }
    }
}
