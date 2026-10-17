// SPDX-License-Identifier: LGPL-3.0-only

//! Publish the terminal verification decision.

use super::*;

impl ShareVerificationActor {
    pub(in crate::actors::share_verification) fn publish_complete(
        &self,
        e3_id: E3id,
        kind: VerificationKind,
        dishonest_parties: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
    ) {
        if let Err(err) = self.bus.publish(
            ShareVerificationComplete {
                e3_id,
                kind,
                dishonest_parties,
            },
            ec,
        ) {
            error!("Failed to publish ShareVerificationComplete: {err}");
        }
    }
}
