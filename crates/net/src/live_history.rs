// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::{Arc, OnceLock};

/// The time from which this node stores the network's history live.
///
/// It stays unset until startup has ended and the gossip that the node held during startup is
/// durable. From then on, the node stores each gossip event when it receives it. History replies
/// carry this time, so a requester knows which range a reply vouches for.
#[derive(Clone, Debug, Default)]
pub struct LiveHistory(Arc<OnceLock<u128>>);

impl LiveHistory {
    /// The time from which the node stores history live, or `None` while it still starts up.
    pub fn since(&self) -> Option<u128> {
        self.0.get().copied()
    }

    /// Record the time from which the node stores history live. Only the first time counts.
    pub(crate) fn begin(&self, ts: u128) {
        let _ = self.0.set(ts);
    }
}
