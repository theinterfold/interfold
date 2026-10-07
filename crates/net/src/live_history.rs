// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::{Arc, Mutex};

/// The time from which this node stores the network's history live.
///
/// It stays unset until startup has ended and the gossip that the node held during startup is
/// durable. From then on, the node stores each gossip event when it receives it. History replies
/// carry this time as a hint, so a requester asks more peers when no source observed its range
/// live. It is revoked for the rest of the process when the node knows that it lost gossip.
#[derive(Clone, Debug, Default)]
pub struct LiveHistory(Arc<Mutex<State>>);

#[derive(Clone, Copy, Debug, Default)]
enum State {
    #[default]
    Starting,
    Live(u128),
    Revoked,
}

impl LiveHistory {
    /// The time from which the node stores history live, or `None` while it still starts up and
    /// after it lost gossip.
    pub fn since(&self) -> Option<u128> {
        match *self.0.lock().expect("live history lock poisoned") {
            State::Live(ts) => Some(ts),
            State::Starting | State::Revoked => None,
        }
    }

    /// Record the time from which the node stores history live. Only the first time counts.
    pub(crate) fn begin(&self, ts: u128) {
        let mut state = self.0.lock().expect("live history lock poisoned");
        if matches!(*state, State::Starting) {
            *state = State::Live(ts);
        }
    }

    /// The node lost gossip that it received, so its history has a gap that it cannot see.
    pub(crate) fn revoke(&self) {
        *self.0.lock().expect("live history lock poisoned") = State::Revoked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_history_begins_once_and_a_loss_ends_it_for_good() {
        let live = LiveHistory::default();
        assert_eq!(live.since(), None);
        live.begin(7);
        live.begin(9);
        assert_eq!(live.since(), Some(7));
        live.revoke();
        live.begin(11);
        assert_eq!(live.since(), None);
    }
}
