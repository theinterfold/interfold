// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A bounded record of E3s whose phase ended.

use e3_events::E3id;
use std::collections::VecDeque;

/// The most E3s that one record keeps. A long-running node sees an unbounded number of E3s, so the
/// oldest entry drops out first.
pub(crate) const MAX_CLOSED_E3S: usize = 1_024;

/// Record that the phase of `e3_id` ended. The record keeps the newest `MAX_CLOSED_E3S` E3s.
pub(crate) fn record_closed_e3(closed: &mut VecDeque<E3id>, e3_id: &E3id) {
    if closed.contains(e3_id) {
        return;
    }
    if closed.len() == MAX_CLOSED_E3S {
        closed.pop_front();
    }
    closed.push_back(e3_id.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_oldest_e3_drops_out_when_the_record_is_full() {
        let mut closed = VecDeque::new();
        for id in 0..MAX_CLOSED_E3S {
            record_closed_e3(&mut closed, &E3id::new(id.to_string(), 1));
        }
        record_closed_e3(&mut closed, &E3id::new("0", 1));
        assert_eq!(closed.len(), MAX_CLOSED_E3S, "a repeat adds nothing");

        record_closed_e3(&mut closed, &E3id::new("new", 1));
        assert_eq!(closed.len(), MAX_CLOSED_E3S);
        assert!(!closed.contains(&E3id::new("0", 1)));
        assert!(closed.contains(&E3id::new("1", 1)));
        assert!(closed.contains(&E3id::new("new", 1)));
    }
}
