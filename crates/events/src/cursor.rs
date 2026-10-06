// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::EventContextSeq;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum SeqCursor {
    Done,
    Next(u64),
}

pub fn compute_seq_cursor<T: EventContextSeq>(events: &[T], limit: usize) -> SeqCursor {
    if events.len() == limit {
        let last_seq = events.last().map(|e| e.seq()).unwrap_or(0);
        SeqCursor::Next(last_seq)
    } else {
        SeqCursor::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::EventContextSeq;

    struct MockEvent(u64);
    impl EventContextSeq for MockEvent {
        fn seq(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn the_cursor_is_done_below_the_limit_and_points_at_the_last_seq_at_it() {
        let cases: [(&[u64], usize, SeqCursor); 3] = [
            (&[], 10, SeqCursor::Done),
            (&[1, 2], 10, SeqCursor::Done),
            (&[100, 200, 300], 3, SeqCursor::Next(300)),
        ];

        for (seqs, limit, expected) in cases {
            let events: Vec<MockEvent> = seqs.iter().copied().map(MockEvent).collect();
            assert_eq!(
                compute_seq_cursor(&events, limit),
                expected,
                "seqs={seqs:?} limit={limit}"
            );
        }
    }
}
