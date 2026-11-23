// SPDX-License-Identifier: LGPL-3.0-only

use alloy::primitives::U256;
use e3_events::E3id;
use std::collections::HashMap;

/// One slot per low byte of the request number on a configured chain. A singleton is exact;
/// on collision the collector must filter the indicated journal span for the actual E3.
#[derive(Default)]
pub(super) struct EarlyShares(HashMap<(u64, u8), Hint>);

struct Hint {
    min_id: U256,
    max_id: U256,
    first: u64,
    last: u64,
}

impl EarlyShares {
    fn key(id: &E3id) -> Option<((u64, u8), U256)> {
        // The EVM adapter emits canonical decimal uint256s. Aliases must not consume another
        // request's hint, and arbitrary peer strings must never be retained.
        let text = id.e3_id();
        if text.is_empty()
            || text.len() > 78
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let n = U256::from_str_radix(text, 10).ok()?;
        Some(((id.chain_id(), n.as_limbs()[0] as u8), n))
    }

    pub(super) fn note(&mut self, id: &E3id, seq: u64) {
        let Some((key, n)) = Self::key(id) else {
            return;
        };
        let hint = self.0.entry(key).or_insert(Hint {
            min_id: n,
            max_id: n,
            first: seq,
            last: seq,
        });
        hint.min_id = hint.min_id.min(n);
        hint.max_id = hint.max_id.max(n);
        hint.first = hint.first.min(seq);
        hint.last = hint.last.max(seq);
    }

    pub(super) fn take(&mut self, id: &E3id) -> Option<(u64, u64)> {
        let (key, n) = Self::key(id)?;
        let hint = self.0.get_mut(&key)?;
        if !(hint.min_id..=hint.max_id).contains(&n) {
            return None;
        }
        let range = (hint.first, hint.last);
        if hint.min_id == hint.max_id {
            self.0.remove(&key);
        } else if hint.min_id == n {
            hint.min_id += U256::from(256);
        } else if hint.max_id == n {
            hint.max_id -= U256::from(256);
        }
        Some(range)
    }
}
