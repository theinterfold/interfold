// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One chain's operator registry over time, from its logs: each operator's activity, ticket
//! balance, and bond owner. The registry reads these at T−1 for a request made at T, so selection
//! uses the chain's history, not its head; a ticket also needs the operator active and enabled when
//! it is submitted.

use crate::{selection::Eligible, UnixSecs};
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Registry {
    operators: BTreeMap<Address, Operator>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Operator {
    active: History<bool>,
    balance: History<U256>,
    owner: History<Address>,
    /// Whether the ciphernode registry lists the operator now.
    enabled: bool,
}

/// Values over time. A value counts from its timestamp on; a later value with the same timestamp
/// replaces it, as a later log in the same block does on chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct History<T> {
    points: Vec<(UnixSecs, T)>,
}

impl<T> Default for History<T> {
    fn default() -> Self {
        Self { points: Vec::new() }
    }
}

impl<T: Copy> History<T> {
    fn set(&mut self, time: UnixSecs, value: T) {
        match self.points.last_mut() {
            Some((last, current)) if *last == time => *current = value,
            _ => self.points.push((time, value)),
        }
    }

    fn at(&self, time: UnixSecs) -> Option<T> {
        let index = self.points.partition_point(|(at, _)| *at <= time);
        index.checked_sub(1).map(|index| self.points[index].1)
    }

    fn latest(&self) -> Option<T> {
        self.points.last().map(|(_, value)| *value)
    }
}

impl Registry {
    pub(crate) fn set_active(&mut self, time: UnixSecs, operator: Address, active: bool) {
        self.operators
            .entry(operator)
            .or_default()
            .active
            .set(time, active);
    }

    pub(crate) fn set_balance(&mut self, time: UnixSecs, operator: Address, balance: U256) {
        self.operators
            .entry(operator)
            .or_default()
            .balance
            .set(time, balance);
    }

    pub(crate) fn set_owner(&mut self, time: UnixSecs, operator: Address, owner: Address) {
        self.operators
            .entry(operator)
            .or_default()
            .owner
            .set(time, owner);
    }

    pub(crate) fn set_enabled(&mut self, operator: Address, enabled: bool) {
        self.operators.entry(operator).or_default().enabled = enabled;
    }

    /// Whether the registry still takes `operator`'s ticket, which needs it enabled and active now
    /// as well as eligible at the request.
    pub(crate) fn can_submit(&self, operator: Address) -> bool {
        self.operators
            .get(&operator)
            .is_some_and(|operator| operator.enabled && operator.active.latest() == Some(true))
    }

    /// Whether `operator` is active now, and whether the ciphernode registry lists it.
    pub(crate) fn standing(&self, operator: Address) -> (bool, bool) {
        self.operators
            .get(&operator)
            .map_or((false, false), |operator| {
                (operator.active.latest() == Some(true), operator.enabled)
            })
    }

    /// A new eligibility configuration makes every operator inactive until it refreshes against
    /// it; its refresh logs the operator active again.
    pub(crate) fn reset_activity(&mut self, time: UnixSecs) {
        for operator in self.operators.values_mut() {
            operator.active.set(time, false);
        }
    }

    /// Every operator the registry's logs named.
    pub(crate) fn operators(&self) -> impl Iterator<Item = Address> + '_ {
        self.operators.keys().copied()
    }

    /// Every operator active at `time` with at least one ticket at `price`, and its owner then.
    pub(crate) fn eligible_at(&self, time: UnixSecs, price: U256) -> Vec<Eligible> {
        if price.is_zero() {
            return Vec::new();
        }
        self.operators
            .iter()
            .filter(|(_, operator)| operator.active.at(time) == Some(true))
            .filter_map(|(address, operator)| {
                let balance = operator.balance.at(time)?;
                let tickets = u64::try_from(balance / price).unwrap_or(u64::MAX);
                (tickets > 0).then(|| Eligible {
                    operator: *address,
                    tickets,
                    owner: operator.owner.at(time),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator(n: u8) -> Address {
        Address::repeat_byte(n)
    }

    #[test]
    fn eligibility_reads_the_history_at_the_given_time() {
        let mut registry = Registry::default();
        registry.set_active(100, operator(1), true);
        registry.set_balance(100, operator(1), U256::from(30));
        registry.set_owner(100, operator(1), operator(9));
        registry.set_balance(200, operator(1), U256::from(50));
        registry.set_active(300, operator(1), false);

        assert!(registry.eligible_at(99, U256::from(10)).is_empty());
        let at = |time| registry.eligible_at(time, U256::from(10));
        assert_eq!(
            at(150),
            vec![Eligible {
                operator: operator(1),
                tickets: 3,
                owner: Some(operator(9)),
            }]
        );
        assert_eq!(at(250)[0].tickets, 5);
        assert!(at(300).is_empty());
    }

    #[test]
    fn a_later_value_in_the_same_block_replaces_the_earlier_one() {
        let mut registry = Registry::default();
        registry.set_active(100, operator(1), true);
        registry.set_balance(100, operator(1), U256::from(10));
        registry.set_active(100, operator(1), false);
        assert!(registry.eligible_at(100, U256::from(10)).is_empty());
    }

    #[test]
    fn a_new_eligibility_configuration_makes_every_operator_inactive_until_it_refreshes() {
        let mut registry = Registry::default();
        for n in [1, 2] {
            registry.set_active(100, operator(n), true);
            registry.set_balance(100, operator(n), U256::from(10));
        }
        registry.reset_activity(200);
        registry.set_active(250, operator(2), true);
        let eligible: Vec<Address> = registry
            .eligible_at(300, U256::from(10))
            .into_iter()
            .map(|eligible| eligible.operator)
            .collect();
        assert_eq!(eligible, vec![operator(2)]);
        assert_eq!(registry.eligible_at(199, U256::from(10)).len(), 2);
    }

    /// Governance can remove a bonded operator, whose activity then says nothing about its ticket.
    #[test]
    fn a_ticket_needs_the_operator_enabled_and_active_now() {
        let mut registry = Registry::default();
        registry.set_active(100, operator(1), true);
        assert!(!registry.can_submit(operator(1)));
        registry.set_enabled(operator(1), true);
        assert!(registry.can_submit(operator(1)));
        registry.set_active(200, operator(1), false);
        assert!(!registry.can_submit(operator(1)));
        registry.set_active(300, operator(1), true);
        registry.set_enabled(operator(1), false);
        assert!(!registry.can_submit(operator(1)));
        assert!(!registry.can_submit(operator(2)));
    }
}
