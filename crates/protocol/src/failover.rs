// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Which member aggregates a phase, and when the next member takes over.

use crate::UnixSecs;
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The aggregator of one phase is the first member in committee order that the chain has not
/// expelled, that H members have not found sending a failing proof, and that has not let its
/// budget run out in this phase. Its budget starts once the phase's inputs are ready at this node,
/// and starts again whenever another member becomes the aggregator. When no member is left to
/// take over, the last one stays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Failover {
    budget: u64,
    unresponsive: BTreeSet<Address>,
    convicted: BTreeSet<Address>,
    round: Option<Round>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Round {
    aggregator: Address,
    /// None once no member is left to take over.
    deadline: Option<UnixSecs>,
}

impl Failover {
    pub(crate) fn new(budget: u64) -> Self {
        Self {
            budget,
            unresponsive: BTreeSet::new(),
            convicted: BTreeSet::new(),
            round: None,
        }
    }

    /// H members found `member` sending a failing proof: it aggregates no more, and a round it
    /// leads hands over at the next `pass_deadlines`. Whether this is news.
    pub(crate) fn convict(&mut self, member: Address) -> bool {
        self.convicted.insert(member)
    }

    /// Whether H members found `member` sending a failing proof.
    pub(crate) fn is_convicted(&self, member: &Address) -> bool {
        self.convicted.contains(member)
    }

    pub(crate) fn aggregator(
        &self,
        members: &[Address],
        expelled: &BTreeSet<Address>,
    ) -> Option<Address> {
        self.candidates(members, expelled).next()
    }

    pub(crate) fn inputs_ready(
        &mut self,
        now: UnixSecs,
        members: &[Address],
        expelled: &BTreeSet<Address>,
    ) {
        if self.round.is_none() {
            self.start_round(now, members, expelled);
        }
    }

    pub(crate) fn pass_deadlines(
        &mut self,
        now: UnixSecs,
        members: &[Address],
        expelled: &BTreeSet<Address>,
    ) {
        let Some(round) = self.round.clone() else {
            return;
        };
        if self.aggregator(members, expelled) != Some(round.aggregator) {
            self.start_round(now, members, expelled);
            return;
        }
        if round.deadline.is_none_or(|deadline| now < deadline) {
            return;
        }
        if self.candidates(members, expelled).nth(1).is_some() {
            self.unresponsive.insert(round.aggregator);
            self.start_round(now, members, expelled);
        } else if let Some(round) = &mut self.round {
            round.deadline = None;
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        self.round.as_ref()?.deadline
    }

    fn start_round(&mut self, now: UnixSecs, members: &[Address], expelled: &BTreeSet<Address>) {
        self.round = self.aggregator(members, expelled).map(|aggregator| Round {
            aggregator,
            deadline: Some(now + self.budget),
        });
    }

    fn candidates<'a>(
        &'a self,
        members: &'a [Address],
        expelled: &'a BTreeSet<Address>,
    ) -> impl Iterator<Item = Address> + 'a {
        members
            .iter()
            .filter(|member| {
                !expelled.contains(*member)
                    && !self.unresponsive.contains(*member)
                    && !self.convicted.contains(*member)
            })
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<Address> {
        (1..=3).map(Address::repeat_byte).collect()
    }

    #[test]
    fn the_first_member_aggregates_until_its_budget_runs_out() {
        let mut failover = Failover::new(600);
        let none = BTreeSet::new();
        assert_eq!(failover.aggregator(&members(), &none), Some(members()[0]));
        failover.pass_deadlines(10_000, &members(), &none);
        assert_eq!(failover.aggregator(&members(), &none), Some(members()[0]));

        failover.inputs_ready(100, &members(), &none);
        failover.inputs_ready(200, &members(), &none);
        assert_eq!(failover.next_deadline(), Some(700));
        failover.pass_deadlines(699, &members(), &none);
        assert_eq!(failover.aggregator(&members(), &none), Some(members()[0]));
        failover.pass_deadlines(700, &members(), &none);
        assert_eq!(failover.aggregator(&members(), &none), Some(members()[1]));
        assert_eq!(failover.next_deadline(), Some(1_300));
    }

    #[test]
    fn an_expelled_aggregator_hands_over_with_a_fresh_budget() {
        let mut failover = Failover::new(600);
        failover.inputs_ready(100, &members(), &BTreeSet::new());
        let expelled = BTreeSet::from([members()[0]]);
        failover.pass_deadlines(400, &members(), &expelled);
        assert_eq!(
            failover.aggregator(&members(), &expelled),
            Some(members()[1])
        );
        assert_eq!(failover.next_deadline(), Some(1_000));
    }

    #[test]
    fn a_convicted_aggregator_hands_over_with_a_fresh_budget() {
        let mut failover = Failover::new(600);
        let none = BTreeSet::new();
        failover.inputs_ready(100, &members(), &none);
        assert!(failover.convict(members()[0]));
        assert!(!failover.convict(members()[0]));
        failover.pass_deadlines(400, &members(), &none);
        assert_eq!(failover.aggregator(&members(), &none), Some(members()[1]));
        assert_eq!(failover.next_deadline(), Some(1_000));
    }

    #[test]
    fn the_last_member_stays_when_no_one_is_left_to_take_over() {
        let mut failover = Failover::new(600);
        let none = BTreeSet::new();
        failover.inputs_ready(0, &members(), &none);
        for now in [600, 1_200, 1_800] {
            failover.pass_deadlines(now, &members(), &none);
        }
        assert_eq!(failover.aggregator(&members(), &none), Some(members()[2]));
        assert_eq!(failover.next_deadline(), None);
    }
}
