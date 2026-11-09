// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The committee key (C5). Every member keeps the roster members' keyshares and folds, so any
//! member can take over as the key aggregator. The aggregator checks every roster member's C1,
//! folds the members' folds one at a time as they arrive, sums the keyshares into the key, proves
//! C5 with the fold of them, and asks the chain writer to publish it. An aggregator that has
//! started finishes, even after another member takes over; the chain accepts one key.

use super::{
    AggregatedKey, Dkg, DkgWork, KeyPublication, KeyshareMessage, NodeFoldMessage,
    SignedAttestation,
};
use crate::{
    failover::Failover,
    node::{Effect, Submission, Transaction},
    proof::{ProofType, ZkProof},
    UnixSecs,
};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The key aggregator's budget, from when every roster keyshare is here. It also waits for every
/// roster member's fold, which can take long to prove.
const PUBLIC_KEY_BUDGET: UnixSecs = 40 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Aggregation {
    /// The first signed keyshare of each member. Before the roster is known every member's are
    /// kept; only roster members' count.
    pub(super) keyshares: BTreeMap<Address, KeyshareMessage>,
    /// The first attested fold of each member, kept the same way.
    folds: BTreeMap<Address, NodeFoldMessage>,
    failover: Failover,
    work: Work,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Work {
    /// Not this node's work, or not yet.
    Idle,
    /// This node aggregates: it checks the keyshares and folds the roster's folds.
    Building(Box<Building>),
    Aggregating,
    Submitted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Building {
    /// The C1 verdict of each roster member so far.
    verdicts: BTreeMap<Address, bool>,
    /// The fold of the roster's first `filled` slots.
    accumulator: Option<ZkProof>,
    filled: usize,
    /// One step of the fold runs at a time, and each step needs the one before it.
    folding: bool,
}

impl Default for Aggregation {
    fn default() -> Self {
        Self {
            keyshares: BTreeMap::new(),
            folds: BTreeMap::new(),
            failover: Failover::new(PUBLIC_KEY_BUDGET),
            work: Work::Idle,
        }
    }
}

impl Dkg {
    pub(super) fn admits_keyshare(&self, member: Address, message: &KeyshareMessage) -> bool {
        self.counts_for_the_key(member)
            && !self.aggregation.keyshares.contains_key(&member)
            && message
                .c1
                .is_signed_by(member, self.e3, ProofType::C1PkGeneration)
    }

    pub(super) fn receive_keyshare(&mut self, member: Address, message: KeyshareMessage) {
        self.aggregation.keyshares.insert(member, message);
    }

    pub(super) fn admits_fold(&self, member: Address, message: &NodeFoldMessage) -> bool {
        self.counts_for_the_key(member)
            && !self.aggregation.folds.contains_key(&member)
            && self.attests(member, message)
    }

    pub(super) fn receive_fold(&mut self, member: Address, message: NodeFoldMessage) {
        self.record_fold(member, message);
    }

    pub(super) fn record_keyshare(&mut self, member: Address, message: KeyshareMessage) {
        self.aggregation.keyshares.entry(member).or_insert(message);
    }

    pub(super) fn record_fold(&mut self, member: Address, message: NodeFoldMessage) {
        self.aggregation.folds.entry(member).or_insert(message);
    }

    pub(super) fn keyshare_checked(&mut self, member: Address, valid: bool) {
        if let Work::Building(building) = &mut self.aggregation.work {
            building.verdicts.entry(member).or_insert(valid);
        }
    }

    /// A step of the roster's fold finished. A repeated job's second result changes nothing.
    pub(super) fn roster_folded(&mut self, slot: u32, accumulator: ZkProof) {
        let Work::Building(building) = &mut self.aggregation.work else {
            return;
        };
        if building.folding && slot as usize == building.filled {
            building.accumulator = Some(accumulator);
            building.filled += 1;
            building.folding = false;
        }
    }

    pub(super) fn key_aggregated(&mut self, key: AggregatedKey) -> Vec<Effect> {
        let (Work::Aggregating, Some(roster)) = (&self.aggregation.work, self.roster_members())
        else {
            return Vec::new();
        };
        let attestations = roster
            .iter()
            .filter_map(|member| {
                let fold = self.aggregation.folds.get(member)?;
                Some(SignedAttestation {
                    party_id: self.party_id(*member)?,
                    node: *member,
                    sk_agg_commit: fold.fold.sk_agg_commit,
                    esm_agg_commit: fold.fold.esm_agg_commit,
                    signature: fold.attestation.clone(),
                })
            })
            .collect();
        self.aggregation.work = Work::Submitted;
        vec![Effect::Submit(Submission {
            e3: self.e3,
            transaction: Transaction::PublishCommittee(KeyPublication {
                commitment: key.commitment,
                public_key: key.public_key,
                proof: key.proof,
                attestations,
            }),
        })]
    }

    /// Start the aggregator's budget once every roster keyshare is here; as the aggregator, check
    /// the keyshares, fold the roster's folds as they arrive, and aggregate once every C1 passed
    /// and every slot is folded.
    pub(super) fn advance_aggregation(&mut self, now: UnixSecs) -> Vec<Effect> {
        let Some(roster) = self.roster_members() else {
            return Vec::new();
        };
        let keyshares: Option<Vec<KeyshareMessage>> = roster
            .iter()
            .map(|member| self.aggregation.keyshares.get(member).cloned())
            .collect();
        let Some(keyshares) = keyshares else {
            return Vec::new();
        };
        self.aggregation
            .failover
            .inputs_ready(now, &self.members, &self.expelled);
        let aggregator = self
            .aggregation
            .failover
            .aggregator(&self.members, &self.expelled);
        let mut effects = Vec::new();
        if self.aggregation.work == Work::Idle && aggregator == Some(self.me) {
            self.aggregation.work = Work::Building(Box::default());
            effects.extend(roster.iter().zip(&keyshares).map(|(member, keyshare)| {
                self.run(DkgWork::CheckKeyshare {
                    member: *member,
                    committee: self.members.clone(),
                    keyshare: Box::new(keyshare.clone()),
                })
            }));
        }
        let Work::Building(building) = &self.aggregation.work else {
            return effects;
        };
        let (filled, folding) = (building.filled, building.folding);
        if let Some(member) = roster.get(filled).filter(|_| !folding) {
            if let Some(fold) = self.aggregation.folds.get(member) {
                let step = DkgWork::FoldRoster {
                    slot: filled as u32,
                    slots: roster.len(),
                    fold: fold.fold.proof.clone(),
                    accumulator: building.accumulator.clone(),
                };
                effects.push(self.run(step));
                if let Work::Building(building) = &mut self.aggregation.work {
                    building.folding = true;
                }
            }
            return effects;
        }
        let all_valid = roster
            .iter()
            .all(|member| building.verdicts.get(member) == Some(&true));
        let (true, Some(accumulator)) = (
            all_valid && filled == roster.len(),
            building.accumulator.clone(),
        ) else {
            return effects;
        };
        let folds: Option<Vec<_>> = roster
            .iter()
            .map(|member| Some(self.aggregation.folds.get(member)?.fold.clone()))
            .collect();
        let Some(folds) = folds else {
            return effects;
        };
        self.aggregation.work = Work::Aggregating;
        effects.push(self.run(DkgWork::AggregateKey {
            committee: self.members.clone(),
            roster,
            keyshares,
            folds,
            accumulator,
        }));
        effects
    }

    /// `member` aggregates the committee key no more; whether this is news.
    pub(super) fn convict_key_aggregator(&mut self, member: Address) -> bool {
        self.aggregation.failover.convict(member)
    }

    pub(super) fn pass_aggregation_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        if self.aggregation.work == Work::Idle {
            self.aggregation
                .failover
                .pass_deadlines(now, &self.members, &self.expelled);
        }
        self.advance_aggregation(now)
    }

    pub(super) fn aggregation_deadline(&self) -> Option<UnixSecs> {
        match self.aggregation.work {
            Work::Idle => self.aggregation.failover.next_deadline(),
            _ => None,
        }
    }

    /// A member's keyshare and fold count once the roster holds it; before the roster is known
    /// any member's are kept.
    fn counts_for_the_key(&self, member: Address) -> bool {
        member != self.me
            && self.is_member(member)
            && self
                .roster_members()
                .is_none_or(|roster| roster.contains(&member))
    }
}
