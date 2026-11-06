// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The committee key (C5). Every member keeps the roster members' keyshares and folds, so any
//! member can take over as the key aggregator. The aggregator checks every roster member's C1,
//! sums the keyshares into the key, proves C5 with the folds, and asks the chain writer to
//! publish it. An aggregator that has started finishes, even after another member takes over;
//! the chain accepts one key.

use super::{
    AggregatedKey, Dkg, DkgWork, KeyPublication, KeyshareMessage, NodeFoldMessage,
    SignedAttestation,
};
use crate::{
    failover::Failover,
    node::{Effect, Submission, Transaction},
    proof::ProofType,
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
    /// This node aggregates: the C1 verdict of each roster member so far.
    CheckingKeyshares(BTreeMap<Address, bool>),
    Aggregating,
    Submitted,
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
        if let Work::CheckingKeyshares(verdicts) = &mut self.aggregation.work {
            verdicts.entry(member).or_insert(valid);
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
    /// the keyshares, then aggregate once every C1 passed and every fold is here.
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
        match &self.aggregation.work {
            Work::Idle if aggregator == Some(self.me) => {
                self.aggregation.work = Work::CheckingKeyshares(BTreeMap::new());
                roster
                    .iter()
                    .zip(keyshares)
                    .map(|(member, keyshare)| {
                        self.run(DkgWork::CheckKeyshare {
                            member: *member,
                            committee: self.members.clone(),
                            keyshare: Box::new(keyshare),
                        })
                    })
                    .collect()
            }
            Work::CheckingKeyshares(verdicts) => {
                let all_valid = roster
                    .iter()
                    .all(|member| verdicts.get(member) == Some(&true));
                let folds: Option<Vec<_>> = roster
                    .iter()
                    .map(|member| Some(self.aggregation.folds.get(member)?.fold.clone()))
                    .collect();
                let (true, Some(folds)) = (all_valid, folds) else {
                    return Vec::new();
                };
                self.aggregation.work = Work::Aggregating;
                vec![self.run(DkgWork::AggregateKey {
                    committee: self.members.clone(),
                    roster,
                    keyshares,
                    folds,
                })]
            }
            Work::Idle | Work::Aggregating | Work::Submitted => Vec::new(),
        }
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
