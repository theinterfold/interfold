// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CommitteeFinalized {
    pub e3_id: E3id,
    pub committee: Vec<String>,
    pub scores: Vec<String>,
    pub chain_id: u64,
}

impl CommitteeFinalized {
    /// Sort committee members by ascending address so every node derives the same
    /// deterministic ordering, matching the on-chain registry's canonical address-ascending
    /// `topNodes` layout (see `_sortTopNodesByAscendingAddress` in `CiphernodeRegistryOwnable`).
    /// The node with the numerically lowest address ends up at index 0 (= party 0).
    /// Address comparison is done in lowercase to be independent of EIP-55 checksumming.
    pub fn sort_by_score(&mut self) {
        let mut indices: Vec<usize> = (0..self.committee.len()).collect();
        indices.sort_by_key(|&i| self.committee[i].to_lowercase());

        let sorted_committee: Vec<String> =
            indices.iter().map(|&i| self.committee[i].clone()).collect();
        let sorted_scores: Vec<String> = if self.scores.len() == self.committee.len() {
            indices.iter().map(|&i| self.scores[i].clone()).collect()
        } else {
            self.scores.clone()
        };

        self.committee = sorted_committee;
        self.scores = sorted_scores;
    }
}

impl Display for CommitteeFinalized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
