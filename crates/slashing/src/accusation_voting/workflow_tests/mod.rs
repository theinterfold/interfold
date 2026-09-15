// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::primitives::FixedBytes;
use e3_events::{InterfoldEventData, Unsequenced};

struct FixedClock(u64);
impl Clock for FixedClock {
    fn unix_now_secs(&self) -> u64 {
        self.0
    }
}

/// A throwaway sequenced [`EventContext`] for driving service calls in
/// tests. The service never inspects the context beyond cloning it onto
/// emitted actions, so any well-formed origin context works.
fn ctx() -> EventContext<Sequenced> {
    let vote = AccusationVote {
        e3_id: E3id::new("42", CHAIN_ID),
        accusation_id: [0u8; 32],
        voter: Address::ZERO,
        data_hash: [0u8; 32],
        issued_at: 0,
        deadline: 0,
        signature: ArcBytes::default(),
    };
    EventContext::<Unsequenced>::from(InterfoldEventData::from(vote)).sequence(0)
}

const CHAIN_ID: u64 = 31337;
const VALIDITY: u64 = 1_800;
const SKEW: u64 = 30;
const NOW: u64 = 1_700_000_000;

fn signer(byte: u8) -> PrivateKeySigner {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    PrivateKeySigner::from_bytes(&FixedBytes::<32>::from(bytes)).unwrap()
}

fn voting_with(
    me: &PrivateKeySigner,
    committee: Vec<Address>,
    circuit_threshold_t: usize,
    vote_quorum_h: usize,
) -> AccusationVoting {
    AccusationVoting::new(
        E3id::new("42", CHAIN_ID),
        me.clone(),
        "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap(),
        committee,
        circuit_threshold_t,
        vote_quorum_h,
        VALIDITY,
        SKEW,
        e3_fhe_params::BfvPreset::default(),
        Arc::new(FixedClock(NOW)),
    )
}

/// Build and sign a vote as `who` for the given accusation/data hash.
fn signed_vote(
    who: &PrivateKeySigner,
    slashing_manager: Address,
    e3_id: &E3id,
    accusation_id: [u8; 32],
    data_hash: [u8; 32],
    deadline: u64,
) -> AccusationVote {
    let mut vote = AccusationVote {
        e3_id: e3_id.clone(),
        accusation_id,
        voter: who.address(),
        data_hash,
        issued_at: deadline.saturating_sub(VALIDITY),
        deadline,
        signature: ArcBytes::default(),
    };
    let digest = AccusationVoting::vote_digest(&vote, slashing_manager);
    let sig = who.sign_hash_sync(&FixedBytes::<32>::from(digest)).unwrap();
    vote.signature = ArcBytes::from_bytes(&sig.as_bytes());
    vote
}

fn insert_pending(
    v: &mut AccusationVoting,
    accuser: &PrivateKeySigner,
    accused: Address,
    data_hash: [u8; 32],
    deadline: u64,
    own_vote: AccusationVote,
) -> [u8; 32] {
    let accusation = ProofFailureAccusation {
        e3_id: v.e3_id.clone(),
        accuser: accuser.address(),
        accused,
        accused_party_id: 1,
        proof_type: ProofType::C1PkGeneration,
        proof_instance: 0,
        data_hash,
        issued_at: deadline.saturating_sub(VALIDITY),
        deadline,
        signed_payload: None,
        signature: ArcBytes::default(),
    };
    let id = AccusationVoting::accusation_id(&accusation);
    v.pending.insert(
        id,
        PendingAccusation {
            accusation,
            votes_for: vec![own_vote],
            ec: ctx(),
        },
    );
    id
}

mod outcomes;
/// Digest computation must be deterministic for identical inputs and must
/// differ when any bound field changes.
mod voting;
