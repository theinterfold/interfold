// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Builders for tests of the protocol machines.

use crate::{
    dkg::{DkgMessage, DkgTiming, DkgWork, DkgWorkResult, KeyMessage, OwnKey},
    node::{
        Body, ChainEvent, ChainFact, Effect, Input, Job, JobDone, LogPosition, PeerMessage, Signed,
        Signing, Work, WorkResult,
    },
    proof::{ProofType, ZkProof},
    BlobRef, E3Id,
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use e3_committee::CiphernodesCommitteeSize;

pub fn e3(number: u64) -> E3Id {
    E3Id {
        chain_id: 1,
        number: U256::from(number),
    }
}

/// The operator number of the node under test, above every peer number the tests use.
pub const ME: u64 = 10_000;

/// Operator `n`'s key; `n` starts at 1.
pub fn operator(n: u64) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::from(U256::from(n))).expect("a nonzero scalar")
}

pub fn address(n: u64) -> Address {
    operator(n).address()
}

/// Operator `n`'s signature over `hash`, as its signer makes it.
pub fn signature(n: u64, hash: B256) -> Bytes {
    let signature = operator(n).sign_hash_sync(&hash).expect("signing works");
    Bytes::from(signature.as_bytes().to_vec())
}

/// Operator `n`'s signer answering a signature request.
pub fn sign(n: u64, signing: &Signing) -> Input {
    Input::Signed(Signed {
        e3: signing.e3,
        purpose: signing.purpose,
        signature: signature(n, signing.hash),
    })
}

/// The one signature request among `effects`.
pub fn signing(effects: &[Effect]) -> &Signing {
    let mut requests = effects.iter().filter_map(|effect| match effect {
        Effect::Sign(signing) => Some(signing),
        _ => None,
    });
    let signing = requests.next().expect("a signature request");
    assert!(requests.next().is_none(), "one signature request");
    signing
}

pub fn proof(fill: u8) -> ZkProof {
    ZkProof {
        data: Bytes::from(vec![fill; 8]),
        public_inputs: vec![B256::repeat_byte(fill)],
    }
}

/// Operator `n`'s C0 key for `e3`, correctly signed.
pub fn key_from(e3: E3Id, n: u64) -> Input {
    key(e3, n, proof(n as u8), n)
}

/// A C0 key message that claims operator `sender`, signed by operator `signer`. The key follows
/// from the proof, so different proofs make different keys.
pub fn key(e3: E3Id, sender: u64, proof: ZkProof, signer: u64) -> Input {
    let hash = proof.payload_signing_hash(e3, ProofType::C0PkBfv);
    Input::Peer(PeerMessage {
        e3,
        sender: address(sender),
        body: Body::Dkg(DkgMessage::EncryptionKey(KeyMessage {
            key: BlobRef {
                hash: keccak256(&proof.data),
                len: 1_000,
            },
            signature: signature(signer, hash),
            proof,
        })),
    })
}

/// A keypair the job runner made for this node; different fills make different keys.
pub fn own_key(fill: u8) -> OwnKey {
    OwnKey {
        public: BlobRef {
            hash: B256::repeat_byte(fill),
            len: 1_000,
        },
        secret: BlobRef {
            hash: B256::repeat_byte(!fill),
            len: 100,
        },
        proof: proof(fill),
    }
}

pub fn key_made(e3: E3Id, own: OwnKey) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::EncryptionKeyMade(own)),
    })
}

/// The job runner's verdict on operator `n`'s key.
pub fn key_checked(e3: E3Id, n: u64, valid: bool) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::EncryptionKeyChecked {
            sender: address(n),
            valid,
        }),
    })
}

/// The members whose keys `effects` ask the job runner to check, in order.
pub fn key_checks(effects: &[Effect]) -> Vec<Address> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Run(Job {
                work: Work::Dkg(DkgWork::CheckEncryptionKey { sender, .. }),
                ..
            }) => Some(*sender),
            _ => None,
        })
        .collect()
}

pub fn chain(block: u64, fact: ChainFact) -> Input {
    Input::Chain(ChainEvent {
        at: LogPosition {
            chain_id: 1,
            block,
            log_index: 0,
        },
        fact,
    })
}

pub fn requested(block: u64, e3: E3Id) -> Input {
    chain(
        block,
        ChainFact::E3Requested {
            e3,
            committee_size: CiphernodesCommitteeSize::Minimum,
        },
    )
}

/// DKG deadline 10,000 with a 1,000-second window: the key cutoff is at 9,100.
pub const TIMING: DkgTiming = DkgTiming {
    deadline: 10_000,
    window: 1_000,
};

pub fn finalized(block: u64, e3: E3Id, members: Vec<Address>) -> Input {
    chain(
        block,
        ChainFact::CommitteeFinalized {
            e3,
            members,
            dkg: TIMING,
        },
    )
}
