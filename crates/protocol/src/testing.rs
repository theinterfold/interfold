// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Builders for tests of the protocol machines.

use crate::{
    dkg::{
        DecryptionKeyMessage, DkgMessage, DkgTiming, DkgWork, DkgWorkResult, KeyMessage,
        OwnDecryptionKey, OwnKey, OwnShares, RecipientShares, SharesMessage,
    },
    node::{
        Body, ChainEvent, ChainFact, Effect, Input, Job, JobDone, LogPosition, PeerMessage, Signed,
        Signing, Work, WorkResult,
    },
    proof::{ProofType, SignedProof, ZkProof},
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
        signatures: signing
            .hashes
            .iter()
            .map(|hash| signature(n, *hash))
            .collect(),
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
            proof: SignedProof {
                signature: signature(signer, hash),
                proof,
            },
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

/// Threshold shares the job runner made for this node: one entry per recipient, three Shamir
/// rows each.
pub fn own_shares(recipients: &[u64]) -> OwnShares {
    OwnShares {
        pk_share: BlobRef {
            hash: B256::repeat_byte(0xaa),
            len: 1_000,
        },
        own_share: BlobRef {
            hash: B256::repeat_byte(0xab),
            len: 100,
        },
        c1: proof(0xc1),
        c2a: proof(0xca),
        c2b: proof(0xcb),
        recipients: recipients
            .iter()
            .map(|n| {
                let shares = RecipientShares {
                    shares: BlobRef {
                        hash: B256::repeat_byte(*n as u8),
                        len: 1_000,
                    },
                    c3a: vec![proof(0x3a); 3],
                    c3b: vec![proof(0x3b); 3],
                };
                (address(*n), shares)
            })
            .collect(),
    }
}

pub fn shares_made(e3: E3Id, own: OwnShares) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::SharesMade(own)),
    })
}

/// Operator `dealer`'s shares for operator `recipient`, correctly signed.
pub fn shares_from(e3: E3Id, dealer: u64, recipient: u64) -> Input {
    shares(e3, dealer, recipient, dealer)
}

/// Shares that claim operator `dealer`, every proof signed by operator `signer`. Each dealer's C2
/// proofs differ, so each dealer's contribution does.
pub fn shares(e3: E3Id, dealer: u64, recipient: u64, signer: u64) -> Input {
    let signed = |proof_type, proof: ZkProof| SignedProof {
        signature: signature(signer, proof.payload_signing_hash(e3, proof_type)),
        proof,
    };
    let rows = |proof_type| (0..3).map(|row| signed(proof_type, proof(row))).collect();
    Input::Peer(PeerMessage {
        e3,
        sender: address(dealer),
        body: Body::Dkg(DkgMessage::Shares(Box::new(SharesMessage {
            recipient: address(recipient),
            pk_share: BlobRef {
                hash: B256::repeat_byte(dealer as u8),
                len: 1_000,
            },
            shares: BlobRef {
                hash: keccak256([dealer as u8, recipient as u8]),
                len: 1_000,
            },
            c2a: signed(ProofType::C2aSkShareComputation, proof(dealer as u8)),
            c2b: signed(ProofType::C2bESmShareComputation, proof(!(dealer as u8))),
            c3a: rows(ProofType::C3aSkShareEncryption),
            c3b: rows(ProofType::C3bESmShareEncryption),
        }))),
    })
}

/// The job runner's verdict on operator `dealer`'s shares for this node.
pub fn shares_checked(e3: E3Id, dealer: u64, valid: bool) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::SharesChecked {
            dealer: address(dealer),
            valid,
        }),
    })
}

/// A decryption key the job runner made for this node, with one smudging-noise set.
pub fn own_decryption_key(fill: u8) -> OwnDecryptionKey {
    OwnDecryptionKey {
        key: BlobRef {
            hash: B256::repeat_byte(fill),
            len: 100,
        },
        c4a: proof(fill),
        c4b: vec![proof(!fill)],
    }
}

pub fn decryption_key_made(e3: E3Id, own: OwnDecryptionKey) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::DecryptionKeyMade(own)),
    })
}

/// Operator `member`'s C4 proofs, signed by operator `signer`.
pub fn decryption_key(e3: E3Id, member: u64, signer: u64) -> Input {
    let signed = |proof_type, proof: ZkProof| SignedProof {
        signature: signature(signer, proof.payload_signing_hash(e3, proof_type)),
        proof,
    };
    Input::Peer(PeerMessage {
        e3,
        sender: address(member),
        body: Body::Dkg(DkgMessage::DecryptionKey(DecryptionKeyMessage {
            c4a: signed(ProofType::C4aSkShareDecryption, proof(member as u8)),
            c4b: vec![signed(
                ProofType::C4bESmShareDecryption,
                proof(!(member as u8)),
            )],
        })),
    })
}

/// The job runner's verdict on operator `member`'s C4 proofs.
pub fn decryption_key_checked(e3: E3Id, member: u64, valid: bool) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::DecryptionKeyChecked {
            member: address(member),
            valid,
        }),
    })
}

/// The members each Ready report among `effects` names, in order.
pub fn ready_sent(effects: &[Effect]) -> Vec<Vec<Address>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Gossip(PeerMessage {
                body: Body::Dkg(DkgMessage::Ready(dealers)),
                ..
            }) => Some(dealers.iter().map(|dealer| dealer.member).collect()),
            _ => None,
        })
        .collect()
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
