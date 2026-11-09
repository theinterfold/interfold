// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Builders for tests of the protocol machines.

use crate::{
    accusation::{Fault, Verdict},
    decryption::{
        DecryptionMessage, DecryptionWorkResult, OwnShares as DecryptionOwnShares,
        PlaintextPublication, SharesMessage as DecryptionSharesMessage,
    },
    dkg::{
        AggregatedKey, AttestationContext, DecryptionKeyMessage, DkgMessage, DkgTiming, DkgWork,
        DkgWorkResult, FoldAttestation, KeyMessage, KeyshareMessage, NodeFold, NodeFoldMessage,
        OwnDecryptionKey, OwnKey, OwnShares, RecipientShares, SharesMessage,
    },
    node::{
        Body, ChainEvent, ChainFact, CommitteeRequest, CryptoParams, DataRef, Effect, Fetched,
        Input, Job, JobDone, LogPosition, PeerMessage, Signed, Signing, Work, WorkResult,
    },
    proof::{ProofType, SignedProof, ZkProof},
    BlobRef, E3Id, UnixSecs,
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
        data: BlobRef::of(&[fill; 8]),
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
                hash: keccak256(proof.data.hash),
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
        secret: crate::SealedRef {
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
            verdict: verdict(valid),
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
        own_share: crate::SealedRef {
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
                    shares: Some(BlobRef {
                        hash: B256::repeat_byte(*n as u8),
                        len: 1_000,
                    }),
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
            verdict: verdict(valid),
        }),
    })
}

/// A decryption key the job runner made for this node, with one smudging-noise set.
pub fn own_decryption_key(fill: u8) -> OwnDecryptionKey {
    OwnDecryptionKey {
        key: crate::SealedRef {
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
            verdict: verdict(valid),
        }),
    })
}

/// Operator `member`'s keyshare, its C1 signed by operator `signer`.
pub fn keyshare(e3: E3Id, member: u64, signer: u64) -> Input {
    let c1 = proof(member as u8);
    Input::Peer(PeerMessage {
        e3,
        sender: address(member),
        body: Body::Dkg(DkgMessage::Keyshare(KeyshareMessage {
            pk_share: BlobRef {
                hash: B256::repeat_byte(member as u8),
                len: 1_000,
            },
            c1: SignedProof {
                signature: signature(
                    signer,
                    c1.payload_signing_hash(e3, ProofType::C1PkGeneration),
                ),
                proof: c1,
            },
        })),
    })
}

pub fn node_fold(fill: u8) -> NodeFold {
    NodeFold {
        proof: proof(fill),
        sk_agg_commit: B256::repeat_byte(fill),
        esm_agg_commit: B256::repeat_byte(!fill),
    }
}

/// Operator `member`'s fold, attested for committee slot `party_id` by operator `signer`.
pub fn fold(e3: E3Id, member: u64, party_id: u64, signer: u64) -> Input {
    let fold = node_fold(member as u8);
    let attestation = FoldAttestation {
        e3,
        verifier: ATTESTATION.verifier,
        registry: ATTESTATION.registry,
        party_id,
        sk_agg_commit: fold.sk_agg_commit,
        esm_agg_commit: fold.esm_agg_commit,
    };
    Input::Peer(PeerMessage {
        e3,
        sender: address(member),
        body: Body::Dkg(DkgMessage::NodeFold(NodeFoldMessage {
            fold,
            attestation: signature(signer, attestation.signing_hash()),
        })),
    })
}

pub fn proofs_folded(e3: E3Id, fold: NodeFold) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::ProofsFolded(fold)),
    })
}

pub fn keyshare_checked(e3: E3Id, member: u64, valid: bool) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::KeyshareChecked {
            member: address(member),
            verdict: verdict(valid),
        }),
    })
}

/// One step of the roster's fold finished.
pub fn roster_folded(e3: E3Id, slot: u32, fill: u8) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::RosterFolded {
            slot,
            accumulator: proof(fill),
        }),
    })
}

pub fn key_aggregated(e3: E3Id, fill: u8) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::KeyAggregated(AggregatedKey {
            public_key: BlobRef {
                hash: B256::repeat_byte(fill),
                len: 2_000,
            },
            commitment: B256::repeat_byte(!fill),
            proof: proof(fill),
        })),
    })
}

pub const KEY_COMMITMENT: B256 = B256::repeat_byte(0xc0);

/// The ciphertext's bytes in the blob store, once fetched.
pub const CIPHERTEXT: BlobRef = BlobRef {
    hash: B256::repeat_byte(0xc7),
    len: 4_000,
};

/// Where the chain says the ciphertext's bytes are.
pub const CIPHERTEXT_DATA: DataRef = DataRef {
    hash: CIPHERTEXT.hash,
    block: 70,
    leaf: 3,
};

/// After the DKG window, so decryption has its own.
pub const DECRYPTION_DEADLINE: UnixSecs = 200_000;

/// The ciphertext's deadline: after the DKG window, before decryption's.
pub const COMPUTE_DEADLINE: UnixSecs = 150_000;

/// The committee deadline the registry reports for a request.
pub const COMMITTEE_DEADLINE: UnixSecs = 100;

/// The chain's key for `e3`, with the committee in the registry's order and the roster.
pub fn key_published(block: u64, e3: E3Id, committee: Vec<Address>, roster: Vec<Address>) -> Input {
    chain(
        block,
        ChainFact::KeyPublished {
            e3,
            committee,
            roster,
            commitment: KEY_COMMITMENT,
            compute_deadline: COMPUTE_DEADLINE,
            anchors: Default::default(),
        },
    )
}

pub fn ciphertext_ready(block: u64, e3: E3Id) -> Input {
    chain(
        block,
        ChainFact::CiphertextReady {
            e3,
            ciphertext: CIPHERTEXT_DATA,
            deadline: DECRYPTION_DEADLINE,
        },
    )
}

pub fn ciphertext_fetched(e3: E3Id) -> Input {
    Input::Fetched(Fetched {
        e3,
        blob: CIPHERTEXT,
    })
}

/// One decryption share and its C6 proof, made by the job runner for this node.
pub fn own_decryption_shares(fill: u8) -> DecryptionOwnShares {
    DecryptionOwnShares {
        shares: vec![BlobRef {
            hash: B256::repeat_byte(fill),
            len: 500,
        }],
        c6: vec![proof(fill)],
    }
}

pub fn decryption_shares_made(e3: E3Id, own: DecryptionOwnShares) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Decryption(DecryptionWorkResult::SharesMade(own)),
    })
}

/// Operator `member`'s decryption share of one ciphertext, its C6 signed by operator `signer`.
pub fn decryption_shares(e3: E3Id, member: u64, signer: u64) -> Input {
    let c6 = proof(member as u8);
    Input::Peer(PeerMessage {
        e3,
        sender: address(member),
        body: Body::Decryption(DecryptionMessage::Shares(DecryptionSharesMessage {
            shares: vec![BlobRef {
                hash: B256::repeat_byte(member as u8),
                len: 500,
            }],
            c6: vec![SignedProof {
                signature: signature(
                    signer,
                    c6.payload_signing_hash(e3, ProofType::C6ThresholdShareDecryption),
                ),
                proof: c6,
            }],
        })),
    })
}

pub fn decryption_shares_checked(e3: E3Id, member: u64, valid: bool) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Decryption(DecryptionWorkResult::SharesChecked {
            member: address(member),
            verdict: verdict(valid),
        }),
    })
}

pub fn plaintext_made(e3: E3Id, fill: u8) -> Input {
    Input::Job(JobDone {
        e3,
        result: WorkResult::Decryption(DecryptionWorkResult::PlaintextMade(PlaintextPublication {
            plaintext: BlobRef {
                hash: B256::repeat_byte(fill),
                len: 64,
            },
            proof: proof(fill),
        })),
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
/// A peer's message as gossip announces it, before its blobs are fetched.
pub fn announced(input: Input) -> Input {
    let Input::Peer(message) = input else {
        panic!("a peer message")
    };
    Input::Announced(message)
}

/// The senders of the messages whose blobs the node asked for.
pub fn fetched_from(effects: &[Effect]) -> Vec<Address> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::FetchBlobs(fetch) => Some(fetch.message.sender),
            _ => None,
        })
        .collect()
}

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

/// A fact in its own block, whose timestamp is its number.
pub fn chain(block: u64, fact: ChainFact) -> Input {
    Input::Chain(ChainEvent {
        at: LogPosition {
            chain_id: 1,
            block,
            log_index: 0,
        },
        time: block,
        fact,
    })
}

pub fn requested(block: u64, e3: E3Id) -> Input {
    chain(
        block,
        ChainFact::E3Requested {
            e3,
            params: params(CiphernodesCommitteeSize::Minimum),
            interfold: INTERFOLD,
            attestation: ATTESTATION,
            request: REQUEST,
            committee_deadline: COMMITTEE_DEADLINE,
            seed: None,
        },
    )
}

pub const INTERFOLD: Address = Address::repeat_byte(0x1f);

/// A request at timestamp 1 that keeps one candidate per owner, at one token a ticket.
pub const REQUEST: CommitteeRequest = CommitteeRequest {
    time: 1,
    ticket_price: U256::from_limbs([1, 0, 0, 0]),
    owner_cap: false,
    dkg_window: TIMING.window,
};

pub fn params(committee_size: CiphernodesCommitteeSize) -> CryptoParams {
    CryptoParams {
        param_set: 0,
        committee_size,
        seed: B256::repeat_byte(0x5e),
    }
}

pub const ATTESTATION: AttestationContext = AttestationContext {
    registry: Address::repeat_byte(0x8e),
    verifier: Address::repeat_byte(0x9f),
};

/// DKG deadline 100,000 with a 10,000-second window: the key cutoff is at 91,000 and the share
/// checkpoint at 97,500, so the 10-minute roster and 40-minute key budgets fit.
pub const TIMING: DkgTiming = DkgTiming {
    deadline: 100_000,
    window: 10_000,
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

/// The check of operator `n`'s key, which found its C0 proof failing.
pub fn key_failed(e3: E3Id, n: u64, data_hash: B256) -> Input {
    let fault = Fault {
        proof_type: ProofType::C0PkBfv,
        proof: proof(n as u8),
        data_hash,
    };
    Input::Job(JobDone {
        e3,
        result: WorkResult::Dkg(DkgWorkResult::EncryptionKeyChecked {
            sender: address(n),
            verdict: Verdict::Fails(fault),
        }),
    })
}

/// A check's verdict that is valid or invalid without a failing proof.
pub fn verdict(valid: bool) -> Verdict {
    match valid {
        true => Verdict::Valid,
        false => Verdict::Invalid,
    }
}
