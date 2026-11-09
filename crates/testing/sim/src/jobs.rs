// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{keccak256, Address, B256};
use e3_protocol::{
    accusation::{AccusationWork, AccusationWorkResult, Fault, Verdict},
    decryption::{
        DecryptionWork, DecryptionWorkResult, OwnShares as DecryptionShares, PlaintextPublication,
    },
    dkg::{
        AggregatedKey, DkgWork, DkgWorkResult, NodeFold, OwnDecryptionKey, OwnKey, OwnShares,
        RecipientShares,
    },
    node::{CryptoParams, Job, Work, WorkResult},
    proof::{ProofType, ZkProof},
    BlobRef, E3Id, SealedRef,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::BTreeMap;

/// What runs the nodes' jobs, and what a requester's computation publishes as ciphertext.
pub trait Jobs {
    fn run(&mut self, node: usize, job: &Job) -> WorkResult;
    /// The ciphertext the chain publishes once the committee key `public_key` is out.
    fn ciphertext(&mut self, e3: E3Id, params: &CryptoParams, public_key: BlobRef) -> BlobRef;
}

pub struct MockJobs {
    rng: ChaCha8Rng,
    /// A dealer whose C2a proof fails.
    faulty: Option<Address>,
}

/// The statement of a mock proof that fails its check.
const FAILS: B256 = B256::repeat_byte(0xfa);

impl MockJobs {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            faulty: None,
        }
    }

    /// Mock jobs in which `dealer` deals with a C2a proof that fails.
    pub fn with_faulty(seed: u64, dealer: Address) -> Self {
        Self {
            faulty: Some(dealer),
            ..Self::new(seed)
        }
    }
}

impl Jobs for MockJobs {
    fn run(&mut self, _node: usize, job: &Job) -> WorkResult {
        self.mock(job)
    }

    fn ciphertext(&mut self, _: E3Id, _: &CryptoParams, public_key: BlobRef) -> BlobRef {
        blob(keccak256(public_key.hash))
    }
}

impl MockJobs {
    /// Mock work: no cryptography, but the same shape of results, drawn fresh on every run as real
    /// key and share generation are. A check passes when the checked bytes are the ones the mock
    /// derived for them.
    fn mock(&mut self, job: &Job) -> WorkResult {
        let result = match &job.work {
            Work::Dkg(DkgWork::MakeEncryptionKey) => {
                let proof = self.proof();
                let public = blob(keccak256(proof.data.hash));
                DkgWorkResult::EncryptionKeyMade(OwnKey {
                    public,
                    secret: sealed(keccak256(public.hash)),
                    proof,
                })
            }
            Work::Dkg(DkgWork::CheckEncryptionKey { sender, key, proof }) => {
                DkgWorkResult::EncryptionKeyChecked {
                    sender: *sender,
                    verdict: verdict(key.hash == keccak256(proof.data.hash)),
                }
            }
            Work::Dkg(DkgWork::MakeShares {
                dealer,
                committee,
                keys,
                ..
            }) => {
                let fails = self.faulty == Some(*dealer);
                let pk_share = blob(self.hash());
                let recipients = committee
                    .iter()
                    .filter(|member| *member != dealer)
                    .map(|member| {
                        let delivered = keys.contains_key(member).then(|| {
                            blob(keccak256(
                                [pk_share.hash.as_slice(), member.as_slice()].concat(),
                            ))
                        });
                        let shares = RecipientShares {
                            shares: delivered,
                            c3a: (0..3).map(|_| self.proof()).collect(),
                            c3b: (0..3).map(|_| self.proof()).collect(),
                        };
                        (*member, shares)
                    })
                    .collect();
                let c1 = ZkProof {
                    public_inputs: vec![pk_share.hash],
                    ..self.proof()
                };
                DkgWorkResult::SharesMade(OwnShares {
                    pk_share,
                    own_share: sealed(self.hash()),
                    c1,
                    c2a: match fails {
                        true => ZkProof {
                            public_inputs: vec![FAILS],
                            ..self.proof()
                        },
                        false => self.proof(),
                    },
                    c2b: self.proof(),
                    recipients,
                })
            }
            Work::Dkg(DkgWork::CheckShares {
                dealer, message, ..
            }) => {
                let expected = keccak256(
                    [
                        message.pk_share.hash.as_slice(),
                        message.recipient.as_slice(),
                    ]
                    .concat(),
                );
                DkgWorkResult::SharesChecked {
                    dealer: *dealer,
                    verdict: match message.c2a.proof.public_inputs == [FAILS] {
                        true => Verdict::Fails(fault(
                            ProofType::C2aSkShareComputation,
                            &message.c2a.proof,
                        )),
                        false => verdict(message.shares.hash == expected),
                    },
                }
            }
            Work::Dkg(DkgWork::MakeDecryptionKey { c2, .. }) => {
                let binds = |proof: ZkProof| ZkProof {
                    public_inputs: vec![c2_commitment(c2)],
                    ..proof
                };
                DkgWorkResult::DecryptionKeyMade(OwnDecryptionKey {
                    key: sealed(self.hash()),
                    c4a: binds(self.proof()),
                    c4b: vec![binds(self.proof())],
                })
            }
            Work::Dkg(DkgWork::CheckDecryptionKey {
                member,
                c2,
                message,
                ..
            }) => DkgWorkResult::DecryptionKeyChecked {
                member: *member,
                verdict: verdict(message.c4a.proof.public_inputs == [c2_commitment(c2)]),
            },
            Work::Dkg(DkgWork::FoldProofs { .. }) => DkgWorkResult::ProofsFolded(NodeFold {
                proof: self.proof(),
                sk_agg_commit: self.hash(),
                esm_agg_commit: self.hash(),
            }),
            Work::Dkg(DkgWork::CheckKeyshare {
                member, keyshare, ..
            }) => DkgWorkResult::KeyshareChecked {
                member: *member,
                verdict: verdict(keyshare.c1.proof.public_inputs == [keyshare.pk_share.hash]),
            },
            Work::Decryption(work) => return self.decrypt(work),
            Work::Accusation(AccusationWork::Verify { proof_type, proof }) => {
                return WorkResult::Accusation(AccusationWorkResult::Verified {
                    proof_type: *proof_type,
                    proof: proof.clone(),
                    fails: proof.public_inputs == [FAILS],
                    data_hash: data_hash(proof),
                })
            }
            Work::Dkg(DkgWork::FoldRoster { slot, .. }) => DkgWorkResult::RosterFolded {
                slot: *slot,
                accumulator: self.proof(),
            },
            Work::Dkg(DkgWork::AggregateKey { keyshares, .. }) => {
                let shares: Vec<u8> = keyshares
                    .iter()
                    .flat_map(|keyshare| keyshare.pk_share.hash.0)
                    .collect();
                let public_key = blob(keccak256(shares));
                DkgWorkResult::KeyAggregated(AggregatedKey {
                    public_key,
                    commitment: keccak256(public_key.hash),
                    proof: self.proof(),
                })
            }
        };
        WorkResult::Dkg(result)
    }

    /// Mock decryption: a share binds the domain in its C6 inputs, and the plaintext follows from
    /// the ciphertext alone, so every aggregator gets the same one.
    fn decrypt(&mut self, work: &DecryptionWork) -> WorkResult {
        let result = match work {
            DecryptionWork::MakeShares {
                key,
                ciphertext,
                domain,
            } => DecryptionWorkResult::SharesMade(DecryptionShares {
                shares: vec![blob(keccak256([key.hash, ciphertext.hash].concat()))],
                c6: vec![ZkProof {
                    public_inputs: vec![*domain],
                    ..self.proof()
                }],
            }),
            DecryptionWork::CheckShares {
                member,
                domain,
                message,
                ..
            } => DecryptionWorkResult::SharesChecked {
                member: *member,
                verdict: verdict(
                    message
                        .c6
                        .iter()
                        .all(|proof| proof.proof.public_inputs == [*domain]),
                ),
            },
            DecryptionWork::AggregatePlaintext { ciphertext, .. } => {
                DecryptionWorkResult::PlaintextMade(PlaintextPublication {
                    plaintext: blob(keccak256(ciphertext.hash)),
                    proof: self.proof(),
                })
            }
        };
        WorkResult::Decryption(result)
    }

    fn hash(&mut self) -> B256 {
        B256::from(self.rng.random::<[u8; 32]>())
    }

    fn proof(&mut self) -> ZkProof {
        ZkProof {
            data: blob(self.hash()),
            public_inputs: vec![self.hash()],
        }
    }
}

fn sealed(hash: B256) -> SealedRef {
    SealedRef { hash, len: 1_000 }
}

fn blob(hash: B256) -> BlobRef {
    BlobRef { hash, len: 1_000 }
}

/// What a mock C4 proof commits to: the roster dealers' C2 statements, in roster order.
fn c2_commitment(c2: &BTreeMap<Address, (ZkProof, ZkProof)>) -> B256 {
    let statements: Vec<u8> = c2
        .values()
        .flat_map(|(c2a, c2b)| c2a.public_inputs.iter().chain(&c2b.public_inputs))
        .flat_map(|word| word.0)
        .collect();
    keccak256(statements)
}

fn verdict(valid: bool) -> Verdict {
    match valid {
        true => Verdict::Valid,
        false => Verdict::Invalid,
    }
}

/// A mock proof's evidence hash: mock jobs hold no proof bytes, so its blob's hash stands in.
fn data_hash(proof: &ZkProof) -> B256 {
    keccak256(proof.data.hash)
}

fn fault(proof_type: ProofType, proof: &ZkProof) -> Fault {
    Fault {
        proof_type,
        proof: proof.clone(),
        data_hash: data_hash(proof),
    }
}
