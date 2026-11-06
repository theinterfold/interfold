// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A Minimum committee through every job with real threshold-BFV math: keys, shares, decryption
//! keys, the committee key, encryption, decryption shares, and the plaintext.

use crate::{trbfv, Blobs, JobRunner, MemoryBlobs};
use alloy_primitives::{Address, B256};
use e3_committee::CiphernodesCommitteeSize;
use e3_crypto::Cipher;
use e3_fhe_params::BfvPreset;
use e3_protocol::{
    decryption::{DecryptionWork, DecryptionWorkResult, SharesMessage as DecryptionShares},
    dkg::{DkgWork, DkgWorkResult, KeyshareMessage, OwnKey, OwnShares, SharesMessage},
    node::{CryptoParams, Job, Work, WorkResult},
    proof::SignedProof,
    BlobRef, E3Id,
};
use std::collections::BTreeMap;

fn params() -> CryptoParams {
    let param_set = (0..=u8::MAX)
        .find(|set| {
            BfvPreset::from_on_chain_param_set(*set) == Some(BfvPreset::InsecureThreshold64)
        })
        .expect("development chains support the insecure set");
    CryptoParams {
        param_set,
        committee_size: CiphernodesCommitteeSize::Minimum,
        seed: B256::ZERO,
    }
}

fn job(work: Work) -> Job {
    Job {
        e3: E3Id {
            chain_id: 1,
            number: Default::default(),
        },
        params: params(),
        work,
    }
}

fn dkg(runner: &JobRunner<MemoryBlobs>, work: DkgWork) -> DkgWorkResult {
    match runner.run(&job(Work::Dkg(work))).unwrap() {
        WorkResult::Dkg(result) => result,
        other => panic!("a DKG result, got {other:?}"),
    }
}

fn decryption(runner: &JobRunner<MemoryBlobs>, work: DecryptionWork) -> DecryptionWorkResult {
    match runner.run(&job(Work::Decryption(work))).unwrap() {
        WorkResult::Decryption(result) => result,
        other => panic!("a decryption result, got {other:?}"),
    }
}

fn unsigned(proof: e3_protocol::proof::ZkProof) -> SignedProof {
    SignedProof {
        proof,
        signature: Default::default(),
    }
}

#[tokio::test]
async fn a_committee_s_jobs_decrypt_what_its_key_encrypts() {
    let blobs = MemoryBlobs::default();
    let mut members: Vec<Address> = (1..=3).map(Address::repeat_byte).collect();
    members.sort();
    let mut runners = Vec::new();
    for member in &members {
        let cipher = Cipher::from_password(&format!("node {member}"))
            .await
            .unwrap();
        runners.push(JobRunner::new(blobs.clone(), cipher));
    }

    let keys: Vec<OwnKey> = runners
        .iter()
        .map(|runner| match dkg(runner, DkgWork::MakeEncryptionKey) {
            DkgWorkResult::EncryptionKeyMade(own) => own,
            other => panic!("{other:?}"),
        })
        .collect();
    for (runner, key) in runners.iter().zip(&keys) {
        let checked = dkg(
            runner,
            DkgWork::CheckEncryptionKey {
                sender: members[0],
                key: keys[0].public,
                proof: keys[0].proof.clone(),
            },
        );
        assert_eq!(
            checked,
            DkgWorkResult::EncryptionKeyChecked {
                sender: members[0],
                valid: true
            }
        );
        let _ = key;
    }

    let dealt: Vec<OwnShares> = (0..3)
        .map(|dealer| {
            let others = (0..3)
                .filter(|other| *other != dealer)
                .map(|other| (members[other], keys[other].public))
                .collect();
            match dkg(
                &runners[dealer],
                DkgWork::MakeShares {
                    dealer: members[dealer],
                    committee: members.clone(),
                    own_key: keys[dealer].public,
                    keys: others,
                },
            ) {
                DkgWorkResult::SharesMade(made) => made,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    let message = |dealer: usize, recipient: usize| {
        let shares = &dealt[dealer].recipients[&members[recipient]];
        SharesMessage {
            recipient: members[recipient],
            pk_share: dealt[dealer].pk_share,
            shares: shares.shares,
            c2a: unsigned(dealt[dealer].c2a.clone()),
            c2b: unsigned(dealt[dealer].c2b.clone()),
            c3a: shares.c3a.iter().cloned().map(unsigned).collect(),
            c3b: shares.c3b.iter().cloned().map(unsigned).collect(),
        }
    };
    let checked = dkg(
        &runners[1],
        DkgWork::CheckShares {
            dealer: members[0],
            committee: members.clone(),
            secret: keys[1].secret,
            message: Box::new(message(0, 1)),
        },
    );
    assert_eq!(
        checked,
        DkgWorkResult::SharesChecked {
            dealer: members[0],
            valid: true
        }
    );
    let swapped = SharesMessage {
        shares: message(0, 2).shares,
        ..message(0, 1)
    };
    let tampered = dkg(
        &runners[1],
        DkgWork::CheckShares {
            dealer: members[0],
            committee: members.clone(),
            secret: keys[1].secret,
            message: Box::new(swapped),
        },
    );
    assert_eq!(
        tampered,
        DkgWorkResult::SharesChecked {
            dealer: members[0],
            valid: false
        }
    );

    // The roster is the first two members; each sums the other's shares and its own.
    let roster = [0, 1];
    let decryption_keys: Vec<BlobRef> = roster
        .iter()
        .map(|&member| {
            let other = roster
                .iter()
                .copied()
                .find(|other| *other != member)
                .unwrap();
            let shares = BTreeMap::from([(members[other], message(other, member).shares)]);
            match dkg(
                &runners[member],
                DkgWork::MakeDecryptionKey {
                    committee: members.clone(),
                    secret: keys[member].secret,
                    own_share: dealt[member].own_share,
                    shares,
                    c2: BTreeMap::new(),
                },
            ) {
                DkgWorkResult::DecryptionKeyMade(made) => made.key,
                other => panic!("{other:?}"),
            }
        })
        .collect();

    let keyshares: Vec<KeyshareMessage> = roster
        .iter()
        .map(|&member| KeyshareMessage {
            pk_share: dealt[member].pk_share,
            c1: unsigned(dealt[member].c1.clone()),
        })
        .collect();
    for keyshare in &keyshares {
        let checked = dkg(
            &runners[2],
            DkgWork::CheckKeyshare {
                member: members[0],
                committee: members.clone(),
                keyshare: Box::new(keyshare.clone()),
            },
        );
        assert_eq!(
            checked,
            DkgWorkResult::KeyshareChecked {
                member: members[0],
                valid: true
            }
        );
    }
    let key = match dkg(
        &runners[2],
        DkgWork::AggregateKey {
            committee: members.clone(),
            roster: roster.iter().map(|member| members[*member]).collect(),
            keyshares,
            folds: Vec::new(),
        },
    ) {
        DkgWorkResult::KeyAggregated(key) => key,
        other => panic!("{other:?}"),
    };

    let message_values = vec![7u64, 11, 13];
    let ciphertext = crate::encrypt(&blobs, &params(), &key.public_key, &message_values).unwrap();

    let domain = B256::repeat_byte(0xd0);
    let shares: BTreeMap<Address, DecryptionShares> = roster
        .iter()
        .zip(&decryption_keys)
        .map(|(&member, key)| {
            match decryption(
                &runners[member],
                DecryptionWork::MakeShares {
                    key: *key,
                    ciphertext,
                    domain,
                },
            ) {
                DecryptionWorkResult::SharesMade(made) => (
                    members[member],
                    DecryptionShares {
                        shares: made.shares,
                        c6: made.c6.into_iter().map(unsigned).collect(),
                    },
                ),
                other => panic!("{other:?}"),
            }
        })
        .collect();
    for (member, message) in &shares {
        let checked = decryption(
            &runners[2],
            DecryptionWork::CheckShares {
                member: *member,
                committee: members.clone(),
                ciphertext,
                domain,
                message: Box::new(message.clone()),
            },
        );
        assert_eq!(
            checked,
            DecryptionWorkResult::SharesChecked {
                member: *member,
                valid: true
            }
        );
    }
    let published = match decryption(
        &runners[2],
        DecryptionWork::AggregatePlaintext {
            committee: members.clone(),
            ciphertext,
            domain,
            shares,
        },
    ) {
        DecryptionWorkResult::PlaintextMade(published) => published,
        other => panic!("{other:?}"),
    };
    let decrypted = blobs.get(&published.plaintext).unwrap();
    let values: Vec<u64> = decrypted
        .chunks(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    assert_eq!(values[..3], message_values[..]);
}

#[tokio::test]
async fn a_secret_is_stored_sealed_and_a_key_that_does_not_decode_fails_its_check() {
    let blobs = MemoryBlobs::default();
    let cipher = Cipher::from_password("node").await.unwrap();
    let runner = JobRunner::new(blobs.clone(), cipher);
    let DkgWorkResult::EncryptionKeyMade(own) = dkg(&runner, DkgWork::MakeEncryptionKey) else {
        panic!("a key");
    };
    let dkg_params = trbfv::dkg_params(&params()).unwrap();
    let stored = blobs.get(&own.secret).unwrap();
    assert!(e3_trbfv::helpers::deserialize_secret_key(&stored, &dkg_params).is_err());
    assert!(e3_trbfv::helpers::deserialize_secret_key(
        &runner.unseal(&own.secret).unwrap(),
        &dkg_params
    )
    .is_ok());

    let garbage = blobs.put(b"not a key").unwrap();
    let proof =
        crate::placeholder::proof(&blobs, e3_protocol::proof::ProofType::C0PkBfv, b"not a key")
            .unwrap();
    let checked = dkg(
        &runner,
        DkgWork::CheckEncryptionKey {
            sender: Address::ZERO,
            key: garbage,
            proof,
        },
    );
    assert_eq!(
        checked,
        DkgWorkResult::EncryptionKeyChecked {
            sender: Address::ZERO,
            valid: false
        }
    );
}
