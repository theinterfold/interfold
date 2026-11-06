// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DKG's jobs: BFV keys (C0), threshold shares (C1-C3), the decryption key (C4), and the
//! committee key (C5), with the same library calls as the current node. Proofs are placeholders
//! that commit to what the real proofs bind, and prove nothing.

use crate::{
    placeholder, trbfv, Blobs, JobError, JobRunner, OwnShareRows, RecipientCiphertexts,
    SealedDecryptionKey,
};
use alloy_primitives::{keccak256, Address};
use e3_protocol::{
    dkg::{
        AggregatedKey, DkgWork, DkgWorkResult, KeyshareMessage, NodeFold, OwnDecryptionKey, OwnKey,
        OwnShares, RecipientShares, SharesMessage,
    },
    node::CryptoParams,
    proof::{ProofType, ZkProof},
    BlobRef,
};
use e3_trbfv::{
    calculate_decryption_key::{calculate_decryption_key, CalculateDecryptionKeyRequest},
    gen_esi_sss::{gen_esi_sss, GenEsiSssRequest},
    gen_pk_share_and_sk_sss::{gen_pk_share_and_sk_sss, GenPkShareAndSkSssRequest},
    helpers::{deserialize_secret_key, serialize_secret_key},
    shares::{BfvEncryptedShare, BfvEncryptedShares, Encrypted, ShamirShare},
};
use fhe::{
    bfv::{PublicKey, SecretKey},
    mbfv::{AggregateIter, PublicKeyShare},
};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::rngs::OsRng;
use rand_core::UnwrapErr;
use std::collections::BTreeMap;

impl<B: Blobs> JobRunner<B> {
    pub(crate) fn run_dkg(
        &self,
        params: &CryptoParams,
        work: &DkgWork,
    ) -> Result<DkgWorkResult, JobError> {
        Ok(match work {
            DkgWork::MakeEncryptionKey => {
                DkgWorkResult::EncryptionKeyMade(self.make_encryption_key(params)?)
            }
            DkgWork::CheckEncryptionKey { sender, key, proof } => {
                DkgWorkResult::EncryptionKeyChecked {
                    sender: *sender,
                    valid: self.check_encryption_key(params, key, proof)?,
                }
            }
            DkgWork::MakeShares {
                dealer,
                committee,
                own_key,
                keys,
            } => DkgWorkResult::SharesMade(
                self.make_shares(params, *dealer, committee, own_key, keys)?,
            ),
            DkgWork::CheckShares {
                dealer,
                secret,
                message,
                ..
            } => DkgWorkResult::SharesChecked {
                dealer: *dealer,
                valid: self.check_shares(params, secret, message)?,
            },
            DkgWork::MakeDecryptionKey {
                secret,
                own_share,
                shares,
                ..
            } => DkgWorkResult::DecryptionKeyMade(
                self.make_decryption_key(params, secret, own_share, shares)?,
            ),
            DkgWork::CheckDecryptionKey { member, .. } => DkgWorkResult::DecryptionKeyChecked {
                member: *member,
                valid: true,
            },
            DkgWork::FoldProofs { proofs } => DkgWorkResult::ProofsFolded(NodeFold {
                proof: placeholder::proof(&self.blobs, ProofType::C5PkAggregation, &[])?,
                sk_agg_commit: keccak256(placeholder::statements(proofs)),
                esm_agg_commit: keccak256(placeholder::statements(proofs).repeat(2)),
            }),
            DkgWork::CheckKeyshare {
                member, keyshare, ..
            } => DkgWorkResult::KeyshareChecked {
                member: *member,
                valid: self.check_keyshare(params, keyshare)?,
            },
            DkgWork::AggregateKey { keyshares, .. } => {
                DkgWorkResult::KeyAggregated(self.aggregate_key(params, keyshares)?)
            }
        })
    }

    pub(crate) fn make_encryption_key(&self, params: &CryptoParams) -> Result<OwnKey, JobError> {
        let bfv = trbfv::dkg_params(params)?;
        let mut rng = UnwrapErr(OsRng);
        let secret = SecretKey::random(&bfv, &mut rng);
        let public = PublicKey::new(&secret, &mut rng).to_bytes();
        let secret = serialize_secret_key(&secret).map_err(JobError::crypto)?;
        Ok(OwnKey {
            public: self.blobs.put(&public)?,
            secret: self.seal(&secret)?,
            proof: placeholder::proof(&self.blobs, ProofType::C0PkBfv, &public)?,
        })
    }

    /// A key counts when it decodes under the request's DKG parameters and its proof commits to
    /// it.
    pub(crate) fn check_encryption_key(
        &self,
        params: &CryptoParams,
        key: &BlobRef,
        proof: &ZkProof,
    ) -> Result<bool, JobError> {
        let bfv = trbfv::dkg_params(params)?;
        let Ok(bytes) = self.blobs.get(key) else {
            return Ok(false);
        };
        let decodes = PublicKey::from_bytes(&bytes, &bfv).is_ok();
        Ok(decodes && placeholder::commits_to(proof, &bytes))
    }

    /// Generate this dealer's public-key share and its secret-key and smudging-noise shares, and
    /// encrypt each member's shares to that member's C0 key. A member without a key keeps a slot
    /// encrypted under this dealer's own key, which it never receives; the dealer's own slot stays
    /// in plaintext, sealed, for its decryption key.
    fn make_shares(
        &self,
        params: &CryptoParams,
        dealer: Address,
        committee: &[Address],
        own_key: &BlobRef,
        keys: &BTreeMap<Address, BlobRef>,
    ) -> Result<OwnShares, JobError> {
        let party = trbfv::party(committee, dealer)?;
        let config = trbfv::config(params)?;
        let dkg = trbfv::dkg_params(params)?;
        let mut rng = UnwrapErr(OsRng);
        let generated = gen_pk_share_and_sk_sss(
            &mut rng,
            &self.cipher,
            GenPkShareAndSkSssRequest {
                trbfv_config: config.clone(),
                crp: trbfv::crp(params)?,
                lambda: trbfv::lambda(params)?,
                num_ciphertexts: trbfv::ciphertexts(params)?,
            },
        )
        .map_err(JobError::crypto)?;
        let smudging = gen_esi_sss(
            &mut rng,
            &self.cipher,
            GenEsiSssRequest {
                trbfv_config: config,
                e_sm_raw: generated.e_sm_raw.clone(),
            },
        )
        .map_err(JobError::crypto)?;
        let sk_sss = generated
            .sk_sss
            .decrypt(&self.cipher)
            .map_err(JobError::crypto)?;
        let esi_sss: Vec<_> = smudging
            .esi_sss
            .into_iter()
            .map(|shares| shares.decrypt(&self.cipher))
            .collect::<Result<_, _>>()
            .map_err(JobError::crypto)?;

        let own_public =
            PublicKey::from_bytes(&self.blobs.get(own_key)?, &dkg).map_err(JobError::crypto)?;
        let recipient_keys = committee
            .iter()
            .map(|member| match keys.get(member) {
                Some(key) => {
                    PublicKey::from_bytes(&self.blobs.get(key)?, &dkg).map_err(JobError::crypto)
                }
                None => Ok(own_public.clone()),
            })
            .collect::<Result<Vec<_>, JobError>>()?;
        let slots: Vec<usize> = (0..committee.len()).collect();
        let encrypt = |secret| {
            BfvEncryptedShares::encrypt_all_extended_for_share_indices(
                secret,
                &recipient_keys,
                &slots,
                &dkg,
                &mut UnwrapErr(OsRng),
                Some(party),
            )
            .map(|(shares, _witnesses)| shares)
            .map_err(JobError::crypto)
        };
        let sk_encrypted = encrypt(&sk_sss)?;
        let esi_encrypted = esi_sss.iter().map(encrypt).collect::<Result<Vec<_>, _>>()?;

        let own = OwnShareRows {
            sk: sk_sss
                .extract_party_share(party)
                .map_err(JobError::crypto)?,
            esi: esi_sss
                .iter()
                .map(|shares| shares.extract_party_share(party))
                .collect::<Result<_, _>>()
                .map_err(JobError::crypto)?,
        };
        let pk_share = self.blobs.put(&generated.pk_share)?;
        let mut recipients = BTreeMap::new();
        for (slot, member) in committee.iter().enumerate() {
            if !keys.contains_key(member) || *member == dealer {
                continue;
            }
            let ciphertexts = RecipientCiphertexts {
                sk: sk_encrypted
                    .clone_share(slot)
                    .ok_or(JobError::crypto("no share for a slot"))?,
                esi: esi_encrypted
                    .iter()
                    .map(|shares| {
                        shares
                            .clone_share(slot)
                            .ok_or(JobError::crypto("no share for a slot"))
                    })
                    .collect::<Result<_, _>>()?,
            };
            let rows = ciphertexts.sk.num_moduli();
            let bytes = bincode::serialize(&ciphertexts).map_err(JobError::crypto)?;
            let shares = self.blobs.put(&bytes)?;
            recipients.insert(
                *member,
                RecipientShares {
                    shares,
                    c3a: (0..rows)
                        .map(|_| {
                            placeholder::proof(&self.blobs, ProofType::C3aSkShareEncryption, &bytes)
                        })
                        .collect::<Result<_, _>>()?,
                    c3b: (0..rows)
                        .map(|_| {
                            placeholder::proof(
                                &self.blobs,
                                ProofType::C3bESmShareEncryption,
                                &bytes,
                            )
                        })
                        .collect::<Result<_, _>>()?,
                },
            );
        }
        let own = bincode::serialize(&own).map_err(JobError::crypto)?;
        Ok(OwnShares {
            pk_share,
            own_share: self.seal(&own)?,
            c1: placeholder::proof(&self.blobs, ProofType::C1PkGeneration, &generated.pk_share)?,
            c2a: placeholder::proof(
                &self.blobs,
                ProofType::C2aSkShareComputation,
                &generated.pk_share,
            )?,
            c2b: placeholder::proof(
                &self.blobs,
                ProofType::C2bESmShareComputation,
                &generated.pk_share,
            )?,
            recipients,
        })
    }

    /// Shares count when every C3 commits to the delivered ciphertexts and they decrypt under
    /// this node's C0 secret. Only the real C3 proof shows that the dealer encrypted them to this
    /// node's key: BFV decryption under another key yields noise, not an error.
    fn check_shares(
        &self,
        params: &CryptoParams,
        secret: &BlobRef,
        message: &SharesMessage,
    ) -> Result<bool, JobError> {
        let Ok(bytes) = self.blobs.get(&message.shares) else {
            return Ok(false);
        };
        let committed = message
            .c3a
            .iter()
            .chain(&message.c3b)
            .all(|c3| placeholder::commits_to(&c3.proof, &bytes));
        let Ok(ciphertexts) = bincode::deserialize::<RecipientCiphertexts>(&bytes) else {
            return Ok(false);
        };
        Ok(committed && self.decrypt_shares(params, secret, ciphertexts).is_ok())
    }

    /// Sum the roster dealers' shares for this node, its own included, into its decryption key.
    fn make_decryption_key(
        &self,
        params: &CryptoParams,
        secret: &BlobRef,
        own_share: &BlobRef,
        shares: &BTreeMap<Address, BlobRef>,
    ) -> Result<OwnDecryptionKey, JobError> {
        let own: OwnShareRows =
            bincode::deserialize(&self.unseal(own_share)?).map_err(JobError::crypto)?;
        let mut sk_collected = vec![own.sk];
        let mut esi_collected: Vec<Vec<ShamirShare>> =
            own.esi.into_iter().map(|esi| vec![esi]).collect();
        for blob in shares.values() {
            let dealt = self.decrypt_shares(params, secret, self.recipient_ciphertexts(blob)?)?;
            sk_collected.push(dealt.sk);
            for (collected, esi) in esi_collected.iter_mut().zip(dealt.esi) {
                collected.push(esi);
            }
        }
        let encrypt = |shares: Vec<ShamirShare>| {
            shares
                .into_iter()
                .map(|share| Encrypted::new(share, &self.cipher))
                .collect::<Result<Vec<_>, _>>()
                .map_err(JobError::crypto)
        };
        let key = calculate_decryption_key(
            &self.cipher,
            CalculateDecryptionKeyRequest {
                trbfv_config: trbfv::config(params)?,
                sk_sss_collected: encrypt(sk_collected)?,
                esi_sss_collected: esi_collected
                    .into_iter()
                    .map(encrypt)
                    .collect::<Result<_, _>>()?,
            },
        )
        .map_err(JobError::crypto)?;
        let sealed = SealedDecryptionKey {
            sk_poly_sum: key
                .sk_poly_sum
                .access_raw(&self.cipher)
                .map_err(JobError::crypto)?,
            es_poly_sum: key
                .es_poly_sum
                .iter()
                .map(|sum| sum.access_raw(&self.cipher))
                .collect::<Result<_, _>>()
                .map_err(JobError::crypto)?,
        };
        let sealed = bincode::serialize(&sealed).map_err(JobError::crypto)?;
        let key = self.seal(&sealed)?;
        Ok(OwnDecryptionKey {
            key,
            c4a: placeholder::proof(
                &self.blobs,
                ProofType::C4aSkShareDecryption,
                key.hash.as_slice(),
            )?,
            c4b: vec![placeholder::proof(
                &self.blobs,
                ProofType::C4bESmShareDecryption,
                key.hash.as_slice(),
            )?],
        })
    }

    /// A keyshare counts when its public-key share decodes and its C1 commits to it.
    fn check_keyshare(
        &self,
        params: &CryptoParams,
        keyshare: &KeyshareMessage,
    ) -> Result<bool, JobError> {
        let Ok(bytes) = self.blobs.get(&keyshare.pk_share) else {
            return Ok(false);
        };
        let bfv = trbfv::threshold_params(params)?;
        let crp = trbfv::crp_poly(params)?;
        let decodes = PublicKeyShare::deserialize(&bytes, &bfv, crp).is_ok();
        Ok(decodes && placeholder::commits_to(&keyshare.c1.proof, &bytes))
    }

    /// Sum the roster's public-key shares into the committee key.
    fn aggregate_key(
        &self,
        params: &CryptoParams,
        keyshares: &[KeyshareMessage],
    ) -> Result<AggregatedKey, JobError> {
        let bfv = trbfv::threshold_params(params)?;
        let crp = trbfv::crp_poly(params)?;
        let shares = keyshares
            .iter()
            .map(|keyshare| {
                let bytes = self.blobs.get(&keyshare.pk_share)?;
                PublicKeyShare::deserialize(&bytes, &bfv, crp.clone()).map_err(JobError::crypto)
            })
            .collect::<Result<Vec<_>, JobError>>()?;
        let key: PublicKey = shares.into_iter().aggregate().map_err(JobError::crypto)?;
        let bytes = key.to_bytes();
        Ok(AggregatedKey {
            public_key: self.blobs.put(&bytes)?,
            commitment: keccak256(&bytes),
            proof: placeholder::proof(&self.blobs, ProofType::C5PkAggregation, &bytes)?,
        })
    }

    fn recipient_ciphertexts(&self, blob: &BlobRef) -> Result<RecipientCiphertexts, JobError> {
        bincode::deserialize(&self.blobs.get(blob)?).map_err(JobError::crypto)
    }

    fn decrypt_shares(
        &self,
        params: &CryptoParams,
        secret: &BlobRef,
        ciphertexts: RecipientCiphertexts,
    ) -> Result<OwnShareRows, JobError> {
        let dkg = trbfv::dkg_params(params)?;
        let secret =
            deserialize_secret_key(&self.unseal(secret)?, &dkg).map_err(JobError::crypto)?;
        let degree = dkg.degree();
        let decrypt = |share: BfvEncryptedShare| {
            share
                .decrypt(&secret, &dkg, degree)
                .map_err(JobError::crypto)
        };
        Ok(OwnShareRows {
            sk: decrypt(ciphertexts.sk)?,
            esi: ciphertexts
                .esi
                .into_iter()
                .map(decrypt)
                .collect::<Result<_, _>>()?,
        })
    }
}
