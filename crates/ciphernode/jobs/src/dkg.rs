// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DKG's jobs: BFV keys (C0), threshold shares (C1-C3), the decryption key (C4), the node
//! fold, and the committee key (C5 and the DKG aggregation), with the same library calls as the
//! current node.

use crate::{
    placeholder, proofs, proofs::Prover, trbfv, Blobs, JobError, Jobs, OwnShareRows,
    RecipientCiphertexts, SealedDecryptionKey,
};
use alloy_primitives::{keccak256, Address, B256};
use e3_crypto::SensitiveBytes;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_protocol::{
    accusation::Verdict,
    dkg::{
        AggregatedKey, DecryptionKeyMessage, DkgProofs, DkgWork, DkgWorkResult, KeyshareMessage,
        NodeFold, OwnDecryptionKey, OwnKey, OwnShares, RecipientShares, SharesMessage,
    },
    node::CryptoParams,
    proof::{ProofType, SignedProof, ZkProof},
    BlobRef, SealedRef,
};
use e3_trbfv::{
    calculate_decryption_key::{calculate_decryption_key, CalculateDecryptionKeyRequest},
    gen_esi_sss::{gen_esi_sss, GenEsiSssRequest},
    gen_pk_share_and_sk_sss::{
        gen_pk_share_and_sk_sss, GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse,
    },
    helpers::{
        deserialize_secret_key, serialize_secret_key, try_poly_ntt_from_bytes,
        try_poly_pb_from_bytes,
    },
    shares::{
        BfvEncryptedShare, BfvEncryptedShares, BfvEncryptionWitness, Encrypted, ShamirShare,
        SharedSecret,
    },
};
use e3_zk_config::{CircuitName, CircuitVariant, DkgInputType};
use e3_zk_prover::{
    extract_node_fold_agg_commits, prove_dkg_aggregation, prove_node_dkg_fold, DkgAggregationInput,
    DkgShareDecryptionCircuit, NodeDkgFoldInput, PkAggregationCircuit, PkCircuit,
    PkGenerationCircuit, Provable, ShareComputationCircuit, ShareEncryptionCircuit,
};
use e3_zk_witness::{
    compute_dkg_pk_commitment_from_public_key_bytes, compute_pk_commitment_from_keyshare_bytes,
    compute_share_encryption_commitment_from_message,
    dkg::{
        share_computation::ShareComputationCircuitData,
        share_decryption::ShareDecryptionCircuitData, share_encryption::ShareEncryptionCircuitData,
    },
    threshold::{pk_aggregation::PkAggregationCircuitData, pk_generation::PkGenerationCircuitData},
};
use fhe::{
    bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, PublicKeyShare},
};
use fhe_traits::{DeserializeParametrized, FheEncoder, Serialize};
use ndarray::Array2;
use num_bigint::BigInt;
use rayon::prelude::*;
use std::{collections::BTreeMap, sync::Arc};

impl<B: Blobs> Jobs<'_, B> {
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
                    verdict: self.check_encryption_key(params, key, proof)?,
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
                committee,
                secret,
                own_key,
                message,
            } => DkgWorkResult::SharesChecked {
                dealer: *dealer,
                verdict: self.check_shares(params, committee, secret, own_key, message)?,
            },
            DkgWork::MakeDecryptionKey {
                member,
                secret,
                own_share,
                shares,
                ..
            } => DkgWorkResult::DecryptionKeyMade(
                self.make_decryption_key(params, *member, secret, own_share, shares)?,
            ),
            DkgWork::CheckDecryptionKey {
                member,
                committee,
                c2,
                message,
            } => DkgWorkResult::DecryptionKeyChecked {
                member: *member,
                verdict: self.check_decryption_key(params, *member, committee, c2, message)?,
            },
            DkgWork::FoldProofs {
                member,
                committee,
                proofs,
            } => DkgWorkResult::ProofsFolded(self.fold_proofs(params, *member, committee, proofs)?),
            DkgWork::CheckKeyshare {
                member, keyshare, ..
            } => DkgWorkResult::KeyshareChecked {
                member: *member,
                verdict: self.check_keyshare(params, keyshare)?,
            },
            DkgWork::AggregateKey {
                committee,
                roster,
                keyshares,
                folds,
            } => DkgWorkResult::KeyAggregated(
                self.aggregate_key(params, committee, roster, keyshares, folds)?,
            ),
        })
    }

    pub(crate) fn make_encryption_key(&self, params: &CryptoParams) -> Result<OwnKey, JobError> {
        let bfv = trbfv::dkg_params(params)?;
        let mut rng = self.rng("encryption key")?;
        let secret = SecretKey::random(&bfv, &mut rng);
        let public = PublicKey::new(&secret, &mut rng);
        let proof = self.prove_encryption_key(params, &public)?;
        let secret = serialize_secret_key(&secret).map_err(JobError::crypto)?;
        Ok(OwnKey {
            public: self.blobs.put(&public.to_bytes())?,
            secret: self.seal(&secret)?,
            proof,
        })
    }

    /// C0: the key is a BFV public key under the request's DKG parameters.
    fn prove_encryption_key(
        &self,
        params: &CryptoParams,
        public: &PublicKey,
    ) -> Result<ZkProof, JobError> {
        let Some(prover) = self.prover() else {
            return placeholder::proof(&self.blobs, ProofType::C0PkBfv, &public.to_bytes());
        };
        let dkg = trbfv::dkg_params(params)?;
        let config = e3_zk_config::dkg::pk::Configs::new(&dkg).map_err(JobError::crypto)?;
        self.prove(prover, params, PkCircuit, &config, public, "c0")
    }

    /// A key counts when it decodes under the request's DKG parameters and its C0 proof holds.
    pub(crate) fn check_encryption_key(
        &self,
        params: &CryptoParams,
        key: &BlobRef,
        proof: &ZkProof,
    ) -> Result<Verdict, JobError> {
        let bfv = trbfv::dkg_params(params)?;
        let bytes = self.blobs.get(key)?;
        if PublicKey::from_bytes(&bytes, &bfv).is_err() {
            return Ok(Verdict::Invalid);
        }
        let Some(prover) = self.prover() else {
            return Ok(placeholder::verdict(placeholder::commits_to(proof, &bytes)));
        };
        // A valid proof counts only for the key bytes it commits to.
        let commitment = compute_dkg_pk_commitment_from_public_key_bytes(
            &bytes,
            trbfv::threshold_preset(params)?,
        )
        .ok()
        .map(B256::from);
        if commitment.is_none()
            || proofs::field(proof, CircuitName::PkBfv, "pk_commitment") != commitment
        {
            return Ok(Verdict::Invalid);
        }
        self.verdict(prover, params, [(ProofType::C0PkBfv, proof)])
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
        let mut rng = self.rng("shares")?;
        let generated = gen_pk_share_and_sk_sss(
            &mut rng,
            self.cipher,
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
            self.cipher,
            GenEsiSssRequest {
                trbfv_config: config,
                e_sm_raw: generated.e_sm_raw.clone(),
            },
        )
        .map_err(JobError::crypto)?;
        let sk_sss = generated
            .sk_sss
            .clone()
            .decrypt(self.cipher)
            .map_err(JobError::crypto)?;
        let esi_sss: Vec<_> = smudging
            .esi_sss
            .into_iter()
            .map(|shares| shares.decrypt(self.cipher))
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
        let encrypt = |purpose: String, secret| {
            BfvEncryptedShares::encrypt_all_extended_for_share_indices(
                secret,
                &recipient_keys,
                &slots,
                &dkg,
                &mut self.rng(&purpose)?,
                Some(party),
            )
            .map_err(JobError::crypto)
        };
        let (sk_encrypted, sk_witnesses) = encrypt("sk encryption".into(), &sk_sss)?;
        let (esi_encrypted, esi_witnesses): (Vec<_>, Vec<_>) = esi_sss
            .iter()
            .enumerate()
            .map(|(index, shares)| encrypt(format!("esi encryption {index}"), shares))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();

        let c3_config =
            e3_zk_config::dkg::share_encryption::Configs::new(&dkg).map_err(JobError::crypto)?;
        let recipients = || {
            committee
                .par_iter()
                .enumerate()
                .filter(|(_, member)| **member != dealer)
                .map(|(slot, member)| {
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
                    let bytes = bincode::serialize(&ciphertexts).map_err(JobError::crypto)?;
                    let shares = match keys.contains_key(member) {
                        true => Some(self.blobs.put(&bytes)?),
                        false => None,
                    };
                    // C3: each share row's ciphertext encrypts that row under the recipient's key.
                    let prove =
                        |proof_type: ProofType, row: usize, witness: &BfvEncryptionWitness| {
                            let Some(prover) = self.prover() else {
                                return placeholder::proof(&self.blobs, proof_type, &bytes);
                            };
                            let data = ShareEncryptionCircuitData {
                                plaintext: Plaintext::try_encode(
                                    &witness.share_row,
                                    Encoding::poly(),
                                    &dkg,
                                )
                                .map_err(JobError::crypto)?,
                                ciphertext: witness.ciphertext.clone(),
                                public_key: recipient_keys[slot].clone(),
                                u_rns: witness.u_rns.clone(),
                                e0_rns: witness.e0_rns.clone(),
                                e1_rns: witness.e1_rns.clone(),
                            };
                            let work = format!("{proof_type:?}-{slot}-{row}");
                            self.prove(
                                prover,
                                params,
                                ShareEncryptionCircuit,
                                &c3_config,
                                &data,
                                &work,
                            )
                        };
                    let c3 = |proof_type, witnesses: Vec<&BfvEncryptionWitness>| {
                        witnesses
                            .into_par_iter()
                            .enumerate()
                            .map(|(row, witness)| prove(proof_type, row, witness))
                            .collect::<Result<Vec<_>, _>>()
                    };
                    let (c3a, c3b) = rayon::join(
                        || {
                            c3(
                                ProofType::C3aSkShareEncryption,
                                sk_witnesses[slot].iter().collect(),
                            )
                        },
                        || {
                            let rows = esi_witnesses.iter().flat_map(|esi| &esi[slot]);
                            c3(ProofType::C3bESmShareEncryption, rows.collect())
                        },
                    );
                    Ok((
                        *member,
                        RecipientShares {
                            shares,
                            c3a: c3a?,
                            c3b: c3b?,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, JobError>>()
        };
        let dealing = || match self.prover() {
            Some(prover) => self.prove_dealing(prover, params, &generated, &sk_sss, &esi_sss),
            None => {
                let bound =
                    |proof_type| placeholder::proof(&self.blobs, proof_type, &generated.pk_share);
                Ok((
                    bound(ProofType::C1PkGeneration)?,
                    bound(ProofType::C2aSkShareComputation)?,
                    bound(ProofType::C2bESmShareComputation)?,
                ))
            }
        };
        let (recipients, dealing) = rayon::join(recipients, dealing);
        let (recipients, (c1, c2a, c2b)) = (recipients?, dealing?);
        let pk_share = self.blobs.put(&generated.pk_share)?;
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
        let own = bincode::serialize(&own).map_err(JobError::crypto)?;
        Ok(OwnShares {
            pk_share,
            own_share: self.seal(&own)?,
            c1,
            c2a,
            c2b,
            recipients,
        })
    }

    /// C1: the public-key share comes from the secret key, its key error, and the smudging
    /// noise. C2a and C2b: the Shamir shares of the secret key and of the smudging noise share
    /// them.
    fn prove_dealing(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        generated: &GenPkShareAndSkSssResponse,
        sk_sss: &SharedSecret,
        esi_sss: &[SharedSecret],
    ) -> Result<(ZkProof, ZkProof, ZkProof), JobError> {
        let preset = trbfv::threshold_preset(params)?;
        let threshold = trbfv::threshold_params(params)?;
        let raw = |bytes: &SensitiveBytes| bytes.access_raw(self.cipher).map_err(JobError::crypto);
        let sk = try_poly_pb_from_bytes(&raw(&generated.sk_raw)?, &threshold)
            .map_err(JobError::crypto)?;
        let eek = try_poly_ntt_from_bytes(&raw(&generated.eek_raw)?, &threshold)
            .map_err(JobError::crypto)?;
        let e_sm = try_poly_pb_from_bytes(&raw(&generated.e_sm_raw)?, &threshold)
            .map_err(JobError::crypto)?;
        let pk0_share = try_poly_ntt_from_bytes(&generated.pk0_share_raw, &threshold)
            .map_err(JobError::crypto)?;
        let [esi_sss] = esi_sss else {
            return Err(JobError::crypto("C2b proves one smudging-noise sharing"));
        };

        let c1 = PkGenerationCircuitData {
            pk0_share: CrtPolynomial::from_fhe_polynomial(&pk0_share),
            eek: CrtPolynomial::from_fhe_polynomial(&eek),
            e_sm: CrtPolynomial::from_fhe_polynomial(&e_sm),
            e_sm_lifted: Polynomial::from_fhe_polynomial(&e_sm),
            sk: CrtPolynomial::from_fhe_polynomial(&sk),
        };
        let mut centered_sk = CrtPolynomial::from_fhe_polynomial(&sk);
        centered_sk
            .center(threshold.moduli())
            .map_err(JobError::crypto)?;
        let shares = |secret: &SharedSecret| -> Vec<Array2<BigInt>> {
            let moduli = secret.moduli_data();
            moduli.iter().map(|rows| rows.mapv(BigInt::from)).collect()
        };
        let c2a = ShareComputationCircuitData {
            dkg_input_type: DkgInputType::SecretKey,
            secret: centered_sk,
            secret_sss: shares(sk_sss),
        };
        let c2b = ShareComputationCircuitData {
            dkg_input_type: DkgInputType::SmudgingNoise,
            secret: CrtPolynomial::from_fhe_polynomial(&e_sm),
            secret_sss: shares(esi_sss),
        };
        let committee = params.committee_size;
        let c1_config =
            e3_zk_config::threshold::pk_generation::Configs::new(preset, &threshold, committee)
                .map_err(JobError::crypto)?;
        let c2_config =
            e3_zk_config::dkg::share_computation::Configs::new(preset, &threshold, committee)
                .map_err(JobError::crypto)?;
        let (c1, (c2a, c2b)) = rayon::join(
            || self.prove(prover, params, PkGenerationCircuit, &c1_config, &c1, "c1"),
            || {
                rayon::join(
                    || {
                        self.prove(
                            prover,
                            params,
                            ShareComputationCircuit,
                            &c2_config,
                            &c2a,
                            "c2a",
                        )
                    },
                    || {
                        self.prove(
                            prover,
                            params,
                            ShareComputationCircuit,
                            &c2_config,
                            &c2b,
                            "c2b",
                        )
                    },
                )
            },
        );
        Ok((c1?, c2a?, c2b?))
    }

    /// Shares count when they decrypt, under this node's C0 secret, to the rows the dealer's C2
    /// proofs commit to for this node's slot, each C3 encrypts such a row to this node's key, and
    /// their C2 and C3 proofs hold.
    fn check_shares(
        &self,
        params: &CryptoParams,
        committee: &[Address],
        secret: &SealedRef,
        own_key: &ZkProof,
        message: &SharesMessage,
    ) -> Result<Verdict, JobError> {
        let bytes = self.blobs.get(&message.shares)?;
        let dkg = trbfv::dkg_params(params)?;
        let key = self.secret_key(&dkg, secret)?;
        let Ok(ciphertexts) = bincode::deserialize::<RecipientCiphertexts>(&bytes) else {
            return Ok(Verdict::Invalid);
        };
        let Ok(shares) = decrypt_shares(&key, &dkg, &ciphertexts) else {
            return Ok(Verdict::Invalid);
        };
        let c3 = message
            .c3a
            .iter()
            .map(|c3| (ProofType::C3aSkShareEncryption, &c3.proof))
            .chain(
                message
                    .c3b
                    .iter()
                    .map(|c3| (ProofType::C3bESmShareEncryption, &c3.proof)),
            );
        let Some(prover) = self.prover() else {
            let committed = c3
                .into_iter()
                .all(|(_, proof)| placeholder::commits_to(proof, &bytes));
            return Ok(placeholder::verdict(committed));
        };
        let party = trbfv::party(committee, message.recipient)?;
        let rows = trbfv::threshold_params(params)?.moduli().len();
        if !self.dealt_as_committed(params, party, &shares, message)?
            || !c3_names_this_node(own_key, party, rows, message)
        {
            return Ok(Verdict::Invalid);
        }
        let c2 = [
            (ProofType::C2aSkShareComputation, &message.c2a.proof),
            (ProofType::C2bESmShareComputation, &message.c2b.proof),
        ];
        self.verdict(prover, params, c2.into_iter().chain(c3))
    }

    /// Whether the shares this node decrypted are the ones the dealer's C2 proofs commit to for
    /// this node's slot, committed as this node's C4 will commit them. BFV decryption under
    /// another key yields noise, not an error, so this is what shows that the dealer encrypted
    /// the right shares to this node's key.
    fn dealt_as_committed(
        &self,
        params: &CryptoParams,
        party: usize,
        shares: &OwnShareRows,
        message: &SharesMessage,
    ) -> Result<bool, JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let dkg = trbfv::dkg_params(params)?;
        let msg_bit = e3_zk_config::dkg::share_decryption::Configs::new(&threshold, &dkg)
            .map_err(JobError::crypto)?
            .bits
            .msg_bit;
        let rows = threshold.moduli().len();
        // C2's public inputs: the secret's commitment, then each party's row commitments.
        let committed = |share: &ShamirShare, c2: &ZkProof| {
            share.nrows() == rows
                && share
                    .rows()
                    .into_iter()
                    .enumerate()
                    .all(|(row, coefficients)| {
                        let reversed = coefficients.iter().rev().map(|c| BigInt::from(*c));
                        let commitment = compute_share_encryption_commitment_from_message(
                            &Polynomial::new(reversed.collect()),
                            msg_bit,
                        );
                        let commitment = proofs::word(&commitment);
                        commitment.is_some()
                            && c2.public_inputs.get(1 + party * rows + row) == commitment.as_ref()
                    })
        };
        let [esi] = shares.esi.as_slice() else {
            return Ok(false);
        };
        Ok(committed(&shares.sk, &message.c2a.proof) && committed(esi, &message.c2b.proof))
    }

    /// Sum the roster dealers' shares for this node, its own included, into its decryption key.
    fn make_decryption_key(
        &self,
        params: &CryptoParams,
        member: Address,
        secret: &SealedRef,
        own_share: &SealedRef,
        shares: &BTreeMap<Address, BlobRef>,
    ) -> Result<OwnDecryptionKey, JobError> {
        let own: OwnShareRows =
            bincode::deserialize(&self.unseal(own_share)?).map_err(JobError::crypto)?;
        let dkg = trbfv::dkg_params(params)?;
        let secret = self.secret_key(&dkg, secret)?;
        let dealt = shares
            .iter()
            .map(|(dealer, blob)| Ok((*dealer, self.recipient_ciphertexts(blob)?)))
            .collect::<Result<BTreeMap<_, _>, JobError>>()?;
        let mut sk_collected = vec![own.sk.clone()];
        let mut esi_collected: Vec<Vec<ShamirShare>> =
            own.esi.iter().map(|esi| vec![esi.clone()]).collect();
        for ciphertexts in dealt.values() {
            let shares = decrypt_shares(&secret, &dkg, ciphertexts)?;
            sk_collected.push(shares.sk);
            for (collected, esi) in esi_collected.iter_mut().zip(shares.esi) {
                collected.push(esi);
            }
        }
        let encrypt = |shares: Vec<ShamirShare>| {
            shares
                .into_iter()
                .map(|share| Encrypted::new(share, self.cipher))
                .collect::<Result<Vec<_>, _>>()
                .map_err(JobError::crypto)
        };
        let key = calculate_decryption_key(
            self.cipher,
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
                .access_raw(self.cipher)
                .map_err(JobError::crypto)?,
            es_poly_sum: key
                .es_poly_sum
                .iter()
                .map(|sum| sum.access_raw(self.cipher))
                .collect::<Result<_, _>>()
                .map_err(JobError::crypto)?,
        };
        let sealed = bincode::serialize(&sealed).map_err(JobError::crypto)?;
        let key = self.seal(&sealed)?;
        let (c4a, c4b) = match self.prover() {
            Some(prover) => {
                self.prove_decryption_key(prover, params, &dkg, member, &secret, &own, &dealt)?
            }
            None => (
                placeholder::proof(
                    &self.blobs,
                    ProofType::C4aSkShareDecryption,
                    key.hash.as_slice(),
                )?,
                vec![placeholder::proof(
                    &self.blobs,
                    ProofType::C4bESmShareDecryption,
                    key.hash.as_slice(),
                )?],
            ),
        };
        Ok(OwnDecryptionKey { key, c4a, c4b })
    }

    /// C4a and C4b: this node decrypted the roster dealers' shares for it with its C0 key. Each
    /// proof takes the roster in party order, with this node's own share in plaintext. `dkg` is
    /// the parameters `secret` was read with: decryption needs the ciphertexts to share them.
    #[allow(clippy::too_many_arguments)]
    fn prove_decryption_key(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        dkg: &Arc<BfvParameters>,
        member: Address,
        secret: &SecretKey,
        own: &OwnShareRows,
        dealt: &BTreeMap<Address, RecipientCiphertexts>,
    ) -> Result<(ZkProof, Vec<ZkProof>), JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let config = e3_zk_config::dkg::share_decryption::Configs::new(&threshold, dkg)
            .map_err(JobError::crypto)?;
        let mut roster: Vec<Address> = dealt.keys().copied().chain([member]).collect();
        roster.sort();
        let data = |share: fn(&RecipientCiphertexts) -> &BfvEncryptedShare, own: &ShamirShare| {
            let honest_ciphertexts = roster
                .iter()
                .map(|dealer| {
                    let Some(dealt) = dealt.get(dealer) else {
                        return Ok(None);
                    };
                    let ciphertexts = share(dealt).ciphertext_bytes().iter();
                    ciphertexts
                        .map(|bytes| Ciphertext::from_bytes(bytes, dkg).map_err(JobError::crypto))
                        .collect::<Result<_, _>>()
                        .map(Some)
                })
                .collect::<Result<_, JobError>>()?;
            Ok::<_, JobError>(ShareDecryptionCircuitData {
                secret_key: secret.clone(),
                honest_ciphertexts,
                own_plaintext_share: own.rows().into_iter().map(|row| row.to_vec()).collect(),
            })
        };
        let [own_esi] = own.esi.as_slice() else {
            return Err(JobError::crypto("C4b proves one smudging-noise sharing"));
        };
        let c4a = data(|dealt| &dealt.sk, &own.sk)?;
        let c4b = data(
            |dealt| {
                dealt
                    .esi
                    .first()
                    .expect("a dealer's shares hold one smudging sharing")
            },
            own_esi,
        )?;
        let (c4a, c4b) = rayon::join(
            || {
                self.prove(
                    prover,
                    params,
                    DkgShareDecryptionCircuit,
                    &config,
                    &c4a,
                    "c4a",
                )
            },
            || {
                self.prove(
                    prover,
                    params,
                    DkgShareDecryptionCircuit,
                    &config,
                    &c4b,
                    "c4b",
                )
            },
        );
        Ok((c4a?, vec![c4b?]))
    }

    /// One recursive proof of this member's C0-C4 proofs. Its last public inputs commit to the
    /// member's secret-key and smudging-noise shares, which the member attests for its slot.
    fn fold_proofs(
        &self,
        params: &CryptoParams,
        member: Address,
        committee: &[Address],
        proofs: &DkgProofs,
    ) -> Result<NodeFold, JobError> {
        let Some(prover) = self.prover() else {
            let statements = placeholder::statements(proofs);
            return Ok(NodeFold {
                proof: placeholder::proof(&self.blobs, ProofType::C5PkAggregation, &[])?,
                sk_agg_commit: keccak256(&statements),
                esm_agg_commit: keccak256(statements.repeat(2)),
            });
        };
        let size = params.committee_size.values();
        let rows = trbfv::threshold_params(params)?.moduli().len();
        let load = |proof: &ZkProof, proof_type| {
            proofs::load(&self.blobs, proof, proofs::circuit(proof_type))
        };
        // A C3 proof's slot is its recipient's party ID times the share rows, plus its row.
        let c3 = |c3: &BTreeMap<Address, Vec<ZkProof>>, proof_type| {
            let mut folded = (Vec::new(), Vec::new());
            for (recipient, row_proofs) in c3 {
                let party = trbfv::party(committee, *recipient)?;
                for (row, proof) in row_proofs.iter().enumerate() {
                    folded.0.push(load(proof, proof_type)?);
                    folded
                        .1
                        .push(u32::try_from(party * rows + row).map_err(JobError::crypto)?);
                }
            }
            Ok::<_, JobError>(folded)
        };
        let (c3a, slots_a) = c3(&proofs.c3a, ProofType::C3aSkShareEncryption)?;
        let (c3b, slots_b) = c3(&proofs.c3b, ProofType::C3bESmShareEncryption)?;
        let [c4b] = proofs.c4b.as_slice() else {
            return Err(JobError::crypto("the fold takes one smudging-noise C4"));
        };
        let input = NodeDkgFoldInput {
            c0_proof: &load(&proofs.c0, ProofType::C0PkBfv)?,
            c1_proof: &load(&proofs.c1, ProofType::C1PkGeneration)?,
            c2a_proof: &load(&proofs.c2a, ProofType::C2aSkShareComputation)?,
            c2b_proof: &load(&proofs.c2b, ProofType::C2bESmShareComputation)?,
            c3a_inner_proofs: &c3a,
            c3b_inner_proofs: &c3b,
            c3_slot_indices_a: &slots_a,
            c3_slot_indices_b: &slots_b,
            c3_total_slots: size.n * rows,
            c4a_proof: &load(&proofs.c4a, ProofType::C4aSkShareDecryption)?,
            c4b_proof: &load(c4b, ProofType::C4bESmShareDecryption)?,
            party_id: trbfv::party(committee, member)? as u64,
        };
        let (work, artifacts) = (self.work("fold"), self.artifacts(prover, params)?);
        let fold = prover
            .proving(|zk| prove_node_dkg_fold(zk, &input, &work, &artifacts))?
            .proof;
        let (_, commits) =
            extract_node_fold_agg_commits(&fold, size.n, size.h, rows).map_err(JobError::crypto)?;
        Ok(NodeFold {
            proof: proofs::store(&self.blobs, &fold)?,
            sk_agg_commit: B256::from(commits.sk_agg_commit),
            esm_agg_commit: B256::from(commits.esm_agg_commit),
        })
    }

    /// A roster member's decryption key counts when its C4 proofs hold for the roster dealers'
    /// shares.
    fn check_decryption_key(
        &self,
        params: &CryptoParams,
        member: Address,
        committee: &[Address],
        c2: &BTreeMap<Address, (ZkProof, ZkProof)>,
        message: &DecryptionKeyMessage,
    ) -> Result<Verdict, JobError> {
        let Some(prover) = self.prover() else {
            return Ok(Verdict::Valid);
        };
        if !self.sums_committed_shares(params, member, committee, c2, message)? {
            return Ok(Verdict::Invalid);
        }
        let c4b = message
            .c4b
            .iter()
            .map(|c4b| (ProofType::C4bESmShareDecryption, &c4b.proof));
        let c4a = (ProofType::C4aSkShareDecryption, &message.c4a.proof);
        self.verdict(prover, params, std::iter::once(c4a).chain(c4b))
    }

    /// Whether a member's C4 proofs take, for each roster dealer, the share commitments that
    /// dealer's C2 proofs made for the member's slot.
    fn sums_committed_shares(
        &self,
        params: &CryptoParams,
        member: Address,
        committee: &[Address],
        c2: &BTreeMap<Address, (ZkProof, ZkProof)>,
        message: &DecryptionKeyMessage,
    ) -> Result<bool, JobError> {
        let [c4b] = message.c4b.as_slice() else {
            return Ok(false);
        };
        let rows = trbfv::threshold_params(params)?.moduli().len();
        let party = trbfv::party(committee, member)?;
        // C4's public inputs: each roster dealer's row commitments, in roster order.
        let takes = |c4: &ZkProof, dealt: fn(&(ZkProof, ZkProof)) -> &ZkProof| {
            c2.values().enumerate().all(|(dealer, proofs)| {
                (0..rows).all(|row| {
                    let committed = dealt(proofs).public_inputs.get(1 + party * rows + row);
                    committed.is_some() && c4.public_inputs.get(dealer * rows + row) == committed
                })
            })
        };
        Ok(takes(&message.c4a.proof, |proofs| &proofs.0) && takes(&c4b.proof, |proofs| &proofs.1))
    }

    /// A keyshare counts when its public-key share decodes and its C1 proof holds.
    fn check_keyshare(
        &self,
        params: &CryptoParams,
        keyshare: &KeyshareMessage,
    ) -> Result<Verdict, JobError> {
        let bytes = self.blobs.get(&keyshare.pk_share)?;
        let bfv = trbfv::threshold_params(params)?;
        if PublicKeyShare::deserialize(&bytes, &bfv, trbfv::crp_poly(params)?).is_err() {
            return Ok(Verdict::Invalid);
        }
        let c1 = &keyshare.c1.proof;
        let Some(prover) = self.prover() else {
            return Ok(placeholder::verdict(placeholder::commits_to(c1, &bytes)));
        };
        let crp = trbfv::crp_poly(params)?;
        let commitment = compute_pk_commitment_from_keyshare_bytes(&bytes, &bfv, &crp)
            .ok()
            .map(B256::from);
        if commitment.is_none()
            || proofs::field(c1, CircuitName::PkGeneration, "pk_commitment") != commitment
        {
            return Ok(Verdict::Invalid);
        }
        self.verdict(prover, params, [(ProofType::C1PkGeneration, c1)])
    }

    /// Sum the roster's public-key shares into the committee key. Its proof, which
    /// `publishCommittee` verifies, folds C5 with the roster members' node folds, and its last
    /// public input is the key commitment.
    fn aggregate_key(
        &self,
        params: &CryptoParams,
        committee: &[Address],
        roster: &[Address],
        keyshares: &[KeyshareMessage],
        folds: &[NodeFold],
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
        let pk0_shares = shares
            .iter()
            .map(|share| CrtPolynomial::from_fhe_polynomial(&share.p0_share()))
            .collect();
        let key: PublicKey = shares.into_iter().aggregate().map_err(JobError::crypto)?;
        let bytes = key.to_bytes();
        let public_key = self.blobs.put(&bytes)?;
        let Some(prover) = self.prover() else {
            let commitment = keccak256(&bytes);
            return Ok(AggregatedKey {
                public_key,
                commitment,
                proof: placeholder::key_aggregation(&self.blobs, committee, roster, commitment)?,
            });
        };
        let artifacts = self.artifacts(prover, params)?;
        let c5_config =
            e3_zk_config::threshold::pk_aggregation::Configs::new(&bfv, params.committee_size)
                .map_err(JobError::crypto)?;
        let c5 = PkAggregationCircuitData {
            public_key: key,
            pk0_shares,
        };
        // C5 takes the variant the DKG aggregation verifies inside it.
        let work = self.work("c5");
        let c5 = prover.proving(|zk| {
            let variant = CircuitVariant::Default;
            PkAggregationCircuit.prove_with_variant(zk, &c5_config, &c5, &work, variant, &artifacts)
        })?;
        let folds = folds
            .iter()
            .map(|fold| proofs::load(&self.blobs, &fold.proof, CircuitName::NodeFold))
            .collect::<Result<Vec<_>, _>>()?;
        let party_ids = roster
            .iter()
            .map(|member| Ok(trbfv::party(committee, *member)? as u64))
            .collect::<Result<Vec<_>, JobError>>()?;
        let input = DkgAggregationInput {
            node_fold_proofs: &folds,
            nodes_fold_proof: None,
            c5_proof: &c5,
            party_ids: &party_ids,
            committee_addresses: committee,
        };
        let (work, preset) = (self.work("dkg"), trbfv::threshold_preset(params)?);
        let proof = prover.proving(|zk| {
            prove_dkg_aggregation(zk, &input, &work, preset, params.committee_size)
        })?;
        let proof = proofs::store(&self.blobs, &proof)?;
        let commitment = *proof.public_inputs.last().ok_or(JobError::crypto(
            "the DKG aggregation proof has no public inputs",
        ))?;
        Ok(AggregatedKey {
            public_key,
            commitment,
            proof,
        })
    }

    fn recipient_ciphertexts(&self, blob: &BlobRef) -> Result<RecipientCiphertexts, JobError> {
        bincode::deserialize(&self.blobs.get(blob)?).map_err(JobError::crypto)
    }

    /// This node's C0 secret key, unsealed.
    fn secret_key(
        &self,
        dkg: &Arc<BfvParameters>,
        secret: &SealedRef,
    ) -> Result<SecretKey, JobError> {
        deserialize_secret_key(&self.unseal(secret)?, dkg).map_err(JobError::crypto)
    }
}

/// A dealer's shares for this node, decrypted with its C0 secret key.
fn decrypt_shares(
    key: &SecretKey,
    dkg: &Arc<BfvParameters>,
    ciphertexts: &RecipientCiphertexts,
) -> Result<OwnShareRows, JobError> {
    let degree = dkg.degree();
    let decrypt = |share: &BfvEncryptedShare| {
        share
            .clone()
            .decrypt(key, dkg, degree)
            .map_err(JobError::crypto)
    };
    Ok(OwnShareRows {
        sk: decrypt(&ciphertexts.sk)?,
        esi: ciphertexts
            .esi
            .iter()
            .map(decrypt)
            .collect::<Result<_, _>>()?,
    })
}

/// Whether the dealer's C3 proofs are the ones this node's fold can use: one per share row, each
/// encrypting to this node's key (as its C0 proof commits to it) the row that the dealer's C2
/// commits to for this node's slot. C4 binds those same row commitments, so a C3 made for
/// another slot or row would not count.
pub(crate) fn c3_names_this_node(
    own_key: &ZkProof,
    party: usize,
    rows: usize,
    message: &SharesMessage,
) -> bool {
    let Some(key) = proofs::field(own_key, CircuitName::PkBfv, "pk_commitment") else {
        return false;
    };
    let names = |c3s: &[SignedProof], c2: &ZkProof| {
        c3s.len() == rows
            && c3s.iter().enumerate().all(|(row, c3)| {
                let field = |name| proofs::field(&c3.proof, CircuitName::ShareEncryption, name);
                field("expected_pk_commitment") == Some(key)
                    && field("expected_message_commitment")
                        == c2.public_inputs.get(1 + party * rows + row).copied()
            })
    };
    names(&message.c3a, &message.c2a.proof) && names(&message.c3b, &message.c2b.proof)
}
