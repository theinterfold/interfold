// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The decryption jobs: a roster member's decryption shares (C6) and the plaintext from exactly
//! T+1 members' shares (C7), with the current node's library calls.

use crate::{
    placeholder, proofs, proofs::Prover, trbfv, Blobs, JobError, Jobs, SealedDecryptionKey,
};
use alloy_primitives::{Address, B256, U256};
use e3_bfv_client::compute_ct_commitment_with_params;
use e3_committee_hash::split_decryption_domain;
use e3_crypto::SensitiveBytes;
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_protocol::{
    accusation::Verdict,
    decryption::{
        DecryptionWork, DecryptionWorkResult, OwnShares, PlaintextPublication, SharesMessage,
    },
    dkg::KeyAnchor,
    node::CryptoParams,
    proof::{ProofType, ZkProof},
    BlobRef, SealedRef,
};
use e3_trbfv::{
    calculate_decryption_share::{calculate_decryption_share, CalculateDecryptionShareRequest},
    calculate_threshold_decryption::{
        calculate_threshold_decryption, CalculateThresholdDecryptionRequest,
    },
    helpers::try_poly_pb_from_bytes,
};
use e3_utils::utility_types::ArcBytes;
use e3_zk_config::{CircuitName, CircuitVariant, MAX_MSG_NON_ZERO_COEFFS, MESSAGE_COEFF_BYTE_LEN};
use e3_zk_prover::{
    prove_decryption_aggregation_jobs, DecryptedSharesAggregationCircuit, DecryptionAggregationJob,
    Provable, ThresholdShareDecryptionCircuit,
};
use e3_zk_witness::{
    compute_threshold_decryption_share_commitment,
    threshold::{
        decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData,
        share_decryption::ShareDecryptionCircuitData,
    },
};
use fhe::bfv::Ciphertext;
use fhe_traits::DeserializeParametrized;
use rayon::prelude::*;
use std::collections::BTreeMap;

impl<B: Blobs> Jobs<'_, B> {
    pub(crate) fn run_decryption(
        &self,
        params: &CryptoParams,
        work: &DecryptionWork,
    ) -> Result<DecryptionWorkResult, JobError> {
        Ok(match work {
            DecryptionWork::MakeShares {
                key,
                ciphertext,
                domain,
            } => DecryptionWorkResult::SharesMade(
                self.decryption_shares(params, key, ciphertext, *domain)?,
            ),
            DecryptionWork::CheckShares {
                member,
                ciphertext,
                domain,
                anchor,
                message,
                ..
            } => DecryptionWorkResult::SharesChecked {
                member: *member,
                verdict: self
                    .check_decryption_shares(params, ciphertext, *domain, *anchor, message)?,
            },
            DecryptionWork::AggregatePlaintext {
                committee,
                ciphertext,
                shares,
                ..
            } => DecryptionWorkResult::PlaintextMade(
                self.plaintext(params, committee, ciphertext, shares)?,
            ),
        })
    }

    fn decryption_shares(
        &self,
        params: &CryptoParams,
        key: &SealedRef,
        ciphertext: &BlobRef,
        domain: B256,
    ) -> Result<OwnShares, JobError> {
        let key: SealedDecryptionKey =
            bincode::deserialize(&self.unseal(key)?).map_err(JobError::crypto)?;
        let ciphertexts = self.ciphertexts(ciphertext)?;
        let sensitive = |bytes: &Vec<u8>| {
            SensitiveBytes::new(bytes.clone(), self.cipher).map_err(JobError::crypto)
        };
        let response = calculate_decryption_share(
            self.cipher,
            CalculateDecryptionShareRequest {
                name: "decryption share".to_owned(),
                trbfv_config: trbfv::config(params)?,
                ciphertexts: ciphertexts.clone(),
                sk_poly_sum: sensitive(&key.sk_poly_sum)?,
                es_poly_sum: key
                    .es_poly_sum
                    .iter()
                    .map(sensitive)
                    .collect::<Result<_, _>>()?,
            },
        )
        .map_err(JobError::crypto)?;
        let shares: Vec<BlobRef> = response
            .d_share_poly
            .iter()
            .map(|share| self.blobs.put(share))
            .collect::<Result<_, _>>()?;
        let c6 = match self.prover() {
            Some(prover) => self.prove_decryption_shares(
                prover,
                params,
                &key,
                &ciphertexts,
                &response.d_share_poly,
                domain,
            )?,
            None => response
                .d_share_poly
                .iter()
                .map(|share| {
                    let bound = [share.as_ref(), domain.as_slice()].concat();
                    placeholder::proof(&self.blobs, ProofType::C6ThresholdShareDecryption, &bound)
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(OwnShares { shares, c6 })
    }

    /// C6, per ciphertext: the share is the ciphertext decrypted with this member's decryption
    /// key, smudged with its noise, under the decryption domain.
    fn prove_decryption_shares(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        key: &SealedDecryptionKey,
        ciphertexts: &[ArcBytes],
        shares: &[ArcBytes],
        domain: B256,
    ) -> Result<Vec<ZkProof>, JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let config = e3_zk_config::threshold::share_decryption::Configs::new(&threshold)
            .map_err(JobError::crypto)?;
        let poly = |bytes: &[u8]| {
            let poly = try_poly_pb_from_bytes(bytes, &threshold).map_err(JobError::crypto)?;
            Ok::<_, JobError>(CrtPolynomial::from_fhe_polynomial(&poly))
        };
        let s = poly(&key.sk_poly_sum)?;
        if key.es_poly_sum.is_empty() {
            return Err(JobError::crypto("the decryption key has no smudging noise"));
        }
        let domain = split_decryption_domain(domain);
        ciphertexts
            .par_iter()
            .zip(shares)
            .enumerate()
            .map(|(index, (ciphertext, share))| {
                // One smudging-noise sum serves every ciphertext.
                let noise = &key.es_poly_sum[index % key.es_poly_sum.len()];
                let data = ShareDecryptionCircuitData {
                    ciphertext: Ciphertext::from_bytes(ciphertext, &threshold)
                        .map_err(JobError::crypto)?,
                    s: s.clone(),
                    e: poly(noise)?,
                    d_share: poly(share)?,
                    domain_hi: domain.hi,
                    domain_lo: domain.lo,
                };
                let work = format!("c6-{index}");
                self.prove(
                    prover,
                    params,
                    ThresholdShareDecryptionCircuit,
                    &config,
                    &data,
                    &work,
                )
            })
            .collect()
    }

    /// Shares count when each C6 proves its share of its ciphertext under the decryption domain,
    /// with the key commitments the chain recorded for the member.
    fn check_decryption_shares(
        &self,
        params: &CryptoParams,
        ciphertext: &BlobRef,
        domain: B256,
        anchor: Option<KeyAnchor>,
        message: &SharesMessage,
    ) -> Result<Verdict, JobError> {
        let Some(prover) = self.prover() else {
            if message.shares.len() != message.c6.len() {
                return Ok(Verdict::Invalid);
            }
            for (share, c6) in message.shares.iter().zip(&message.c6) {
                let bound = [self.blobs.get(share)?.as_slice(), domain.as_slice()].concat();
                if !placeholder::commits_to(&c6.proof, &bound) {
                    return Ok(Verdict::Invalid);
                }
            }
            return Ok(Verdict::Valid);
        };
        let c6 = message
            .c6
            .iter()
            .map(|c6| (ProofType::C6ThresholdShareDecryption, &c6.proof));
        self.checked(prover, params, c6, || {
            let ciphertexts = self.ciphertexts(ciphertext)?;
            let Some(anchor) = anchor else {
                return Ok(false);
            };
            if message.shares.len() != message.c6.len() || message.shares.len() != ciphertexts.len()
            {
                return Ok(false);
            }
            for ((share, c6), ciphertext) in
                message.shares.iter().zip(&message.c6).zip(&ciphertexts)
            {
                let share = self.blobs.get(share)?;
                if !self.c6_binds(params, &c6.proof, ciphertext, &share, domain, anchor)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }

    /// Whether a valid C6 would be about this share of this ciphertext, under this domain, made
    /// with the key whose commitments the chain recorded for the member. A copied proof names
    /// another member's commitments.
    fn c6_binds(
        &self,
        params: &CryptoParams,
        c6: &ZkProof,
        ciphertext: &[u8],
        share: &[u8],
        domain: B256,
        anchor: KeyAnchor,
    ) -> Result<bool, JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let field = |name| proofs::field(c6, CircuitName::ThresholdShareDecryption, name);
        let domain = split_decryption_domain(domain);
        let limbs = [("domain_hi", domain.hi), ("domain_lo", domain.lo)];
        let in_domain = limbs
            .into_iter()
            .all(|(name, limb)| field(name) == Some(B256::from(U256::from(limb))));
        let ciphertext = compute_ct_commitment_with_params(ciphertext, &threshold)
            .ok()
            .map(B256::from);
        let d_native_bit = e3_zk_config::threshold::share_decryption::Configs::new(&threshold)
            .map_err(JobError::crypto)?
            .bits
            .d_native_bit;
        let share = try_poly_pb_from_bytes(share, &threshold)
            .ok()
            .and_then(|share| {
                proofs::word(&compute_threshold_decryption_share_commitment(
                    &CrtPolynomial::from_fhe_polynomial(&share),
                    d_native_bit,
                    MAX_MSG_NON_ZERO_COEFFS,
                ))
            });
        let keyed = field("expected_sk_commitment") == Some(anchor.sk_agg_commit)
            && field("expected_e_sm_commitment") == Some(anchor.esm_agg_commit);
        Ok(keyed
            && in_domain
            && ciphertext.is_some()
            && field("ct_commitment") == ciphertext
            && share.is_some()
            && field("d_commitment") == share)
    }

    /// The plaintext of the first ciphertext, which is what `publishPlaintextOutput` takes.
    fn plaintext(
        &self,
        params: &CryptoParams,
        committee: &[Address],
        ciphertext: &BlobRef,
        shares: &BTreeMap<Address, SharesMessage>,
    ) -> Result<PlaintextPublication, JobError> {
        let d_share_polys = shares
            .iter()
            .map(|(member, message)| {
                let party = trbfv::party(committee, *member)? as u64;
                let polys = message
                    .shares
                    .iter()
                    .map(|share| Ok(ArcBytes::from_bytes(&self.blobs.get(share)?)))
                    .collect::<Result<Vec<_>, JobError>>()?;
                Ok((party, polys))
            })
            .collect::<Result<Vec<_>, JobError>>()?;
        let response = calculate_threshold_decryption(CalculateThresholdDecryptionRequest {
            trbfv_config: trbfv::config(params)?,
            d_share_polys,
            ciphertexts: self.ciphertexts(ciphertext)?,
        })
        .map_err(JobError::crypto)?;
        let mut plaintext = response
            .plaintext
            .first()
            .ok_or(JobError::crypto("no plaintext"))?
            .to_vec();
        // The plaintext is published as C7 proves it: the circuit's fixed number of message
        // coefficients, whose hash the decryption verifier checks.
        plaintext.resize(MAX_MSG_NON_ZERO_COEFFS * MESSAGE_COEFF_BYTE_LEN, 0);
        let proof = match self.prover() {
            Some(prover) => self.prove_plaintext(prover, params, committee, shares, &plaintext)?,
            None => placeholder::proof(
                &self.blobs,
                ProofType::C7DecryptedSharesAggregation,
                &plaintext,
            )?,
        };
        Ok(PlaintextPublication {
            plaintext: self.blobs.put(&plaintext)?,
            proof,
        })
    }

    /// The proof `publishPlaintextOutput` verifies: C7, that the T+1 members' shares of the first
    /// ciphertext combine into the plaintext, folded with their C6 proofs.
    fn prove_plaintext(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        committee: &[Address],
        shares: &BTreeMap<Address, SharesMessage>,
        plaintext: &[u8],
    ) -> Result<ZkProof, JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let mut d_share_polys = Vec::new();
        let mut reconstructing_parties = Vec::new();
        let mut c6 = Vec::new();
        for (member, message) in shares {
            let (Some(share), Some(proof)) = (message.shares.first(), message.c6.first()) else {
                return Err(JobError::crypto(
                    "a member sent no share of the first ciphertext",
                ));
            };
            d_share_polys.push(
                try_poly_pb_from_bytes(&self.blobs.get(share)?, &threshold)
                    .map_err(JobError::crypto)?,
            );
            // The circuit numbers parties from one.
            reconstructing_parties.push(trbfv::party(committee, *member)? + 1);
            c6.push(proofs::load(
                &self.blobs,
                &proof.proof,
                proofs::circuit(ProofType::C6ThresholdShareDecryption),
            )?);
        }
        let c7 = DecryptedSharesAggregationCircuitData {
            d_share_polys,
            reconstructing_parties,
            message_vec: e3_bfv_client::decode_bytes_to_vec_u64(plaintext)
                .map_err(JobError::crypto)?,
        };
        let config = e3_zk_config::threshold::decrypted_shares_aggregation::Configs::new(
            &threshold,
            params.committee_size,
        )
        .map_err(JobError::crypto)?;
        let (work, artifacts) = (self.work("c7"), self.artifacts(prover, params)?);
        // C7 takes the variant the decryption aggregation verifies inside it.
        let c7 = prover.proving(|zk| {
            let variant = CircuitVariant::Default;
            DecryptedSharesAggregationCircuit
                .prove_with_variant(zk, &config, &c7, &work, variant, &artifacts)
        })?;
        let slots: Vec<u32> = (0..c6.len() as u32).collect();
        let job = DecryptionAggregationJob {
            c6_inner_proofs: &c6,
            c6_slot_indices: &slots,
            c7_proof: &c7,
        };
        let (work, preset) = (self.work("decryption"), trbfv::threshold_preset(params)?);
        let proofs = prover.proving(|zk| {
            let (slots, size) = (c6.len(), params.committee_size);
            prove_decryption_aggregation_jobs(zk, slots, &[job], committee, &work, preset, size)
        })?;
        let proof = proofs
            .first()
            .ok_or(JobError::crypto("no decryption aggregation proof"))?;
        proofs::store(&self.blobs, proof)
    }

    /// The ciphertext blob holds the bytes the chain's content hash names: one serialized
    /// ciphertext.
    fn ciphertexts(&self, blob: &BlobRef) -> Result<Vec<ArcBytes>, JobError> {
        Ok(vec![ArcBytes::from_bytes(&self.blobs.get(blob)?)])
    }
}
