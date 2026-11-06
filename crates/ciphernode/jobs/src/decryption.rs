// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The decryption jobs: a roster member's decryption shares (C6) and the plaintext from exactly
//! T+1 members' shares (C7), with the current node's library calls and placeholder proofs.

use crate::{placeholder, trbfv, Blobs, JobError, JobRunner, SealedDecryptionKey};
use alloy_primitives::{Address, B256};
use e3_crypto::SensitiveBytes;
use e3_protocol::{
    decryption::{
        DecryptionWork, DecryptionWorkResult, OwnShares, PlaintextPublication, SharesMessage,
    },
    node::CryptoParams,
    proof::ProofType,
    BlobRef,
};
use e3_trbfv::{
    calculate_decryption_share::{calculate_decryption_share, CalculateDecryptionShareRequest},
    calculate_threshold_decryption::{
        calculate_threshold_decryption, CalculateThresholdDecryptionRequest,
    },
};
use e3_utils::utility_types::ArcBytes;
use std::collections::BTreeMap;

impl<B: Blobs> JobRunner<B> {
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
                domain,
                message,
                ..
            } => DecryptionWorkResult::SharesChecked {
                member: *member,
                valid: self.check_decryption_shares(message, *domain),
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
        key: &BlobRef,
        ciphertext: &BlobRef,
        domain: B256,
    ) -> Result<OwnShares, JobError> {
        let key: SealedDecryptionKey =
            bincode::deserialize(&self.unseal(key)?).map_err(JobError::crypto)?;
        let sensitive =
            |bytes: Vec<u8>| SensitiveBytes::new(bytes, &self.cipher).map_err(JobError::crypto);
        let response = calculate_decryption_share(
            &self.cipher,
            CalculateDecryptionShareRequest {
                name: "decryption share".to_owned(),
                trbfv_config: trbfv::config(params)?,
                ciphertexts: self.ciphertexts(ciphertext)?,
                sk_poly_sum: sensitive(key.sk_poly_sum)?,
                es_poly_sum: key
                    .es_poly_sum
                    .into_iter()
                    .map(sensitive)
                    .collect::<Result<_, _>>()?,
            },
        )
        .map_err(JobError::crypto)?;
        let shares: Vec<BlobRef> = response
            .d_share_poly
            .iter()
            .map(|share| self.blobs.put(share))
            .collect();
        let c6 = response
            .d_share_poly
            .iter()
            .map(|share| {
                let bound = [share.as_ref(), domain.as_slice()].concat();
                placeholder::proof(&self.blobs, ProofType::C6ThresholdShareDecryption, &bound)
            })
            .collect();
        Ok(OwnShares { shares, c6 })
    }

    /// Shares count when each C6 commits to its share under the decryption domain.
    fn check_decryption_shares(&self, message: &SharesMessage, domain: B256) -> bool {
        message.shares.len() == message.c6.len()
            && message.shares.iter().zip(&message.c6).all(|(share, c6)| {
                self.blobs.get(share).is_ok_and(|bytes| {
                    let bound = [bytes.as_slice(), domain.as_slice()].concat();
                    placeholder::commits_to(&c6.proof, &bound)
                })
            })
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
        let plaintext = response
            .plaintext
            .first()
            .ok_or(JobError::crypto("no plaintext"))?;
        Ok(PlaintextPublication {
            plaintext: self.blobs.put(plaintext),
            proof: placeholder::proof(
                &self.blobs,
                ProofType::C7DecryptedSharesAggregation,
                plaintext,
            ),
        })
    }

    /// The ciphertext blob holds the bytes the chain's content hash names: one serialized
    /// ciphertext.
    fn ciphertexts(&self, blob: &BlobRef) -> Result<Vec<ArcBytes>, JobError> {
        Ok(vec![ArcBytes::from_bytes(&self.blobs.get(blob)?)])
    }
}
