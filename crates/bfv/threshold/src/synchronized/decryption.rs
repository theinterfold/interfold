// SPDX-License-Identifier: LGPL-3.0-only

use crate::PartyId;
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use fhe::{
    bfv::{Ciphertext, Plaintext},
    trbfv::{DecryptionShare, PartyPrfKeys, SmudgingNoise, SynchronizedDecryptor},
};
use fhe_math::rq::{Ntt, Poly, PowerBasis};

fn coordinates(ids: &[PartyId], count: usize, n: usize) -> Result<Vec<usize>> {
    ensure!(ids.len() == count, "Incorrect designated-set size");
    let mut result = Vec::with_capacity(ids.len());
    for (index, &id) in ids.iter().enumerate() {
        let id = usize::try_from(id).context("Party ID exceeds native index width")?;
        ensure!(id < n, "Party ID is outside the committee");
        ensure!(
            index == 0 || ids[index - 1] < ids[index],
            "Party IDs must be strictly increasing"
        );
        result.push(id + 1);
    }
    Ok(result)
}

/// Proposed initial policy: the lowest canonical T+1 IDs from the published H-roster.
/// This validates the complete roster, not just the selected prefix. Calling it does not authenticate
/// the roster or enable synchronized admission; policy ratification remains a protocol-review gate.
pub fn select_designated_set(
    roster: &[PartyId],
    committee: CiphernodesCommitteeSize,
) -> Result<Vec<PartyId>> {
    let config = committee.values();
    coordinates(roster, config.h, config.n)?;
    Ok(roster[..config.threshold + 1].to_vec())
}

/// An in-memory contribution retaining its original ciphertext digest and designated set.
/// Authentication, E3 binding and durable replay remain the caller's obligations.
#[derive(Clone, Debug)]
pub struct SynchronizedShare {
    designated: Vec<PartyId>,
    inner: DecryptionShare,
}

impl SynchronizedShare {
    /// Native polynomial plus zero-based runtime owner and designated IDs, for proof preparation.
    pub fn into_parts(self) -> (Poly<PowerBasis>, PartyId, Vec<PartyId>) {
        let (poly, owner, _) = self.inner.into_parts();
        (poly, (owner - 1) as PartyId, self.designated)
    }
}

/// Consumes caller-sampled local noise. Retry/recovery must reuse the successful output, not call
/// this again with freshly sampled noise. No attempt or multi-output policy is implemented here.
pub fn create_share(
    decryptor: &SynchronizedDecryptor,
    party_id: PartyId,
    designated: &[PartyId],
    ciphertext: &Ciphertext,
    secret: &Poly<Ntt>,
    noise: SmudgingNoise,
    keys: &PartyPrfKeys,
) -> Result<SynchronizedShare> {
    let ids = coordinates(
        designated,
        decryptor.threshold() + 1,
        decryptor.committee_size(),
    )?;
    let owner = usize::try_from(party_id).context("Party ID exceeds native index width")?;
    ensure!(
        owner < decryptor.committee_size(),
        "Share owner is outside the committee"
    );
    let inner = decryptor.decryption_share(ciphertext, secret, owner + 1, &ids, noise, keys)?;
    Ok(SynchronizedShare {
        designated: designated.to_vec(),
        inner,
    })
}

/// Sum exactly the expected set's already-weighted shares, adding c0 once. Never interpolate again.
pub fn reconstruct(
    decryptor: &SynchronizedDecryptor,
    designated: &[PartyId],
    ciphertext: &Ciphertext,
    shares: Vec<SynchronizedShare>,
) -> Result<Plaintext> {
    coordinates(
        designated,
        decryptor.threshold() + 1,
        decryptor.committee_size(),
    )?;
    ensure!(
        shares.len() == designated.len(),
        "Synchronized reconstruction requires exactly T+1 shares"
    );
    ensure!(
        shares.iter().all(|share| share.designated == designated),
        "Mixed designated sets"
    );
    let shares: Vec<_> = shares.into_iter().map(|share| share.inner).collect();
    Ok(decryptor.decrypt_from_shares(&shares, ciphertext)?)
}
