// SPDX-License-Identifier: LGPL-3.0-only

use crate::{shares::ShamirShare, PartyId};
use anyhow::{ensure, Context, Result};
use e3_fhe_params::{BfvParamSet, BfvProfile};
use fhe::trbfv::{PartyPrfKeyTransport, PartyPrfKeys, PRF_KEY_LEN};
use rand::{CryptoRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Directed key bytes, little-endian as consumed by fhe.rs. Never serialize into ordinary snapshots.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrfKey([u8; PRF_KEY_LEN]);

impl fmt::Debug for PrfKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrfKey").finish_non_exhaustive()
    }
}

impl PrfKey {
    pub fn random<R: RngCore + CryptoRng>(profile: BfvProfile, rng: &mut R) -> Result<Self> {
        let bits = key_bits(profile)?;
        let mut key = Self([0; PRF_KEY_LEN]);
        rng.fill_bytes(&mut key.0[..bits.div_ceil(8)]);
        if bits % 8 != 0 {
            key.0[bits / 8] &= (1 << (bits % 8)) - 1;
        }
        Ok(key)
    }

    pub fn from_bytes(profile: BfvProfile, bytes: [u8; PRF_KEY_LEN]) -> Result<Self> {
        let key = Self(bytes);
        key.validate(profile)?;
        Ok(key)
    }

    pub fn as_bytes(&self) -> &[u8; PRF_KEY_LEN] {
        &self.0
    }

    fn validate(&self, profile: BfvProfile) -> Result<()> {
        let bits = key_bits(profile)?;
        for bit in bits..PRF_KEY_LEN * 8 {
            ensure!(
                self.0[bit / 8] & (1 << (bit % 8)) == 0,
                "PRF key exceeds profile width"
            );
        }
        Ok(())
    }
}

fn key_bits(profile: BfvProfile) -> Result<usize> {
    let bits = profile
        .prf_key_bits()
        .context("Profile has no synchronized PRF keys")?;
    ensure!(
        bits > 0 && bits <= PRF_KEY_LEN * 8,
        "Unsupported PRF key width"
    );
    Ok(bits)
}

fn packing_parameters(profile: BfvProfile, share: &ShamirShare) -> Result<(BfvParamSet, usize)> {
    let bits = key_bits(profile)?;
    let threshold = BfvParamSet::from(profile.threshold_preset());
    let transport = profile.dkg_parameters();
    ensure!(
        share.dim() == (threshold.moduli.len(), threshold.degree),
        "Invalid SK-share shape"
    );
    ensure!(
        bits <= threshold.degree,
        "PRF key does not fit in limb zero"
    );
    let q_max = threshold
        .moduli
        .iter()
        .copied()
        .max()
        .context("Missing threshold moduli")?;
    ensure!(
        Some(transport.plaintext_modulus) == q_max.checked_mul(2),
        "Synchronized transport must reserve one key bit per coefficient"
    );
    Ok((threshold, bits))
}

/// In native coefficient order, limb zero carries `s[j] + bit[j] * q_0`.
/// Other limbs and coefficients beyond the key width remain unchanged. The result contains secret
/// key bits: encrypt it with the existing SK-share transport; never log or persist it in plaintext.
pub fn pack_key(profile: BfvProfile, share: &ShamirShare, key: &PrfKey) -> Result<ShamirShare> {
    let (threshold, bits) = packing_parameters(profile, share)?;
    key.validate(profile)?;
    for (row, &q) in share.rows().into_iter().zip(threshold.moduli) {
        ensure!(
            row.iter().all(|&value| value < q),
            "Noncanonical SK-share residue"
        );
    }
    let mut data = share.view().to_owned();
    for j in 0..bits {
        let bit = (key.0[j / 8] >> (j % 8)) & 1;
        data[[0, j]] += u64::from(bit) * threshold.moduli[0];
    }
    Ok(ShamirShare::new(data))
}

pub fn unpack_key(profile: BfvProfile, packed: &ShamirShare) -> Result<(ShamirShare, PrfKey)> {
    let (threshold, bits) = packing_parameters(profile, packed)?;
    for (limb, row) in packed.rows().into_iter().enumerate() {
        let q = threshold.moduli[limb];
        for (j, &value) in row.iter().enumerate() {
            let limit = if limb == 0 && j < bits { 2 * q } else { q };
            ensure!(value < limit, "Noncanonical packed SK-share coefficient");
        }
    }
    let mut data = packed.view().to_owned();
    let mut key = PrfKey([0; PRF_KEY_LEN]);
    let q = threshold.moduli[0];
    for j in 0..bits {
        let bit = data[[0, j]] / q;
        data[[0, j]] %= q;
        key.0[j / 8] |= (bit as u8) << (j % 8);
    }
    Ok((ShamirShare::new(data), key))
}

/// `outgoing[j] = k_{i,j}` and `incoming[j] = k_{j,i}`, indexed by full-committee runtime ID.
/// Matching dealer/recipient provenance is established by authenticated DKG, not by this constructor.
pub fn assemble_party_keys(
    profile: BfvProfile,
    party_id: PartyId,
    outgoing: &[PrfKey],
    incoming: &[PrfKey],
) -> Result<PartyPrfKeys> {
    let owner = usize::try_from(party_id).context("Party ID exceeds native index width")?;
    let n = outgoing.len();
    ensure!(
        owner < n && incoming.len() == n,
        "Invalid directed PRF-key dimensions"
    );
    for key in outgoing.iter().chain(incoming) {
        key.validate(profile)?;
    }
    // Check metadata before transferring raw-byte copies to the upstream zeroizing owner.
    let transport = PartyPrfKeyTransport::new(
        owner + 1,
        n,
        outgoing.iter().map(|key| key.0).collect(),
        incoming.iter().map(|key| key.0).collect(),
    )?;
    Ok(PartyPrfKeys::from_transport(transport)?)
}
