// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvProfile;
use fhe::{
    bfv::Ciphertext,
    trbfv::{DecryptionShare, PartyPrfKeyTransport, PartyPrfKeys, SynchronizedDecryptor},
};
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::BigInt;
use zeroize::Zeroizing;

/// The caller supplies the confirmed H and designated prefix in runtime coordinates. Native
/// transport indexes both key columns by full committee slot; C4 retains incoming keys in H order.
#[allow(clippy::too_many_arguments)]
pub fn weighted_share(
    profile: BfvProfile,
    committee: CiphernodesCommitteeSize,
    owner: u32,
    roster: &[u32],
    designated: &[u32],
    outgoing: &[[u8; 32]],
    incoming: &[[u8; 32]],
    sk: &Poly<PowerBasis>,
    ciphertext: &Ciphertext,
    noise: &[BigInt],
) -> Result<DecryptionShare> {
    let values = committee.values();
    ensure!(
        roster.len() == values.h
            && roster.windows(2).all(|p| p[0] < p[1])
            && roster.get(..=values.threshold) == Some(designated)
            && designated.contains(&owner)
            && incoming.len() == roster.len()
            && outgoing.len() == values.n,
        "invalid synchronized owner, roster or key dimensions"
    );
    let (generator, params) = super::noise::noise_generator(profile, committee)?;
    let mut slots = Zeroizing::new(vec![[0; 32]; values.n]);
    for (&id, &key) in roster.iter().zip(incoming) {
        *slots
            .get_mut(id as usize)
            .context("dealer outside committee")? = key;
    }
    let coord = owner as usize + 1;
    let set = designated
        .iter()
        .map(|&id| id as usize + 1)
        .collect::<Vec<_>>();
    let keys = PartyPrfKeys::from_transport(PartyPrfKeyTransport::new(
        coord,
        values.n,
        outgoing.to_vec(),
        std::mem::take(&mut *slots),
    )?)?;
    let draw = generator.wrap_signed_coefficients(noise)?;
    let decryptor = SynchronizedDecryptor::new(values.n, values.threshold, params)?;
    let ntt = Zeroizing::new(sk.clone().into_ntt());
    Ok(decryptor.decryption_share(ciphertext, &ntt, coord, &set, draw, &keys)?)
}
