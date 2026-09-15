// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Derive an operational l-BFV relinearization key from accepted share bytes.

use anyhow::{ensure, Result};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_utils::ArcBytes;
use fhe::aggregate::AggregateIter;
use fhe::trlbfv::{aggregate_relinearization_key, LBFVPublicKey, PublicKeyShare, RelinKeyShare};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};

/// Aggregate accepted public-key and RLK contributions in one canonical order.
///
/// The caller must perform signer, party-set, session, and commitment validation before calling
/// this adapter. The returned bytes are the operational `LBFVRelinearizationKey` serialization.
pub fn aggregate_lbfv_relinearization_key(
    preset: BfvPreset,
    public_key_share_bytes: &[ArcBytes],
    rlk_share_bytes: &[ArcBytes],
) -> Result<ArcBytes> {
    ensure!(
        preset == BfvPreset::SecureThreshold16384,
        "operational l-BFV RLK requires SecureThreshold16384"
    );
    ensure!(
        !public_key_share_bytes.is_empty() && public_key_share_bytes.len() == rlk_share_bytes.len(),
        "public-key and RLK share counts must be equal and nonzero"
    );

    let (params, _) = build_pair_for_preset(preset)?;
    let public_key_shares = public_key_share_bytes
        .iter()
        .map(|bytes| PublicKeyShare::from_bytes(bytes, &params))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let rlk_shares = rlk_share_bytes
        .iter()
        .map(|bytes| RelinKeyShare::from_bytes(bytes, &params))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let public_key: LBFVPublicKey = public_key_shares.into_iter().aggregate()?;
    let operational = aggregate_relinearization_key(&rlk_shares, &public_key)?;
    Ok(ArcBytes::from_bytes(&operational.to_bytes()))
}
