// SPDX-License-Identifier: LGPL-3.0-only

use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{build_pair_for_preset, utils::compute_modulus_bit, BfvPreset};
use e3_zk_config::threshold::{pk_generation, user_data_encryption, user_data_encryption_chunked};

/// Commitments link these circuits, so a width that drifts compiles and then fails every proof.
#[test]
fn circuits_hashing_centered_threshold_residues_share_one_width() {
    for preset in BfvPreset::PAIR_PRESETS {
        let (threshold, _) = build_pair_for_preset(preset).unwrap();
        let bit = compute_modulus_bit(&threshold);

        let generation =
            pk_generation::Configs::new(preset, &threshold, CiphernodesCommitteeSize::Minimum)
                .unwrap();
        assert_eq!(generation.bits.pk_bit, bit, "{preset:?} C1 pk");
        assert_eq!(generation.bits.e_sm_bit, bit, "{preset:?} C1 e_sm");

        let user = user_data_encryption::Configs::new(&threshold).unwrap();
        assert_eq!(user.bits.pk_bit, bit, "{preset:?} user pk");
        assert_eq!(user.bits.ct_bit, bit, "{preset:?} user ct");

        let chunked = user_data_encryption_chunked::Configs::new(&threshold).unwrap();
        assert_eq!(chunked.bits.pk_bit, bit, "{preset:?} chunked user pk");
        assert_eq!(chunked.bits.ct_bit, bit, "{preset:?} chunked user ct");
    }
}
