// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_fhe_params::BfvPreset;

/// `seq` slot of the C1 inner proof.
pub(crate) const C1_SEQ: usize = 1;

/// Number of inner-proof `seq` slots (C0..C4) of the node fold:
/// C0, C1, C2a, C2b (4) + C3a (sk) + C3b (esm) + C4a, C4b (2).
/// The l-BFV path proves no C1 and leaves the [`C1_SEQ`] slot empty (see [`proves_c1`]).
pub(crate) fn total_expected_for(sk_enc_count: usize, e_sm_enc_count: usize) -> usize {
    4 + sk_enc_count + e_sm_enc_count + 2
}

/// Whether an E3 on threshold preset `preset` proves C1. Only the trBFV path does: on the l-BFV
/// path the row proofs bind `sk` and the C2b chunk leaves bound `e_sm`.
pub(crate) fn proves_c1(preset: BfvPreset) -> bool {
    !e3_fhe_params::is_lbfv_path(preset)
}
