// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Total number of inner proofs (C0..C4) expected before the fold can run:
/// C0, C1, C2a, C2b (4) + C3a (sk) + C3b (esm) + C4a, C4b (2).
pub(crate) fn total_expected_for(sk_enc_count: usize, e_sm_enc_count: usize) -> usize {
    4 + sk_enc_count + e_sm_enc_count + 2
}
