// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// C7-CKKS: aggregates T+1 CKKS decryption shares into the plaintext ring
// element `u_global`. The coefficient window is the FULL ring degree
// (`DECRYPTED_SHARES_AGGREGATION_CKKS_N`), not BFV's sparse-message
// `MAX_MSG_NON_ZERO_COEFFS`: CKKS occupies every coefficient, and C6-CKKS
// hashes the same N-wide window into `d_commitment`, so this is what makes
// the C6 -> C7 link hold.
//
// DOMAIN BINDING: `domain_hi`/`domain_lo` are the same two words C6-CKKS
// exposes (the E3 decryption domain: interfold address, committee hash,
// committee pk commitment). They are public inputs so the on-chain
// `CkksDecryptionVerifier` can pin this proof to THIS E3; without them a
// valid C7 proof for one E3 was replayable against any other E3 whose
// committee reconstructed the same `u_global`.

use lib::configs::ckks_aggregation::{
    DECRYPTED_SHARES_AGGREGATION_CKKS_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_CKKS_CONFIGS,
    DECRYPTED_SHARES_AGGREGATION_CKKS_L, DECRYPTED_SHARES_AGGREGATION_CKKS_N,
};
use lib::configs::default::T;
use lib::core::threshold::decrypted_shares_aggregation_ckks::DecryptedSharesAggregationCkks;
use lib::math::polynomial::Polynomial;

fn main(
    expected_d_commitments: pub [Field; T + 1],
    party_ids: pub [Field; T + 1],
    domain_hi: pub Field,
    domain_lo: pub Field,
    decryption_shares: [[Polynomial<DECRYPTED_SHARES_AGGREGATION_CKKS_N>; DECRYPTED_SHARES_AGGREGATION_CKKS_L]; T + 1],
    u_global: pub Polynomial<DECRYPTED_SHARES_AGGREGATION_CKKS_N>,
    crt_quotients: [Polynomial<DECRYPTED_SHARES_AGGREGATION_CKKS_N>; DECRYPTED_SHARES_AGGREGATION_CKKS_L],
) {
    // Domain words are bound by being public inputs the verifier checks
    // against the E3's on-chain decryption domain (same as C6-CKKS).
    let _ = (domain_hi, domain_lo);
    let aggregation: DecryptedSharesAggregationCkks<DECRYPTED_SHARES_AGGREGATION_CKKS_N, DECRYPTED_SHARES_AGGREGATION_CKKS_L, T, DECRYPTED_SHARES_AGGREGATION_CKKS_BIT_D_NATIVE> = DecryptedSharesAggregationCkks::new(
        DECRYPTED_SHARES_AGGREGATION_CKKS_CONFIGS,
        expected_d_commitments,
        decryption_shares,
        party_ids,
        u_global,
        crt_quotients,
    );

    aggregation.execute();
}
