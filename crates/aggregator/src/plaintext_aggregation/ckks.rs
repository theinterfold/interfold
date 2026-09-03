// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS plaintext aggregation: combine t+1 decryption shares and produce
//! the CANONICAL on-chain bytes for `PlaintextAggregated.decrypted_output`.
//!
//! The BFV path routes through a `ComputeRequest` + C6 verification before
//! `format_decrypted_plaintext`. The CKKS seam mirrors the keyshare
//! pattern: this pure function is the whole aggregation step, and the
//! actor branch dispatches to it on `E3Scheme::Ckks` E3s (C6/C7-CKKS proof
//! verification joins the flow when the CKKS proof emission lands —
//! the C7-CKKS circuit itself is already built and nargo-verified).
//!
//! DETERMINISM CONTRACT (the reason this module exists): on-chain bytes
//! must be identical whichever honest t+1 subset reconstructs. Raw CKKS
//! decryption is NOT subset-independent — each subset's smudging noise
//! differs below the precision floor — so the canonical encoding truncates
//! to `CKKS_OUTPUT_DECIMALS` decimal places, which the flooding
//! calculator's precision wall guarantees is noise-free. The test below
//! enforces byte-equality across two different subsets.

use anyhow::{Context as _, Result};
use e3_trckks::program::encode_fixed_point_output;
use e3_trckks::threshold_decryption::{
    calculate_threshold_decryption, CalculateThresholdDecryptionRequest,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;

/// Protocol constant: decimal places of the canonical fixed-point output.
/// Must stay below the flooding calculator's declared `precision_loss`
/// (insecure preset: ~0.3 absolute error >> 1e-6 would violate this; the
/// demo presets therefore declare precision_loss accordingly — see
/// `fhe::trckks::CkksSmudgingBoundCalculator`). A production deployment
/// derives this FROM `precision_loss`: decimals = floor(-log10(loss)).
pub const CKKS_OUTPUT_DECIMALS: u32 = 2;

/// Combine `t+1` decryption shares for one ciphertext output and encode
/// the result canonically for on-chain publication.
///
/// `shares` are `(party_id, share_bytes)` in any order; `ciphertext` is
/// the evaluated E3 output.
pub fn aggregate_ckks_plaintext(
    config: &TrCkksConfig,
    shares: Vec<(u64, ArcBytes)>,
    ciphertext: &ArcBytes,
) -> Result<ArcBytes> {
    // `TRCKKS::decrypt` takes EXACTLY t+1 shares. The collector gathers
    // one from every honest-roster member (N), so pick the t+1 lowest
    // party ids — deterministic, and the truncating fixed-point encoding
    // below makes the on-chain bytes identical for ANY chosen subset.
    let mut shares = shares;
    shares.sort_by_key(|(pid, _)| *pid);
    shares.truncate(config.threshold() as usize + 1);
    let (party_ids, decryption_shares): (Vec<u64>, Vec<ArcBytes>) = shares.into_iter().unzip();
    let response = calculate_threshold_decryption(CalculateThresholdDecryptionRequest {
        trckks_config: config.clone(),
        ciphertext: ciphertext.clone(),
        decryption_shares,
        party_ids,
    })
    .context("CKKS threshold decryption failed")?;
    let bytes = encode_fixed_point_output(&response.values, CKKS_OUTPUT_DECIMALS)
        .context("fixed-point encoding failed")?;
    Ok(ArcBytes::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::config::insecure_512_params;
    use e3_trckks::dkg::{
        aggregate_collected_shares, aggregate_pk_shares, gen_pk_share_and_sk_sss,
        share_poly_to_bytes, GenPkShareAndSkSssRequest,
    };
    use e3_trckks::program::decode_fixed_point_output;
    use e3_trckks::threshold_decryption::{
        calculate_decryption_share, CalculateDecryptionShareRequest,
    };
    use fhe::ckks::CkksEncoder;
    use fhe_traits::Serialize as FheSerialize;
    use rand::RngCore;

    const N: u64 = 5;
    const T: u64 = 2;

    /// The determinism contract: two DIFFERENT t+1 subsets produce
    /// byte-identical on-chain output.
    #[test]
    fn onchain_bytes_are_subset_independent() {
        let params = insecure_512_params().unwrap();
        let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), N, T);
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let mut rng = rand::rng();

        // DKG through the job payloads.
        let responses: Vec<_> = (0..N)
            .map(|_| {
                gen_pk_share_and_sk_sss(
                    &mut rng,
                    GenPkShareAndSkSssRequest {
                        trckks_config: config.clone(),
                        crp_seed: seed,
                        smudging_bits: 20,
                    },
                )
                .unwrap()
            })
            .collect();
        let pk_bytes: Vec<_> = responses.iter().map(|r| r.pk_share.clone()).collect();
        let pk = aggregate_pk_shares(&config, seed, &pk_bytes).unwrap();
        let sk_dealt: Vec<_> = responses.iter().map(|r| r.sk_sss.clone()).collect();
        let es_dealt: Vec<_> = responses.iter().map(|r| r.es_sss.clone()).collect();
        let member_shares: Vec<_> = (0..N as usize)
            .map(|j| {
                let sk = aggregate_collected_shares(&config, &sk_dealt, j).unwrap();
                let es = aggregate_collected_shares(&config, &es_dealt, j).unwrap();
                (share_poly_to_bytes(&sk), share_poly_to_bytes(&es))
            })
            .collect();

        // Encrypt + evaluate (a sum, like a real E3).
        let encoder = CkksEncoder::new(&params);
        let a = pk
            .try_encrypt(&encoder.encode(&[123.45], 0).unwrap(), &mut rng)
            .unwrap();
        let b = pk
            .try_encrypt(&encoder.encode(&[-23.45], 0).unwrap(), &mut rng)
            .unwrap();
        let ct = ArcBytes::from_bytes(&a.try_add(&b).unwrap().to_bytes());

        let share_for = |pid: u64| -> (u64, ArcBytes) {
            let (sk, es) = &member_shares[(pid - 1) as usize];
            let share = calculate_decryption_share(CalculateDecryptionShareRequest {
                name: format!("party-{pid}"),
                trckks_config: config.clone(),
                ciphertext: ct.clone(),
                sk_poly_sum: sk.clone(),
                es_poly_sum: es.clone(),
            })
            .unwrap()
            .decryption_share;
            (pid, share)
        };

        // Two different t+1 subsets.
        let out_a =
            aggregate_ckks_plaintext(&config, vec![share_for(1), share_for(2), share_for(3)], &ct)
                .unwrap();
        let out_b =
            aggregate_ckks_plaintext(&config, vec![share_for(3), share_for(4), share_for(5)], &ct)
                .unwrap();

        assert_eq!(out_a, out_b, "on-chain bytes must be subset-independent");

        // And they decode to the right value.
        let values = decode_fixed_point_output(&out_a, CKKS_OUTPUT_DECIMALS).unwrap();
        assert!((values[0] - 100.0).abs() < 0.01, "decoded {}", values[0]);
    }
}
