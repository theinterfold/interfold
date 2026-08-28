// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS evaluation policies: the computations a Secure Process runs over
//! submitted ciphertexts.
//!
//! These are plain-Rust equivalents of what the RISC Zero guest would
//! execute (guest integration deliberately deferred). Each policy consumes
//! serialized ciphertexts and produces the ciphertext(s) the committee is
//! asked to threshold-decrypt — never more.

use crate::TrCkksConfig;
use anyhow::{bail, Context as _, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksRelinearizationKey};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::Rng;
use serde::{Deserialize, Serialize};

fn decode_cts(config: &TrCkksConfig, cts: &[ArcBytes]) -> Result<Vec<CkksCiphertext>> {
    let params = config.params()?;
    cts.iter()
        .map(|bytes| {
            CkksCiphertext::from_bytes(bytes, &params).context("failed to decode ciphertext")
        })
        .collect()
}

/// Homomorphic sum of all inputs (weighted aggregation base case).
///
/// Output: one ciphertext, `sum_i ct_i`.
pub fn sum_policy(config: &TrCkksConfig, inputs: &[ArcBytes]) -> Result<ArcBytes> {
    let cts = decode_cts(config, inputs)?;
    let (first, rest) = cts
        .split_first()
        .context("sum policy requires at least one input")?;
    let mut acc = first.clone();
    for ct in rest {
        acc = acc.try_add(ct)?;
    }
    Ok(ArcBytes::from_bytes(&acc.to_bytes()))
}

/// Statistics policy: computes the two aggregates needed for mean/variance.
///
/// Output: `(sum, sum_of_squares)` ciphertexts. Requires parameters with at
/// least one multiplication level and the joint relinearization key.
pub fn statistics_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    rlk: &CkksRelinearizationKey,
) -> Result<(ArcBytes, ArcBytes)> {
    let cts = decode_cts(config, inputs)?;
    if cts.is_empty() {
        bail!("statistics policy requires at least one input");
    }

    let mut ct_sum = cts[0].clone();
    for ct in &cts[1..] {
        ct_sum = ct_sum.try_add(ct)?;
    }

    let mut ct_sumsq: Option<CkksCiphertext> = None;
    for ct in &cts {
        let mut sq = ct.try_mul(ct)?;
        rlk.relinearizes(&mut sq)?;
        ct_sumsq = Some(match ct_sumsq {
            None => sq,
            Some(acc) => acc.try_add(&sq)?,
        });
    }
    let mut ct_sumsq = ct_sumsq.context("unreachable: inputs checked non-empty")?;
    ct_sumsq.rescale()?;

    Ok((
        ArcBytes::from_bytes(&ct_sum.to_bytes()),
        ArcBytes::from_bytes(&ct_sumsq.to_bytes()),
    ))
}

/// One masked comparison for the auction policy: `mask * (ct_a - ct_b)` with
/// a fresh uniform mask in `[1, 8)`. The sign of the decryption reveals the
/// ordering; the mask blinds the magnitude.
pub fn masked_difference_policy<R: Rng>(
    config: &TrCkksConfig,
    ct_a: &ArcBytes,
    ct_b: &ArcBytes,
    rng: &mut R,
) -> Result<ArcBytes> {
    let params = config.params()?;
    let encoder = CkksEncoder::new(&params);
    let cts = decode_cts(config, &[ct_a.clone(), ct_b.clone()])?;

    let diff = cts[0].try_sub(&cts[1])?;
    let mask = rng.random_range(1.0f64..8.0);
    let mask_pt = encoder.encode(&[mask], diff.level)?;
    let mut masked = diff.try_mul_plaintext(&mask_pt)?;
    masked.rescale()?;
    Ok(ArcBytes::from_bytes(&masked.to_bytes()))
}

/// Result of the auction policy: the comparison schedule outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionOutcome {
    /// Index of the winning bidder.
    pub winner: usize,
    /// Index of the runner-up (whose bid is the clearing price).
    pub second: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{insecure_512_mul_params, insecure_512_params};
    use crate::dkg::{
        aggregate_collected_shares, aggregate_pk_shares, gen_pk_share_and_sk_sss,
        share_poly_to_bytes, GenPkShareAndSkSssRequest,
    };
    use crate::threshold_decryption::{
        calculate_decryption_share, calculate_threshold_decryption,
        CalculateDecryptionShareRequest, CalculateThresholdDecryptionRequest,
    };
    use fhe::ckks::CkksEncoder;
    use fhe::trckks::{CkksCrp, CkksRelinKeyGenerator, CkksRelinKeyShare, R1Aggregated, R2};
    use fhe_traits::Serialize as FheSerialize;
    use rand::RngCore;
    use std::sync::Arc;

    const N_PARTIES: u64 = 5;
    const THRESHOLD: u64 = 2;
    const SMUDGING_BITS: usize = 20;

    struct Committee {
        config: TrCkksConfig,
        pk: fhe::ckks::CkksPublicKey,
        /// Per party: (sk_share_bytes, es_share_bytes).
        member_shares: Vec<(ArcBytes, ArcBytes)>,
    }

    /// Full serialized DKG: every step passes through the job-payload types,
    /// exactly as the node actors would drive it.
    fn run_dkg(config: &TrCkksConfig, crp_seed: [u8; 32]) -> Committee {
        let mut rng = rand::rng();

        // Dealing round (each member independently).
        let responses: Vec<_> = (0..N_PARTIES)
            .map(|_| {
                gen_pk_share_and_sk_sss(
                    &mut rng,
                    GenPkShareAndSkSssRequest {
                        trckks_config: config.clone(),
                        crp_seed,
                        smudging_bits: SMUDGING_BITS,
                    },
                )
                .unwrap()
            })
            .collect();

        // Public key aggregation (anyone).
        let pk_bytes: Vec<_> = responses.iter().map(|r| r.pk_share.clone()).collect();
        let pk = aggregate_pk_shares(config, crp_seed, &pk_bytes).unwrap();

        // Each member aggregates its received rows.
        let sk_dealt: Vec<_> = responses.iter().map(|r| r.sk_sss.clone()).collect();
        let es_dealt: Vec<_> = responses.iter().map(|r| r.es_sss.clone()).collect();
        let member_shares = (0..N_PARTIES as usize)
            .map(|j| {
                let sk = aggregate_collected_shares(config, &sk_dealt, j).unwrap();
                let es = aggregate_collected_shares(config, &es_dealt, j).unwrap();
                (share_poly_to_bytes(&sk), share_poly_to_bytes(&es))
            })
            .collect();

        Committee {
            config: config.clone(),
            pk,
            member_shares,
        }
    }

    /// Threshold-decrypt via the serialized job payloads.
    fn threshold_open(committee: &Committee, ct_bytes: &ArcBytes) -> Vec<f64> {
        let parties: Vec<u64> = (1..=THRESHOLD + 1).collect();
        let shares: Vec<ArcBytes> = parties
            .iter()
            .map(|&j| {
                let (sk, es) = &committee.member_shares[(j - 1) as usize];
                calculate_decryption_share(CalculateDecryptionShareRequest {
                    name: format!("party-{j}"),
                    trckks_config: committee.config.clone(),
                    ciphertext: ct_bytes.clone(),
                    sk_poly_sum: sk.clone(),
                    es_poly_sum: es.clone(),
                })
                .unwrap()
                .decryption_share
            })
            .collect();

        calculate_threshold_decryption(CalculateThresholdDecryptionRequest {
            trckks_config: committee.config.clone(),
            ciphertext: ct_bytes.clone(),
            decryption_shares: shares,
            party_ids: parties,
        })
        .unwrap()
        .values
    }

    fn encrypt_value(
        committee: &Committee,
        params: &Arc<fhe::ckks::CkksParameters>,
        value: f64,
    ) -> ArcBytes {
        let mut rng = rand::rng();
        let encoder = CkksEncoder::new(params);
        let pt = encoder.encode(&[value], 0).unwrap();
        let ct = committee.pk.try_encrypt(&pt, &mut rng).unwrap();
        ArcBytes::from_bytes(&ct.to_bytes())
    }

    /// E2E: DKG -> encrypt -> sum policy -> threshold decrypt.
    #[test]
    fn e2e_sum_policy() {
        let mut rng = rand::rng();
        let params = insecure_512_params().unwrap();
        let config = TrCkksConfig::new(
            ArcBytes::from_bytes(&params.to_bytes()),
            N_PARTIES,
            THRESHOLD,
        );
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let committee = run_dkg(&config, seed);

        let values = [10.5, -3.25, 7.0];
        let inputs: Vec<ArcBytes> = values
            .iter()
            .map(|v| encrypt_value(&committee, &params, *v))
            .collect();

        let ct_sum = sum_policy(&config, &inputs).unwrap();
        let opened = threshold_open(&committee, &ct_sum);

        let expected: f64 = values.iter().sum();
        assert!(
            (opened[0] - expected).abs() < 0.2,
            "sum: {} vs {expected}",
            opened[0]
        );
    }

    /// E2E: DKG (+ multiparty relin key) -> encrypt -> statistics policy ->
    /// threshold decrypt -> mean/variance.
    #[test]
    fn e2e_statistics_policy() {
        let mut rng = rand::rng();
        let params = insecure_512_mul_params().unwrap();
        let config = TrCkksConfig::new(
            ArcBytes::from_bytes(&params.to_bytes()),
            N_PARTIES,
            THRESHOLD,
        );
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        // Multiparty relin-key CRP and per-member secrets. NOTE: the relin
        // key must be for the SAME joint secret as the pk, so this test
        // builds its committee from explicit member secrets used for both
        // protocols (the lean job API doesn't expose per-member secrets).
        let mut rlk_seed = [0u8; 32];
        rng.fill_bytes(&mut rlk_seed);
        let crp_rlk = CkksCrp::vec_from_seed(&params, rlk_seed, params.moduli().len()).unwrap();
        let sks: Vec<_> = (0..N_PARTIES)
            .map(|_| fhe::ckks::CkksSecretKey::random(&params, &mut rng))
            .collect();
        let crp_pk = CkksCrp::from_seed(&params, seed).unwrap();
        let pk_shares: Vec<_> = sks
            .iter()
            .map(|sk| fhe::trckks::CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng).unwrap())
            .collect();
        let pk = fhe::trckks::CkksPublicKeyShare::aggregate(&pk_shares).unwrap();

        let trckks =
            fhe::trckks::TRCKKS::new(N_PARTIES as usize, THRESHOLD as usize, params.clone())
                .unwrap();
        let mut sk_dealt = Vec::new();
        let mut es_dealt = Vec::new();
        for sk_i in &sks {
            let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref()).unwrap();
            sk_dealt.push(crate::dkg::ShareMatrices::from_arrays(
                &trckks
                    .generate_secret_shares_from_poly(sk_poly, &mut rng)
                    .unwrap(),
            ));
            let es = trckks
                .generate_smudging_error(SMUDGING_BITS, &mut rng)
                .unwrap();
            let es_poly = trckks.smudging_to_poly(&es).unwrap();
            es_dealt.push(crate::dkg::ShareMatrices::from_arrays(
                &trckks
                    .generate_secret_shares_from_poly(es_poly, &mut rng)
                    .unwrap(),
            ));
        }
        let member_shares: Vec<_> = (0..N_PARTIES as usize)
            .map(|j| {
                let sk = aggregate_collected_shares(&config, &sk_dealt, j).unwrap();
                let es = aggregate_collected_shares(&config, &es_dealt, j).unwrap();
                (share_poly_to_bytes(&sk), share_poly_to_bytes(&es))
            })
            .collect();
        let committee = Committee {
            config: config.clone(),
            pk,
            member_shares,
        };

        let generators: Vec<_> = sks
            .iter()
            .map(|sk| CkksRelinKeyGenerator::new(sk, &crp_rlk, &mut rng).unwrap())
            .collect();
        let r1: Vec<_> = generators
            .iter()
            .map(|g| g.round_1(&mut rng).unwrap())
            .collect();
        let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1).unwrap());
        let r2: Vec<_> = generators
            .iter()
            .map(|g| g.round_2(&r1_agg, &mut rng).unwrap())
            .collect();
        let rlk = CkksRelinKeyShare::<R2>::aggregate_into_key(r2).unwrap();

        // Data providers.
        let measurements = [36.6f64, 37.1, 36.8, 37.4, 36.5];
        let inputs: Vec<ArcBytes> = measurements
            .iter()
            .map(|v| encrypt_value(&committee, &params, *v))
            .collect();

        // Policy (the Secure Process computation).
        let (ct_sum, ct_sumsq) = statistics_policy(&config, &inputs, &rlk).unwrap();

        // Committee opens only the aggregates.
        let sum = threshold_open(&committee, &ct_sum)[0];
        let sumsq = threshold_open(&committee, &ct_sumsq)[0];

        let n = measurements.len() as f64;
        let mean = sum / n;
        let variance = sumsq / n - mean * mean;

        let true_mean = measurements.iter().sum::<f64>() / n;
        let true_var = measurements
            .iter()
            .map(|x| (x - true_mean).powi(2))
            .sum::<f64>()
            / n;
        assert!(
            (mean - true_mean).abs() < 0.01,
            "mean {mean} vs {true_mean}"
        );
        assert!(
            (variance - true_var).abs() < 0.1,
            "variance {variance} vs {true_var}"
        );
    }

    /// E2E: DKG -> encrypted bids -> masked-difference tournament ->
    /// threshold decrypt winner price (sealed-bid Vickrey auction).
    #[test]
    fn e2e_auction_policy() {
        let mut rng = rand::rng();
        let params = insecure_512_mul_params().unwrap();
        let config = TrCkksConfig::new(
            ArcBytes::from_bytes(&params.to_bytes()),
            N_PARTIES,
            THRESHOLD,
        );
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let committee = run_dkg(&config, seed);

        let bids = [312.5f64, 875.25, 640.0, 899.99, 405.75];
        let cts: Vec<ArcBytes> = bids
            .iter()
            .map(|b| encrypt_value(&committee, &params, *b))
            .collect();

        // compare(i, j): sign of the threshold-decrypted masked difference.
        let mut compare = |i: usize, j: usize| -> bool {
            let masked = masked_difference_policy(&config, &cts[i], &cts[j], &mut rng).unwrap();
            threshold_open(&committee, &masked)[0] > 0.0
        };

        let mut winner = 0usize;
        let mut candidates = Vec::new();
        for i in 1..bids.len() {
            if compare(i, winner) {
                candidates.push(winner);
                winner = i;
            } else {
                candidates.push(i);
            }
        }
        let mut second = candidates[0];
        for &c in &candidates[1..] {
            if compare(c, second) {
                second = c;
            }
        }

        let clearing_price = threshold_open(&committee, &cts[second])[0];

        let mut sorted = bids.to_vec();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
        assert_eq!(bids[winner], sorted[0], "wrong winner");
        assert!(
            (clearing_price - sorted[1]).abs() < 0.05,
            "clearing price {clearing_price} vs {}",
            sorted[1]
        );

        let outcome = AuctionOutcome { winner, second };
        assert_eq!(outcome.winner, 3);
    }
}
