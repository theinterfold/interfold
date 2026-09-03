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
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksHybridRelinKey, CkksRelinearizationKey};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// The relinearization keys a leveled policy multiplies under: either
/// one RNS-decomposition key PER multiplication level (indexed by level;
/// slots the policy never multiplies at may hold any key) or ONE hybrid
/// key that serves every level (params with special primes). The policy
/// code is identical for both — only [`RelinKeys::relinearize_at`]
/// dispatches.
#[derive(Debug, Clone)]
pub enum RelinKeys {
    /// `keys[level]` relinearizes a 3-component ciphertext at `level`.
    PerLevel(Vec<CkksRelinearizationKey>),
    /// One key for all levels.
    Hybrid(CkksHybridRelinKey),
}

impl RelinKeys {
    /// Relinearize `ct` (3 components) in place at its own level.
    pub fn relinearize_at(&self, ct: &mut CkksCiphertext) -> Result<()> {
        match self {
            RelinKeys::PerLevel(keys) => {
                let key = keys
                    .get(ct.level)
                    .with_context(|| format!("missing relin key for level {}", ct.level))?;
                if key.level() != ct.level {
                    bail!(
                        "relin key slot {} holds a level-{} key",
                        ct.level,
                        key.level()
                    );
                }
                key.relinearizes(ct)?;
            }
            RelinKeys::Hybrid(key) => key.relinearizes(ct)?,
        }
        Ok(())
    }

    /// Whether the keys can relinearize at every level in `0..=max_level`.
    pub fn covers_levels_through(&self, max_level: usize) -> bool {
        match self {
            RelinKeys::PerLevel(keys) => keys.len() > max_level,
            RelinKeys::Hybrid(_) => true,
        }
    }

    /// File name of the ONE joint key a hybrid ceremony writes (mirrors
    /// the ciphernode shell's `HYBRID_RELIN_KEY_FILE`).
    pub const HYBRID_KEY_FILE: &'static str = "rlk_hybrid.bin";

    /// File name of the joint key for `level` (per-level ceremony).
    pub fn level_key_file(level: usize) -> String {
        format!("rlk_level_{level}.bin")
    }

    /// Load the ceremony's joint keys from the directory the ciphernodes
    /// write them to: [`Self::HYBRID_KEY_FILE`] when present (hybrid
    /// params), else `rlk_level_{L}.bin` for every `level` in `levels`,
    /// laid out densely by level (slots the policy never multiplies at
    /// hold a clone of the first loaded key — a wrong-level key errors
    /// loudly if ever used). Hybrid params REQUIRE the hybrid file: a
    /// per-level key set cannot be decoded against them.
    pub fn load_from_dir(
        dir: &std::path::Path,
        params: &std::sync::Arc<fhe::ckks::CkksParameters>,
        levels: &[usize],
    ) -> Result<Self> {
        let hybrid_path = dir.join(Self::HYBRID_KEY_FILE);
        if params.hybrid_enabled() {
            let bytes = std::fs::read(&hybrid_path).with_context(|| {
                format!("missing hybrid ceremony key {}", hybrid_path.display())
            })?;
            return Ok(RelinKeys::Hybrid(CkksHybridRelinKey::from_bytes(
                &bytes, params,
            )?));
        }
        if hybrid_path.exists() {
            bail!(
                "{} exists but the parameters carry no special primes",
                hybrid_path.display()
            );
        }
        let mut loaded: Vec<(usize, CkksRelinearizationKey)> = Vec::with_capacity(levels.len());
        for &level in levels {
            let path = dir.join(Self::level_key_file(level));
            let bytes = std::fs::read(&path)
                .with_context(|| format!("missing ceremony key {}", path.display()))?;
            let key = CkksRelinearizationKey::from_bytes(&bytes, params)?;
            if key.level() != level {
                bail!(
                    "{} holds a level-{} key, expected level {level}",
                    path.display(),
                    key.level()
                );
            }
            loaded.push((level, key));
        }
        let (max_level, filler) = match loaded.first() {
            Some((_, first)) => (
                loaded.iter().map(|(l, _)| *l).max().unwrap_or(0),
                first.clone(),
            ),
            None => bail!("no ceremony levels requested"),
        };
        let mut keys = vec![filler; max_level + 1];
        for (level, key) in loaded {
            keys[level] = key;
        }
        Ok(RelinKeys::PerLevel(keys))
    }
}

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

/// Statistics policy PACKED for the single-opening pipeline: the
/// aggregates land in ONE ciphertext — `sum` in slot 0 and
/// `sum_of_squares` in slot 1 — so the committee threshold-decrypts
/// exactly once (the node pipeline serves one ciphertext output per E3;
/// the smudging share is single-use per ciphertext).
///
/// INPUT CONTRACT: each input is a slot-replicated encryption of the
/// participant's value NORMALIZED by the public cap `K` (the demo
/// encrypts `salary / K`). The opened slots carry `S * sum / K` and
/// `S * sumsq / K^2` where `S` (`output_scale`) is a PUBLIC factor that
/// keeps the aggregates meaningful under the canonical on-chain
/// fixed-point encoding (2 decimals): with S = 10^4 a normalized
/// aggregate ~0.44 opens as ~4400.00 (6+ significant digits). The caller
/// divides by `S` and multiplies back by `K` / `K^2`. Normalization keeps
/// every message ≤ S*n ≈ 2^17, fitting the transport-capped 36-bit limbs
/// of the ParamSet-3 preset.
///
/// The genuine ct×ct squares are relinearized at LEVEL 0 on purpose: the
/// joint (multiparty) relin key's noise is ~n× a single-key one, and the
/// level-0 placement lets the subsequent rescale divide that noise by
/// q2 ≈ 2^36 — relinearizing after rescale (level 1) left the noise
/// visible at the percent level in the variance.
///
/// Layout (3-limb `statistics_transport_params` / on-chain ParamSet 3,
/// delta = 2^40, s = 2^8; joint relin key = level-0 ceremony key):
///
/// ```text
///   sq   = sum_i relin_L0(ct_i * ct_i)               level 0, delta^2
///   out1 = rescale( sq * onehot1(S @ s) )            level 1, delta^2*s/q2
///   out0 = rescale( (sum_i ct_i) * onehot0(S @ delta*s) )
///                                                    level 1, delta^2*s/q2
///   out  = out0 + out1                               (scale-exact, ~2^52)
/// ```
pub fn statistics_packed_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    rlk: &CkksRelinearizationKey,
    output_scale: f64,
) -> Result<ArcBytes> {
    let params = config.params()?;
    if params.moduli().len() < 3 {
        bail!("packed statistics needs at least three moduli (one mult level)");
    }
    if rlk.level() != 0 {
        bail!(
            "packed statistics squares at level 0; got a level-{} relin key",
            rlk.level()
        );
    }
    if !(1.0..=1e6).contains(&output_scale) {
        bail!("output_scale must be in [1, 1e6] (headroom analysis)");
    }
    let encoder = CkksEncoder::new(&params);
    let delta = params.scale();
    // Mask scale s: message*scale = S*n * delta^2*s must stay below
    // Q0 ≈ 2^108 at level 0 and S*n * delta^2*s/q2 below Q1 ≈ 2^72 after
    // the rescale; with delta = 2^40, S ≤ 10^6 and n ≤ 8, s = 2^8 keeps
    // ≥2 bits of headroom. Decoded noise ~ relin_noise*S/delta^2 stays
    // ≤ 1e-5 slot units.
    let s = 2f64.powi(8);
    let cts = decode_cts(config, inputs)?;
    if cts.is_empty() {
        bail!("statistics policy requires at least one input");
    }

    // Sum branch: homomorphic sum, masked into slot 0 (scaled by S).
    let mut ct_sum = cts[0].clone();
    for ct in &cts[1..] {
        ct_sum = ct_sum.try_add(ct)?;
    }
    let mask_sum = encoder.encode_with_scale(&[output_scale], 0, delta * s)?;
    let mut m_sum = ct_sum.try_mul_plaintext(&mask_sum)?;
    m_sum.rescale()?; // level 1, scale delta^2*s/q2

    // Sum-of-squares branch: GENUINE ct×ct squares, relinearized at
    // level 0, summed, then masked into slot 1 (scaled by S).
    let mut ct_sumsq: Option<CkksCiphertext> = None;
    for ct in &cts {
        let mut sq = ct.try_mul(ct)?; // level 0, scale delta^2
        rlk.relinearizes(&mut sq)?;
        ct_sumsq = Some(match ct_sumsq {
            None => sq,
            Some(acc) => acc.try_add(&sq)?,
        });
    }
    let ct_sumsq = ct_sumsq.context("unreachable: inputs checked non-empty")?;
    let mask_sumsq = encoder.encode_with_scale(&[0.0, output_scale], 0, s)?;
    let mut m_sumsq = ct_sumsq.try_mul_plaintext(&mask_sumsq)?;
    m_sumsq.rescale()?; // level 1, scale delta^2*s/q2

    let out = m_sum.try_add(&m_sumsq)?;
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

/// Homomorphic SIGN EXTRACTION over all-pairs auction differences — the
/// leak-eliminating upgrade of `auction_round_policy`.
///
/// Phase 1 (pack, 1 level): all pairwise differences are packed into ONE
/// ciphertext, each normalized into `[-1, 1]` by its one-hot mask:
/// `y = rescale( sum_p onehot_p(1/B) * (ct_a - ct_b) )`.
///
/// Phase 2 (iterate, 3 levels each): the cubic sign map
///
/// ```text
///   f(y) = 1.5*y - 0.5*y^3 = (1.5 - 0.5*y^2) * y
/// ```
///
/// is applied SLOT-WISE to the packed ciphertext — two relinearized
/// ciphertext products per iteration TOTAL (not per pair):
///
/// ```text
///   w = rescale(relin(y * y))                  (ct x ct, level L)
///   u = rescale(w * pt(-0.5))                  (plaintext mul)
///   t = u + pt(1.5 at u.scale)                 (plaintext add)
///   y' = rescale(relin(t * y))                 (ct x ct, level L+2)
/// ```
///
/// Iteration `i` therefore multiplies at levels `1+3i` and `3+3i`;
/// `rlks` must relinearize at every multiplication level: ONE hybrid key
/// ([`RelinKeys::Hybrid`], the ceremony of
/// [`fhe::trckks::CkksHybridRelinKeyGenerator`] — what ParamSet 2 runs)
/// or a per-level key set ([`RelinKeys::PerLevel`],
/// [`fhe::trckks::CkksRelinKeyGenerator::new_leveled`]).
/// `sign_extraction_params(iterations)` builds the matching modulus
/// ladder (one 45-bit base + 40-bit rescale limbs, delta = 2^40, plus
/// the hybrid special primes).
///
/// Convergence: |f(x)| >= 1.49|x| near 0 with fixed points at ±1, so
/// after `k` iterations any gap `>= B * 1.5^-k` has been driven to ±1.
/// With 12 iterations, gaps down to ~2% of the bound decrypt as exactly
/// ±1 (a 1000-unit bound resolves 20-unit gaps); the opened slots carry
/// the comparison BITS and nothing else. Smaller gaps shrink toward 0
/// rather than leaking their magnitude (verified in the e2e test).
pub fn sign_extraction_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    pairs: &[(usize, usize)],
    bound: f64,
    iterations: usize,
    rlks: &RelinKeys,
) -> Result<ArcBytes> {
    if bound <= 0.0 {
        bail!("bid bound must be positive");
    }
    if iterations == 0 {
        bail!("sign extraction needs at least one iteration");
    }
    let params = config.params()?;
    let encoder = CkksEncoder::new(&params);
    let slots = params.degree() / 2;
    if pairs.len() > slots {
        bail!("{} pairs exceed {slots} slots", pairs.len());
    }
    let max_mul_level = 3 * iterations;
    if !rlks.covers_levels_through(max_mul_level) {
        bail!("need relin keys through level {max_mul_level}");
    }
    let delta = params.scale();
    let cts = decode_cts(config, inputs)?;

    // Phase 1: pack normalized differences.
    let mut acc: Option<CkksCiphertext> = None;
    for (p, &(a, b)) in pairs.iter().enumerate() {
        let (ct_a, ct_b) = (
            cts.get(a).context("pair index out of range")?,
            cts.get(b).context("pair index out of range")?,
        );
        let diff = ct_a.try_sub(ct_b)?;
        let mut mask = vec![0.0f64; p + 1];
        mask[p] = 1.0 / bound;
        let masked = diff.try_mul_plaintext(&encoder.encode_with_scale(&mask, 0, delta)?)?;
        acc = Some(match acc {
            None => masked,
            Some(prev) => prev.try_add(&masked)?,
        });
    }
    let mut y = acc.context("policy needs at least one pair")?;
    y.rescale()?;

    // Phase 2: iterate the cubic sign map slot-wise.
    for _ in 0..iterations {
        // w = y^2, relinearized at y's level, rescaled.
        let mut w = y.try_mul(&y)?;
        rlks.relinearize_at(&mut w)
            .context("relinearizing the squaring")?;
        w.rescale()?;

        // u = -0.5 * w (plaintext), rescaled.
        let mut u = w.try_mul_plaintext(&encoder.encode_with_scale(
            &vec![-0.5f64; slots],
            w.level,
            delta,
        )?)?;
        u.rescale()?;

        // t = u + 1.5 encoded at u's exact scale.
        let t = u.try_add_plaintext(&encoder.encode_with_scale(
            &vec![1.5f64; slots],
            u.level,
            u.scale,
        )?)?;

        // y' = t * y (y mod-switched to t's level), relinearized, rescaled.
        let mut y_at_t = y.clone();
        y_at_t.mod_switch_to_level(t.level)?;
        let mut next = t.try_mul(&y_at_t)?;
        rlks.relinearize_at(&mut next)
            .context("relinearizing the update")?;
        next.rescale()?;
        y = next;
    }

    Ok(ArcBytes::from_bytes(&y.to_bytes()))
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

    /// E2E: DKG (+ multiparty relin key at level 1) over the ParamSet-3
    /// statistics transport params -> encrypted salaries -> PACKED
    /// statistics policy (sum/K in slot 0, relinearized sum-of-squares/K^2
    /// in slot 1 of ONE ciphertext) -> ONE threshold opening ->
    /// mean/variance.
    #[test]
    fn e2e_statistics_packed_policy() {
        let mut rng = rand::rng();
        let params = crate::config::statistics_transport_params().unwrap();
        let config = TrCkksConfig::new(
            ArcBytes::from_bytes(&params.to_bytes()),
            N_PARTIES,
            THRESHOLD,
        );
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut rlk_seed = [0u8; 32];
        rng.fill_bytes(&mut rlk_seed);
        // The packed policy squares (and relinearizes) at LEVEL 0.
        let rlk_level = 0usize;
        let crp_len = params.moduli().len() - rlk_level;
        let crp_rlk =
            CkksCrp::vec_from_seed_leveled(&params, rlk_seed, crp_len, rlk_level).unwrap();
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
            .map(|sk| {
                CkksRelinKeyGenerator::new_leveled(sk, &crp_rlk, rlk_level, &mut rng).unwrap()
            })
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

        let salaries = [52000.0f64, 61000.0, 48500.0, 75000.0, 58000.0];
        let cap = 200000.0f64;
        // SLOT-REPLICATED and NORMALIZED by the public cap, like the
        // demo's `ckks_encrypt --normalizer`: the packed policy's one-hot
        // masks pick lanes, and normalization keeps messages ≤ 1.
        let slots = params.degree() / 2;
        let encoder = CkksEncoder::new(&params);
        let inputs: Vec<ArcBytes> = salaries
            .iter()
            .map(|v| {
                let pt = encoder.encode(&vec![*v / cap; slots], 0).unwrap();
                let ct = committee.pk.try_encrypt(&pt, &mut rng).unwrap();
                ArcBytes::from_bytes(&ct.to_bytes())
            })
            .collect();

        let ct_out = statistics_packed_policy(&config, &inputs, &rlk, 10_000.0).unwrap();
        let opened = threshold_open(&committee, &ct_out);

        let n = salaries.len() as f64;
        // Opened slots carry S*sum/K and S*sumsq/K^2: decode back.
        let (sum, sumsq) = (opened[0] / 10_000.0 * cap, opened[1] / 10_000.0 * cap * cap);
        let mean = sum / n;
        let variance = sumsq / n - mean * mean;

        let true_mean = salaries.iter().sum::<f64>() / n;
        let true_var = salaries
            .iter()
            .map(|x| (x - true_mean).powi(2))
            .sum::<f64>()
            / n;
        assert!(
            (mean - true_mean).abs() / true_mean < 0.001,
            "mean {mean} vs {true_mean}"
        );
        assert!(
            (variance - true_var).abs() / true_var < 0.01,
            "variance {variance} vs {true_var}"
        );
    }

    /// E2E: DKG (+ ONE two-round HYBRID relin ceremony, through the wire
    /// framing) -> slot-replicated encrypted bids -> ITERATED sign
    /// extraction (all pairs, one ciphertext, 12 cubic rounds through the
    /// rescale ladder, every relinearization under the SAME key) -> ONE
    /// threshold opening -> BINARY signs. Asserts every comparison bit is
    /// correct AND every opened magnitude is saturated (>= 0.95), i.e.
    /// the output leaks the order and nothing about the gaps.
    #[test]
    fn e2e_sign_extraction_policy() {
        use fhe::trckks::{CkksHybridRelinKeyGenerator, CkksHybridRelinKeyShare, R1};
        let mut rng = rand::rng();
        const ITERATIONS: usize = 12;
        let params = crate::config::sign_extraction_params(ITERATIONS).unwrap();
        assert!(params.hybrid_enabled(), "the ladder carries special primes");
        let config = TrCkksConfig::new(
            ArcBytes::from_bytes(&params.to_bytes()),
            N_PARTIES,
            THRESHOLD,
        );
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
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

        // ONE multiparty hybrid ceremony (wire round-trip on every
        // message, exactly as the ciphernodes exchange them).
        let mut rlk_seed = [0u8; 32];
        rng.fill_bytes(&mut rlk_seed);
        let crp = CkksCrp::vec_from_seed_qp(&params, rlk_seed).unwrap();
        let generators: Vec<_> = sks
            .iter()
            .map(|sk| CkksHybridRelinKeyGenerator::new(sk, &crp, &mut rng).unwrap())
            .collect();
        let r1: Vec<_> = generators
            .iter()
            .map(|g| {
                let bytes = g.round_1(&mut rng).unwrap().to_bytes();
                CkksHybridRelinKeyShare::<R1>::from_bytes(&bytes, &params).unwrap()
            })
            .collect();
        let r1_agg = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(r1).unwrap());
        let r2: Vec<_> = generators
            .iter()
            .map(|g| {
                let bytes = g.round_2(&r1_agg, &mut rng).unwrap().to_bytes();
                CkksHybridRelinKeyShare::<R2>::from_bytes(&bytes, &params).unwrap()
            })
            .collect();
        let key_bytes = CkksHybridRelinKeyShare::<R2>::aggregate_into_key_with_r1(r2, r1_agg)
            .unwrap()
            .to_bytes();
        let rlks = RelinKeys::Hybrid(
            fhe::ckks::CkksHybridRelinKey::from_bytes(&key_bytes, &params).unwrap(),
        );
        assert_eq!(params.dnum(), 13);

        // Bidders: slot-replicated encryptions; includes a 2% gap
        // (402 vs 382) that the mask policy would leak and the sign map
        // must still binarize.
        let bids = [220.5f64, 815.0, 74.25, 402.0, 382.0];
        let bound = 1000.0;
        let slots = params.degree() / 2;
        let encoder = CkksEncoder::new(&params);
        let inputs: Vec<ArcBytes> = bids
            .iter()
            .map(|b| {
                let ct = committee
                    .pk
                    .try_encrypt(&encoder.encode(&vec![*b; slots], 0).unwrap(), &mut rng)
                    .unwrap();
                ArcBytes::from_bytes(&ct.to_bytes())
            })
            .collect();

        let pairs: Vec<(usize, usize)> = (0..bids.len())
            .flat_map(|i| ((i + 1)..bids.len()).map(move |j| (i, j)))
            .collect();
        let out =
            sign_extraction_policy(&config, &inputs, &pairs, bound, ITERATIONS, &rlks).unwrap();
        let opened = threshold_open(&committee, &out);

        for (p, &(a, b)) in pairs.iter().enumerate() {
            let expected = bids[a] > bids[b];
            assert_eq!(
                opened[p] > 0.0,
                expected,
                "pair {p} ({a},{b}): opened {} bids {} vs {}",
                opened[p],
                bids[a],
                bids[b]
            );
            // BINARIZED: saturated magnitude regardless of gap size.
            assert!(
                (opened[p].abs() - 1.0).abs() < 0.05,
                "pair {p} not binarized: {} (gap {})",
                opened[p],
                (bids[a] - bids[b]).abs()
            );
        }
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
