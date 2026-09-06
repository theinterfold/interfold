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

/// Number of features one credit applicant submits.
pub const CREDIT_FEATURES: usize = 8;

/// Coefficient stride between applicants in the packed credit output:
/// applicant `i`'s masked score is coefficient `CREDIT_APPLICANT_STRIDE * i`.
/// One applicant's product `X_i · V` occupies the 15 coefficients
/// `s_i − 7 ..= s_i + 7` (`X` has 8 taps at `t^1..t^8`, `V` has 8 taps), so
/// a stride of 16 keeps the applicants' footprints DISJOINT — no
/// applicant's masked cross terms ever land on another's score.
pub const CREDIT_APPLICANT_STRIDE: usize = 16;

/// Exclusive upper bound of every per-feature additive mask `μ_j`:
/// `μ_j ∈ [0, CREDIT_MASK_BOUND)` uniform, drawn by the APPLICANT. With
/// features in `[0, 1]` the opened masked feature `x_j + μ_j` reveals
/// `x_j` only at the range edges (statistical distance `≤ 1/1024` per
/// feature). Coordinate with the encryption/app-validity circuits: each
/// masked feature coefficient is `x_j + μ_j` with `x_j ∈ [0, 1]` and
/// `μ_j ∈ [0, 2^10)`, i.e. the coefficient is in `[0, 1025]`.
pub const CREDIT_MASK_BOUND: f64 = 1024.0;

/// Sup-norm bound the policy enforces on the public weights and bias
/// (wrap-around analysis in [`credit_linear_logit_policy`]).
pub const CREDIT_WEIGHT_BOUND: f64 = 8.0;

/// Maximum number of applicants one packed credit output can hold
/// (`N / CREDIT_APPLICANT_STRIDE`).
pub fn credit_max_applicants(params: &fhe::ckks::CkksParameters) -> usize {
    params.degree() / CREDIT_APPLICANT_STRIDE
}

/// The plaintext COEFFICIENT vector an applicant encrypts (client side):
/// coefficient `j + 1` holds the masked feature `x_j + μ_j`, coefficient
/// `0` is unused (0), everything above coefficient 8 is 0. Encode it with
/// `CkksEncoder::encode_coefficients(&coeffs, 0, params.scale())`.
pub fn credit_applicant_coefficients(
    features: &[f64; CREDIT_FEATURES],
    masks: &[f64; CREDIT_FEATURES],
) -> Result<Vec<f64>> {
    let mut coeffs = vec![0.0f64; CREDIT_FEATURES + 1];
    for j in 0..CREDIT_FEATURES {
        if !(0.0..=1.0).contains(&features[j]) {
            bail!("feature {j} = {} is outside [0, 1]", features[j]);
        }
        if !(0.0..CREDIT_MASK_BOUND).contains(&masks[j]) {
            bail!(
                "mask {j} = {} is outside [0, {CREDIT_MASK_BOUND})",
                masks[j]
            );
        }
        coeffs[j + 1] = features[j] + masks[j];
    }
    Ok(coeffs)
}

/// Coefficients of the weight plaintext for the applicant at coefficient
/// offset `shift`: `V_shift(t) = −t^shift · Σ_j w_j t^{N−j−1} mod (t^N + 1)`.
/// For the applicant polynomial `X(t) = Σ_j (x_j + μ_j) t^{j+1}` the
/// product `X · V_shift` has coefficient `shift` equal to `⟨w, x + μ⟩`
/// (each `t^{j+1}` meets `t^{N−j−1}` at `t^N ≡ −1`; the leading minus
/// cancels the sign).
pub fn credit_weight_coefficients(
    weights: &[f64; CREDIT_FEATURES],
    degree: usize,
    shift: usize,
) -> Result<Vec<f64>> {
    if shift >= degree {
        bail!("shift {shift} is outside the ring degree {degree}");
    }
    let mut coeffs = vec![0.0f64; degree];
    for (j, w) in weights.iter().enumerate() {
        let mut e = shift + degree - j - 1;
        let mut c = -w;
        if e >= degree {
            e -= degree;
            c = -c;
        }
        coeffs[e] += c;
    }
    Ok(coeffs)
}

/// The applicant's own unmasking step: the opened coefficient
/// `CREDIT_APPLICANT_STRIDE * i` minus `⟨w, μ_i⟩` is the linear score
/// `z = ⟨w, x_i⟩ + b`; the credit probability is the logistic `σ(z)`,
/// applied CLIENT-SIDE (public, monotone — the committee's job is only
/// the private weighted sum).
pub fn credit_unmask(
    opened: f64,
    weights: &[f64; CREDIT_FEATURES],
    masks: &[f64; CREDIT_FEATURES],
) -> f64 {
    opened - weights.iter().zip(masks).map(|(w, m)| w * m).sum::<f64>()
}

/// The exact logistic function the applicant applies to the unmasked
/// linear score.
pub fn logistic(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// Read the packed credit output's applicant coefficients from a decrypted
/// plaintext: `out[i] = coefficient CREDIT_APPLICANT_STRIDE * i` (the
/// masked linear score of applicant `i`). The aggregation path for
/// ParamSet 4 must decode COEFFICIENTS (this function), never slots.
pub fn credit_scores_from_plaintext(
    params: &std::sync::Arc<fhe::ckks::CkksParameters>,
    pt: &fhe::ckks::CkksPlaintext,
    applicants: usize,
) -> Result<Vec<f64>> {
    if applicants == 0 {
        bail!("no applicants");
    }
    let encoder = CkksEncoder::new(params);
    let count = CREDIT_APPLICANT_STRIDE * (applicants - 1) + 1;
    let coeffs = encoder.decode_coefficients(pt, count)?;
    Ok((0..applicants)
        .map(|i| coeffs[CREDIT_APPLICANT_STRIDE * i])
        .collect())
}

/// LINEAR credit LOGIT over COEFFICIENT-encoded applicant ciphertexts
/// (the v1 credit variant, kept as a tested library policy; the shipped
/// credit app runs [`credit_sigmoid_policy`]) — rotation-free (fhe.rs CKKS has no Galois keys),
/// relinearization-free (ciphertext × plaintext only, ONE level), and
/// packed: every applicant's masked score lands in a distinct coefficient
/// of the ONE output ciphertext the committee threshold-decrypts.
///
/// The committee runs NO app logic. This variant needs NO relin-key
/// ceremony (ciphertext × plaintext only) — which is exactly why it is
/// no longer the showcase: BFV would serve it equally well. It is NOT
/// what ParamSet 4 runs any more (its plan is `PerLevel([1, 2])` for the
/// sigmoid policy); it stays here, tested on the same params, as the
/// ceremony-free reference point. Its opened output is COEFFICIENT
/// encoded, so callers decode it with [`credit_scores_from_plaintext`],
/// never through the ParamSet-4 slot layout of the node pipeline.
///
/// # Layout and algebra (client ⇄ program contract)
///
/// Applicant `i` encrypts (coefficient encoding, scale `Δ`, level 0)
///
/// ```text
///   X_i(t) = Σ_{j<8} (x_{i,j} + μ_{i,j}) · t^{j+1}
/// ```
///
/// with features `x_{i,j} ∈ [0, 1]` and PER-FEATURE masks
/// `μ_{i,j} ∈ [0, CREDIT_MASK_BOUND)` drawn and kept by the applicant
/// ([`credit_applicant_coefficients`]). The program builds, for applicant
/// offset `s_i = CREDIT_APPLICANT_STRIDE · i`, the plaintext
///
/// ```text
///   V_i(t) = −t^{s_i} · Σ_{j<8} w_j · t^{N−j−1}     (mod t^N + 1)
/// ```
///
/// ([`credit_weight_coefficients`]) and evaluates
///
/// ```text
///   out = rescale( Σ_i ct(X_i) × pt(V_i) ) + pt( Σ_i b · t^{s_i} )
/// ```
///
/// In `X_i · V_i` the term `(x_j + μ_j) t^{j+1} · (−w_j t^{s_i+N−j−1})`
/// is `−w_j (x_j + μ_j) t^{s_i+N} = +w_j (x_j + μ_j) t^{s_i}`, so
///
/// ```text
///   out[s_i] = ⟨w, x_i⟩ + ⟨w, μ_i⟩ + b
/// ```
///
/// and the applicant recovers `z_i = out[s_i] − ⟨w, μ_i⟩`
/// ([`credit_unmask`]) then `σ(z_i)` ([`logistic`]) locally. Every other
/// coefficient of `X_i · V_i` (`s_i + k`, `k ∈ ±1..7`) is
/// `Σ_{j'−j=k} ±w_j (x_{i,j'} + μ_{i,j'})` — a public linear function of
/// the MASKED features only, hence leak-free up to the mask range edges.
///
/// # Why per-feature masks (and not one mask in coefficient 0)
///
/// Multiplication by a fixed non-zero `W` is a BIJECTION of
/// `Q[t]/(t^N + 1)` (`t^N + 1` is irreducible over `Q` for `N` a power of
/// two, so the quotient is a field). Hence `t^a W` lies in the span of
/// `{t^p W : p ∈ S}` iff `a ∈ S`: the mask polynomial's support must
/// CONTAIN the feature support `{1..8}` for the opened product to be
/// independent of the features. A single mask `m` at `t^0` (or anywhere
/// outside `{1..8}`) leaves the 15 coefficients of `x · W` — 15 public
/// linear equations in 8 unknowns — bare in the opening, and any identity
/// term (`ct × pt(1)`) exposes the raw features at `t^{j+1}`. Per-feature
/// additive masks are therefore the only rotation-free, relin-free
/// leak-free layout.
///
/// # Magnitudes (ParamSet 4: 36-bit limbs, `Δ = 2^40`)
///
/// Client coefficient `≤ 1025 · Δ < 2^51` (i64 encoder cap 2^63); level-0
/// product coefficient `≤ 8 · 8 · 1025 · Δ² < 2^96 ≪ Q_0/2 ≈ 2^143`
/// (`|w_j| ≤ CREDIT_WEIGHT_BOUND`); the opening at level 1 has scale
/// `Δ²/q_top ≈ 2^44`, so the 20-bit demo smudging noise decodes to
/// `≈ 2^-22` and the bias plaintext `b · 2^44` fits i64 exactly.
pub fn credit_linear_logit_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    weights: &[f64; CREDIT_FEATURES],
    bias: f64,
) -> Result<ArcBytes> {
    let params = config.params()?;
    if params.moduli().len() < 2 {
        bail!("credit scoring needs at least two moduli (one rescale)");
    }
    if inputs.is_empty() {
        bail!("credit scoring needs at least one applicant");
    }
    let max_applicants = credit_max_applicants(&params);
    if inputs.len() > max_applicants {
        bail!(
            "{} applicants exceed the {max_applicants} coefficient slots of one output",
            inputs.len()
        );
    }
    for (j, w) in weights.iter().enumerate() {
        if !w.is_finite() || w.abs() > CREDIT_WEIGHT_BOUND {
            bail!("weight {j} = {w} outside [-{CREDIT_WEIGHT_BOUND}, {CREDIT_WEIGHT_BOUND}]");
        }
    }
    if !bias.is_finite() || bias.abs() > CREDIT_WEIGHT_BOUND {
        bail!("bias {bias} outside [-{CREDIT_WEIGHT_BOUND}, {CREDIT_WEIGHT_BOUND}]");
    }
    let encoder = CkksEncoder::new(&params);
    let delta = params.scale();
    let degree = params.degree();
    let cts = decode_cts(config, inputs)?;

    let mut acc: Option<CkksCiphertext> = None;
    for (i, ct) in cts.iter().enumerate() {
        if ct.level != 0 {
            bail!(
                "applicant {i} ciphertext is at level {}, expected 0",
                ct.level
            );
        }
        let shift = CREDIT_APPLICANT_STRIDE * i;
        let v = encoder.encode_coefficients(
            &credit_weight_coefficients(weights, degree, shift)?,
            0,
            delta,
        )?;
        let prod = ct.try_mul_plaintext(&v)?;
        acc = Some(match acc {
            None => prod,
            Some(prev) => prev.try_add(&prod)?,
        });
    }
    let mut out = acc.context("unreachable: inputs checked non-empty")?;
    out.rescale()?;

    // Bias at every applicant's coefficient, encoded at the rescaled
    // ciphertext's EXACT scale (plaintext addition requires it).
    let mut bias_coeffs = vec![0.0f64; CREDIT_APPLICANT_STRIDE * (cts.len() - 1) + 1];
    for i in 0..cts.len() {
        bias_coeffs[CREDIT_APPLICANT_STRIDE * i] = bias;
    }
    let bias_pt = encoder.encode_coefficients(&bias_coeffs, out.level, out.scale)?;
    let out = out.try_add_plaintext(&bias_pt)?;
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

// ---------------------------------------------------------------------
// Credit v2: homomorphic sigmoid over SLOT-packed logits.
// ---------------------------------------------------------------------

/// Exclusive upper bound of the applicant's OUTPUT mask `m_i` in credit
/// v2: `m_i ∈ [0, CREDIT_OUTPUT_MASK_BOUND)` uniform with 2^-10
/// granularity, drawn by the applicant and encrypted in slot `i` of its
/// mask ciphertext. The opened slot is `σ(z_i) + m_i ∈ [0, 1025)`: to
/// everyone but applicant `i` it is a uniform-looking number (the score
/// lives in `[0, 1]`, the mask range is 1024 wide).
pub const CREDIT_OUTPUT_MASK_BOUND: f64 = 1024.0;

/// Sup-norm bound on the public-model logit an applicant may submit
/// (`|w_j| ≤ CREDIT_WEIGHT_BOUND`, `x_j ∈ [0, 1]`, `|b| ≤ 8` ⇒
/// `|z| ≤ 72`). The policy's wrap analysis uses this ceiling.
pub const CREDIT_LOGIT_BOUND: f64 = 72.0;

/// Coefficients of the odd-cubic logistic approximation the program
/// evaluates homomorphically: `σ(z) ≈ 0.5 + c1·z + c3·z³`. Least-squares
/// fit on `[-4, 4]` (max error 5.1e-2 there, 3.9e-2 on `[-3, 3]`); the
/// polynomial is monotone for `|z| < 4.05` and turns back beyond, so a
/// logit outside `[-4, 4]` recovers a saturated value on the wrong side —
/// the caveat every polynomial sigmoid in HE inference carries. The
/// client displays `σ_cubic`, and the demo's public model keeps `|z| ≤ 4`.
pub const CREDIT_SIGMOID_C1: f64 = 0.197;
/// See [`CREDIT_SIGMOID_C1`].
pub const CREDIT_SIGMOID_C3: f64 = -0.004;

/// The cubic logistic approximation the network evaluates
/// (`0.5 + 0.197·z − 0.004·z³`) — the applicant's oracle for what the
/// unmasked slot should read.
pub fn sigmoid_cubic(z: f64) -> f64 {
    0.5 + CREDIT_SIGMOID_C1 * z + CREDIT_SIGMOID_C3 * z * z * z
}

/// Maximum applicants one credit-v2 round can hold: one SLOT per
/// applicant (`N / 2`).
pub fn credit_v2_max_applicants(params: &fhe::ckks::CkksParameters) -> usize {
    params.slots()
}

/// The slot vector applicant `index` encrypts for one value: `value` in
/// slot `index`, every other slot 0 — the layout the credit-v2 validity
/// leg proves for BOTH the logit ciphertext (`value = z_i`) and the mask
/// ciphertext (`value = m_i`). Encode it with `CkksEncoder::encode(&v, 0)`.
pub fn credit_slot_vector(value: f64, index: usize, slots: usize) -> Result<Vec<f64>> {
    if index >= slots {
        bail!("applicant index {index} is outside the {slots} slots");
    }
    let mut v = vec![0.0f64; index + 1];
    v[index] = value;
    Ok(v)
}

/// The applicant's own recovery in credit v2: opened slot `i` minus the
/// output mask `m_i` is the network-computed `σ_cubic(z_i)`.
pub fn credit_v2_unmask(opened: f64, mask: f64) -> f64 {
    opened - mask
}

/// Credit v2: the network computes the LOGISTIC of every applicant's
/// public-model logit HOMOMORPHICALLY, slot-wise, and adds the
/// applicant's own output mask — ONE packed output ciphertext for the
/// committee to threshold-decrypt, in which slot `i` is
/// `σ_cubic(z_i) + m_i`. The logit `z_i` is never in any opened value,
/// and only applicant `i` (holding `m_i`) can read `σ(z_i)`.
///
/// The committee runs NO app logic: this function is called by the E3
/// PROGRAM (and the `ckks_credit_eval` binary); ciphernodes run the DKG,
/// the per-level relin-key ceremony at levels 1 and 2
/// (`RelinCeremonyPlan::PerLevel([1, 2])` for ParamSet 4), and one
/// threshold decryption. The two ciphertext × ciphertext products are
/// the reason this app is CKKS with a ceremony rather than BFV.
///
/// # Input contract (client ⇄ validity leg ⇄ program)
///
/// `inputs` holds TWO ciphertexts per applicant, in submission order:
/// `[ct_z_0, ct_m_0, ct_z_1, ct_m_1, ...]`. Applicant `i` (assigned slot
/// index `i` on-chain) encrypts, slot-encoded at level 0 / scale Δ:
///
/// ```text
///   ct_z,i : slot i = z_i = ⟨w, x_i⟩ + b   (the PUBLIC model's logit the
///            applicant computes over its Merkle-attested features;
///            |z_i| ≤ CREDIT_LOGIT_BOUND), every other slot 0
///   ct_m,i : slot i = m_i ∈ [0, CREDIT_OUTPUT_MASK_BOUND), other slots 0
/// ```
///
/// ([`credit_slot_vector`]). The validity leg proves both layouts: the
/// logit equals the affine function of the attested features under the
/// round's registered weights, the mask is in range, all other slots 0.
///
/// # Algebra (slot-wise; no rotations — applicants pack themselves by
/// choosing disjoint slots)
///
/// With `r_ℓ` the modulus dropped by the rescale out of level `ℓ`
/// (every plaintext constant is slot-REPLICATED via `encode_constant`,
/// so each product scales every slot pointwise):
///
/// ```text
///   Z    = Σ_i ct_z,i                            L0, Δ            slot i = z_i
///   M    = Σ_i ct_m,i                            L0, Δ            slot i = m_i
///   Z1   = rescale(Z × pt(1 @r0))                L1, Δ            z, aligned
///   W    = rescale(relin_L1(Z1 × Z1))            L2, Δ²/r1        z²
///   Zc   = rescale(rescale(Z × pt(c3 @Δ)) × pt(1 @r1))
///                                                L2, Δ²/r0        c3·z
///   C    = rescale(relin_L2(W × Zc))             L3, Δ⁴/(r0 r1 r2) c3·z³
///   Lin  = Z × pt(c1 @Δ) → rescale → × pt(1 @r1) → rescale
///          → × pt(1 @Δ²/r1) → rescale           L3, Δ⁴/(r0 r1 r2) c1·z
///   Mo   = M through the same three steps (c = 1)
///                                                L3, same scale    m
///   out  = C + Lin + Mo + pt(0.5 @ out.scale)    L3
/// ```
///
/// The plaintext scales are chosen so every branch reaches level 3 at
/// the SAME scale `Δ⁴/(r0 r1 r2) ≈ 2^52` — `try_add` /
/// `try_add_plaintext` refuse mismatched scales. Two ct×ct products
/// (relinearized with the level-1 and level-2 multiparty keys), three
/// rescales, output at level 3 with two limbs.
///
/// Empty slots: an unused slot opens as `σ_cubic(0) + 0 = 0.5` —
/// harmless (no applicant, no mask, no information).
///
/// # Magnitudes (ParamSet 4: 5 × 36-bit limbs, Δ = 2^40)
///
/// Inputs `|z| ≤ 72`, `m < 1024` encode below 2^50. `Z1 × Z1` at level
/// 1: `z² ≤ 2^13` at scale 2^80 → 2^93 ≪ Q_1/2 ≈ 2^143. `W × Zc` at
/// level 2: `|c3·z³| ≤ 1493 < 2^11` at scale 2^88 → 2^99 < Q_2/2 ≈ 2^107.
/// Output at level 3: `|σ + m| < 1025` at scale 2^52 → 2^62 < Q_3/2 ≈
/// 2^71. The multiparty relin noise (~2^51 per product) is divided by
/// the following rescale (2^36) and lands ≈ 2^-29 below one unit at the
/// 2^44 intermediate scale; the 20-bit demo smudging noise decodes to
/// ≈ 2^-32.
pub fn credit_sigmoid_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    rlks: &RelinKeys,
) -> Result<ArcBytes> {
    let params = config.params()?;
    if params.moduli().len() < 4 {
        bail!("credit v2 needs at least four moduli (three rescales)");
    }
    if inputs.is_empty() || !inputs.len().is_multiple_of(2) {
        bail!(
            "credit v2 takes (logit, mask) ciphertext PAIRS per applicant; got {} inputs",
            inputs.len()
        );
    }
    let applicants = inputs.len() / 2;
    let max_applicants = credit_v2_max_applicants(&params);
    if applicants > max_applicants {
        bail!("{applicants} applicants exceed the {max_applicants} slots of one output");
    }
    if !rlks.covers_levels_through(2) {
        bail!("credit v2 needs relin keys for levels 1 and 2");
    }
    let encoder = CkksEncoder::new(&params);
    let delta = params.scale();
    let cts = decode_cts(config, inputs)?;
    for (i, ct) in cts.iter().enumerate() {
        if ct.level != 0 || ct.len() != 2 {
            bail!(
                "input {i} must be a fresh level-0 ciphertext (level {}, {} components)",
                ct.level,
                ct.len()
            );
        }
    }

    // Pack: Z = Σ logits, M = Σ masks (disjoint slots by construction).
    let mut z: Option<CkksCiphertext> = None;
    let mut m: Option<CkksCiphertext> = None;
    for pair in cts.chunks_exact(2) {
        z = Some(match z {
            None => pair[0].clone(),
            Some(acc) => acc.try_add(&pair[0])?,
        });
        m = Some(match m {
            None => pair[1].clone(),
            Some(acc) => acc.try_add(&pair[1])?,
        });
    }
    let z = z.context("unreachable: inputs checked non-empty")?;
    let m = m.context("unreachable: inputs checked non-empty")?;

    // The modulus dropped by the rescale out of `level`.
    let dropped = |level: usize| -> Result<f64> {
        let ctx = params.context_at_level(level)?;
        Ok(*ctx.moduli().last().context("empty chain")? as f64)
    };
    let (r0, r1) = (dropped(0)?, dropped(1)?);

    // (ct × replicated constant `c` at plaintext scale `s`) then rescale.
    let scaled_step = |ct: &CkksCiphertext, c: f64, s: f64| -> Result<CkksCiphertext> {
        let mut out = ct.try_mul_plaintext(&encoder.encode_constant(c, ct.level, s)?)?;
        out.rescale()?;
        Ok(out)
    };
    let step = |ct: &CkksCiphertext, c: f64| scaled_step(ct, c, delta);

    // z aligned to level 1 at scale Δ (pt scale r0 cancels the rescale).
    let z1 = scaled_step(&z, 1.0, r0)?;
    // z² at level 2 (scale Δ²/r1), relinearized with the LEVEL-1 key.
    let mut w = z1.try_mul(&z1)?;
    rlks.relinearize_at(&mut w)
        .context("relinearizing z² (level-1 key)")?;
    w.rescale()?;

    // c3·z at level 2 (scale Δ²/r0), then c3·z³ at level 3 under the
    // LEVEL-2 key (scale Δ⁴/(r0 r1 r2)).
    let zc = scaled_step(&step(&z, CREDIT_SIGMOID_C3)?, 1.0, r1)?;
    let mut cubic = w.try_mul(&zc)?;
    rlks.relinearize_at(&mut cubic)
        .context("relinearizing z³ (level-2 key)")?;
    cubic.rescale()?;

    // Linear and mask branches: three plaintext steps at scales
    // (Δ, r1, Δ²/r1) bring a level-0 ciphertext at scale Δ to exactly
    // the cubic branch's Δ⁴/(r0 r1 r2) at level 3.
    let bridge = |ct: &CkksCiphertext, c: f64| -> Result<CkksCiphertext> {
        let a = step(ct, c)?;
        let b = scaled_step(&a, 1.0, r1)?;
        scaled_step(&b, 1.0, delta * delta / r1)
    };
    let lin = bridge(&z, CREDIT_SIGMOID_C1)?;
    let mask = bridge(&m, 1.0)?;

    let out = cubic.try_add(&lin)?.try_add(&mask)?;
    let half = encoder.encode_constant(0.5, out.level, out.scale)?;
    let out = out.try_add_plaintext(&half)?;
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

// ---------------------------------------------------------------------------
// ParamSet 5: COEFFICIENT-encoded inner products (matching / treasury /
// federated averaging). One ct×ct product under the level-0 relin key,
// one rescale, opened at level 1.
//
// Encoding contract (shared with the app validity circuits — pin BOTH sides):
//
//   forward(a)  = Σ_{j<k} a_j · t^{j+1}                  (coefficients 1..k)
//   reversed(b) = Σ_{j<k} b_j · t^{N−j−1}                (coefficients N−k..N−1)
//
//   forward(a) · reversed(b) ≡ −⟨a,b⟩ · t^0 + (cross terms on t^1..t^{N−1})
//
// because a_j t^{j+1} · b_j t^{N−j−1} = a_j b_j t^N = −a_j b_j (t^N ≡ −1 in
// Z[t]/(t^N+1)), and every UNMATCHED pair lands on a non-zero coefficient.
// The cross terms are linear equations in the private inputs, so they are
// never opened bare: each party also encrypts a uniform MASK polynomial
// (coefficients 1..COEFFICIENT_MASK_WIDTH, values in [0, COEFFICIENT_MASK_BOUND))
// that the policy ADDS to the product before the opening. Only coefficient 0
// (and, for federated averaging, the block 0..d) carries signal; the
// aggregator publishes exactly `COEFFICIENT_OUTPUT_COUNT` leading
// coefficients (`program::OutputLayout::Coefficients`).
//
// Why the network does the product: neither party may learn the other's
// vector, and the score itself must not be computable from anything
// published — with the product done homomorphically, ONLY the opened
// inner product ever exists in the clear. (Doing it client-side would
// require one party to hold both vectors.)
// ---------------------------------------------------------------------------

/// Vector length every ParamSet-5 app packs (coefficients `1..=k` forward,
/// `N−k..N−1` reversed). Bounded so the cross-term block never reaches the
/// block the mask must cover: `2k < N`.
pub const COEFFICIENT_VECTOR_LEN: usize = 64;
/// Cross-term mask: uniform in `[0, COEFFICIENT_MASK_BOUND)` on coefficients
/// `1..=COEFFICIENT_MASK_WIDTH`. `2^10` is the DEMO hiding ratio (matches
/// the credit app); a production deployment sizes it statistically.
pub const COEFFICIENT_MASK_BOUND: f64 = 1024.0;
/// Coefficients the mask covers: everything the product can touch except 0.
pub const COEFFICIENT_MASK_WIDTH: usize = 2 * COEFFICIENT_VECTOR_LEN;

/// Check that a ParamSet-5 input is a fresh level-0, two-component
/// ciphertext (the contract every coefficient policy relies on).
fn expect_fresh(ct: &CkksCiphertext, what: &str) -> Result<()> {
    if ct.level != 0 || ct.len() != 2 {
        bail!(
            "{what} must be a fresh level-0 ciphertext (level {}, {} components)",
            ct.level,
            ct.len()
        );
    }
    Ok(())
}

/// Sum a non-empty list of ciphertexts.
fn sum_cts(cts: &[CkksCiphertext], what: &str) -> Result<CkksCiphertext> {
    let mut acc: Option<CkksCiphertext> = None;
    for ct in cts {
        acc = Some(match acc {
            None => ct.clone(),
            Some(a) => a.try_add(ct)?,
        });
    }
    acc.ok_or_else(|| anyhow::anyhow!("{what}: no inputs"))
}

/// Shared core of the three coefficient policies: `relin_L0(F · R) + M`,
/// rescaled once. `f` is a FORWARD-encoded operand, `r` a REVERSED one, `m`
/// the summed mask ciphertext (level 0, scale Δ — it is brought to the
/// product's level/scale by one plaintext step).
fn coefficient_product_masked(
    config: &TrCkksConfig,
    f: &CkksCiphertext,
    r: &CkksCiphertext,
    m: &CkksCiphertext,
    rlk: &CkksRelinearizationKey,
) -> Result<CkksCiphertext> {
    let params = config.params()?;
    if params.moduli().len() < 3 {
        bail!("coefficient policies need at least three moduli (one mult level)");
    }
    if rlk.level() != 0 {
        bail!(
            "coefficient policies multiply at level 0; got a level-{} relin key",
            rlk.level()
        );
    }
    let encoder = CkksEncoder::new(&params);
    let delta = params.scale();

    // F · R at level 0 (scale Δ²), relinearised, then ONE rescale → level 1.
    let mut prod = f.try_mul(r)?;
    rlk.relinearizes(&mut prod)?;
    prod.rescale()?;

    // Bring the mask (level 0, scale Δ) to the same level and scale:
    // multiply by the constant 1 encoded at scale Δ and rescale — the
    // exact same step the product took.
    let one = encoder.encode_constant(1.0, m.level, delta)?;
    let mut mask = m.try_mul_plaintext(&one)?;
    mask.rescale()?;

    prod.try_add(&mask).context("adding the cross-term mask")
}

/// Private matching score (two parties).
///
/// `inputs = [f_a, r_b, m_a, m_b]`: A's vector FORWARD-encoded, B's
/// REVERSED-encoded, and both parties' cross-term masks. Output coefficient
/// 0 = `−⟨a, b⟩` (the sign is the `t^N ≡ −1` wrap; the app negates).
/// Coefficients `1..` are cross terms + masks and carry no usable signal.
pub fn matching_score_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    rlk: &CkksRelinearizationKey,
) -> Result<ArcBytes> {
    if inputs.len() != 4 {
        bail!(
            "matching takes [forward_a, reversed_b, mask_a, mask_b]; got {} inputs",
            inputs.len()
        );
    }
    let cts = decode_cts(config, inputs)?;
    for (ct, what) in cts
        .iter()
        .zip(["forward_a", "reversed_b", "mask_a", "mask_b"])
    {
        expect_fresh(ct, what)?;
    }
    let m = cts[2].try_add(&cts[3])?;
    let out = coefficient_product_masked(config, &cts[0], &cts[1], &m, rlk)?;
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

/// Treasury risk (n DAOs, one scalar).
///
/// Each DAO `i` submits `(f_i, r_i, m_i)`: its exposure vector `x_i`
/// FORWARD-encoded, the SAME vector weighted by the public risk weights
/// `w ∘ x_i` REVERSED-encoded (the validity circuit proves this relation),
/// and a cross-term mask. The policy aggregates FIRST — `F = Σ f_i`,
/// `R = Σ r_i` — and multiplies once, so coefficient 0 of the output is
/// `−Σ_a w_a · (Σ_i x_{i,a})²`: the weighted variance-like risk of the
/// AGGREGATE book. No DAO's book, and not even the aggregate book, is
/// ever opened — only the one risk number.
pub fn treasury_risk_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    rlk: &CkksRelinearizationKey,
) -> Result<ArcBytes> {
    if inputs.is_empty() || inputs.len() % 3 != 0 {
        bail!(
            "treasury risk takes (forward, reversed, mask) triples; got {} inputs",
            inputs.len()
        );
    }
    let cts = decode_cts(config, inputs)?;
    let mut fs = Vec::new();
    let mut rs = Vec::new();
    let mut ms = Vec::new();
    for (i, triple) in cts.chunks(3).enumerate() {
        expect_fresh(&triple[0], &format!("dao {i} forward"))?;
        expect_fresh(&triple[1], &format!("dao {i} reversed"))?;
        expect_fresh(&triple[2], &format!("dao {i} mask"))?;
        fs.push(triple[0].clone());
        rs.push(triple[1].clone());
        ms.push(triple[2].clone());
    }
    let f = sum_cts(&fs, "treasury forward")?;
    let r = sum_cts(&rs, "treasury reversed")?;
    let m = sum_cts(&ms, "treasury masks")?;
    let out = coefficient_product_masked(config, &f, &r, &m, rlk)?;
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

/// Federated averaging (n clients, private sample counts).
///
/// Each client `i` submits `(g_i, c_i)`: its gradient vector `g` on
/// coefficients `1..=d` with the constant `1` on coefficient `d+1`
/// (FORWARD layout shifted by nothing — see below), and its sample count
/// `n_i` as a CONSTANT polynomial (coefficient 0 only). The policy computes
/// `Σ_i n_i · G_i` — a genuine ct×ct product per client, since `n_i` is
/// private — and the sum. Because `c_i` has ONLY coefficient 0, the
/// product is an exact scalar multiple: coefficient `j` of the output is
/// `Σ_i n_i · g_{i,j}` for `j ∈ 1..=d` and coefficient `d+1` is `Σ_i n_i`.
/// The app divides to get the weighted mean. No masks are needed: there
/// are no cross terms (scalar × vector), and only aggregates are opened.
///
/// `d` must be ≤ [`COEFFICIENT_VECTOR_LEN`] so the whole block lands inside
/// the published [`crate::program::COEFFICIENT_OUTPUT_COUNT`] coefficients
/// (`d + 2 ≤ 64` ⇒ `d ≤ 62`).
pub fn federated_average_policy(
    config: &TrCkksConfig,
    inputs: &[ArcBytes],
    rlk: &CkksRelinearizationKey,
) -> Result<ArcBytes> {
    if inputs.is_empty() || inputs.len() % 2 != 0 {
        bail!(
            "federated averaging takes (gradient, count) pairs; got {} inputs",
            inputs.len()
        );
    }
    if rlk.level() != 0 {
        bail!(
            "federated averaging multiplies at level 0; got a level-{} relin key",
            rlk.level()
        );
    }
    let cts = decode_cts(config, inputs)?;
    let mut acc: Option<CkksCiphertext> = None;
    for (i, pair) in cts.chunks(2).enumerate() {
        expect_fresh(&pair[0], &format!("client {i} gradient"))?;
        expect_fresh(&pair[1], &format!("client {i} count"))?;
        let mut weighted = pair[0].try_mul(&pair[1])?;
        rlk.relinearizes(&mut weighted)?;
        acc = Some(match acc {
            None => weighted,
            Some(a) => a.try_add(&weighted)?,
        });
    }
    let mut out = acc.ok_or_else(|| anyhow::anyhow!("federated averaging: no inputs"))?;
    out.rescale()?;
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

/// Client-side helpers for the ParamSet-5 layouts (shared by the apps'
/// plaintext builders, the validity-circuit witness generators and the
/// policy tests — ONE definition of the encoding).
pub mod coefficient_layout {
    use super::{COEFFICIENT_MASK_WIDTH, COEFFICIENT_VECTOR_LEN};

    /// `Σ_j a_j t^{j+1}` as a length-`n` coefficient vector.
    pub fn forward(a: &[f64], n: usize) -> Vec<f64> {
        assert!(a.len() <= COEFFICIENT_VECTOR_LEN, "vector too long");
        let mut c = vec![0.0; n];
        for (j, v) in a.iter().enumerate() {
            c[j + 1] = *v;
        }
        c
    }

    /// `Σ_j b_j t^{N−j−1}` as a length-`n` coefficient vector.
    pub fn reversed(b: &[f64], n: usize) -> Vec<f64> {
        assert!(b.len() <= COEFFICIENT_VECTOR_LEN, "vector too long");
        let mut c = vec![0.0; n];
        for (j, v) in b.iter().enumerate() {
            c[n - j - 1] = *v;
        }
        c
    }

    /// Cross-term mask: `mask[j]` on coefficient `j` for `j ∈ 1..=width`,
    /// zero elsewhere (coefficient 0 is NEVER masked — it is the result).
    pub fn mask(values: &[f64], n: usize) -> Vec<f64> {
        assert!(values.len() <= COEFFICIENT_MASK_WIDTH, "mask too wide");
        let mut c = vec![0.0; n];
        for (j, v) in values.iter().enumerate() {
            c[j + 1] = *v;
        }
        c
    }

    /// Federated-averaging gradient block: `g` on `1..=d`, `1.0` on `d+1`.
    pub fn gradient_block(g: &[f64], n: usize) -> Vec<f64> {
        assert!(g.len() + 2 <= super::super::program::COEFFICIENT_OUTPUT_COUNT);
        let mut c = vec![0.0; n];
        for (j, v) in g.iter().enumerate() {
            c[j + 1] = *v;
        }
        c[g.len() + 1] = 1.0;
        c
    }

    /// Sample count as a constant polynomial (coefficient 0 only).
    pub fn constant(v: f64, n: usize) -> Vec<f64> {
        let mut c = vec![0.0; n];
        c[0] = v;
        c
    }
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

    // -----------------------------------------------------------------
    // ParamSet 5 (coefficient inner products) e2e tests.
    // -----------------------------------------------------------------

    /// Committee with a LEVEL-0 per-level relin key for the given params
    /// (the ParamSet-3/5 shape). Mirrors the inline setup of
    /// `e2e_statistics_packed_policy`.
    fn committee_with_level0_rlk(
        params: &Arc<fhe::ckks::CkksParameters>,
    ) -> (TrCkksConfig, Committee, CkksRelinearizationKey) {
        let mut rng = rand::rng();
        let config = TrCkksConfig::new(
            ArcBytes::from_bytes(&params.to_bytes()),
            N_PARTIES,
            THRESHOLD,
        );
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut rlk_seed = [0u8; 32];
        rng.fill_bytes(&mut rlk_seed);
        let rlk_level = 0usize;
        let crp_len = params.moduli().len() - rlk_level;
        let crp_rlk = CkksCrp::vec_from_seed_leveled(params, rlk_seed, crp_len, rlk_level).unwrap();
        let sks: Vec<_> = (0..N_PARTIES)
            .map(|_| fhe::ckks::CkksSecretKey::random(params, &mut rng))
            .collect();
        let crp_pk = CkksCrp::from_seed(params, seed).unwrap();
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
        (config, committee, rlk)
    }

    /// Encrypt a full coefficient vector (length N) at level 0, scale Δ.
    fn encrypt_coefficients(
        committee: &Committee,
        params: &Arc<fhe::ckks::CkksParameters>,
        coeffs: &[f64],
    ) -> ArcBytes {
        let mut rng = rand::rng();
        let encoder = CkksEncoder::new(params);
        let pt = encoder
            .encode_coefficients(coeffs, 0, params.scale())
            .unwrap();
        let ct = committee.pk.try_encrypt(&pt, &mut rng).unwrap();
        ArcBytes::from_bytes(&ct.to_bytes())
    }

    fn uniform_mask(rng: &mut impl Rng, width: usize) -> Vec<f64> {
        (0..width)
            .map(|_| rng.random_range(0.0..COEFFICIENT_MASK_BOUND).floor())
            .collect()
    }

    /// E2E: matching — A forward, B reversed, both masked; ONE ct×ct under
    /// the level-0 ceremony key; the opening's coefficient 0 is −⟨a,b⟩ to
    /// 1e-3 and every other published coefficient is mask-dominated (the
    /// cross terms are not recoverable from the output).
    #[test]
    fn e2e_matching_score_policy() {
        let mut rng = rand::rng();
        let params = crate::config::coefficient_transport_params().unwrap();
        let (config, committee, rlk) = committee_with_level0_rlk(&params);
        let n = params.degree();

        let a: Vec<f64> = (0..16).map(|_| rng.random_range(-1.0..1.0)).collect();
        let b: Vec<f64> = (0..16).map(|_| rng.random_range(-1.0..1.0)).collect();
        let expected: f64 = a.iter().zip(&b).map(|(x, y)| x * y).sum();

        let m_a = uniform_mask(&mut rng, COEFFICIENT_MASK_WIDTH);
        let m_b = uniform_mask(&mut rng, COEFFICIENT_MASK_WIDTH);
        let inputs = vec![
            encrypt_coefficients(&committee, &params, &coefficient_layout::forward(&a, n)),
            encrypt_coefficients(&committee, &params, &coefficient_layout::reversed(&b, n)),
            encrypt_coefficients(&committee, &params, &coefficient_layout::mask(&m_a, n)),
            encrypt_coefficients(&committee, &params, &coefficient_layout::mask(&m_b, n)),
        ];

        let ct_out = matching_score_policy(&config, &inputs, &rlk).unwrap();
        let opened = threshold_open(&committee, &ct_out);
        assert_eq!(
            opened.len(),
            crate::program::COEFFICIENT_OUTPUT_COUNT,
            "ParamSet 5 publishes exactly the leading coefficient block"
        );
        let score = -opened[0];
        assert!(
            (score - expected).abs() < 1e-3,
            "matching score {score} vs {expected}"
        );
        // Cross terms are hidden: with |a|,|b| ≤ 1 the bare cross term on
        // coefficient j has magnitude ≤ 16, the mask sum is ≥ 0 and
        // uniform in [0, 2048). Check the published values are NOT the
        // bare cross terms (they differ by the mask, which is ≥ 16 with
        // overwhelming probability across 32 coefficients).
        let mut hidden = 0usize;
        for (j, v) in opened.iter().enumerate().skip(1).take(32) {
            let bare_bound = 16.0;
            if v.abs() > bare_bound {
                hidden += 1;
            }
            let _ = j;
        }
        assert!(
            hidden >= 28,
            "only {hidden}/32 cross terms were mask-dominated"
        );
    }

    /// E2E: treasury risk — three DAOs, four assets, public risk weights.
    /// Aggregate FIRST, multiply once; coefficient 0 is
    /// −Σ_a w_a (Σ_i x_{i,a})² to 1e-3.
    #[test]
    fn e2e_treasury_risk_policy() {
        let mut rng = rand::rng();
        let params = crate::config::coefficient_transport_params().unwrap();
        let (config, committee, rlk) = committee_with_level0_rlk(&params);
        let n = params.degree();

        let w = [0.30f64, 0.10, 0.45, 0.15]; // public risk weights
        let books: Vec<Vec<f64>> = (0..3)
            .map(|_| (0..4).map(|_| rng.random_range(0.0..0.3)).collect())
            .collect();
        let agg: Vec<f64> = (0..4).map(|a| books.iter().map(|x| x[a]).sum()).collect();
        let expected: f64 = agg.iter().zip(&w).map(|(x, wa)| wa * x * x).sum();

        let mut inputs = Vec::new();
        for x in &books {
            let wx: Vec<f64> = x.iter().zip(&w).map(|(v, wa)| v * wa).collect();
            let m = uniform_mask(&mut rng, COEFFICIENT_MASK_WIDTH);
            inputs.push(encrypt_coefficients(
                &committee,
                &params,
                &coefficient_layout::forward(x, n),
            ));
            inputs.push(encrypt_coefficients(
                &committee,
                &params,
                &coefficient_layout::reversed(&wx, n),
            ));
            inputs.push(encrypt_coefficients(
                &committee,
                &params,
                &coefficient_layout::mask(&m, n),
            ));
        }

        let ct_out = treasury_risk_policy(&config, &inputs, &rlk).unwrap();
        let opened = threshold_open(&committee, &ct_out);
        let risk = -opened[0];
        assert!(
            (risk - expected).abs() < 1e-3,
            "treasury risk {risk} vs {expected}"
        );
    }

    /// E2E: federated averaging — four clients, d = 8 gradient entries,
    /// PRIVATE sample counts; ct×ct per client; opened block is
    /// [Σ n_i g_i (1..=d), Σ n_i (d+1)]; the weighted mean matches 1e-3.
    #[test]
    fn e2e_federated_average_policy() {
        let mut rng = rand::rng();
        let params = crate::config::coefficient_transport_params().unwrap();
        let (config, committee, rlk) = committee_with_level0_rlk(&params);
        let n = params.degree();
        let d = 8usize;

        let grads: Vec<Vec<f64>> = (0..4)
            .map(|_| (0..d).map(|_| rng.random_range(-1.0..1.0)).collect())
            .collect();
        let counts = [37.0f64, 120.0, 5.0, 64.0];
        let total: f64 = counts.iter().sum();
        let expected: Vec<f64> = (0..d)
            .map(|j| {
                grads
                    .iter()
                    .zip(&counts)
                    .map(|(g, c)| g[j] * c)
                    .sum::<f64>()
                    / total
            })
            .collect();

        let mut inputs = Vec::new();
        for (g, c) in grads.iter().zip(&counts) {
            inputs.push(encrypt_coefficients(
                &committee,
                &params,
                &coefficient_layout::gradient_block(g, n),
            ));
            inputs.push(encrypt_coefficients(
                &committee,
                &params,
                &coefficient_layout::constant(*c, n),
            ));
        }

        let ct_out = federated_average_policy(&config, &inputs, &rlk).unwrap();
        let opened = threshold_open(&committee, &ct_out);
        let opened_total = opened[d + 1];
        assert!(
            (opened_total - total).abs() < 1e-2,
            "Σ n_i {opened_total} vs {total}"
        );
        for j in 0..d {
            let mean_j = opened[j + 1] / opened_total;
            assert!(
                (mean_j - expected[j]).abs() < 1e-3,
                "weighted mean[{j}] {mean_j} vs {}",
                expected[j]
            );
        }
        // Coefficient 0 carries nothing (no cross terms: scalar × vector).
        assert!(
            opened[0].abs() < 1e-2,
            "coefficient 0 should be ~0, got {}",
            opened[0]
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

    /// Coefficient-encoded LINEAR credit logit (the v1 library policy)
    /// over the ParamSet-4 credit params: random features and per-feature
    /// masks for several applicants, ONE packed output, decrypted (single
    /// key — the algebra check) and read as COEFFICIENTS. Asserts (a) every applicant's coefficient is
    /// `⟨w, x_i + μ_i⟩ + b` within 1e-4, (b) unmasking yields the linear
    /// score and `σ` of it, (c) the opened values are NOT close to the
    /// true scores (mask range dominates), and (d) the applicant
    /// footprints are disjoint (a non-zero applicant's cross terms never
    /// touch coefficient 0).
    #[test]
    fn credit_linear_logit_policy_coefficient_algebra() {
        use fhe::ckks::{CkksPublicKey, CkksSecretKey};
        let mut rng = rand::rng();
        let params = crate::config::credit_transport_params().unwrap();
        let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), 3, 1);
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();

        let weights = [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2];
        let bias = -0.8;
        let applicants = 5;
        let mut features = Vec::new();
        let mut masks = Vec::new();
        let mut inputs = Vec::new();
        for _ in 0..applicants {
            let x: [f64; CREDIT_FEATURES] = std::array::from_fn(|_| rng.random_range(0.0f64..=1.0));
            let mu: [f64; CREDIT_FEATURES] =
                std::array::from_fn(|_| rng.random_range(0.0f64..CREDIT_MASK_BOUND));
            let coeffs = credit_applicant_coefficients(&x, &mu).unwrap();
            let pt = encoder
                .encode_coefficients(&coeffs, 0, params.scale())
                .unwrap();
            let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
            inputs.push(ArcBytes::from_bytes(&ct.to_bytes()));
            features.push(x);
            masks.push(mu);
        }

        let out = credit_linear_logit_policy(&config, &inputs, &weights, bias).unwrap();
        let out_ct = CkksCiphertext::from_bytes(&out, &params).unwrap();
        assert_eq!(out_ct.level, 1, "one rescale");
        assert_eq!(out_ct.len(), 2, "no ct×ct, nothing to relinearize");
        let pt = sk.try_decrypt(&out_ct).unwrap();
        let opened = credit_scores_from_plaintext(&params, &pt, applicants).unwrap();

        for i in 0..applicants {
            let dot =
                |v: &[f64; CREDIT_FEATURES]| weights.iter().zip(v).map(|(w, a)| w * a).sum::<f64>();
            let expected_masked = dot(&features[i]) + dot(&masks[i]) + bias;
            assert!(
                (opened[i] - expected_masked).abs() < 1e-4,
                "applicant {i}: opened {} vs {expected_masked}",
                opened[i]
            );
            let z = credit_unmask(opened[i], &weights, &masks[i]);
            let true_z = dot(&features[i]) + bias;
            assert!(
                (z - true_z).abs() < 1e-4,
                "applicant {i}: z {z} vs {true_z}"
            );
            assert!((logistic(z) - logistic(true_z)).abs() < 1e-4);
            // The opening alone says nothing about the score: masks of up
            // to 1024 per feature dominate a score in [-8, 8].
            assert!(
                (opened[i] - true_z).abs() > 0.5,
                "applicant {i}: masked value {} too close to the score {true_z}",
                opened[i]
            );
        }

        // Rejections: out-of-range inputs and too many applicants.
        assert!(credit_applicant_coefficients(&[1.5; 8], &[0.0; 8]).is_err());
        assert!(credit_applicant_coefficients(&[0.5; 8], &[CREDIT_MASK_BOUND; 8]).is_err());
        assert!(credit_linear_logit_policy(&config, &inputs, &[9.0; 8], bias).is_err());
        assert!(credit_linear_logit_policy(&config, &[], &weights, bias).is_err());
        let too_many: Vec<_> =
            std::iter::repeat_n(inputs[0].clone(), credit_max_applicants(&params) + 1).collect();
        assert!(credit_linear_logit_policy(&config, &too_many, &weights, bias).is_err());
    }

    /// Credit v2 algebra, single key: three applicants in slots 0/1/2
    /// encrypt (logit, mask) pairs; the policy's cubic-sigmoid output
    /// (two relinearized ct×ct products under level-1 and level-2 keys)
    /// decrypts so that slot i − m_i = σ_cubic(z_i) within 1e-3, empty
    /// slots read 0.5, the raw opened slots sit far from every score, and
    /// malformed inputs are refused.
    #[test]
    fn credit_sigmoid_policy_slot_algebra() {
        use fhe::ckks::{CkksPublicKey, CkksRelinearizationKey, CkksSecretKey};
        let mut rng = rand::rng();
        let params = crate::config::credit_transport_params().unwrap();
        let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), 3, 1);
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();
        let rlk1 = CkksRelinearizationKey::new_leveled(&sk, 1, &mut rng).unwrap();
        let rlk2 = CkksRelinearizationKey::new_leveled(&sk, 2, &mut rng).unwrap();
        let rlks = RelinKeys::PerLevel(vec![rlk1.clone(), rlk1, rlk2]);
        let slots = params.slots();

        let logits = [-3.2f64, 0.4, 2.9];
        let masks = [517.25f64, 3.0, 1023.5];
        let mut inputs = Vec::new();
        for (i, (z, m)) in logits.iter().zip(&masks).enumerate() {
            for v in [*z, *m] {
                let pt = encoder
                    .encode(&credit_slot_vector(v, i, slots).unwrap(), 0)
                    .unwrap();
                let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
                inputs.push(ArcBytes::from_bytes(&ct.to_bytes()));
            }
        }
        let out = credit_sigmoid_policy(&config, &inputs, &rlks).unwrap();
        let out_ct = CkksCiphertext::from_bytes(&out, &params).unwrap();
        assert_eq!(out_ct.level, 3, "three rescales");
        assert_eq!(out_ct.len(), 2, "relinearized");
        let opened = encoder.decode(&sk.try_decrypt(&out_ct).unwrap()).unwrap();
        for (i, (z, m)) in logits.iter().zip(&masks).enumerate() {
            let want = sigmoid_cubic(*z);
            let got = credit_v2_unmask(opened[i], *m);
            assert!(
                (got - want).abs() < 1e-3,
                "slot {i}: unmasked {got} vs σ_cubic({z}) = {want}"
            );
            assert!(
                (want - logistic(*z)).abs() < 0.06,
                "cubic approximation drifted: {want} vs {}",
                logistic(*z)
            );
            // The raw slot is not close to any applicant's score.
            for zz in &logits {
                assert!((opened[i] - sigmoid_cubic(*zz)).abs() > 0.5);
            }
        }
        // Unused slot: σ_cubic(0) + 0 = 0.5.
        assert!((opened[3] - 0.5).abs() < 1e-3, "empty slot {}", opened[3]);

        // Rejections: odd input count, no inputs, missing keys, bad slot.
        assert!(credit_sigmoid_policy(&config, &inputs[..3], &rlks).is_err());
        assert!(credit_sigmoid_policy(&config, &[], &rlks).is_err());
        let no_keys = RelinKeys::PerLevel(vec![]);
        assert!(credit_sigmoid_policy(&config, &inputs, &no_keys).is_err());
        assert!(credit_slot_vector(1.0, slots, slots).is_err());
    }

    /// E2E credit v2 through the serialized job payloads: DKG + TWO
    /// per-level multiparty relin ceremonies (levels 1 and 2, wire
    /// round-trip) → three applicants' (logit, mask) slot pairs → the
    /// sigmoid policy → ONE threshold opening → each applicant unmasks
    /// σ_cubic(z_i) within 1e-2.
    #[test]
    fn e2e_credit_sigmoid_policy() {
        let mut rng = rand::rng();
        let params = crate::config::credit_transport_params().unwrap();
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

        // Per-level ceremonies at the levels the policy multiplies at.
        let levels = e3_fhe_params::ckks_presets::CREDIT_RELIN_LEVELS;
        let mut keys: Vec<Option<fhe::ckks::CkksRelinearizationKey>> = vec![None; 3];
        for &level in &levels {
            let mut rlk_seed = [0u8; 32];
            rng.fill_bytes(&mut rlk_seed);
            let crp_len = params.moduli().len() - level;
            let crp = CkksCrp::vec_from_seed_leveled(&params, rlk_seed, crp_len, level).unwrap();
            let generators: Vec<_> = sks
                .iter()
                .map(|sk| CkksRelinKeyGenerator::new_leveled(sk, &crp, level, &mut rng).unwrap())
                .collect();
            let r1: Vec<_> = generators
                .iter()
                .map(|g| {
                    let bytes = g.round_1(&mut rng).unwrap().to_bytes();
                    CkksRelinKeyShare::<fhe::trckks::R1>::from_bytes(&bytes, &params).unwrap()
                })
                .collect();
            let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1).unwrap());
            let r2: Vec<_> = generators
                .iter()
                .map(|g| {
                    let bytes = g.round_2(&r1_agg, &mut rng).unwrap().to_bytes();
                    CkksRelinKeyShare::<R2>::from_bytes(&bytes, &params).unwrap()
                })
                .collect();
            let key_bytes = CkksRelinKeyShare::<R2>::aggregate_into_key_with_r1(r2, r1_agg)
                .unwrap()
                .to_bytes();
            let key = fhe::ckks::CkksRelinearizationKey::from_bytes(&key_bytes, &params).unwrap();
            assert_eq!(key.level(), level);
            keys[level] = Some(key);
        }
        let filler = keys[1].clone().unwrap();
        let rlks = RelinKeys::PerLevel(
            keys.into_iter()
                .map(|k| k.unwrap_or_else(|| filler.clone()))
                .collect(),
        );

        // Applicants: slot i holds (z_i, m_i).
        let weights = [1.7f64, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2];
        let bias = -0.8f64;
        let slots = params.slots();
        let encoder = CkksEncoder::new(&params);
        let applicants = 3usize;
        let mut logits = Vec::new();
        let mut masks = Vec::new();
        let mut inputs = Vec::new();
        for i in 0..applicants {
            let x: [f64; CREDIT_FEATURES] = std::array::from_fn(|_| rng.random_range(0.0f64..=1.0));
            let z: f64 = weights.iter().zip(&x).map(|(w, a)| w * a).sum::<f64>() + bias;
            let mask = (rng.random_range(0u32..(1 << 20)) as f64) / 1024.0;
            for v in [z, mask] {
                let pt = encoder
                    .encode(&credit_slot_vector(v, i, slots).unwrap(), 0)
                    .unwrap();
                let ct = committee.pk.try_encrypt(&pt, &mut rng).unwrap();
                inputs.push(ArcBytes::from_bytes(&ct.to_bytes()));
            }
            logits.push(z);
            masks.push(mask);
        }

        let out = credit_sigmoid_policy(&config, &inputs, &rlks).unwrap();
        let opened = threshold_open(&committee, &out);
        for i in 0..applicants {
            let got = credit_v2_unmask(opened[i], masks[i]);
            let want = sigmoid_cubic(logits[i]);
            assert!(
                (got - want).abs() < 1e-2,
                "applicant {i}: {got} vs σ_cubic({}) = {want}",
                logits[i]
            );
        }
        assert!((opened[applicants] - 0.5).abs() < 1e-2);
    }

    /// The weight plaintext's algebra, checked on PLAINTEXTS: for
    /// applicant offset `shift`, `X · V_shift` has coefficient `shift`
    /// equal to `⟨w, x⟩` and its other non-zero coefficients stay inside
    /// `shift − 7 ..= shift + 7` (wrapping to the top of the ring for
    /// shift 0), i.e. one stride away from the next applicant's slot.
    #[test]
    fn credit_weight_plaintext_footprint() {
        let n = 512usize;
        let weights = [0.5, -1.0, 0.25, 2.0, -0.75, 1.5, 0.0, -0.125];
        let x = [0.1, 0.9, 0.3, 0.7, 0.5, 0.2, 0.8, 0.6];
        let mut xc = vec![0.0; n];
        for (j, v) in x.iter().enumerate() {
            xc[j + 1] = *v;
        }
        // Negacyclic schoolbook product.
        let mul = |a: &[f64], b: &[f64]| {
            let mut out = vec![0.0; n];
            for (i, ai) in a.iter().enumerate() {
                if *ai == 0.0 {
                    continue;
                }
                for (j, bj) in b.iter().enumerate() {
                    if *bj == 0.0 {
                        continue;
                    }
                    let e = i + j;
                    if e >= n {
                        out[e - n] -= ai * bj;
                    } else {
                        out[e] += ai * bj;
                    }
                }
            }
            out
        };
        let dot: f64 = weights.iter().zip(x).map(|(w, v)| w * v).sum();
        for i in 0..(n / CREDIT_APPLICANT_STRIDE) {
            let shift = CREDIT_APPLICANT_STRIDE * i;
            let v = credit_weight_coefficients(&weights, n, shift).unwrap();
            let prod = mul(&xc, &v);
            assert!((prod[shift] - dot).abs() < 1e-9, "shift {shift}");
            for (k, c) in prod.iter().enumerate() {
                if *c == 0.0 {
                    continue;
                }
                let dist = ((k as isize - shift as isize).rem_euclid(n as isize))
                    .min((shift as isize - k as isize).rem_euclid(n as isize));
                assert!(
                    dist <= 7,
                    "shift {shift}: coefficient {k} is outside the footprint"
                );
            }
        }
        assert!(credit_weight_coefficients(&weights, n, n).is_err());
    }
}
