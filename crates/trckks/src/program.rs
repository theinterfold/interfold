// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The sealed-bid auction as an E3 PROGRAM: slot-batched bracket rounds
//! that fit the one-request-one-decrypt E3 lifecycle, plus the canonical
//! fixed-point result encoding the on-chain path publishes.
//!
//! ## Fitting the tournament into E3 rounds
//!
//! The naive tournament needs ~2(k-1) sequential threshold openings — one
//! per comparison — which does not fit a lifecycle where each E3 request
//! ends in ONE decryption. The batching trick (no rotation keys needed):
//!
//! For a bracket round with pairs `(a_p, b_p)`, build
//!
//! ```text
//!   round_ct = Σ_p  onehot_p ⊙ ( r_p · (ct_{a_p} − ct_{b_p}) )
//! ```
//!
//! where `onehot_p` is the PLAINTEXT slot indicator for slot `p` and `r_p`
//! a fresh positive mask. REQUIREMENT: bids must be encrypted REPLICATED
//! across all slots (`encode(&[bid; N/2])`) — plaintext multiplication is
//! slot-wise, and with a slot-0-only encoding the one-hot would extract an
//! empty slot. Replication is the standard rotation-free packing trick and
//! needs no Galois keys. Replication is NOT checkable homomorphically, so
//! the E3 program must enforce it at submission time (e.g. via the
//! encryption proof's message-replication constraint).
//! With replication, `onehot_p ⊙ diff` places the pair's masked
//! difference in slot `p` and zeroes the rest, so the sum packs the WHOLE
//! ROUND into one ciphertext. ONE threshold opening reveals every pair's
//! sign — nothing else — and a k-bidder auction is `ceil(log2 k)` E3
//! rounds for the winner plus a candidate bracket for the clearing price,
//! instead of 2(k-1) rounds.
//!
//! Capacity: N/2 slots per ciphertext (256 pairs at N=512), enough for a
//! 512-bidder bracket round in ONE ciphertext at the insecure preset.
//!
//! ## On-chain result encoding
//!
//! `PlaintextAggregated.decrypted_output` carries opaque bytes; BFV puts
//! ABI-encoded u64s there. CKKS results are fixed-point: the canonical
//! encoding is [`encode_fixed_point_output`] — big-endian i128 at a
//! declared decimal scale, one 16-byte word per value, solidity-decodable
//! as `int128[]`. Precision beyond `10^-decimals` is intentionally
//! truncated: committee members' smudging noise makes trailing digits
//! non-deterministic across t+1-subsets, and on-chain bytes must be
//! reproducible by any honest quorum.

use crate::TrCkksConfig;
use anyhow::{bail, Context as _, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParameters};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// One bracket-round request: pair up the still-alive bidders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionRound {
    /// Pairs of input indices compared this round: `(a, b)` asks
    /// "is bid[a] > bid[b]?" — answered by the sign of slot `p`.
    pub pairs: Vec<(usize, usize)>,
}

impl AuctionRound {
    /// Single-shot mode: ALL pairwise comparisons `(i, j)` for `i < j` in
    /// one round. With `k` bidders that is `k*(k-1)/2` pairs — at N=512
    /// (256 slots) any `k <= 22` fits in ONE ciphertext, so the full
    /// auction needs exactly one E3 evaluation and one threshold opening.
    ///
    /// The decrypted signs give a complete dominance matrix: the winner is
    /// the bidder that wins every comparison it appears in (see
    /// [`winner_from_all_pairs`]). Losing bids are still never decrypted —
    /// only masked pairwise differences leave the program.
    pub fn all_pairs(k: usize) -> Self {
        let mut pairs = Vec::with_capacity(k * (k.saturating_sub(1)) / 2);
        for i in 0..k {
            for j in (i + 1)..k {
                pairs.push((i, j));
            }
        }
        Self { pairs }
    }
}

/// Resolve the single-shot all-pairs round: returns `(winner, second)`
/// bidder indices from the decrypted slot signs.
///
/// `signs[p] > 0` means `pairs[p].0` bid higher. The winner is the bidder
/// with `k-1` wins; the second-highest is the bidder with `k-2` wins
/// (unique for distinct bids). Ties (equal bids => a zero-ish sign) are
/// broken toward the lower index, matching `apply_round`.
pub fn winner_from_all_pairs(
    round: &AuctionRound,
    k: usize,
    signs: &[f64],
) -> Result<(usize, usize)> {
    if k < 2 {
        bail!("all-pairs auction needs at least two bidders");
    }
    if signs.len() < round.pairs.len() {
        bail!(
            "round has {} pairs but only {} decrypted slots",
            round.pairs.len(),
            signs.len()
        );
    }
    let mut wins = vec![0usize; k];
    for (p, &(a, b)) in round.pairs.iter().enumerate() {
        if a >= k || b >= k {
            bail!("pair ({a},{b}) out of range for {k} bidders");
        }
        if signs[p] > 0.0 {
            wins[a] += 1;
        } else {
            wins[b] += 1;
        }
    }
    let winner = (0..k)
        .max_by_key(|&i| (wins[i], usize::MAX - i))
        .expect("k >= 2");
    let second = (0..k)
        .filter(|&i| i != winner)
        .max_by_key(|&i| (wins[i], usize::MAX - i))
        .expect("k >= 2");
    Ok((winner, second))
}

/// The auction program state across rounds, driven by the caller between
/// E3 requests (each round = one E3 computation + one threshold opening).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionBracket {
    /// Bidder indices still alive.
    pub alive: Vec<usize>,
    /// Losers to the current champion (candidates for second place).
    pub candidates: Vec<usize>,
    /// Set when the winner is decided and the candidate bracket runs.
    pub finding_second: bool,
}

impl AuctionBracket {
    /// Start a bracket over `k` bidders.
    pub fn new(k: usize) -> Self {
        Self {
            alive: (0..k).collect(),
            candidates: Vec::new(),
            finding_second: false,
        }
    }

    /// The next round's pairing, or `None` when the auction is decided.
    /// Odd bidder out gets a bye (advances unpaired).
    pub fn next_round(&self) -> Option<AuctionRound> {
        if self.alive.len() < 2 {
            return None;
        }
        let pairs = self
            .alive
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| (c[0], c[1]))
            .collect();
        Some(AuctionRound { pairs })
    }

    /// Feed a decrypted round: `signs[p] > 0` means `pairs[p].0` won.
    /// Returns the (winner, second) once both brackets have resolved.
    pub fn apply_round(
        &mut self,
        round: &AuctionRound,
        signs: &[f64],
    ) -> Result<Option<(usize, usize)>> {
        if signs.len() < round.pairs.len() {
            bail!(
                "round has {} pairs but only {} decrypted slots",
                round.pairs.len(),
                signs.len()
            );
        }
        let mut next = Vec::with_capacity(self.alive.len() / 2 + 1);
        for (p, &(a, b)) in round.pairs.iter().enumerate() {
            let (won, lost) = if signs[p] > 0.0 { (a, b) } else { (b, a) };
            next.push(won);
            // Losers to the eventual champion are second-place candidates;
            // conservatively track all losers this round in the winner
            // bracket (the champion's actual opponents form a superset
            // filter later — Vickrey correctness needs only that the true
            // second loses ONLY to the champion, so it survives until it
            // meets them and is therefore among these losers).
            if !self.finding_second {
                self.candidates.push(lost);
            }
        }
        // Odd bidder advances on a bye.
        if self.alive.len() % 2 == 1 {
            next.push(*self.alive.last().expect("non-empty"));
        }
        self.alive = next;

        if self.alive.len() == 1 {
            if !self.finding_second {
                // Winner decided: run the candidate bracket.
                let winner = self.alive[0];
                self.finding_second = true;
                self.alive = std::mem::take(&mut self.candidates);
                self.candidates = vec![winner];
                if self.alive.len() == 1 {
                    return Ok(Some((winner, self.alive[0])));
                }
            } else {
                let second = self.alive[0];
                let winner = self.candidates[0];
                return Ok(Some((winner, second)));
            }
        }
        Ok(None)
    }
}

/// The Secure-Process side of one round: build the slot-batched round
/// ciphertext from the submitted bid ciphertexts.
pub fn auction_round_policy(
    config: &TrCkksConfig,
    bids: &[ArcBytes],
    round: &AuctionRound,
    rng: &mut impl Rng,
) -> Result<ArcBytes> {
    let params = config.params()?;
    let encoder = CkksEncoder::new(&params);
    let slots = params.degree() / 2;
    if round.pairs.len() > slots {
        bail!(
            "round has {} pairs; ciphertext has {slots} slots",
            round.pairs.len()
        );
    }
    let cts: Vec<CkksCiphertext> = bids
        .iter()
        .map(|b| CkksCiphertext::from_bytes(b, &params).context("bad bid ciphertext"))
        .collect::<Result<_>>()?;

    let mut acc: Option<CkksCiphertext> = None;
    for (p, &(a, b)) in round.pairs.iter().enumerate() {
        let (ct_a, ct_b) = (
            cts.get(a).context("pair index out of range")?,
            cts.get(b).context("pair index out of range")?,
        );
        let diff = ct_a.try_sub(ct_b)?;
        // One-hot mask carrying the pair's fresh positive mask in slot p.
        let mut mask = vec![0.0f64; p + 1];
        // Mask range vs the wrap wall: masked slot values superpose in the
        // COEFFICIENT domain (sum over slots enters each coefficient via
        // the inverse embedding), so the wall binds on the sum of all
        // masked pair magnitudes, not per-slot values. Empirically at the
        // insecure-512 preset (~2^19 total budget at the doubled scale),
        // r < 32 with |a-b| <= ~1000 and up to ~28 pairs stays safely
        // under it (r = 64 flips marginal signs, r = 256 wraps outright).
        // 5 bits of multiplicative masking (vs the old 3) widens the
        // observer interval for |a-b| from (v/8, v] to (v/32, v].
        mask[p] = rng.random_range(1.0f64..32.0);
        let masked = diff.try_mul_plaintext(&encoder.encode(&mask, diff.level)?)?;
        acc = Some(match acc {
            None => masked,
            Some(prev) => prev.try_add(&masked)?,
        });
    }
    let out = acc.context("round must have at least one pair")?;
    // No rescale: decrypting at the doubled scale keeps smudging noise
    // negligible relative to the signal (see machine_tests for the same
    // reasoning); the decoder divides by the ciphertext's own scale.
    Ok(ArcBytes::from_bytes(&out.to_bytes()))
}

/// How an E3 output plaintext is read back and published, a PURE function
/// of the CKKS parameters (every node/aggregator/client derives the same
/// layout from the on-chain params without configuration):
///
/// * slot-encoded outputs at 2 decimals (ParamSets 0/2/3): `decode`
///   (canonical embedding) → fixed point at [`SLOT_OUTPUT_DECIMALS`];
/// * the credit-v2 output (ParamSet 4): ALSO slot-encoded, `σ_cubic(z_i) + m_i`
///   in slot `i`, but published at [`CREDIT_OUTPUT_DECIMALS`]: the mask is
///   up to 1024 while the score needs ~1e-3, so two decimals would truncate
///   the applicant's unmasked probability. The 20-bit demo smudging decodes
///   to ≈2^-36 at the level-3 scale, far below the 4th decimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputLayout {
    Slots,
    CreditSlots,
    /// ParamSet 5: the output is COEFFICIENT-encoded (an inner product on
    /// coefficient 0, further results on the following coefficients) and
    /// published as the first [`COEFFICIENT_OUTPUT_COUNT`] coefficients at
    /// [`COEFFICIENT_OUTPUT_DECIMALS`].
    Coefficients,
}

/// Decimals of the canonical fixed-point encoding for slot outputs.
pub const SLOT_OUTPUT_DECIMALS: u32 = 2;
/// Decimals of the canonical fixed-point encoding for the credit output.
pub const CREDIT_OUTPUT_DECIMALS: u32 = 4;
/// Decimals of the canonical fixed-point encoding for the coefficient
/// (ParamSet 5) output. Inner products of cap-normalised vectors and
/// mask-scaled sums need ~1e-4 resolution; the 20-bit demo smudging
/// decodes to ~2^-24, well below the 4th decimal.
pub const COEFFICIENT_OUTPUT_DECIMALS: u32 = 4;
/// How many leading coefficients the ParamSet-5 output publishes. The
/// three coefficient policies place their results on coefficients
/// `0..COEFFICIENT_OUTPUT_COUNT`; everything above is cross-term garbage
/// (masked) that must NOT be published.
pub const COEFFICIENT_OUTPUT_COUNT: usize = 64;

/// The output layout for `params` (ParamSet 4 ⇔ credit slots).
pub fn output_layout_for(params: &CkksParameters) -> OutputLayout {
    match e3_fhe_params::ckks_presets::ckks_on_chain_param_set_for(params) {
        Ok(4) => OutputLayout::CreditSlots,
        Ok(5) => OutputLayout::Coefficients,
        _ => OutputLayout::Slots,
    }
}

/// Decimals the on-chain fixed-point bytes carry for `params`.
pub fn output_decimals_for(params: &CkksParameters) -> u32 {
    match output_layout_for(params) {
        OutputLayout::Slots => SLOT_OUTPUT_DECIMALS,
        OutputLayout::CreditSlots => CREDIT_OUTPUT_DECIMALS,
        OutputLayout::Coefficients => COEFFICIENT_OUTPUT_DECIMALS,
    }
}

/// Decode a threshold-decrypted output plaintext to the values the
/// canonical encoding publishes (layout per [`output_layout_for`]).
pub fn decode_output_plaintext(
    params: &std::sync::Arc<CkksParameters>,
    pt: &fhe::ckks::CkksPlaintext,
) -> Result<Vec<f64>> {
    let encoder = CkksEncoder::new(params);
    match output_layout_for(params) {
        OutputLayout::Slots | OutputLayout::CreditSlots => Ok(encoder.decode(pt)?),
        OutputLayout::Coefficients => {
            Ok(encoder.decode_coefficients(pt, COEFFICIENT_OUTPUT_COUNT)?)
        }
    }
}

/// Canonical fixed-point on-chain encoding: big-endian `i128` words at
/// `10^decimals` scale — `int128[]` on the solidity side.
pub fn encode_fixed_point_output(values: &[f64], decimals: u32) -> Result<Vec<u8>> {
    let scale = 10f64.powi(decimals as i32);
    let mut out = Vec::with_capacity(values.len() * 16);
    for &v in values {
        if !v.is_finite() {
            bail!("non-finite value cannot be published");
        }
        let scaled = (v * scale).round();
        if scaled.abs() >= 2f64.powi(127) {
            bail!("value {v} overflows i128 at {decimals} decimals");
        }
        out.extend_from_slice(&(scaled as i128).to_be_bytes());
    }
    Ok(out)
}

/// Decode [`encode_fixed_point_output`] bytes back to floats.
pub fn decode_fixed_point_output(bytes: &[u8], decimals: u32) -> Result<Vec<f64>> {
    if !bytes.len().is_multiple_of(16) {
        bail!(
            "fixed-point output length {} not a multiple of 16",
            bytes.len()
        );
    }
    let scale = 10f64.powi(decimals as i32);
    Ok(bytes
        .chunks_exact(16)
        .map(|c| i128::from_be_bytes(c.try_into().expect("chunk is 16 bytes")) as f64 / scale)
        .collect())
}
