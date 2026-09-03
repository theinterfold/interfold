// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Canonical CKKS parameter presets, paired to the on-chain `ParamSet`
//! enum exactly like the BFV presets: a CKKS E3 requests `paramSet` only
//! (the scheme comes from the E3 program address => protocol mapping),
//! and every node derives the SAME CKKS parameters from that value.
//!
//! This module is also the single source of every committee-wide CKKS
//! decision that must hold WITHOUT node configuration: the param set
//! behind a byte string ([`ckks_on_chain_param_set_for`]), the DKG
//! transport preset ([`ckks_dkg_transport_preset`]), the relin-ceremony
//! plan ([`relin_ceremony_plan_for_param_set`]), and the proof posture
//! ([`CkksProofPosture`]).
//!
//! DKG-transport constraint (see `threshold_keyshare_ckks::encrypted_dkg`):
//! every CKKS ciphertext modulus must be ≤ the paired DKG preset's
//! plaintext modulus, because dealt share coefficients travel as BFV
//! plaintexts. The insecure pairing uses the BFV threshold moduli
//! `[0xffffee001, 0xffffc4001]` under `InsecureDkg512` (t = 0xffffee001).
//!
//! Hybrid key switching (special primes, [`SIGN_EXTRACTION_SPECIAL_MODULI_BITS`])
//! does NOT touch the transport bound: dealt Shamir shares are over the
//! ciphertext modulus `Q` only (`TRCKKS::coeffs_to_poly` builds them on
//! `context_at_level(0)`), and the special primes `P` are PUBLIC parameters
//! that only key material carries (each party reduces its OWN local secret
//! contribution mod `P` inside the ceremony). So only the `Q` limbs are
//! checked against `t_dkg`, and adding `P` changes no transport preset.

use anyhow::{bail, Context, Result};
use fhe::ckks::{CkksParameters, CkksParametersBuilder};
use std::sync::Arc;

/// CKKS scale for the insecure-512 preset (2^26: fits products under the
/// 36-bit moduli without wrap-around; see machine_tests wrap analysis).
pub const INSECURE_512_CKKS_SCALE_BITS: i32 = 26;

/// CKKS moduli for the insecure-512 preset (transport-compatible with
/// `InsecureDkg512`).
pub const INSECURE_512_CKKS_MODULI: [u64; 2] = [0xffffee001, 0xffffc4001];

/// Sign-extraction iterations baked into the ParamSet-2 ladder. 12
/// iterations binarize gaps down to ~2% of the bid bound (see
/// `e3-trckks::config::sign_extraction_params` and the
/// `e2e_sign_extraction_policy` test).
pub const SIGN_EXTRACTION_ITERATIONS: usize = 12;

/// CKKS scale bits for the sign-extraction ladder (delta = 2^40; rescaling
/// by ~2^40 limbs keeps the working scale pinned across iterations).
pub const SIGN_EXTRACTION_SCALE_BITS: i32 = 40;

/// Special-prime sizes for the sign-extraction ladder's HYBRID key
/// switching: `k = 3` primes of 60 bits (the shape the fhe.rs bench and
/// `ckks::hybrid::tests::single_key_sign_extraction_ladder_n512` run).
/// With the default digit size `alpha = k`, the 38-limb ladder has
/// `dnum = 13` digits and `P ≈ 2^180 > max D_j ≈ 2^125`, so the key-switch
/// noise is divided by `P/D_j ≈ 2^55` — ONE key serves all 24 sign-map
/// multiplication levels (fhe.rs `BENCHMARKS_TRCKKS.md` §5: ceremony
/// upload 115 MiB → 5.4 MiB per party at N=512). These primes are NOT
/// ciphertext moduli: they never travel through the DKG transport (see
/// the module docs) and the Greco/C6 circuits — which bind `Q` limbs
/// only — are unchanged.
pub const SIGN_EXTRACTION_SPECIAL_MODULI_BITS: [usize; 3] = [60, 60, 60];

/// Modulus sizes for the sign-extraction ladder: one 45-bit base plus
/// `1 + 3*iterations` 40-bit rescale limbs (the pack step consumes one
/// level, each cubic iteration three). MUST mirror
/// `e3_trckks::config::sign_extraction_params` — fhe-params cannot depend
/// on e3-trckks (dependency cycle), so the shape is duplicated here and
/// pinned by a byte-equality test in e3-trckks.
pub fn sign_extraction_moduli_sizes(iterations: usize) -> Vec<usize> {
    let mut sizes = vec![45usize];
    sizes.extend(std::iter::repeat_n(40usize, 1 + 3 * iterations));
    sizes
}

/// CKKS moduli for the statistics preset (ParamSet 3): three 36-bit
/// NTT-friendly primes, EVERY one ≤ the standard `InsecureDkg512`
/// plaintext modulus (t = 0xffffee001) — the DKG transport needs NO wide
/// escalation, unlike the sign-extraction ladder. The extra limb gives
/// one genuine ct×ct multiplication level for the relinearized
/// sum-of-squares in the statistics policy. MUST mirror
/// `e3_trckks::config::statistics_transport_params` (dependency
/// direction forbids importing it; pinned by a byte-equality test in
/// e3-trckks).
pub const STATISTICS_CKKS_MODULI: [u64; 3] = [0xffffee001, 0xffffc4001, 0xffffbe001];

/// CKKS scale bits for the statistics preset. delta = 2^40: the level-0
/// squares carry scale delta^2 = 2^80 under Q0 ≈ 2^108 (inputs are
/// normalized to ≤1 by the public cap, so message · scale keeps ≥20 bits
/// of headroom), and the packed output opens at level 1 with scale
/// delta^2 · 2^24 / q2 ≈ 2^68 — the relin noise (divided by q2 in the
/// rescale) and the smudging noise both sit far below it.
pub const STATISTICS_CKKS_SCALE_BITS: i32 = 40;

/// Build the canonical CKKS parameters for an on-chain `ParamSet` value.
/// `0` = insecure-512 (demo). `2` = insecure-512 sign-extraction ladder
/// (leak-free auction winner mode; NEEDS the WIDE DKG transport preset —
/// its 45-bit base exceeds the standard `InsecureDkg512` plaintext
/// modulus). `3` = statistics 3-limb preset (relinearized sum-of-squares;
/// fits the STANDARD transport). Secure presets land with their flooding
/// derivation (`CkksSmudgingBoundCalculator`) — rejecting unknown values
/// keeps version-skewed nodes out of committees they can't serve.
pub fn ckks_params_for_on_chain_param_set(param_set: u8) -> Result<Arc<CkksParameters>> {
    match param_set {
        0 => CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli(&INSECURE_512_CKKS_MODULI)
            .set_scale(2f64.powi(INSECURE_512_CKKS_SCALE_BITS))
            .build_arc()
            .context("failed to build insecure-512 CKKS params"),
        2 => CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&sign_extraction_moduli_sizes(SIGN_EXTRACTION_ITERATIONS))
            .set_special_moduli_sizes(&SIGN_EXTRACTION_SPECIAL_MODULI_BITS)
            .set_scale(2f64.powi(SIGN_EXTRACTION_SCALE_BITS))
            .build_arc()
            .context("failed to build sign-extraction ladder CKKS params"),
        3 => CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli(&STATISTICS_CKKS_MODULI)
            .set_scale(2f64.powi(STATISTICS_CKKS_SCALE_BITS))
            .build_arc()
            .context("failed to build statistics CKKS params"),
        other => bail!(
            "Unknown ParamSet enum value {other} for a CKKS E3 — this node's binary does not \
             recognize this CKKS preset (likely version skew with the on-chain contracts)."
        ),
    }
}

/// Deterministic DKG-transport escalation for CKKS E3s.
///
/// Dealt DKG share coefficients travel as BFV plaintexts mod `t_dkg`, so
/// every CKKS ciphertext modulus must be ≤ the transport preset's
/// plaintext modulus. Given the E3's standard DKG counterpart preset and
/// the CKKS moduli, this returns the counterpart unchanged when it fits
/// and escalates to [`crate::BfvPreset::InsecureDkgWide512`] when any
/// modulus exceeds the standard plaintext modulus (the sign-extraction
/// ladder's 45-bit base needs this). Errors if even the wide preset
/// cannot carry the moduli. PURE function of the E3's parameters — every
/// node derives the same preset (no env, no local state).
pub fn ckks_dkg_transport_preset(
    standard: crate::BfvPreset,
    ckks_moduli: &[u64],
) -> Result<crate::BfvPreset> {
    use crate::BfvParamSet;
    let fits = |preset: crate::BfvPreset| {
        let t = BfvParamSet::from(preset).plaintext_modulus;
        ckks_moduli.iter().all(|q| *q <= t)
    };
    if fits(standard) {
        return Ok(standard);
    }
    let wide = crate::BfvPreset::InsecureDkgWide512;
    if fits(wide) {
        return Ok(wide);
    }
    bail!(
        "CKKS moduli {ckks_moduli:x?} exceed every available DKG transport preset's \
         plaintext modulus"
    )
}

/// [`ckks_dkg_transport_preset`] over serialized CKKS parameter bytes (as
/// carried by `E3Meta.params` / `CiphernodeSelected.params` for CKKS E3s).
pub fn ckks_dkg_transport_preset_from_bytes(
    standard: crate::BfvPreset,
    ckks_params_bytes: &[u8],
) -> Result<crate::BfvPreset> {
    ckks_dkg_transport_preset(standard, decode_ckks_params(ckks_params_bytes)?.moduli())
}

/// Every on-chain `ParamSet` value that names a CKKS preset, in
/// identification order.
pub const CKKS_ON_CHAIN_PARAM_SETS: [u8; 3] = [0, 2, 3];

/// The canonical CKKS param set (set 0). Its C6/C7 artifacts keep the
/// un-suffixed names (`share_decryption_ckks`,
/// `decrypted_shares_aggregation_ckks`); sets 2/3 use `_ps<N>` names.
pub const CKKS_CANONICAL_PARAM_SET: u8 = 0;

fn decode_ckks_params(bytes: &[u8]) -> Result<CkksParameters> {
    use fhe_traits::Deserialize as _;
    CkksParameters::try_deserialize(bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode CKKS params: {e}"))
}

/// Identify which on-chain `ParamSet` value a CKKS parameter set is: the
/// inverse of [`ckks_params_for_on_chain_param_set`], by structural
/// equality (degree, moduli, scale). `E3Requested` carries only the
/// parameter BYTES to the node, so every node re-derives the set from
/// them — the set is the key for everything downstream that must agree
/// committee-wide without configuration (relin levels, proof posture).
/// Errors on a parameter set this binary does not recognize.
pub fn ckks_on_chain_param_set_for(params: &CkksParameters) -> Result<u8> {
    for set in CKKS_ON_CHAIN_PARAM_SETS {
        let known = ckks_params_for_on_chain_param_set(set)?;
        if known.as_ref() == params {
            return Ok(set);
        }
    }
    bail!(
        "CKKS parameters (degree {}, {} moduli) match no known on-chain ParamSet",
        params.degree(),
        params.moduli().len()
    )
}

/// [`ckks_on_chain_param_set_for`] over serialized parameter bytes.
pub fn ckks_on_chain_param_set_from_bytes(ckks_params_bytes: &[u8]) -> Result<u8> {
    ckks_on_chain_param_set_for(&decode_ckks_params(ckks_params_bytes)?)
}

/// Which relinearization-key ceremony the committee runs after the DKG
/// for one param set. A PURE function of the param set, so every node
/// agrees without configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelinCeremonyPlan {
    /// No ceremony: the program multiplies by plaintexts only.
    None,
    /// ONE two-round hybrid ceremony (params carry special primes): the
    /// single `CkksHybridRelinKey` relinearizes at EVERY level.
    Hybrid,
    /// One two-round per-level (RNS-decomposition) ceremony per listed
    /// multiplication level; sorted, unique.
    PerLevel(Vec<usize>),
}

impl RelinCeremonyPlan {
    /// True when a ceremony runs at all.
    pub fn runs_ceremony(&self) -> bool {
        !matches!(self, RelinCeremonyPlan::None)
    }

    /// True for the hybrid (single-key) ceremony.
    pub fn is_hybrid(&self) -> bool {
        matches!(self, RelinCeremonyPlan::Hybrid)
    }

    /// Number of joint keys the ceremony yields.
    pub fn key_count(&self) -> usize {
        match self {
            RelinCeremonyPlan::None => 0,
            RelinCeremonyPlan::Hybrid => 1,
            RelinCeremonyPlan::PerLevel(levels) => levels.len(),
        }
    }
}

/// Multiplication levels the sign-extraction policy relinearizes at: the
/// pack step consumes level 0 and each of the
/// [`SIGN_EXTRACTION_ITERATIONS`] cubic iterations relinearizes twice, at
/// levels `1 + 3i` and `3 + 3i`. Informational for the hybrid plan (one
/// key serves them all); it is what a per-level plan would have to key.
pub fn sign_extraction_mult_levels(iterations: usize) -> Vec<usize> {
    (0..iterations)
        .flat_map(|i| [1 + 3 * i, 3 + 3 * i])
        .collect()
}

/// The relin-ceremony plan of `param_set`:
/// - set 0 (masked-difference auction): plaintext masks only — no
///   ceremony;
/// - set 2 (sign-extraction ladder): HYBRID — the params carry special
///   primes, so one ceremony keys all 24 sign-map levels
///   ([`sign_extraction_mult_levels`]);
/// - set 3 (statistics, L=3): PER-LEVEL at level 0 only. Hybrid is
///   LARGER at tiny depth — with `k=1` the key is `2·dnum·(L+k) = 24`
///   polys vs `2·L² = 18` for the one RNS key the policy needs, and the
///   RNS relin noise is already divided by `q_2` in the rescale that
///   follows — so set 3 stays on per-level keys and the standard
///   transport.
pub fn relin_ceremony_plan_for_param_set(param_set: u8) -> Result<RelinCeremonyPlan> {
    match param_set {
        0 => Ok(RelinCeremonyPlan::None),
        2 => Ok(RelinCeremonyPlan::Hybrid),
        3 => Ok(RelinCeremonyPlan::PerLevel(vec![0])),
        other => bail!("Unknown ParamSet enum value {other} for a CKKS E3 (relin ceremony plan)"),
    }
}

/// The plan a parameter set REQUESTS by its own shape: hybrid whenever it
/// carries special primes. Used to cross-check
/// [`relin_ceremony_plan_for_param_set`] against the params bytes every
/// node received on-chain (a hybrid plan without special primes, or the
/// reverse, is a version skew that must fail loudly).
pub fn relin_plan_matches_params(plan: &RelinCeremonyPlan, params: &CkksParameters) -> bool {
    match plan {
        RelinCeremonyPlan::Hybrid => params.hybrid_enabled(),
        RelinCeremonyPlan::None | RelinCeremonyPlan::PerLevel(_) => !params.hybrid_enabled(),
    }
}

/// Whether one proof type is produced and verified, or — ONLY under the
/// explicit operator off-switch — replaced by a deterministic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPosture {
    /// A real ZK proof is generated, published, and verified.
    Proven,
    /// No proof travels. Reachable ONLY through
    /// [`CkksProofPosture::with_proof_free_override`] (the explicit
    /// off-switch, default OFF); never derived silently. The reason names
    /// the switch that was thrown.
    ProofFree(&'static str),
}

impl ProofPosture {
    /// True when no proof is expected on the wire.
    pub fn is_proof_free(self) -> bool {
        matches!(self, ProofPosture::ProofFree(_))
    }
}

/// The complete proof posture of one CKKS E3, computed ONCE from
/// `(param set, DKG transport preset)` and consulted by every component
/// that emits or verifies a CKKS proof (keyshare shell, zk-prover proof
/// request + verification actors, aggregator). EVERY proof is `Proven`
/// for every known param set: C0 resolves the `pk` artifact under the
/// transport preset's own directory (`insecure-dkg-wide-512` for the wide
/// escalation), C1/C6/C7 resolve per-param-set CKKS artifacts
/// (`pk_generation_ckks_ps<N>`, `share_decryption_ckks[_ps<N>]`,
/// `decrypted_shares_aggregation_ckks[_ps<N>]`), and the ceremony carries
/// per-digit C8 proofs (`relin_round1_hybrid_ckks_digit`). A missing
/// artifact is a fail-closed ERROR at CiphernodeSelected
/// (`e3_zk_prover::ckks_artifacts::check_ckks_artifacts`), never a silent
/// proof-free fallback. The ONLY proof-free path is the explicit operator
/// off-switch [`CkksProofPosture::with_proof_free_override`] (env
/// [`CKKS_ALLOW_PROOF_FREE_ENV`], default OFF), which every node of a committee
/// must set identically — documented in `agent/INVARIANTS.md` §Threshold
/// CKKS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkksProofPosture {
    /// On-chain `ParamSet` value the E3 was requested with.
    pub param_set: u8,
    /// DKG share-transport preset ([`ckks_dkg_transport_preset`]).
    pub transport: crate::BfvPreset,
    /// C0 (transport-key well-formedness) over the transport preset's
    /// own `pk` artifact.
    pub c0: ProofPosture,
    /// C1-CKKS (pk share well-formedness; the rogue-key gate).
    pub c1: ProofPosture,
    /// C6-CKKS (decryption share), per param set.
    pub c6: ProofPosture,
    /// C7-CKKS (plaintext aggregation), per param set.
    pub c7: ProofPosture,
    /// Relin ceremony: C8 per-digit proofs on every hybrid round-1 share
    /// (verified by every receiver before aggregation). `Proven` only
    /// when a ceremony runs at all; a param set with no ceremony reports
    /// `Proven` too (nothing to prove, nothing accepted unproven).
    pub ceremony: ProofPosture,
}

/// Explicit operator off-switch. When set to `1`/`true`, EVERY CKKS proof
/// posture becomes proof-free (C0 transport keys, C1 pk shares, C6/C7,
/// C8 ceremony). Default OFF. This is a committee-wide setting: a node
/// with the switch ON accepts unproven payloads, a node with it OFF
/// rejects them, so mixed committees fail attributably. Intended for
/// demo stacks whose circuit artifacts are not staged; NEVER for
/// production.
pub const CKKS_ALLOW_PROOF_FREE_ENV: &str = "CKKS_ALLOW_PROOF_FREE";

/// Reason string every posture carries under the off-switch.
pub const PROOF_FREE_OVERRIDE_REASON: &str =
    "explicit operator off-switch CKKS_ALLOW_PROOF_FREE=1 (all CKKS proofs disabled)";

/// Whether the explicit off-switch is thrown in this process's
/// environment (`CKKS_ALLOW_PROOF_FREE=1|true`). Pure read; the caller decides
/// what to do with it.
pub fn proof_free_override_from_env() -> bool {
    matches!(
        std::env::var(CKKS_ALLOW_PROOF_FREE_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

impl CkksProofPosture {
    /// Compute the posture for an E3 from its standard DKG counterpart
    /// preset and its serialized CKKS params. Applies the explicit
    /// off-switch from the environment ([`CKKS_ALLOW_PROOF_FREE_ENV`]).
    pub fn from_bytes(standard: crate::BfvPreset, ckks_params_bytes: &[u8]) -> Result<Self> {
        let params = decode_ckks_params(ckks_params_bytes)?;
        let param_set = ckks_on_chain_param_set_for(&params)?;
        let transport = ckks_dkg_transport_preset(standard, params.moduli())?;
        Ok(
            Self::new(param_set, transport)
                .with_proof_free_override(proof_free_override_from_env()),
        )
    }

    /// The proven posture for an already-identified param set and
    /// transport preset (no off-switch applied).
    pub fn new(param_set: u8, transport: crate::BfvPreset) -> Self {
        Self {
            param_set,
            transport,
            c0: ProofPosture::Proven,
            c1: ProofPosture::Proven,
            c6: ProofPosture::Proven,
            c7: ProofPosture::Proven,
            ceremony: ProofPosture::Proven,
        }
    }

    /// Apply the explicit off-switch: `true` flips EVERY posture to
    /// proof-free with [`PROOF_FREE_OVERRIDE_REASON`]; `false` is the
    /// identity.
    pub fn with_proof_free_override(mut self, off_switch: bool) -> Self {
        if off_switch {
            let free = ProofPosture::ProofFree(PROOF_FREE_OVERRIDE_REASON);
            self.c0 = free;
            self.c1 = free;
            self.c6 = free;
            self.c7 = free;
            self.ceremony = free;
        }
        self
    }

    /// True when the off-switch is thrown on this posture.
    pub fn is_proof_free_override(&self) -> bool {
        self.c1.is_proof_free()
    }

    /// One-line operator summary (logged once at `CiphernodeSelected`).
    pub fn summary(&self) -> String {
        fn word(p: ProofPosture) -> &'static str {
            match p {
                ProofPosture::Proven => "proven",
                ProofPosture::ProofFree(_) => "proof-free",
            }
        }
        format!(
            "param_set={} transport={} c0={} c1={} c6={} c7={} ceremony={}",
            self.param_set,
            self.transport.name(),
            word(self.c0),
            word(self.c1),
            word(self.c6),
            word(self.c7),
            word(self.ceremony)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_traits::{Deserialize, Serialize};

    #[test]
    fn insecure_512_roundtrips_and_respects_transport_bound() {
        let params = ckks_params_for_on_chain_param_set(0).unwrap();
        // Transport bound: every modulus ≤ InsecureDkg512 plaintext modulus.
        let t_dkg = crate::constants::insecure_512::dkg::PLAINTEXT_MODULUS;
        for q in params.moduli() {
            assert!(*q <= t_dkg, "modulus {q:#x} exceeds transport t {t_dkg:#x}");
        }
        // Round-trip through the wire encoding.
        let bytes = params.to_bytes();
        let decoded = CkksParameters::try_deserialize(&bytes).unwrap();
        assert_eq!(decoded.moduli(), params.moduli());
        assert_eq!(decoded.degree(), params.degree());
    }

    #[test]
    fn unknown_param_set_is_rejected() {
        assert!(ckks_params_for_on_chain_param_set(7).is_err());
    }

    #[test]
    fn sign_extraction_ladder_fits_wide_transport_and_needs_escalation() {
        let params = ckks_params_for_on_chain_param_set(2).unwrap();
        assert_eq!(params.degree(), 512);
        assert_eq!(
            params.moduli().len(),
            1 + 1 + 3 * SIGN_EXTRACTION_ITERATIONS,
            "45-bit base + (1 + 3*iterations) rescale limbs"
        );
        let t_std = crate::constants::insecure_512::dkg::PLAINTEXT_MODULUS;
        let t_wide = crate::constants::insecure_512::dkg_wide::PLAINTEXT_MODULUS;
        // Every ladder modulus fits the WIDE transport…
        for q in params.moduli() {
            assert!(*q <= t_wide, "modulus {q:#x} exceeds wide t {t_wide:#x}");
        }
        // …the hybrid special primes are 60-bit — WAY above t_wide — and
        // that is fine: they are public key-material moduli, never dealt
        // (`ckks_dkg_transport_preset` checks `moduli()`, not `P`).
        assert_eq!(params.special_moduli().len(), 3, "k = 3 special primes");
        assert!(params.hybrid_enabled());
        assert_eq!(params.dnum(), 13, "dnum = ceil(38 / 3)");
        assert!(params.special_moduli().iter().all(|p| *p > t_wide));
        assert_eq!(
            ckks_dkg_transport_preset(crate::BfvPreset::InsecureDkg512, params.moduli()).unwrap(),
            crate::BfvPreset::InsecureDkgWide512,
            "transport unchanged by the special primes"
        );
        // The params bytes carry the special primes (proto fields) and
        // round-trip: every node re-derives hybrid from the on-chain bytes.
        let decoded = CkksParameters::try_deserialize(&params.to_bytes()).unwrap();
        assert_eq!(decoded.special_moduli(), params.special_moduli());
        assert_eq!(decoded.dnum(), params.dnum());
        // …and the 45-bit base PROVES the escalation is needed (standard
        // InsecureDkg512 transport cannot carry it).
        assert!(
            params.moduli().iter().any(|q| *q > t_std),
            "ladder unexpectedly fits the standard transport — escalation dead code?"
        );
    }

    #[test]
    fn transport_escalation_is_deterministic_and_scheme_correct() {
        use crate::BfvPreset;
        // ParamSet 0 CKKS moduli fit the standard counterpart: no escalation.
        let narrow = ckks_params_for_on_chain_param_set(0).unwrap();
        assert_eq!(
            ckks_dkg_transport_preset(BfvPreset::InsecureDkg512, narrow.moduli()).unwrap(),
            BfvPreset::InsecureDkg512
        );
        // The ParamSet 2 ladder escalates to the wide preset.
        let ladder = ckks_params_for_on_chain_param_set(2).unwrap();
        assert_eq!(
            ckks_dkg_transport_preset(BfvPreset::InsecureDkg512, ladder.moduli()).unwrap(),
            BfvPreset::InsecureDkgWide512
        );
        // Moduli beyond even the wide preset are rejected.
        assert!(ckks_dkg_transport_preset(BfvPreset::InsecureDkg512, &[u64::MAX]).is_err());
    }

    #[test]
    fn param_set_2_keeps_the_param_set_0_bfv_encoding() {
        use crate::BfvPreset;
        // Same BFV preset ⇒ same crypto-config id on-chain: no contract
        // parameter change for the ladder.
        assert_eq!(
            BfvPreset::from_on_chain_param_set(2),
            Some(BfvPreset::InsecureThreshold512)
        );
        assert_eq!(
            BfvPreset::from_on_chain_param_set(0),
            BfvPreset::from_on_chain_param_set(2)
        );
    }

    /// ParamSet 3 (statistics): every modulus fits the STANDARD
    /// `InsecureDkg512` transport — proving NO wide escalation is needed
    /// (unlike the sign-extraction ladder), and the params round-trip.
    #[test]
    fn statistics_preset_fits_standard_transport() {
        let params = ckks_params_for_on_chain_param_set(3).unwrap();
        assert_eq!(params.degree(), 512);
        assert_eq!(params.moduli().len(), 3, "one multiplication level");
        let t_dkg = crate::constants::insecure_512::dkg::PLAINTEXT_MODULUS;
        for q in params.moduli() {
            assert!(*q <= t_dkg, "modulus {q:#x} exceeds standard t {t_dkg:#x}");
        }
        // Deterministic transport derivation: standard preset, unchanged.
        assert_eq!(
            ckks_dkg_transport_preset(crate::BfvPreset::InsecureDkg512, params.moduli()).unwrap(),
            crate::BfvPreset::InsecureDkg512
        );
        // Round-trip through the wire encoding.
        let bytes = params.to_bytes();
        let decoded = CkksParameters::try_deserialize(&bytes).unwrap();
        assert_eq!(decoded.moduli(), params.moduli());
        assert_eq!(decoded.degree(), params.degree());
    }

    #[test]
    fn param_set_3_keeps_the_param_set_0_bfv_encoding() {
        use crate::BfvPreset;
        assert_eq!(
            BfvPreset::from_on_chain_param_set(3),
            Some(BfvPreset::InsecureThreshold512)
        );
        assert_eq!(
            BfvPreset::from_on_chain_param_set(0),
            BfvPreset::from_on_chain_param_set(3)
        );
    }

    /// The set identification is the exact inverse of the builder for
    /// every known set, over the wire bytes the node actually receives.
    #[test]
    fn param_set_identification_round_trips_every_known_set() {
        for set in CKKS_ON_CHAIN_PARAM_SETS {
            let params = ckks_params_for_on_chain_param_set(set).unwrap();
            assert_eq!(ckks_on_chain_param_set_for(&params).unwrap(), set);
            assert_eq!(
                ckks_on_chain_param_set_from_bytes(&params.to_bytes()).unwrap(),
                set
            );
        }
        // A structurally different set (same moduli, different scale) is
        // NOT silently mapped to a known set.
        let stranger = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli(&INSECURE_512_CKKS_MODULI)
            .set_scale(2f64.powi(27))
            .build_arc()
            .unwrap();
        assert!(ckks_on_chain_param_set_for(&stranger).is_err());
    }

    /// The ceremony plan is a pure function of the param set and matches
    /// each set's parameter shape: set 2 is HYBRID (special primes) and
    /// the sign-map levels it must serve all sit inside its chain; set 3
    /// stays per-level at level 0; set 0 runs no ceremony.
    #[test]
    fn relin_ceremony_plan_is_derived_from_the_param_set() {
        assert_eq!(
            relin_ceremony_plan_for_param_set(0).unwrap(),
            RelinCeremonyPlan::None
        );
        assert_eq!(
            relin_ceremony_plan_for_param_set(3).unwrap(),
            RelinCeremonyPlan::PerLevel(vec![0])
        );
        assert_eq!(
            relin_ceremony_plan_for_param_set(2).unwrap(),
            RelinCeremonyPlan::Hybrid
        );
        assert_eq!(relin_ceremony_plan_for_param_set(2).unwrap().key_count(), 1);
        assert!(relin_ceremony_plan_for_param_set(7).is_err());
        for set in CKKS_ON_CHAIN_PARAM_SETS {
            let plan = relin_ceremony_plan_for_param_set(set).unwrap();
            let params = ckks_params_for_on_chain_param_set(set).unwrap();
            assert!(
                relin_plan_matches_params(&plan, &params),
                "set {set}: plan {plan:?} vs hybrid_enabled={}",
                params.hybrid_enabled()
            );
        }
        let ladder = sign_extraction_mult_levels(SIGN_EXTRACTION_ITERATIONS);
        assert_eq!(ladder.len(), 2 * SIGN_EXTRACTION_ITERATIONS);
        assert_eq!(&ladder[..4], &[1, 3, 4, 6]);
        assert!(ladder.windows(2).all(|w| w[0] < w[1]), "sorted, unique");
        let params = ckks_params_for_on_chain_param_set(2).unwrap();
        let depth = params.moduli().len();
        assert!(ladder.iter().all(|l| *l < depth), "level inside the chain");
        // The hybrid gadget has a non-empty digit set at every keyed level.
        assert!(ladder
            .iter()
            .all(|l| params.digits_at_level(*l).unwrap() >= 1));
    }

    /// The proof posture is deterministic per (param set, transport) and
    /// PROVEN for every known set and every proof; proof-free is reachable
    /// only through the explicit off-switch, which flips every entry.
    #[test]
    fn proof_posture_is_explicit_per_param_set() {
        use crate::BfvPreset;
        let std_preset = BfvPreset::InsecureDkg512;
        let posture = |set: u8| {
            let params = ckks_params_for_on_chain_param_set(set).unwrap();
            let transport = ckks_dkg_transport_preset(std_preset, params.moduli()).unwrap();
            CkksProofPosture::new(set, transport)
        };
        let all_proven = |p: &CkksProofPosture| {
            [p.c0, p.c1, p.c6, p.c7, p.ceremony]
                .iter()
                .all(|x| *x == ProofPosture::Proven)
        };
        let set0 = posture(0);
        assert_eq!(set0.transport, BfvPreset::InsecureDkg512);
        assert!(all_proven(&set0));

        let set2 = posture(2);
        assert_eq!(set2.transport, BfvPreset::InsecureDkgWide512);
        assert!(
            all_proven(&set2),
            "wide transport C0 resolves its own artifact dir"
        );
        assert_eq!(set2.transport.artifacts_dir(), "insecure-dkg-wide-512");

        let set3 = posture(3);
        assert_eq!(set3.transport, BfvPreset::InsecureDkg512);
        assert!(all_proven(&set3));

        // Same inputs, same posture (what committee-wide agreement rests on).
        assert_eq!(posture(2), posture(2));
        assert_eq!(
            set2.summary(),
            "param_set=2 transport=INSECURE_DKG_WIDE_512 c0=proven c1=proven c6=proven \
             c7=proven ceremony=proven"
        );

        // The off-switch is explicit and total; `false` is the identity.
        assert_eq!(set2.with_proof_free_override(false), set2);
        let off = set2.with_proof_free_override(true);
        assert!(off.is_proof_free_override());
        assert!([off.c0, off.c1, off.c6, off.c7, off.ceremony]
            .iter()
            .all(|x| *x == ProofPosture::ProofFree(PROOF_FREE_OVERRIDE_REASON)));
        assert!(off.summary().contains("c1=proof-free"));
        assert!(!set2.is_proof_free_override());
    }

    /// `from_bytes` (what every node consumes) is PROVEN for sets 0/2/3
    /// with the knob unset, and the knob only accepts explicit truthy
    /// values. The env read is process-global, so this test owns it.
    #[test]
    fn from_bytes_is_proven_unless_the_knob_is_explicitly_on() {
        use crate::BfvPreset;
        use fhe_traits::Serialize as _;
        let std_preset = BfvPreset::InsecureDkg512;
        std::env::remove_var(CKKS_ALLOW_PROOF_FREE_ENV);
        for set in CKKS_ON_CHAIN_PARAM_SETS {
            let params = ckks_params_for_on_chain_param_set(set).unwrap();
            let p = CkksProofPosture::from_bytes(std_preset, &params.to_bytes()).unwrap();
            assert_eq!(p.param_set, set);
            assert!(!p.is_proof_free_override(), "set {set} must be proven");
            assert!(
                p.summary()
                    .ends_with("c0=proven c1=proven c6=proven c7=proven ceremony=proven"),
                "{}",
                p.summary()
            );
        }
        for off in ["0", "false", "", "no"] {
            std::env::set_var(CKKS_ALLOW_PROOF_FREE_ENV, off);
            assert!(
                !proof_free_override_from_env(),
                "{off:?} must not enable proof-free"
            );
        }
        std::env::set_var(CKKS_ALLOW_PROOF_FREE_ENV, "1");
        assert!(proof_free_override_from_env());
        let params = ckks_params_for_on_chain_param_set(2).unwrap();
        let p = CkksProofPosture::from_bytes(std_preset, &params.to_bytes()).unwrap();
        assert!(p.is_proof_free_override());
        std::env::remove_var(CKKS_ALLOW_PROOF_FREE_ENV);
    }
}
