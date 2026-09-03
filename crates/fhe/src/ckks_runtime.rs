// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS runtime adaptor: the CKKS counterpart of [`crate::runtime::Fhe`].
//!
//! Exposes the SAME four-operation seam the node actors consume for BFV —
//! keyshare generation, decryption-share computation, public-key
//! aggregation, plaintext aggregation — implemented over `fhe::trckks`
//! (CRP-based multiparty keygen + Shamir threshold decryption).
//!
//! Scheme selection: an E3 whose encoded params decode as
//! [`fhe::ckks::CkksParameters`] runs CKKS; BFV params keep the existing
//! [`crate::runtime::Fhe`] path (see [`SchemeParams::from_encoded`]).
//!
//! Differences from the BFV adaptor, dictated by the schemes:
//! - Keyshare generation also deals Shamir share matrices (threshold t-of-n
//!   decryption instead of mbfv's n-of-n additive decryption shares).
//! - `get_aggregate_plaintext` returns fixed-point real values decoded from
//!   the reconstructed ring element (serialized as `Vec<f64>` bincode), not
//!   BFV-decoded `Vec<u64>` bytes.

use anyhow::{anyhow, bail, Context, Result};
use e3_events::OrderedSet;
use e3_utils::{ArcBytes, SharedRng};
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParameters, CkksSecretKey};
use fhe::trckks::{
    CkksCrp, CkksHybridRelinKeyGenerator, CkksHybridRelinKeyShare, CkksPublicKeyShare,
    CkksRelinKeyGenerator, CkksRelinKeyShare, R1Aggregated, R2, TRCKKS,
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{
    Deserialize as FheDeserialize, DeserializeParametrized, DeserializeWithContext,
    Serialize as FheSerialize,
};
use std::sync::Arc;

/// Which scheme an E3's encoded parameters select.
pub enum SchemeParams {
    /// BFV parameters (the existing default).
    Bfv(Arc<fhe::bfv::BfvParameters>),
    /// CKKS parameters (approximate real-number arithmetic).
    Ckks(Arc<CkksParameters>),
}

impl SchemeParams {
    /// Decode E3 params bytes: ABI-encoded BFV first (the on-chain format
    /// `E3Requested` carries today), then protobuf CKKS. The formats are
    /// mutually exclusive (ABI tuple vs protobuf message), so
    /// first-successful-decode is unambiguous.
    pub fn from_encoded(bytes: &[u8]) -> Result<Self> {
        if let Ok(params) = e3_fhe_params::decode_bfv_params_arc(bytes) {
            return Ok(Self::Bfv(params));
        }
        if let Ok(params) = CkksParameters::try_deserialize(bytes) {
            return Ok(Self::Ckks(Arc::new(params)));
        }
        bail!("E3 params decode as neither BFV nor CKKS")
    }
}

/// Threshold-CKKS keyshare material produced by [`CkksFhe::generate_keyshare`].
///
/// The pk share is broadcast; the share matrices are dealt row-wise to the
/// other members (row `j` to party `j+1`); the secret coeffs stay local
/// (encrypted at rest by the caller, like the BFV sk share). `Debug` is
/// implemented manually to keep `sk_coeffs` out of logs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CkksKeyshareMaterial {
    /// This party's serialized public-key share (`p0` polynomial).
    pub pk_share: Vec<u8>,
    /// Dealt Shamir share matrices of the secret contribution
    /// (`[moduli][n_parties][degree]`, flattened per modulus).
    pub sk_sss: Vec<Vec<u64>>,
    /// Dealt Shamir share matrices of the smudging contribution.
    pub es_sss: Vec<Vec<u64>>,
    /// Matrix rows (n_parties) and cols (degree) for reassembly.
    pub rows: usize,
    /// Columns per matrix (ring degree).
    pub cols: usize,
    /// This party's secret contribution coefficients (SENSITIVE).
    pub sk_coeffs: Vec<i64>,
    /// This party's smudging contribution coefficients (SENSITIVE) — the
    /// C2b proof witness. Same lifetime/at-rest discipline as `sk_coeffs`.
    pub es_coeffs: Vec<i64>,
    /// The pk-share key-generation error `e` coefficients (SENSITIVE) —
    /// the C1-CKKS proof witness (`pk_share = -a*sk + e`). Serde-default
    /// so pre-C1 persisted material still loads (empty = no C1 witness).
    #[serde(default)]
    pub e_coeffs: Vec<i64>,
}

impl std::fmt::Debug for CkksKeyshareMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksKeyshareMaterial")
            .field("pk_share_len", &self.pk_share.len())
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .field("sk_coeffs", &"<redacted>")
            .finish()
    }
}

/// A hybrid round-1 share together with the secrets that produced it (the
/// C8-CKKS witness). SENSITIVE: `u` is the ceremony's ephemeral secret.
#[derive(Clone)]
pub struct CkksHybridRound1Witness {
    /// Serialized share (hybrid wire framing) — what goes on the wire.
    pub share: Vec<u8>,
    /// Ephemeral `u` coefficients (CBD, parameter variance).
    pub u_coeffs: Vec<i64>,
    /// h0-leg errors, one per digit.
    pub e0_coeffs: Vec<Vec<i64>>,
    /// h1-leg errors, one per digit.
    pub e1_coeffs: Vec<Vec<i64>>,
}

impl std::fmt::Debug for CkksHybridRound1Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksHybridRound1Witness")
            .field("share_len", &self.share.len())
            .field("u_coeffs", &"<redacted>")
            .finish()
    }
}

/// Derive the hybrid ceremony's ephemeral `u` coefficients from the
/// per-party seed EXACTLY as fhe.rs
/// `CkksHybridRelinKeyGenerator::new_from_seed` does (bytes 30/31 flipped
/// by `0x48`/`0x59`, then a ChaCha8 CBD sample with the parameter
/// variance). Pinned by `hybrid_u_matches_the_fork_generator`.
pub fn hybrid_u_coeffs_from_seed(params: &CkksParameters, u_seed: [u8; 32]) -> Result<Vec<i64>> {
    use rand::SeedableRng;
    use zeroize::Zeroize;
    let mut seed = u_seed;
    seed[30] ^= 0x48;
    seed[31] ^= 0x59;
    let mut u_rng = rand_chacha::ChaCha8Rng::from_seed(seed);
    let u = fhe_util::sample_vec_cbd(params.degree(), params.variance(), &mut u_rng)
        .map_err(|e| anyhow!("cbd: {e}"))?;
    seed.zeroize();
    Ok(u)
}

/// CKKS counterpart of [`crate::runtime::GetAggregatePublicKey`].
pub struct GetCkksAggregatePublicKey {
    pub keyshares: OrderedSet<ArcBytes>,
}

/// CKKS counterpart of [`crate::runtime::GetAggregatePlaintext`]: combine
/// `threshold + 1` decryption shares and decode to real values.
pub struct GetCkksAggregatePlaintext {
    /// Serialized decryption-share polynomials, in `party_ids` order.
    pub decryption_shares: Vec<ArcBytes>,
    /// 1-based reconstructing party ids.
    pub party_ids: Vec<u64>,
    /// The evaluated ciphertext being opened.
    pub ciphertext_output: Vec<u8>,
}

/// CKKS counterpart of [`crate::runtime::DecryptCiphertext`]: compute one
/// party's decryption share from its aggregated share polynomials.
pub struct CkksDecryptionShareRequest {
    /// This party's aggregated secret-key share polynomial (level 0).
    pub sk_poly_sum: Vec<u8>,
    /// This party's aggregated smudging share polynomial (level 0).
    pub es_poly_sum: Vec<u8>,
    /// The ciphertext to decrypt.
    pub ciphertext: Vec<u8>,
}

/// CKKS FHE runtime adaptor (threshold flavour).
#[derive(Clone)]
pub struct CkksFhe {
    pub params: Arc<CkksParameters>,
    pub crp: CkksCrp,
    n_parties: usize,
    threshold: usize,
    rng: SharedRng,
}

impl CkksFhe {
    /// Create the adaptor for one E3's committee shape.
    pub fn new(
        params: Arc<CkksParameters>,
        crp: CkksCrp,
        n_parties: usize,
        threshold: usize,
        rng: SharedRng,
    ) -> Result<Self> {
        // Validate the committee shape eagerly (TRCKKS::new re-validates).
        TRCKKS::new(n_parties, threshold, params.clone())?;
        Ok(Self {
            params,
            crp,
            n_parties,
            threshold,
            rng,
        })
    }

    /// Build from encoded CKKS params + a deterministic CRP seed (the CKKS
    /// analogue of `create_deterministic_crp_from_default_seed`).
    pub fn from_encoded(
        bytes: &[u8],
        crp_seed: [u8; 32],
        n_parties: usize,
        threshold: usize,
        rng: SharedRng,
    ) -> Result<Self> {
        let params = Arc::new(CkksParameters::try_deserialize(bytes)?);
        let crp = CkksCrp::from_seed(&params, crp_seed)?;
        Self::new(params, crp, n_parties, threshold, rng)
    }

    fn trckks(&self) -> Result<TRCKKS> {
        Ok(TRCKKS::new(
            self.n_parties,
            self.threshold,
            self.params.clone(),
        )?)
    }

    /// Generate this party's DKG contribution: pk share + dealt Shamir
    /// matrices + local secret. `smudging_bits` must come from
    /// `fhe::trckks::CkksSmudgingBoundCalculator` for the target circuit.
    pub fn generate_keyshare(&self, smudging_bits: usize) -> Result<CkksKeyshareMaterial> {
        let trckks = self.trckks()?;
        let mut rng = self.rng.lock().map_err(|_| anyhow!("rng poisoned"))?;

        let sk = CkksSecretKey::random(&self.params, &mut *rng);
        // The pk-share error is sampled HERE (not inside fhe.rs) so it can
        // serve as the C1-CKKS witness; the share is rebuilt with the
        // public math of `CkksPublicKeyShare::new` (pinned against the
        // fork in zk-helpers' `pk_generation_ckks` tests).
        let e_coeffs =
            e3_zk_helpers::circuits::threshold::pk_generation_ckks::sample_pk_share_error(
                &self.params,
                &mut *rng,
            );
        let pk_share = e3_zk_helpers::circuits::threshold::pk_generation_ckks::compute_pk_share(
            &self.params,
            &self.crp,
            sk.coeffs.as_ref(),
            &e_coeffs,
        )
        .map_err(|e| anyhow!("pk share: {e}"))?;

        let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref())?;
        let sk_mats = trckks.generate_secret_shares_from_poly(sk_poly, &mut *rng)?;
        let es = trckks.generate_smudging_error(smudging_bits, &mut *rng)?;
        // Keep the raw smudging coefficients as the C2b proof witness.
        // i64 holds smudging bounds up to 2^62; the flooding calculator's
        // bits stay well below that for any parameter set the encoder
        // itself can represent (coefficients are i64-capped).
        let es_coeffs: Vec<i64> = es
            .iter()
            .map(|c| {
                i64::try_from(c).map_err(|_| {
                    anyhow!("smudging coefficient exceeds i64 — smudging_bits too large")
                })
            })
            .collect::<Result<_>>()?;
        let es_poly = trckks.smudging_to_poly(&es)?;
        let es_mats = trckks.generate_secret_shares_from_poly(es_poly, &mut *rng)?;

        let rows = sk_mats.first().map_or(0, |m| m.nrows());
        let cols = sk_mats.first().map_or(0, |m| m.ncols());
        Ok(CkksKeyshareMaterial {
            pk_share: pk_share.p0_to_bytes(),
            sk_sss: sk_mats
                .iter()
                .map(|m| m.iter().copied().collect())
                .collect(),
            es_sss: es_mats
                .iter()
                .map(|m| m.iter().copied().collect())
                .collect(),
            rows,
            cols,
            sk_coeffs: sk.coeffs.to_vec(),
            es_coeffs,
            e_coeffs,
        })
    }

    /// Aggregate broadcast pk shares into the joint public key.
    pub fn get_aggregate_public_key(&self, msg: GetCkksAggregatePublicKey) -> Result<Vec<u8>> {
        let ctx = self.params.context_at_level(0)?;
        let shares = msg
            .keyshares
            .iter()
            .map(|bytes| {
                let p0 = Poly::<fhe_math::rq::Ntt>::from_bytes(bytes, ctx)
                    .context("failed to decode pk share")?;
                Ok(CkksPublicKeyShare::from_parts(
                    self.params.clone(),
                    p0,
                    self.crp.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(CkksPublicKeyShare::aggregate(&shares)?.to_bytes())
    }

    /// Aggregate dealt rows (one `[L][degree]` row from each dealer) into
    /// this party's serialized share polynomial (level 0).
    pub fn aggregate_rows<'a>(
        &self,
        rows: impl Iterator<Item = &'a [Vec<u64>]>,
    ) -> Result<Vec<u8>> {
        let trckks = self.trckks()?;
        let collected = rows
            .map(|row| {
                let l = row.len();
                let degree = row.first().map_or(0, |r| r.len());
                let mut arr = ndarray::Array2::<u64>::zeros((l, degree));
                for (m, coeffs) in row.iter().enumerate() {
                    if coeffs.len() != degree {
                        bail!("ragged dealt row: modulus {m} has {} coeffs", coeffs.len());
                    }
                    for (i, &c) in coeffs.iter().enumerate() {
                        arr[[m, i]] = c;
                    }
                }
                Ok(arr)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(trckks.aggregate_collected_shares(&collected)?.to_bytes())
    }

    /// Compute this party's decryption share for an evaluated ciphertext.
    pub fn decryption_share(&self, msg: CkksDecryptionShareRequest) -> Result<Vec<u8>> {
        let trckks = self.trckks()?;
        let ct = CkksCiphertext::from_bytes(&msg.ciphertext, &self.params)
            .context("failed to decode ciphertext")?;
        let level0 = self.params.context_at_level(0)?;
        let sk = Poly::<PowerBasis>::from_bytes(&msg.sk_poly_sum, level0)
            .context("failed to decode sk share poly")?;
        let es = Poly::<PowerBasis>::from_bytes(&msg.es_poly_sum, level0)
            .context("failed to decode es share poly")?;
        let sk_at = trckks.project_share_to_level(&sk, ct.level)?;
        let es_at = trckks.project_share_to_level(&es, ct.level)?;
        Ok(trckks
            .decryption_share(&ct, sk_at.into_ntt(), es_at)?
            .to_bytes())
    }

    /// Combine `threshold + 1` decryption shares and decode the CKKS
    /// plaintext to real values (bincode-serialized `Vec<f64>`).
    pub fn get_aggregate_plaintext(&self, msg: GetCkksAggregatePlaintext) -> Result<Vec<u8>> {
        let trckks = self.trckks()?;
        let ct = CkksCiphertext::from_bytes(&msg.ciphertext_output, &self.params)
            .context("failed to decode ciphertext")?;
        let ct_ctx = self.params.context_at_level(ct.level)?;
        let shares = msg
            .decryption_shares
            .iter()
            .map(|bytes| {
                Poly::<PowerBasis>::from_bytes(bytes, ct_ctx)
                    .context("failed to decode decryption share")
            })
            .collect::<Result<Vec<_>>>()?;
        let party_ids: Vec<usize> = msg.party_ids.iter().map(|&x| x as usize).collect();
        let pt = trckks.decrypt(shares, party_ids, &ct)?;
        let values = CkksEncoder::new(&self.params).decode(&pt)?;
        Ok(bincode::serialize(&values)?)
    }

    /// Decode the output of [`CkksFhe::get_aggregate_plaintext`].
    pub fn decode_plaintext_output(bytes: &[u8]) -> Result<Vec<f64>> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Draw a fresh 32-byte secret seed from the runtime RNG (used for the
    /// relin ceremony's per-party ephemeral secret).
    pub fn random_seed(&self) -> Result<[u8; 32]> {
        let mut rng = self.rng.lock().map_err(|_| anyhow!("rng poisoned"))?;
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut *rng, &mut seed);
        Ok(seed)
    }

    // ---- Multiparty relinearization-key ceremony (two rounds/level) ----
    //
    // The generator's ephemeral secret `u` must be IDENTICAL between
    // round 1 and round 2; both methods reconstruct it deterministically
    // from `(u_seed, level)`, so the machine only persists the 32-byte
    // seed across the round boundary (encrypted at rest, zeroized after).

    /// Round 1 of the relin ceremony for `level`: this party's share.
    pub fn relin_round_1(
        &self,
        sk_coeffs: &[i64],
        crp_seed: [u8; 32],
        u_seed: [u8; 32],
        level: usize,
    ) -> Result<Vec<u8>> {
        let mut rng = self.rng.lock().map_err(|_| anyhow!("rng poisoned"))?;
        let sk = CkksSecretKey::new(sk_coeffs.to_vec(), &self.params);
        let len = self.params.context_at_level(level)?.moduli().len();
        let crp = CkksCrp::vec_from_seed_leveled(&self.params, crp_seed, len, level)?;
        let generator =
            CkksRelinKeyGenerator::new_leveled_from_seed(&sk, &crp, level, u_seed, &mut *rng)?;
        Ok(generator.round_1(&mut *rng)?.to_bytes())
    }

    /// Aggregate all parties' round-1 shares (order-independent sum).
    pub fn relin_aggregate_round_1(&self, shares: &[Vec<u8>]) -> Result<Vec<u8>> {
        let parsed = shares
            .iter()
            .map(|b| CkksRelinKeyShare::<fhe::trckks::R1>::from_bytes(b, &self.params))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(CkksRelinKeyShare::<R1Aggregated>::from_shares(parsed)?.to_bytes())
    }

    /// Round 2 of the relin ceremony: this party's share over the
    /// aggregated round 1. `u_seed` MUST equal the round-1 seed.
    pub fn relin_round_2(
        &self,
        sk_coeffs: &[i64],
        crp_seed: [u8; 32],
        u_seed: [u8; 32],
        level: usize,
        r1_aggregated: &[u8],
    ) -> Result<Vec<u8>> {
        let mut rng = self.rng.lock().map_err(|_| anyhow!("rng poisoned"))?;
        let sk = CkksSecretKey::new(sk_coeffs.to_vec(), &self.params);
        let len = self.params.context_at_level(level)?.moduli().len();
        let crp = CkksCrp::vec_from_seed_leveled(&self.params, crp_seed, len, level)?;
        let generator =
            CkksRelinKeyGenerator::new_leveled_from_seed(&sk, &crp, level, u_seed, &mut *rng)?;
        let r1 = std::sync::Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_bytes(
            r1_aggregated,
            &self.params,
        )?);
        Ok(generator.round_2(&r1, &mut *rng)?.to_bytes())
    }

    /// Aggregate all parties' round-2 shares into the joint relin key.
    pub fn relin_aggregate_round_2(
        &self,
        shares: &[Vec<u8>],
        r1_aggregated: &[u8],
    ) -> Result<Vec<u8>> {
        let parsed = shares
            .iter()
            .map(|b| CkksRelinKeyShare::<R2>::from_bytes(b, &self.params))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let r1 = std::sync::Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_bytes(
            r1_aggregated,
            &self.params,
        )?);
        Ok(CkksRelinKeyShare::<R2>::aggregate_into_key_with_r1(parsed, r1)?.to_bytes())
    }

    // ---- HYBRID relinearization-key ceremony (two rounds, ONE key) ----
    //
    // Same protocol over `Q·P` with the digit gadget: no level parameter,
    // one share per round, one joint `CkksHybridRelinKey` serving every
    // level. Requires params with special primes (`hybrid_enabled()`).
    // The ephemeral `u` is again derived from `u_seed` in both rounds.

    /// True when these params carry special primes (hybrid ceremony).
    pub fn hybrid_enabled(&self) -> bool {
        self.params.hybrid_enabled()
    }

    /// Round 1 of the HYBRID relin ceremony: this party's share.
    pub fn hybrid_relin_round_1(
        &self,
        sk_coeffs: &[i64],
        crp_seed: [u8; 32],
        u_seed: [u8; 32],
    ) -> Result<Vec<u8>> {
        Ok(self
            .hybrid_relin_round_1_extended(sk_coeffs, crp_seed, u_seed)?
            .share)
    }

    /// Round 1 of the HYBRID ceremony WITH the C8 witnesses: the share
    /// bytes plus the ephemeral `u` and the per-digit errors that produced
    /// it. `u` is derived from `u_seed` EXACTLY as
    /// `CkksHybridRelinKeyGenerator::new_from_seed` derives it (same
    /// domain-separated ChaCha8 stream), so round 2 — which still runs
    /// through the fork's generator from the same seed — uses the same
    /// `u`. The share is rebuilt with the public math
    /// (`zk_helpers::relin_round1_hybrid_ckks::compute_round_1_share`,
    /// pinned against the fork's `round_1` by aggregating into a working
    /// key).
    pub fn hybrid_relin_round_1_extended(
        &self,
        sk_coeffs: &[i64],
        crp_seed: [u8; 32],
        u_seed: [u8; 32],
    ) -> Result<CkksHybridRound1Witness> {
        use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks::compute_round_1_share;
        let crp = CkksCrp::vec_from_seed_qp(&self.params, crp_seed)?;
        let u_coeffs = hybrid_u_coeffs_from_seed(&self.params, u_seed)?;
        let (e0, e1) = {
            let mut rng = self.rng.lock().map_err(|_| anyhow!("rng poisoned"))?;
            let cbd = |rng: &mut rand_chacha::ChaCha20Rng| -> Result<Vec<i64>> {
                fhe_util::sample_vec_cbd(self.params.degree(), self.params.variance(), rng)
                    .map_err(|e| anyhow!("cbd: {e}"))
            };
            let dnum = self.params.dnum();
            let mut e0 = Vec::with_capacity(dnum);
            let mut e1 = Vec::with_capacity(dnum);
            for _ in 0..dnum {
                e0.push(cbd(&mut rng)?);
            }
            for _ in 0..dnum {
                e1.push(cbd(&mut rng)?);
            }
            (e0, e1)
        };
        let share = compute_round_1_share(&self.params, &crp, sk_coeffs, &u_coeffs, &e0, &e1)
            .map_err(|e| anyhow!("hybrid round 1: {e}"))?;
        Ok(CkksHybridRound1Witness {
            share: share.to_bytes(),
            u_coeffs,
            e0_coeffs: e0,
            e1_coeffs: e1,
        })
    }

    /// Aggregate all parties' hybrid round-1 shares.
    pub fn hybrid_relin_aggregate_round_1(&self, shares: &[Vec<u8>]) -> Result<Vec<u8>> {
        let parsed = shares
            .iter()
            .map(|b| CkksHybridRelinKeyShare::<fhe::trckks::R1>::from_bytes(b, &self.params))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(parsed)?.to_bytes())
    }

    /// Round 2 of the HYBRID relin ceremony over the aggregated round 1.
    /// `u_seed` MUST equal the round-1 seed.
    pub fn hybrid_relin_round_2(
        &self,
        sk_coeffs: &[i64],
        crp_seed: [u8; 32],
        u_seed: [u8; 32],
        r1_aggregated: &[u8],
    ) -> Result<Vec<u8>> {
        let mut rng = self.rng.lock().map_err(|_| anyhow!("rng poisoned"))?;
        let sk = CkksSecretKey::new(sk_coeffs.to_vec(), &self.params);
        let crp = CkksCrp::vec_from_seed_qp(&self.params, crp_seed)?;
        let generator = CkksHybridRelinKeyGenerator::new_from_seed(&sk, &crp, u_seed, &mut *rng)?;
        let r1 = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_bytes(
            r1_aggregated,
            &self.params,
        )?);
        Ok(generator.round_2(&r1, &mut *rng)?.to_bytes())
    }

    /// Aggregate all parties' hybrid round-2 shares into the ONE joint
    /// hybrid relin key (`CkksHybridRelinKey::to_bytes`).
    pub fn hybrid_relin_aggregate_round_2(
        &self,
        shares: &[Vec<u8>],
        r1_aggregated: &[u8],
    ) -> Result<Vec<u8>> {
        let parsed = shares
            .iter()
            .map(|b| CkksHybridRelinKeyShare::<R2>::from_bytes(b, &self.params))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let r1 = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_bytes(
            r1_aggregated,
            &self.params,
        )?);
        Ok(CkksHybridRelinKeyShare::<R2>::aggregate_into_key_with_r1(parsed, r1)?.to_bytes())
    }
}
