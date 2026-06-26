// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    helpers::try_poly_pb_from_bytes,
    shares::{Encrypted, SharedSecret},
    TrBFVConfig,
};
use anyhow::{Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_utils::utility_types::ArcBytes;
use fhe::trbfv::ShareManager;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenEsiSssRequest {
    /// TrBFV configuration
    pub trbfv_config: TrBFVConfig,
    /// Pre-generated smudging noise polynomial (private witness, encrypted at rest).
    pub e_sm_raw: SensitiveBytes,
    /// Deterministic seed for the smudging-noise Shamir sharing. Like the secret-key path, seeding
    /// this makes the regenerated `esi_sss` byte-identical after a crash so the C3b ESM-share
    /// encryption matches what peers recorded (no equivocation / false slash). All-zero falls back
    /// to the supplied entropic RNG.
    #[serde(default)]
    pub secret_seed: [u8; 32],
}

struct InnerRequest {
    pub trbfv_config: TrBFVConfig,
    pub e_sm_raw: ArcBytes,
    pub secret_seed: [u8; 32],
}

impl GenEsiSssRequest {
    fn into_inner(self, cipher: &Cipher) -> Result<InnerRequest> {
        let e_sm_decrypted = self.e_sm_raw.access(cipher)?;
        Ok(InnerRequest {
            trbfv_config: self.trbfv_config,
            e_sm_raw: ArcBytes::from_bytes(&e_sm_decrypted),
            secret_seed: self.secret_seed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenEsiSssResponse {
    /// The smudging noise shares
    pub esi_sss: Vec<Encrypted<SharedSecret>>,
}

impl TryFrom<(InnerResponse, &Cipher)> for GenEsiSssResponse {
    type Error = anyhow::Error;
    fn try_from(
        (value, cipher): (InnerResponse, &Cipher),
    ) -> std::result::Result<Self, Self::Error> {
        Ok(GenEsiSssResponse {
            esi_sss: value
                .esi_sss
                .into_iter()
                .map(|s| Encrypted::new(s, cipher))
                .collect::<Result<_>>()?,
        })
    }
}

struct InnerResponse {
    pub esi_sss: Vec<SharedSecret>,
}

/// This function generates secret shares for the smudging noise (esi_sss) using the provided pre-generated smudging noise polynomial (e_sm_raw).
/// When implementing multiple ciphertext outputs decryptions, we are going to need multiple smudging noise polynomials,
/// so we are generating a vector of smudging noise secret shares (esi_sss) instead of just one in anticipation of that change.
/// We will also need to ensure that all of them are committed to the pk_generation circuit.
pub fn gen_esi_sss<R: RngCore + CryptoRng>(
    rng: &mut R,
    cipher: &Cipher,
    req: GenEsiSssRequest,
) -> Result<GenEsiSssResponse> {
    info!("gen_esi_sss");
    let req: InnerRequest = req.into_inner(cipher)?;

    let params = req.trbfv_config.params();
    let threshold = req.trbfv_config.threshold() as usize;
    let num_ciphernodes = req.trbfv_config.num_parties() as usize;
    let e_sm_raw = req.e_sm_raw;

    info!("gen_esi_sss:mapping...");
    let e_sm_poly = try_poly_pb_from_bytes(&e_sm_raw, &params)?;
    let mut share_manager = ShareManager::new(num_ciphernodes, threshold, params.clone())?;

    info!("gen_esi_sss:generate_secret_shares_from_poly...");

    // Deterministic share sampling when a seed is supplied (see `GenEsiSssRequest::secret_seed`),
    // so a re-issued request reproduces byte-identical shares; entropic fallback when unseeded.
    let mut rng = if req.secret_seed == [0u8; 32] {
        ChaCha20Rng::from_rng(rng)
    } else {
        ChaCha20Rng::from_seed(req.secret_seed)
    };
    let rng = &mut rng;

    let esi_sss = vec![SharedSecret::from(
        share_manager
            .generate_secret_shares_from_poly(e_sm_poly.into(), rng)
            .context("Failed to generate secret shares from poly")?,
    )];

    info!("gen_esi_sss:returning...");

    (InnerResponse { esi_sss }, cipher).try_into()
}
