// SPDX-License-Identifier: LGPL-3.0-only

//! One artificial Minimum decryption. Native setup and sampling are outside the measured phases.
use super::receiver_shares;
use anyhow::{ensure, Context, Result};
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_trbfv::synchronized::PrfKey;
use e3_zk_config::{synchronized::Configs, MAX_MSG_NON_ZERO_COEFFS};
use e3_zk_witness::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
    encoding::fhe_poly_to_crt_centered,
    synchronized::{
        commitments, plaintext_aggregation, threshold_decryption::Opening, KeyBytes, SetupBinding,
    },
};
use fhe::{
    bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{Aggregate as _, PublicKeyShare},
    trbfv::{
        DecryptionShare, PartyPrfKeyTransport, PartyPrfKeys, ShareManager,
        SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator, SynchronizedDecryptor,
    },
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use num_bigint::BigInt;
use zeroize::Zeroizing;

pub const OWNERS: [u32; 2] = [0, 2];
const SETUP: SetupBinding = [2461, 1];
const DOMAIN: [u128; 2] = [2461, 2];

struct Partial {
    sk: Zeroizing<Poly<PowerBasis>>,
    outgoing: Zeroizing<Vec<KeyBytes>>,
    incoming: Zeroizing<Vec<KeyBytes>>,
    noise: Vec<BigInt>,
    share: Poly<PowerBasis>,
    sk_commitment: BigInt,
    bundle: BigInt,
}

pub struct Sample {
    ciphertext: Ciphertext,
    commitment: BigInt,
    partials: Vec<Partial>,
    plaintext: Vec<u64>,
}

impl Sample {
    pub fn generate(cfg: &Configs) -> Result<Self> {
        let committee = cfg.committee.values();
        ensure!(committee.n == 3 && committee.h == OWNERS.len() && committee.threshold == 1);
        let params = &cfg.threshold;
        let preset = cfg.profile.threshold_preset();
        let mut rng = rand::rng();
        let mut manager = ShareManager::new(committee.n, committee.threshold, params.clone())?;
        let crp = create_deterministic_crp_from_default_seed(params);
        let mut public_shares = Vec::new();
        let mut dealer_shares = Vec::new();
        let keys = (0..committee.n)
            .map(|_| {
                (0..committee.n)
                    .map(|_| PrfKey::random(cfg.profile, &mut rng))
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        for _ in OWNERS {
            let secret = SecretKey::random(params, &mut rng);
            public_shares.push(PublicKeyShare::new(&secret, crp.clone(), &mut rng)?);
            let polynomial = manager.coeffs_to_poly_level0(secret.coeffs.as_ref())?;
            dealer_shares.push(manager.generate_secret_shares_from_poly(polynomial, &mut rng)?);
        }
        let pk = PublicKey::from_shares(public_shares)?;
        let encrypt = |v, rng: &mut _| -> Result<_> {
            let pt = Plaintext::try_encode(&[v], Encoding::poly(), params)?;
            Ok(pk.try_encrypt(&pt, rng)?)
        };
        let ciphertext = &encrypt(19u64, &mut rng)? + &encrypt(18u64, &mut rng)?;
        let centered = |p| fhe_poly_to_crt_centered(p, params.moduli());
        let commitment = compute_ciphertext_commitment(
            &centered(&ciphertext[0])?,
            &centered(&ciphertext[1])?,
            cfg.aggregate_bit,
        );
        let generator = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
            params.clone(),
            committee.n,
            preset
                .search_defaults()
                .context("missing search parameters")?
                .z as usize,
            preset.lambda()?,
        )?)?;
        let decryptor =
            SynchronizedDecryptor::new(committee.n, committee.threshold, params.clone())?;
        let coordinates = OWNERS.map(|owner| owner as usize + 1);
        let mut partials = Vec::new();
        let mut native = Vec::new();
        for owner in OWNERS {
            let i = owner as usize;
            let sk = Zeroizing::new(
                manager.aggregate_collected_shares(
                    &dealer_shares
                        .iter()
                        .map(|shares| receiver_shares(shares, i, params))
                        .collect::<Vec<_>>(),
                )?,
            );
            let outgoing =
                Zeroizing::new(keys[i].iter().map(|k| *k.as_bytes()).collect::<Vec<_>>());
            let incoming = Zeroizing::new(
                OWNERS
                    .iter()
                    .map(|&peer| *keys[peer as usize][i].as_bytes())
                    .collect::<Vec<_>>(),
            );
            let sk_commitment = compute_aggregated_shares_commitment(
                &fhe_poly_to_crt_centered(&*sk, params.moduli())?,
                cfg.aggregate_bit,
            );
            let bundle = commitments::key_bundle(
                cfg,
                SETUP,
                owner,
                &OWNERS,
                &sk_commitment,
                &outgoing,
                &incoming,
            )?;
            let ring = PartyPrfKeys::from_transport(PartyPrfKeyTransport::new(
                i + 1,
                committee.n,
                outgoing.to_vec(),
                keys.iter().map(|row| *row[i].as_bytes()).collect(),
            )?)?;
            let noise = fhe_math::rq::sample_uniform_coefficients_bigint(
                &generator.smudging_bound().clone().into(),
                params.degree(),
                &mut rng,
            );
            let share = decryptor.decryption_share(
                &ciphertext,
                &(*sk).clone().into_ntt(),
                i + 1,
                &coordinates,
                generator.wrap_signed_coefficients(&noise)?,
                &ring,
            )?;
            let (share, id, set) = share.into_parts();
            native.push(DecryptionShare::from_parts(
                share.clone(),
                id,
                set,
                &ciphertext,
            )?);
            partials.push(Partial {
                sk,
                outgoing,
                incoming,
                noise,
                share,
                sk_commitment,
                bundle,
            });
        }
        let pt = decryptor.decrypt_from_shares(&native, &ciphertext)?;
        let mut plaintext = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
        ensure!(
            plaintext[0] == 37 && plaintext[1..].iter().all(|&v| v == 0),
            "native decryption did not recover 19 + 18"
        );
        plaintext.truncate(MAX_MSG_NON_ZERO_COEFFS);
        Ok(Self {
            ciphertext,
            commitment,
            partials,
            plaintext,
        })
    }

    pub fn c6_inputs(&self, cfg: &Configs, index: usize) -> Result<serde_json::Value> {
        let p = self
            .partials
            .get(index)
            .context("unknown designated slot")?;
        let owner = OWNERS[index];
        let opening = Opening {
            setup: SETUP,
            domain: DOMAIN,
            owner,
            roster: &OWNERS,
            expected_sk: &p.sk_commitment,
            expected_bundle: &p.bundle,
            expected_ct: &self.commitment,
            outgoing: &p.outgoing,
            incoming: &p.incoming,
            sk: &p.sk,
        };
        Ok(opening.prepare(
            cfg,
            &self.ciphertext,
            &p.noise,
            (
                &p.share,
                owner as usize + 1,
                &OWNERS.map(|i| i as usize + 1),
            ),
        )?)
    }

    pub fn c7_inputs(&self, cfg: &Configs, rows: &[&[u8]]) -> Result<serde_json::Value> {
        ensure!(
            rows.len() == self.partials.len(),
            "missing verified C6 rows"
        );
        let contributions = rows
            .iter()
            .zip(&self.partials)
            .map(|(row, p)| plaintext_aggregation::Contribution {
                public_signals: row,
                share: &p.share,
            })
            .collect::<Vec<_>>();
        Ok(plaintext_aggregation::prepare(
            cfg,
            SETUP,
            DOMAIN,
            &OWNERS,
            &self.ciphertext,
            &contributions,
            &self.plaintext,
        )?)
    }

    /// Independent public expected values for a standalone EVM verifier call.
    pub fn public_authority(&self) -> serde_json::Value {
        let binding = |[hi, lo]: [u128; 2]| format!("0x{hi:032x}{lo:032x}");
        serde_json::json!({
            "setup": binding(SETUP), "domain": binding(DOMAIN), "owners": OWNERS,
            "sk": self.partials.iter().map(|p| format!("0x{:064x}",p.sk_commitment)).collect::<Vec<_>>(),
            "bundles": self.partials.iter().map(|p| format!("0x{:064x}",p.bundle)).collect::<Vec<_>>(),
            "ciphertext": format!("0x{:064x}",self.commitment),
            "plaintext": self.plaintext.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>(),
        })
    }
}
