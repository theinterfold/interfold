// SPDX-License-Identifier: LGPL-3.0-only

//! One local C6 opening, held in memory between native calculation and the flushed-share proof.

use super::provenance::prove;
use crate::ZkProver;
use anyhow::{ensure, Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_events::Proof;
use e3_request::canonical_key::SynchronizedDecryptionPlan;
use e3_trbfv::synchronized::{weighted_share, SealedPrfKeys};
use e3_utils::ArcBytes;
use e3_zk_config::{synchronized::Configs, CircuitName, CircuitVariant};
use e3_zk_witness::synchronized::threshold_decryption::Opening;
use fhe::bfv::Ciphertext;
use fhe_traits::{DeserializeParametrized, Serialize};
use num_bigint::{BigInt, Sign};
use zeroize::Zeroizing;

pub struct PreparedPartial {
    owner: u32,
    share: ArcBytes,
    witness: serde_json::Value,
    config: Configs,
}

// The bounded executor requires Debug even when the receiver disappears.
impl std::fmt::Debug for PreparedPartial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPartial").finish_non_exhaustive()
    }
}

impl PreparedPartial {
    /// Below admission: the caller rechecks the plan and supplies the saved private allocation.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        plan: &SynchronizedDecryptionPlan,
        owner: u32,
        bytes: &ArcBytes,
        sk_poly_sum: &SensitiveBytes,
        outgoing: &SealedPrfKeys,
        incoming: &SealedPrfKeys,
        noise: &[BigInt],
        cipher: &Cipher,
    ) -> Result<Self> {
        let row = plan
            .designated()
            .binary_search(&owner)
            .ok()
            .context("not a designated owner")?;
        let config = Configs::for_profile(plan.profile(), plan.committee())?;
        let setup = plan.setup_binding();
        let authority = plan.authority();
        let open = |sealed: &SealedPrfKeys, count| -> Result<_> {
            let keys = sealed.open(config.profile, setup, owner, count, cipher)?;
            Ok(Zeroizing::new(
                keys.iter().map(|key| *key.as_bytes()).collect::<Vec<_>>(),
            ))
        };
        let outgoing = open(outgoing, config.committee.values().n)?;
        let incoming = open(incoming, authority.party_ids.len())?;
        let sk = Zeroizing::new(e3_trbfv::helpers::try_poly_pb_from_bytes(
            &sk_poly_sum.access(cipher)?,
            &config.threshold,
        )?);
        let ct = Ciphertext::from_bytes(bytes, &config.threshold)?;
        let native = weighted_share(
            config.profile,
            config.committee,
            owner,
            &authority.party_ids,
            plan.designated(),
            &outgoing,
            &incoming,
            &sk,
            &ct,
            noise,
        )?;
        let (share, coordinate, set) = native.into_parts();
        let field = |b: &[u8; 32]| BigInt::from_bytes_be(Sign::Plus, b);
        let opening = Opening {
            setup,
            domain: plan.domain(),
            roster: &authority.party_ids,
            owner,
            expected_sk: &field(&authority.sk_agg_commits[row]),
            expected_bundle: &field(&authority.key_bundle_commits[row]),
            expected_ct: &field(&plan.ciphertext_commitment()),
            outgoing: &outgoing,
            incoming: &incoming,
            sk: &sk,
        };
        let witness = opening.prepare(&config, &ct, noise, (&share, coordinate, &set))?;
        Ok(Self {
            owner,
            share: ArcBytes::from_bytes(&share.to_bytes()),
            witness,
            config,
        })
    }

    pub fn share(&self) -> &ArcBytes {
        &self.share
    }

    /// A cached signature still requires proof verification under the preparation profile.
    /// The caller compares the public row and native share to the current chain/checkpoint.
    pub fn verified_proof(
        self,
        prover: &ZkProver,
        cached: Option<Proof>,
        job: &str,
    ) -> Result<Proof> {
        let namespace = self
            .config
            .profile
            .artifacts_dir_for_committee(self.config.committee)?;
        let role = CircuitName::ThresholdShareDecryption;
        let proof = match cached {
            Some(proof) => proof,
            None => prove(
                prover,
                &self.config,
                role,
                self.witness,
                job,
                CircuitVariant::Recursive,
                None,
            )
            // Private ABI/witness diagnostics are not worker outcomes.
            .map_err(|error| match error.downcast_ref::<crate::ZkError>() {
                Some(
                    crate::ZkError::WitnessGenerationFailed(_)
                    | crate::ZkError::SerializationError(_)
                    | crate::ZkError::InvalidInput(_),
                ) => anyhow::anyhow!("local synchronized C6 witness preparation failed"),
                _ => error,
            })?,
        };
        ensure!(proof.circuit == role, "wrong synchronized proof role");
        ensure!(
            prover.verify_proof(&proof, job, u64::from(self.owner), &namespace)?,
            "local C6 proof failed verification"
        );
        Ok(proof)
    }
}
