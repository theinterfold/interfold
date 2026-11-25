// SPDX-License-Identifier: LGPL-3.0-only

//! Private, write-once checkpoints. No event publication or worker dispatch at this boundary.

use super::ConfirmedSynchronizedDkgSetup;
use crate::ThresholdKeyshareRepositoryFactory;
use alloy::primitives::{keccak256, Address, B256};
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_crypto::{Cipher, SensitiveBytes};
use e3_data::{DataStore, Repositories};
use e3_events::{DecryptionshareCreated, ProofType};
use e3_fhe_params::BfvProfile;
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_request::canonical_key::SynchronizedDecryptionPlan;
use e3_utils::ArcBytes;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use rand::RngCore;
use zeroize::Zeroizing;

/// Replaying the v1 sampler starts the same private stream at offset zero.
pub struct NoiseAllocation {
    seed: Zeroizing<[u8; 32]>,
    profile: BfvProfile,
    committee: CiphernodesCommitteeSize,
}

impl NoiseAllocation {
    pub fn coefficients(&self) -> Result<Vec<num_bigint::BigInt>> {
        e3_trbfv::synchronized::contribution_noise_v1(self.profile, self.committee, &self.seed)
    }
}

pub enum ContributionProgress {
    Reserved(NoiseAllocation),
    Generated {
        noise: NoiseAllocation,
        share: ArcBytes,
    },
    Signed(DecryptionshareCreated),
}

pub struct ContributionStore<'a> {
    store: DataStore,
    cipher: &'a Cipher,
    plan: SynchronizedDecryptionPlan,
    owner: u32,
    binding: B256,
}

impl<'a> ContributionStore<'a> {
    /// Below-admission definition; the live caller must rederive the plan and `confirmed_setup`
    /// and check effects/terminal state before releasing work.
    pub fn for_definition(
        repos: &Repositories,
        plan: SynchronizedDecryptionPlan,
        setup: &ConfirmedSynchronizedDkgSetup<'_>,
        local_signer: Address,
        cipher: &'a Cipher,
    ) -> Result<Self> {
        let owner = setup.recipient();
        ensure!(
            plan.profile() == setup.profile()
                && plan.committee() == setup.committee()
                && plan.matches_setup(setup.authority())
                && plan.signer(owner)? == local_signer,
            "local setup or signer differs from designated request"
        );
        // Do not scope by ciphertext, owner, set, or correlation: a conflict for this local E3
        // must hit the same allocation, not create another namespace.
        let store = repos
            .threshold_keyshare_recovery_payloads(plan.e3_id())
            .scope("synchronized-contribution-v1");
        let binding = plan.local_contribution_binding_v1(owner)?;
        Ok(Self {
            store,
            cipher,
            plan,
            owner,
            binding,
        })
    }

    fn header(&self, slot: &str, parent: B256) -> B256 {
        keccak256([self.binding.as_slice(), slot.as_bytes(), parent.as_slice()].concat())
    }

    /// Read-check-flush even on redrive. An inserted value can be visible after its first
    /// flush failed. The digest of the exact sealed predecessor binds adjacent checkpoints.
    async fn slot(
        &self,
        name: &str,
        parent: B256,
        proposed: Option<&[u8]>,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, B256)>> {
        let store = self.store.scope(name);
        let header = self.header(name, parent);
        let (value, flushed): (SensitiveBytes, bool) = match store.read_checked().await? {
            Some(saved) => (saved, false),
            None => {
                let Some(bytes) = proposed else {
                    return Ok(None);
                };
                let sealed = SensitiveBytes::new([header.as_slice(), bytes].concat(), self.cipher)?;
                if store.write_if_absent_sync(&sealed).await? {
                    (sealed, true)
                } else {
                    (
                        store
                            .read_checked()
                            .await?
                            .context("concurrent contribution checkpoint disappeared")?,
                        false,
                    )
                }
            }
        };
        let mut plain = value.access(self.cipher)?;
        ensure!(
            plain.starts_with(header.as_slice()),
            "contribution belongs to another context or predecessor"
        );
        plain.drain(..32);
        if !flushed {
            store.flush_sync().await?;
        }
        Ok(Some((plain, keccak256(bincode::serialize(&value)?))))
    }

    async fn allocation(&self, create: bool) -> Result<(NoiseAllocation, B256)> {
        let existing = self.slot("allocation", B256::ZERO, None).await?;
        let (bytes, parent) = if let Some(value) = existing {
            value
        } else {
            ensure!(create, "missing noise allocation");
            for slot in ["share", "signed"] {
                ensure!(
                    self.store
                        .scope(slot)
                        .read_checked::<SensitiveBytes>()
                        .await?
                        .is_none(),
                    "missing allocation for existing contribution"
                );
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::rng().fill_bytes(seed.as_mut());
            self.slot("allocation", B256::ZERO, Some(seed.as_slice()))
                .await?
                .context("missing recorded allocation")?
        };
        ensure!(bytes.len() == 32, "invalid C6 noise allocation");
        Ok((
            NoiseAllocation {
                seed: Zeroizing::new(bytes.as_slice().try_into()?),
                profile: self.plan.profile(),
                committee: self.plan.committee(),
            },
            parent,
        ))
    }

    /// First live authorization only. A duplicate observes the winning atomic insert.
    pub async fn reserve(&self) -> Result<ContributionProgress> {
        self.progress(true).await
    }

    /// After restart or an ambiguous dispatch, absence is not evidence of a first authorization.
    pub async fn resume(&self) -> Result<ContributionProgress> {
        self.progress(false).await
    }

    async fn progress(&self, first_authorization: bool) -> Result<ContributionProgress> {
        let (noise, parent) = self.allocation(first_authorization).await?;
        let Some((share, parent)) = self.slot("share", parent, None).await? else {
            ensure!(
                self.store
                    .scope("signed")
                    .read_checked::<SensitiveBytes>()
                    .await?
                    .is_none(),
                "signed contribution is missing its share"
            );
            return Ok(ContributionProgress::Reserved(noise));
        };
        let share = ArcBytes::from_bytes(&share);
        let Some((bytes, _)) = self.slot("signed", parent, None).await? else {
            return Ok(ContributionProgress::Generated { noise, share });
        };
        let bundle = e3_utils::deserialize_exact(&bytes)?;
        self.validate_bundle(&bundle, &share)?;
        Ok(ContributionProgress::Signed(bundle))
    }

    pub async fn record_generated(&self, share: &ArcBytes) -> Result<()> {
        let (_, parent) = self.allocation(false).await?;
        if self
            .store
            .scope("signed")
            .read_checked::<SensitiveBytes>()
            .await?
            .is_some()
        {
            ensure!(
                self.slot("share", parent, None).await?.is_some(),
                "signed contribution is missing its share"
            );
        }
        let cfg = Configs::for_profile(self.plan.profile(), self.plan.committee())?;
        e3_trbfv::helpers::try_poly_pb_from_bytes(share, &cfg.threshold)?;
        let (saved, _) = self
            .slot("share", parent, Some(share))
            .await?
            .context("missing generated share")?;
        ensure!(
            saved.as_slice() == &share[..],
            "different native share already recorded"
        );
        Ok(())
    }

    pub async fn record_signed(&self, bundle: &DecryptionshareCreated) -> Result<()> {
        let (_, parent) = self.allocation(false).await?;
        let (share, parent) = self
            .slot("share", parent, None)
            .await?
            .context("missing native share")?;
        self.validate_bundle(bundle, &ArcBytes::from_bytes(&share))?;
        let bytes = bincode::serialize(bundle)?;
        let (saved, _) = self
            .slot("signed", parent, Some(&bytes))
            .await?
            .context("missing signed bundle")?;
        ensure!(
            saved.as_slice() == bytes,
            "different signed contribution already recorded"
        );
        Ok(())
    }

    fn validate_bundle(&self, bundle: &DecryptionshareCreated, share: &ArcBytes) -> Result<()> {
        let signer = self.plan.signer(self.owner)?;
        let [signed] = bundle.signed_decryption_proofs.as_slice() else {
            anyhow::bail!("expected one signed C6")
        };
        ensure!(
            bundle.e3_id == *self.plan.e3_id()
                && bundle.party_id == u64::from(self.owner)
                && bundle.node.parse::<Address>()? == signer
                && bundle.decryption_share.as_slice() == std::slice::from_ref(share)
                && signed.payload.e3_id == bundle.e3_id
                && signed.payload.proof_type == ProofType::C6ThresholdShareDecryption
                && signed.payload.proof.circuit == CircuitName::ThresholdShareDecryption
                && signed.verify_address(&signer)?,
            "signed contribution differs from local owner, phase, or native share"
        );
        let cfg = Configs::for_profile(self.plan.profile(), self.plan.committee())?;
        let proof = &signed.payload.proof;
        let row = PublicSignals::decode(&cfg, proof.circuit, &proof.public_signals)?;
        let poly = e3_trbfv::helpers::try_poly_pb_from_bytes(share, &cfg.threshold)?;
        let commitment = e3_zk_witness::compute_threshold_decryption_share_commitment(
            &CrtPolynomial::from_fhe_polynomial(&poly),
            cfg.share_bit,
            cfg.threshold.degree(),
        );
        ensure!(
            self.plan.matches_c6(self.owner, &row)
                && row.decryption_share_commitment() == Some(super::commitment_field(&commitment)?),
            "signed C6 row differs from the confirmed plan or full native share"
        );
        Ok(())
    }
}
