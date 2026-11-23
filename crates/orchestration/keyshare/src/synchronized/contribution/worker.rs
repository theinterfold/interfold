// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::Proof;
use e3_request::canonical_key::CanonicalPublicKeys;
use e3_task_pool::{scoped_task_group, TaskPool, TaskTimeouts};
use e3_zk_prover::{synchronized::partial::PreparedPartial, ZkProver};

pub enum LocalContribution {
    ReadyToSign { share: ArcBytes, proof: Proof },
    Signed(DecryptionshareCreated),
}

/// Private work runs in the same bounded pool and cancellation group as this node's E3 effects.
pub struct ContributionWorker {
    pub pool: TaskPool,
    pub task_scope: String,
    pub prover: ZkProver,
}

impl ContributionWorker {
    /// Below admission. The caller owns live phase/deadline checks and the first reservation.
    /// A redrive only reads an allocation; neither queueing nor replay is authority to draw again.
    pub async fn run_definition(
        &self,
        store: &ContributionStore,
        keys: &CanonicalPublicKeys,
        ciphertext: &ArcBytes,
        sk_poly_sum: &SensitiveBytes,
    ) -> Result<LocalContribution> {
        self.run_fenced(store, keys, ciphertext, sk_poly_sum, None)
            .await
    }

    pub(crate) async fn run_fenced(
        &self,
        store: &ContributionStore,
        keys: &CanonicalPublicKeys,
        ciphertext: &ArcBytes,
        sk_poly_sum: &SensitiveBytes,
        deadline: Option<u64>,
    ) -> Result<LocalContribution> {
        let current = {
            let (keys, plan, ct) = (keys.clone(), store.plan.clone(), ciphertext.clone());
            move || {
                if let Some(deadline) = deadline {
                    e3_zk_prover::synchronized::fixed_set::before_expiry(deadline)?;
                }
                plan.check_current(&keys, &ct)
            }
        };
        current()?;
        let group = scoped_task_group(&self.task_scope, store.plan.e3_id());
        let (allocation, parent) = store.allocation(false).await?;
        let prepare = {
            let (plan, owner, ct) = (store.plan.clone(), store.owner, ciphertext.clone());
            let (sk, outgoing, incoming) = (
                sk_poly_sum.clone(),
                store.outgoing.clone(),
                store.incoming.clone(),
            );
            let (cipher, current) = (store.cipher.clone(), current.clone());
            move || {
                current()?;
                PreparedPartial::prepare(
                    &plan,
                    owner,
                    &ct,
                    &sk,
                    &outgoing,
                    &incoming,
                    &allocation.coefficients()?,
                    &cipher,
                )
            }
        };
        let prepared = self
            .pool
            .spawn_in_group(
                group.clone(),
                "synchronized native partial".into(),
                TaskTimeouts::default(),
                prepare,
            )
            .await??;
        current()?;
        let share = prepared.share().clone();
        ensure!(
            store.allocation(false).await?.1 == parent,
            "native allocation changed"
        );
        store.record_generated_at(&share, parent).await?;
        // Reopen the flushed chain. A competing writer can only have recorded the same share.
        let cached = match store.resume().await? {
            ContributionProgress::Generated { share: saved, .. } if saved == share => None,
            ContributionProgress::Signed(bundle)
                if bundle.decryption_share == std::slice::from_ref(&share) =>
            {
                Some(bundle)
            }
            _ => anyhow::bail!("generated share differs from reopened checkpoint"),
        };
        let verify = {
            let current = current.clone();
            let prover = self.prover.clone();
            let job = format!("sync-c6-{:x}", store.binding);
            let signed = cached
                .as_ref()
                .map(|b| b.signed_decryption_proofs[0].payload.proof.clone());
            move || -> Result<Proof> {
                current()?;
                prepared.verified_proof(&prover, signed, &job)
            }
        };
        let proof = self
            .pool
            .spawn_in_group(
                group,
                "synchronized C6".into(),
                TaskTimeouts::default(),
                verify,
            )
            .await??;
        store.validate_proof_row(&proof, &share)?;
        // A signature that arrived while proving wins. Redrive to verify and reuse that exact
        // proof rather than asking the signer for a second bundle.
        let result = match (cached, store.resume().await?) {
            (Some(verified), ContributionProgress::Signed(saved)) if verified == saved => {
                LocalContribution::Signed(saved)
            }
            (None, ContributionProgress::Generated { share: saved, .. }) if saved == share => {
                LocalContribution::ReadyToSign { share, proof }
            }
            _ => {
                anyhow::bail!("contribution checkpoint changed during C6; resume the saved result")
            }
        };
        current()?;
        Ok(result)
    }
}
