// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::synchronized::{ContributionStore, ContributionWorker, LocalContribution};
use e3_events::{DecryptionshareCreated, ProofPayload};

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn observe_contribution_opening(
        &mut self,
        id: &E3id,
        ec: &EventContext<Sequenced>,
    ) {
        if self.effects_enabled
            && self.state.get().is_some_and(|state| state.e3_id == *id)
            && self.canonical_keys.first_live_opening(id).as_ref() == Some(ec)
        {
            self.live_opening = true;
        }
    }
    pub(in crate::actors::threshold_keyshare) fn drive_contribution(
        &mut self,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        if self.params_profile.protocol() != e3_fhe_params::BfvDecryptionProtocol::Synchronized
            || !self.params_profile.admission_enabled()
        {
            return Ok(());
        }
        self.drive_contribution_definition(ctx)
    }

    pub(in crate::actors::threshold_keyshare) fn drive_contribution_definition(
        &mut self,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        if !self.effects_enabled
            || self.ended
            || self.bus.is_shutting_down()
            || self.contribution_running.is_some()
            || self.contribution_delivered
        {
            return Ok(());
        }
        let state = self.state.try_get()?;
        let KeyshareState::ReadyForDecryption(ready) = state.state else {
            return Ok(());
        };
        let keys = self.canonical_keys.clone();
        let Some((ct, ec)) = keys.synchronized_opening(&state.e3_id) else {
            return Ok(());
        };
        let Some(plan) = keys.synchronized_decryption_definition(
            &state.e3_id,
            self.params_profile,
            std::slice::from_ref(&ct),
        )?
        else {
            return Ok(());
        };
        let owner = u32::try_from(state.party_id)?;
        if !plan.designated().contains(&owner) {
            return Ok(());
        }
        let Some(intent) = &self.synchronized_setup else {
            return Ok(());
        };
        let runtime = self
            .decryption_runtime
            .clone()
            .context("missing synchronized worker")?;
        let signer = self.signer.clone();
        let store = ContributionStore::for_definition(
            &self.recovery_payloads.repositories(),
            plan.clone(),
            &intent.confirmed_setup(self.interfold_address, &keys, &self.cipher)?,
            signer.address(),
            &self.cipher,
        )?;
        let first = self.live_opening;
        let reservation = self.live_reservation.clone();
        let bus = self.bus.clone();
        self.contribution_running = Some(
            ctx.spawn(
                async move {
                    let deadline = runtime.open_deadline(&state.e3_id, None).await?;
                    let current = || -> Result<()> {
                        anyhow::ensure!(!bus.is_shutting_down(), "node is stopping");
                        plan.check_current(&keys, &ct)
                    };
                    current()?;
                    reservation
                        .reserve_if_authorized(&store, &keys, first)
                        .await?;
                    let worker = ContributionWorker {
                        pool: runtime.pool.clone(),
                        task_scope: runtime.task_scope.clone(),
                        prover: runtime.prover.clone(),
                    };
                    let result = worker
                        .run_fenced(
                            &store,
                            &keys,
                            &ct,
                            &ready.sk_poly_sum,
                            Some((&runtime, deadline)),
                        )
                        .await?;
                    runtime.open_deadline(plan.e3_id(), Some(deadline)).await?;
                    current()?;
                    let bundle = match result {
                        LocalContribution::Signed(bundle) => bundle,
                        LocalContribution::ReadyToSign { share, proof } => {
                            let signed = SignedProofPayload::sign(
                                ProofPayload {
                                    e3_id: state.e3_id.clone(),
                                    proof_type: ProofType::C6ThresholdShareDecryption,
                                    proof,
                                },
                                &signer,
                            )?;
                            let bundle = DecryptionshareCreated {
                                e3_id: state.e3_id,
                                party_id: state.party_id,
                                node: signer.address().to_string(),
                                decryption_share: vec![share],
                                signed_decryption_proofs: vec![signed],
                            };
                            store.record_signed(&bundle).await?;
                            bundle
                        }
                    };
                    runtime.open_deadline(plan.e3_id(), Some(deadline)).await?;
                    current()?;
                    Ok::<_, anyhow::Error>((plan, ct, bundle, ec))
                }
                .into_actor(self)
                .map(|result, actor, _| {
                    actor.contribution_running = None;
                    if actor.ended || !actor.effects_enabled || actor.bus.is_shutting_down() {
                        return;
                    }
                    let result = result.and_then(|(plan, ct, bundle, ec)| {
                        plan.check_current(&actor.canonical_keys, &ct)?;
                        actor.bus.publish(bundle, ec)?;
                        actor.contribution_delivered = true;
                        Ok(())
                    });
                    if let Err(error) = result {
                        tracing::warn!(%error, "retaining synchronized contribution for redrive");
                    }
                }),
            ),
        );
        Ok(())
    }
}
