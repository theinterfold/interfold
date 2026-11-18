// SPDX-License-Identifier: LGPL-3.0-only

//! Exclusive publication recovery record. No snapshot batching writes this record.

use super::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicationRecord {
    version: u8,
    pub(crate) selected: CiphernodeSelected,
    pub(crate) plan: Option<PublicationPlan>,
    pub(crate) shares: BTreeMap<u32, KeyshareCreated>,
    pub(crate) recipients: BTreeMap<u32, SynchronizedDkgProofPublished>,
    pub(crate) consents: BTreeMap<u32, SignedSynchronizedDkgAttestation>,
    pub(crate) c5: Option<Proof>,
    pub(crate) proof: Option<Proof>,
    pub(crate) started: bool,
    pub(crate) ec: EventContext<Sequenced>,
}

impl PublicationRecord {
    pub(crate) fn new(selected: CiphernodeSelected, ec: EventContext<Sequenced>) -> Self {
        Self {
            version: 1,
            selected,
            plan: None,
            shares: BTreeMap::new(),
            recipients: BTreeMap::new(),
            consents: BTreeMap::new(),
            c5: None,
            proof: None,
            started: false,
            ec,
        }
    }

    fn members(&self) -> Result<Vec<Address>> {
        self.selected
            .committee
            .iter()
            .map(|s| s.parse().map_err(Into::into))
            .collect()
    }

    pub(crate) fn intake(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        interfold: Address,
    ) -> Result<()> {
        let members = self.members()?;
        let id = &self.selected.e3_id;
        match data {
            InterfoldEventData::SynchronizedRecipientProofReady(local) => {
                let plan = PublicationPlan::new(
                    self.selected.clone(),
                    TypedEvent::new(local.clone(), ec.clone()),
                    interfold,
                )?;
                if let Some(old) = &self.plan {
                    ensure!(*old.local == *local, "conflicting local publication batch");
                } else {
                    self.shares.retain(|_, share| plan.keyshare(share).is_ok());
                    self.recipients
                        .retain(|_, peer| plan.recipient(peer).is_ok());
                    self.consents
                        .retain(|id, _| plan.local.setup.dealers.contains(id));
                    self.ec = ec.clone();
                    self.plan = Some(plan);
                }
            }
            InterfoldEventData::KeyshareCreated(share) => {
                let owner = u32::try_from(share.party_id)?;
                let signed = share
                    .signed_pk_generation_proof
                    .as_ref()
                    .context("missing C1")?;
                ensure!(
                    &share.e3_id == id
                        && &signed.payload.e3_id == id
                        && signed.payload.proof_type == ProofType::C1PkGeneration
                        && signed.payload.proof.circuit == CircuitName::PkGeneration
                        && members.get(owner as usize) == Some(&signed.recover_address()?)
                        && members.get(owner as usize) == Some(&share.node.parse()?),
                    "unauthenticated native PK slot"
                );
                if let Some(plan) = &self.plan {
                    plan.keyshare(share)?;
                }
                if let Some(old) = self.shares.get(&owner) {
                    // Before the local plan binds C1, equal native bytes may carry a corrected proof.
                    if self.plan.is_some() && old.pubkey == share.pubkey {
                        return Ok(());
                    }
                    ensure!(
                        self.plan.is_none(),
                        "fixed native PK contribution cannot change"
                    );
                }
                self.shares.insert(owner, share.clone());
            }
            InterfoldEventData::SynchronizedDkgProofPublished(peer) => {
                ensure!(
                    &peer.e3_id == id
                        && peer.role == SynchronizedDkgProofRole::Recipient
                        && peer.context.setup.interfold_address == interfold
                        && peer.context.setup.committee_hash
                            == e3_committee_hash::hash_committee_addresses(&members)
                        && peer.context.setup.crypto_config_id.as_slice()
                            == self.selected.crypto_config_id
                        && members.get(peer.context.party_id as usize)
                            == Some(&peer.recover_address()?),
                    "unauthenticated recipient slot"
                );
                if let Some(plan) = &self.plan {
                    plan.recipient(peer)?;
                }
                if let Some(old) = self.recipients.get(&peer.context.party_id) {
                    if old == peer {
                        return Ok(());
                    }
                    if self.proof.is_some() {
                        ensure!(
                            old.proof.public_signals == peer.proof.public_signals,
                            "completed publication recipient cannot change"
                        );
                        return Ok(());
                    }
                }
                // Before a successful wrapper, a signer may replace invalid proof bytes. Any
                // changed child invalidates the process-local publication correlation.
                self.recipients.insert(peer.context.party_id, peer.clone());
            }
            InterfoldEventData::SynchronizedDkgConsentPublished(message) => {
                let signed = &message.attestation;
                ensure!(
                    &signed.payload.e3_id == id
                        && signed.payload.context.crypto_config_id
                            == self.selected.crypto_config_id
                        && members.get(signed.payload.party_id as usize)
                            == Some(&signed.recover_address()?),
                    "unauthenticated publication consent slot"
                );
                if let Some(plan) = &self.plan {
                    ensure!(
                        plan.local.setup.dealers.contains(&signed.payload.party_id),
                        "outside-H recipient cannot consent"
                    );
                    if let Some(native) = self.native()? {
                        if self.recipients.contains_key(&signed.payload.party_id) {
                            // Domain equality is rechecked against shared chain authority before
                            // output; all other anchors must already agree before replacing a slot.
                            plan.consent(
                                signed.payload.context,
                                &native,
                                &self.recipients,
                                signed,
                            )?;
                        }
                    }
                }
                if let Some(old) = self.consents.get(&signed.payload.party_id) {
                    if old.payload == signed.payload {
                        return Ok(());
                    }
                    ensure!(
                        self.proof.is_none(),
                        "completed publication consent cannot change"
                    );
                }
                self.consents
                    .insert(signed.payload.party_id, signed.clone());
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn native(&self) -> Result<Option<PkAggregationProofRequest>> {
        let Some(plan) = &self.plan else {
            return Ok(None);
        };
        if !plan
            .local
            .setup
            .dealers
            .iter()
            .all(|id| self.shares.contains_key(id))
        {
            return Ok(None);
        }
        Ok(Some(plan.c5_request(&self.shares)?))
    }

    pub(crate) fn work(&self) -> Result<Option<SynchronizedDkgProofRequest>> {
        let (Some(plan), Some(c5), Some(native)) = (&self.plan, &self.c5, self.native()?) else {
            return Ok(None);
        };
        if !plan
            .local
            .setup
            .dealers
            .iter()
            .all(|id| self.recipients.contains_key(id))
        {
            return Ok(None);
        }
        Ok(Some(plan.publication_request(
            &native,
            c5,
            &self.recipients,
        )?))
    }

    pub(crate) fn prune_consents(&mut self, context: Option<SynchronizedDkgContext>) -> Result<()> {
        let Some(context) = context else {
            return Ok(());
        };
        let Some(native) = self.native()? else {
            return Ok(());
        };
        let Some(plan) = &self.plan else {
            return Ok(());
        };
        // A missing recipient is not a verdict on a previously authenticated early consent.
        self.consents.retain(|id, signed| {
            !self.recipients.contains_key(id)
                || plan
                    .consent(context, &native, &self.recipients, signed)
                    .is_ok()
        });
        Ok(())
    }

    pub(crate) fn output(
        &self,
        context: SynchronizedDkgContext,
    ) -> Result<Option<SynchronizedDkgPublicationReady>> {
        let (Some(plan), Some(proof), Some(native), Some(work)) =
            (&self.plan, &self.proof, self.native()?, self.work()?)
        else {
            return Ok(None);
        };
        plan.validate_publication(&native, &work, proof)?;
        let mut consents = Vec::new();
        for id in &plan.local.setup.dealers {
            let Some(signed) = self.consents.get(id) else {
                return Ok(None);
            };
            plan.consent(context, &native, &self.recipients, signed)?;
            consents.push(signed.clone());
        }
        let SynchronizedDkgProofJob::Publication { expected, .. } = work.job else {
            unreachable!()
        };
        Ok(Some(SynchronizedDkgPublicationReady {
            e3_id: self.selected.e3_id.clone(),
            params_profile: work.params_profile,
            committee_size: work.committee_size,
            context: work.context,
            expected,
            proof: proof.clone(),
            consents,
        }))
    }

    pub(crate) fn validate(&self, interfold: Address) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported synchronized publication record version"
        );
        E3Meta::from(&self.selected).validate_identity()?;
        ensure!(
            self.started || (self.c5.is_none() && self.proof.is_none()),
            "publication results lack a started-owner record"
        );
        let members = self.members()?;
        ensure!(
            members.len() == self.selected.threshold_n
                && members.windows(2).all(|pair| pair[0] < pair[1])
                && usize::try_from(self.selected.party_id)? < members.len(),
            "publication selection has invalid canonical slots"
        );
        let mut inputs = Self::new(self.selected.clone(), self.ec.clone());
        if let Some(plan) = &self.plan {
            plan.validate(interfold)?;
            ensure!(
                plan.selected == self.selected,
                "publication record selection differs"
            );
            inputs.intake(
                &InterfoldEventData::from((*plan.local).clone()),
                plan.local.get_ctx(),
                interfold,
            )?;
        }
        for (&id, share) in &self.shares {
            ensure!(
                u64::from(id) == share.party_id,
                "saved native PK slot differs"
            );
            inputs.intake(
                &InterfoldEventData::from(share.clone()),
                &self.ec,
                interfold,
            )?;
        }
        for (&id, peer) in &self.recipients {
            ensure!(id == peer.context.party_id, "saved recipient slot differs");
            inputs.intake(&InterfoldEventData::from(peer.clone()), &self.ec, interfold)?;
        }
        for (&id, signed) in &self.consents {
            ensure!(id == signed.payload.party_id, "saved consent slot differs");
            inputs.intake(
                &InterfoldEventData::from(SynchronizedDkgConsentPublished {
                    attestation: signed.clone(),
                }),
                &self.ec,
                interfold,
            )?;
        }
        if let Some(c5) = &self.c5 {
            self.plan
                .as_ref()
                .context("C5 without local setup")?
                .validate_c5(&self.native()?.context("C5 without native PK")?, c5)?;
        }
        if let Some(proof) = &self.proof {
            self.plan
                .as_ref()
                .context("publication without local setup")?
                .validate_publication(
                    &self.native()?.context("publication without native PK")?,
                    &self
                        .work()?
                        .context("publication without recipient joins")?,
                    proof,
                )?;
        }
        Ok(())
    }
}
