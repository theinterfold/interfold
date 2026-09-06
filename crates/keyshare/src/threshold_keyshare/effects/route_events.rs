// SPDX-License-Identifier: LGPL-3.0-only

//! Route the per-E3 event envelope to typed keyshare handlers.

use super::*;

impl Handler<InterfoldEvent> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphertextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PublicKeyAggregated(data) => {
                let committee_hash =
                    e3_committee_hash::hash_committee_addresses(&data.committee_addresses);
                let pk = ArcBytes::from_bytes(&data.pubkey);
                let _ = self.state.try_mutate(&ec, |mut s| {
                    s.aggregated_pk = Some(pk);
                    s.decryption_domain = Some(e3_committee_hash::DecryptionDomainContext {
                        interfold_address: self.interfold_address,
                        committee_hash,
                        committee_public_key: data.pk_commitment.into(),
                    });
                    Ok(s)
                });
                // CKKS relin ceremony defers its round-1 work until pk
                // consensus is confirmed; release it now.
                if let Err(err) = self.ckks_handle_public_key_aggregated(ec) {
                    tracing::error!("Failed to release CKKS relin round 1: {err}");
                }
            }
            // The chain-observed committee publication carries the same
            // fact as the gossiped PublicKeyAggregated and reaches EVERY
            // node (the gossip only reliably reaches the aggregator's own
            // bus). It is therefore ALSO the authoritative source of the
            // decryption domain: a node that never saw the gossip would
            // otherwise reach decryption with `decryption_domain == None`
            // and the CKKS shell would degrade to a proof-less share
            // (fail-open). Set it here from the on-chain facts —
            // `pk_commitment = keccak256(pubkey)` exactly as the aggregator
            // computes it (`public_key_aggregation/effects/ckks.rs`) — then
            // release the CKKS ceremony; the machine handler is idempotent.
            InterfoldEventData::CommitteePublished(data) => {
                // The C6 decryption domain hashes the committee in ascending
                // address order (== party-id order, what `CommitteeHashLib`
                // hashes on-chain after finalization sorts `topNodes`). Sort
                // explicitly so this recomputation does not depend on the
                // order the chain event happens to carry.
                let mut committee: Vec<alloy::primitives::Address> = Vec::new();
                for node in &data.nodes {
                    match node.parse::<alloy::primitives::Address>() {
                        Ok(a) => committee.push(a),
                        Err(err) => {
                            tracing::error!(
                                "CommitteePublished for {}: invalid node address {node}: {err} — \
                                 not setting the CKKS decryption domain from this event",
                                data.e3_id
                            );
                            committee.clear();
                            break;
                        }
                    }
                }
                if !committee.is_empty() {
                    committee.sort();
                    let committee_hash = e3_committee_hash::hash_committee_addresses(&committee);
                    let pk_commitment: [u8; 32] =
                        alloy::primitives::keccak256(&data.public_key[..]).into();
                    let pk = data.public_key.clone();
                    let _ = self.state.try_mutate(&ec, |mut s| {
                        if s.aggregated_pk.is_none() {
                            s.aggregated_pk = Some(pk);
                        }
                        if s.decryption_domain.is_none() {
                            s.decryption_domain =
                                Some(e3_committee_hash::DecryptionDomainContext {
                                    interfold_address: self.interfold_address,
                                    committee_hash,
                                    committee_public_key: pk_commitment.into(),
                                });
                        }
                        Ok(s)
                    });
                }
                if let Err(err) = self.ckks_handle_public_key_aggregated(ec) {
                    tracing::error!("Failed to release CKKS relin round 1: {err}");
                }
            }
            InterfoldEventData::ThresholdShareCreated(data) => {
                let _ =
                    self.handle_threshold_share_created(TypedEvent::new(data, ec), ctx.address());
            }
            InterfoldEventData::EncryptionKeyCreated(data) => {
                let _ =
                    self.handle_encryption_key_created(TypedEvent::new(data, ec), ctx.address());
            }
            InterfoldEventData::PkGenerationProofSigned(data) => {
                let _ = self.handle_pk_generation_proof_signed(TypedEvent::new(data, ec));
            }
            InterfoldEventData::DkgProofSigned(data) => {
                let _ = self.handle_share_computation_proof_signed(TypedEvent::new(data, ec));
            }
            InterfoldEventData::E3RequestComplete(data) => self.notify_sync(ctx, data),
            InterfoldEventData::E3Failed(data) => {
                warn!(
                    "E3 failed: {:?}. Shutting down ThresholdKeyshare for e3_id={}",
                    data.reason, data.e3_id
                );
                self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
            }
            InterfoldEventData::E3StageChanged(data) => {
                use e3_events::E3Stage;
                match &data.new_stage {
                    E3Stage::Complete | E3Stage::Failed => {
                        info!("E3 reached terminal stage {:?}. Shutting down ThresholdKeyshare for e3_id={}", data.new_stage, data.e3_id);
                        self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
                    }
                    _ => {
                        trace!(
                            "E3 stage changed to {:?} for e3_id={}",
                            data.new_stage,
                            data.e3_id
                        );
                    }
                }
            }
            InterfoldEventData::DecryptionKeyShared(data) => {
                if data.external {
                    // Route based on current state
                    if let Some(state) = self.state.get() {
                        if state.expelled_parties.contains(&data.party_id) {
                            info!(
                                "Dropping DecryptionKeyShared from expelled party {}",
                                data.party_id
                            );
                            return;
                        }
                        if data.party_id >= state.threshold_n || data.party_id == state.party_id {
                            warn!(
                                party_id = data.party_id,
                                e3_id = %data.e3_id,
                                "Dropping DecryptionKeyShared with an invalid sender party"
                            );
                            return;
                        }
                        if state
                            .honest_parties
                            .as_ref()
                            .is_some_and(|parties| !parties.contains(&data.party_id))
                        {
                            warn!(
                                party_id = data.party_id,
                                e3_id = %data.e3_id,
                                "Dropping DecryptionKeyShared from outside the honest committee"
                            );
                            return;
                        }
                        let recovered_event = TypedEvent::new(data.clone(), ec.clone());
                        if let Err(err) = self.record_decryption_key_share(&recovered_event) {
                            error!("Failed to persist DecryptionKeyShared recovery input: {err}");
                            return;
                        }
                        let result = match &state.state {
                            KeyshareState::AggregatingDecryptionKey(_) => {
                                self.handle_early_decryption_key_share(data, ec)
                            }
                            KeyshareState::ReadyForDecryption(_) => {
                                // Delegate to the collector actor
                                if let Some(ref collector) = self.decryption_key_shared_collector {
                                    collector.do_send(TypedEvent::new(data, ec));
                                    Ok(())
                                } else {
                                    warn!(
                                        "DecryptionKeyShared from party {} dropped — no collector (sole honest party)",
                                        data.party_id
                                    );
                                    Ok(())
                                }
                            }
                            other => {
                                trace!(
                                    "DecryptionKeyShared from party {} in unexpected state {:?}, ignoring",
                                    data.party_id,
                                    other.variant_name()
                                );
                                Ok(())
                            }
                        };
                        if let Err(err) = result {
                            error!("Failed to handle DecryptionKeyShared: {err}");
                        }
                    }
                } else {
                    // Own DecryptionKeyShared published by ProofRequestActor.
                    // A3 fast-path: if no other honest parties, publish KeyshareCreated directly.
                    if let Some(state) = self.state.get() {
                        if data.party_id == state.party_id {
                            if let KeyshareState::ReadyForDecryption(_) = state.state {
                                let others = state
                                    .honest_parties
                                    .as_ref()
                                    .map(|h| h.iter().filter(|&&pid| pid != state.party_id).count())
                                    .unwrap_or(0);
                                if others == 0 {
                                    info!(
                                        "No other honest parties for E3 {} — publishing KeyshareCreated directly",
                                        data.e3_id
                                    );
                                    if let Err(err) = self.publish_keyshare_created(ec) {
                                        error!("Failed to publish KeyshareCreated: {err}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            InterfoldEventData::KeyshareCreated(data) => {
                // CKKS C8 anchor: record each party's C1-CKKS sk
                // commitment (no-op on BFV E3s / gate off).
                if let Err(err) = self.ckks_handle_keyshare_created(&data, ec) {
                    error!("Failed to record CKKS C1 sk commitment: {err}");
                }
            }
            InterfoldEventData::RelinCeremonyProofSigned(data) => {
                // CKKS C8: a party's signed per-digit round-1 proofs.
                if let Err(err) = self.ckks_handle_relin_ceremony_proofs(&data, ec) {
                    error!("Failed to handle RelinCeremonyProofSigned: {err}");
                }
            }
            InterfoldEventData::RelinCeremonyShare(data) => {
                // CKKS relin-key ceremony broadcast (round 1 or 2). The
                // machine ignores duplicates; own broadcasts loop back via
                // the local bus and count as our contribution.
                if let Err(err) = self.ckks_handle_relin_ceremony_share(&data, ec) {
                    error!("Failed to handle RelinCeremonyShare: {err}");
                }
            }
            InterfoldEventData::DecryptionShareProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.handle_committee_member_expelled(data, ec);
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                self.handle_committee_member_excluded(data, ec);
            }
            InterfoldEventData::EffectsEnabled(_) => {
                // Broadcast once at the end of boot sync. Re-drive any of this node's own
                // in-flight work that a crash may have interrupted (idempotent downstream).
                if let Err(err) = self.resume_in_flight_work(ec, ctx.address()) {
                    warn!("resume_in_flight_work failed: {err}");
                    #[cfg(test)]
                    eprintln!("resume_in_flight_work failed: {err:#}");
                }
            }
            _ => (),
        }
    }
}
