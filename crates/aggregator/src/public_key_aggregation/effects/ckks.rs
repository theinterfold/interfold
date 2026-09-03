// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS public-key aggregation branch.
//!
//! BFV pk aggregation routes Collecting → VerifyingC1 → C5 → publish. The
//! CKKS path (scheme bound on-chain by the E3 program: program address =>
//! protocol) shares the C1 round — `verify_key_proofs.rs` dispatches every
//! party's signed C1-CKKS proof to the ShareVerificationActor, runs the
//! CKKS `pk_commitment` twin over the received share bytes, and only then
//! calls [`PublicKeyAggregator::ckks_aggregate_and_publish`] with the
//! dishonest set (the ROGUE-KEY GATE: an unproven share is never summed):
//!
//! * The aggregate pk is the CKKS share-sum via [`CkksFhe`], NOT the BFV
//!   runtime (which is never constructed for CKKS E3s).
//! * `pk_commitment` is `keccak256(pubkey)`; the DKG proof/attestation
//!   slots carry the same non-empty placeholders the BFV test path uses
//!   (`publish_result.rs` — accepted only by mock verifiers, rejected by
//!   production ones, keeping the escape hatch in the ciphernode).

use super::super::*;
use alloy::primitives::keccak256;
use e3_events::{CircuitName, Proof};
use e3_fhe::ckks_runtime::GetCkksAggregatePublicKey;
use e3_fhe_params::ckks_presets::{CkksProofPosture, ProofPosture};
use std::collections::BTreeSet;

impl PublicKeyAggregator {
    /// The E3's C1 posture (`CkksProofPosture::c1` from the E3's own
    /// params). `true` ONLY under the explicit operator off-switch.
    pub(in crate::actors::publickey_aggregator) fn ckks_c1_proof_free(&self) -> bool {
        let Some(ckks) = self.ckks.as_ref() else {
            return false;
        };
        let standard = self
            .params_preset
            .dkg_counterpart()
            .unwrap_or(self.params_preset);
        let bytes = {
            use fhe_traits::Serialize as _;
            ckks.params.to_bytes()
        };
        match CkksProofPosture::from_bytes(standard, &bytes) {
            Ok(posture) => matches!(posture.c1, ProofPosture::ProofFree(_)),
            Err(e) => {
                warn!(e3_id = %self.e3_id, "CKKS proof posture unresolvable ({e}) — treating C1 as PROVEN");
                false
            }
        }
    }

    /// Aggregate the HONEST CKKS pk shares and publish `PublicKeyAggregated`.
    ///
    /// Called from the C1 completion handler with the parties C1
    /// verification rejected (`dishonest`), or directly under the
    /// explicit proof-free off-switch (empty set).
    pub(in crate::actors::publickey_aggregator) fn ckks_aggregate_and_publish(
        &mut self,
        ec: EventContext<Sequenced>,
        dishonest: BTreeSet<u64>,
    ) -> Result<()> {
        let PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            canonical_party_nodes,
            ..
        } = self
            .state
            .get()
            .ok_or_else(|| anyhow::anyhow!("Expected VerifyingC1 state"))?
        else {
            return Err(anyhow::anyhow!(
                "ckks_aggregate_and_publish called outside VerifyingC1 state"
            ));
        };

        let ckks = self
            .ckks
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("CKKS runtime missing on CKKS E3"))?;

        // Honest set = arrived shares minus the C1-rejected parties.
        let mut entries: Vec<(u64, String, ArcBytes)> = submission_order
            .iter()
            .filter(|(pid, _, _)| !dishonest.contains(pid))
            .cloned()
            .collect();
        entries.sort_by_key(|(pid, _, _)| *pid);
        let (party_ids, nodes_and_shares): (Vec<u64>, Vec<(String, ArcBytes)>) = entries
            .into_iter()
            .map(|(pid, node, ks)| (pid, (node, ks)))
            .unzip();
        let (honest_nodes, keyshares): (Vec<String>, Vec<ArcBytes>) =
            nodes_and_shares.into_iter().unzip();

        // BFV-style aggregation: each node's `KeyshareCreated.pubkey` is
        // its pk SHARE (p0 polynomial over the common CRP); the aggregator
        // sums them into the joint key. This gives the aggregator a real,
        // eventually-provable aggregation step (C5-CKKS) and matches the
        // BFV pipeline's trust shape.
        info!(
            "Aggregating CKKS public key from {} pk shares...",
            keyshares.len()
        );
        let pubkey = ckks.get_aggregate_public_key(GetCkksAggregatePublicKey {
            keyshares: OrderedSet::from(keyshares.clone()),
        })?;
        let pubkey = ArcBytes::from_bytes(&pubkey);
        let pk_commitment: [u8; 32] = keccak256(&pubkey[..]).into();

        // Committee bindings mirror the BFV publish path.
        let mut full_committee_party_ids: Vec<u64> =
            canonical_party_nodes.keys().copied().collect();
        full_committee_party_ids.sort();
        let committee_addresses =
            committee_addresses_in_party_order(&full_committee_party_ids, &canonical_party_nodes)?;
        let honest_committee_addresses =
            committee_addresses_in_party_order(&party_ids, &canonical_party_nodes)?;

        let nodes = OrderedSet::from(honest_nodes);
        let event = PublicKeyAggregated {
            pubkey: pubkey.clone(),
            e3_id: self.e3_id.clone(),
            nodes: nodes.clone(),
            committee_addresses: committee_addresses.clone(),
            honest_committee_addresses: honest_committee_addresses.clone(),
            pk_commitment,
            // Non-empty placeholders accepted only by mock verifiers (the
            // same convention as the BFV test path in publish_result.rs).
            dkg_aggregator_proof: Some(Proof {
                circuit: CircuitName::DkgAggregator,
                data: ArcBytes::from_bytes(&[1]),
                public_signals: ArcBytes::from_bytes(&pk_commitment),
            }),
            dkg_attestation_bundle: Some(ArcBytes::from_bytes(&[1])),
        };

        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.pending_publication = Some(event.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.bus.publish(event, ec.clone())?;

        self.state.try_mutate(&ec, |_| {
            Ok(PublicKeyAggregatorState::Complete {
                public_key: pubkey,
                keyshares: OrderedSet::new(),
                nodes,
                committee_addresses,
                honest_committee_addresses,
            })
        })?;
        Ok(())
    }
}
