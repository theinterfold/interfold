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
use e3_events::{CircuitName, Proof, SignedProofPayload};
use e3_evm::helpers::encode_ckks_pk_proofs;
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
            c1_proofs,
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

        // Honest set = arrived shares minus the C1-rejected parties. Keep each
        // party's C1-CKKS proof alongside its share: the on-chain
        // `CkksPkVerifier` needs every one of them.
        let mut entries: Vec<(u64, String, ArcBytes, Option<SignedProofPayload>)> =
            submission_order
                .iter()
                .cloned()
                .zip(c1_proofs.iter().cloned())
                .filter(|((pid, _, _), _)| !dishonest.contains(pid))
                .map(|((pid, node, ks), c1)| (pid, node, ks, c1))
                .collect();
        entries.sort_by_key(|(pid, _, _, _)| *pid);
        let party_ids: Vec<u64> = entries.iter().map(|(pid, _, _, _)| *pid).collect();
        let honest_nodes: Vec<String> = entries.iter().map(|(_, n, _, _)| n.clone()).collect();
        let keyshares: Vec<ArcBytes> = entries.iter().map(|(_, _, ks, _)| ks.clone()).collect();
        let party_c1_proofs: Vec<Option<SignedProofPayload>> =
            entries.iter().map(|(_, _, _, c1)| c1.clone()).collect();

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

        // Build the on-chain `CkksPkVerifier` blob from every committee member's
        // C1-CKKS proof. FAIL CLOSED: if the proof-free off-switch ran, or any
        // party's proof is missing, publish NOTHING rather than an empty blob —
        // the on-chain verifier would reject it after the gas was spent, and a
        // silently unverified committee key is exactly what this replaces.
        let ckks_pk_proof_blob = if self.ckks_c1_proof_free() {
            info!(
                e3_id = %self.e3_id,
                "CKKS C1 proof-free off-switch is on — publishing without an on-chain pk proof blob"
            );
            None
        } else {
            let party_proofs: Vec<Proof> = party_c1_proofs
                .iter()
                .enumerate()
                .map(|(index, signed)| {
                    signed
                        .as_ref()
                        .map(|s| s.payload.proof.clone())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "party at index {index} has no C1-CKKS proof; refusing to publish \
                                 an unverifiable committee key"
                            )
                        })
                })
                .collect::<Result<_>>()?;
            let blob = encode_ckks_pk_proofs(&party_proofs, &pubkey)?;
            info!(
                e3_id = %self.e3_id,
                parties = party_proofs.len(),
                bytes = blob.len(),
                "Encoded the CKKS committee-key proof blob for on-chain verification"
            );
            Some(ArcBytes::from_bytes(&blob))
        };

        let event = PublicKeyAggregated {
            pubkey: pubkey.clone(),
            e3_id: self.e3_id.clone(),
            nodes: nodes.clone(),
            committee_addresses: committee_addresses.clone(),
            honest_committee_addresses: honest_committee_addresses.clone(),
            pk_commitment,
            // CKKS has no recursive DKG aggregation circuit; the real evidence
            // travels in `ckks_pk_proof_blob`. These two slots keep the
            // non-empty placeholders the registry's other gates expect.
            dkg_aggregator_proof: Some(Proof {
                circuit: CircuitName::DkgAggregator,
                data: ArcBytes::from_bytes(&[1]),
                public_signals: ArcBytes::from_bytes(&pk_commitment),
            }),
            dkg_attestation_bundle: Some(ArcBytes::from_bytes(&[1])),
            ckks_pk_proof_blob,
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
