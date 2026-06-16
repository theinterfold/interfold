// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ABI encoding for `publishCommittee`'s `dkgAttestationBundle` argument.
//! Must match `DkgFoldAttestationLib` structs in `packages/interfold-contracts`.

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::sol_types::SolValue;
use anyhow::{anyhow, Context as _, Result};
use e3_events::SignedDkgFoldAttestation;
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

alloy::sol! {
    struct DkgFoldAttestationSol {
        uint256 partyId;
        bytes32 skAggCommit;
        bytes32 esmAggCommit;
        bytes signature;
    }

    struct PartySlotBindingSol {
        uint256 partyId;
        address node;
    }
}

/// Build the bundle expected by `DkgFoldAttestationVerifier.verify`.
///
/// `honest_party_ids` must be iterated in ascending order (e.g. a `BTreeSet`).
/// `bindings` are emitted in that order; `attestations` may be any order.
pub fn encode_dkg_attestation_bundle(
    honest_party_ids: &BTreeSet<u64>,
    party_nodes: &HashMap<u64, String>,
    attestations: &HashMap<u64, SignedDkgFoldAttestation>,
) -> Result<Bytes> {
    let mut binding_sols = Vec::with_capacity(honest_party_ids.len());
    let mut attestation_sols = Vec::with_capacity(honest_party_ids.len());

    for party_id in honest_party_ids {
        let node = party_nodes
            .get(party_id)
            .with_context(|| format!("missing party_nodes entry for party {party_id}"))?;
        let att = attestations
            .get(party_id)
            .with_context(|| format!("missing fold attestation for party {party_id}"))?;

        if att.payload.party_id != *party_id {
            return Err(anyhow!(
                "attestation party_id {} does not match binding {}",
                att.payload.party_id,
                party_id
            ));
        }

        binding_sols.push(PartySlotBindingSol {
            partyId: U256::from(*party_id),
            node: Address::from_str(node)
                .with_context(|| format!("invalid committee node address {node}"))?,
        });

        attestation_sols.push(DkgFoldAttestationSol {
            partyId: U256::from(att.payload.party_id),
            skAggCommit: B256::from(att.payload.agg_commits.sk_agg_commit),
            esmAggCommit: B256::from(att.payload.agg_commits.esm_agg_commit),
            signature: att.signature.extract_bytes().into(),
        });
    }

    Ok(Bytes::from(
        (attestation_sols, binding_sols).abi_encode_params(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;
    use alloy::signers::local::PrivateKeySigner;
    use e3_events::{DkgFoldAggCommits, DkgFoldAttestationPayload, E3id};

    #[test]
    fn roundtrip_abi_layout() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let payload = DkgFoldAttestationPayload {
            e3_id: E3id::new("31337", 1),
            verifying_contract: Address::from([0x22u8; 20]),
            party_id: 2,
            agg_commits: DkgFoldAggCommits {
                sk_agg_commit: [1u8; 32],
                esm_agg_commit: [2u8; 32],
            },
        };
        let signed = e3_events::SignedDkgFoldAttestation::sign(payload, &signer).unwrap();

        let mut honest = BTreeSet::new();
        honest.insert(2);
        let mut party_nodes = HashMap::new();
        party_nodes.insert(2, signer.address().to_string());
        let mut attestations = HashMap::new();
        attestations.insert(2, signed);

        let encoded = encode_dkg_attestation_bundle(&honest, &party_nodes, &attestations).unwrap();
        assert!(!encoded.is_empty());

        let typehash = keccak256(
            "DkgFoldAttestation(uint256 e3Id,uint256 partyId,bytes32 skAggCommit,bytes32 esmAggCommit)",
        );
        assert_eq!(typehash.len(), 32);
    }
}
