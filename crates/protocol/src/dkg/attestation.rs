// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{contract_domain, E3Id};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolStruct;
use serde::{Deserialize, Serialize};

mod typed {
    alloy_sol_types::sol! {
        struct DkgFoldAttestation {
            address registry;
            uint256 e3Id;
            uint256 partyId;
            bytes32 skAggCommit;
            bytes32 esmAggCommit;
        }
    }
}

/// A committee member's attestation to its folded DKG proof, checked by
/// `DkgFoldAttestationVerifier`.
/// The registry and fold-attestation verifier that a request froze for its E3. Fold attestations
/// are EIP-712 data under the verifier's domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttestationContext {
    pub registry: Address,
    pub verifier: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FoldAttestation {
    pub e3: E3Id,
    pub verifier: Address,
    pub registry: Address,
    pub party_id: u64,
    pub sk_agg_commit: B256,
    pub esm_agg_commit: B256,
}

impl FoldAttestation {
    /// The EIP-712 hash the verifier checks, under its "InterfoldDkgFoldAttestation" domain.
    pub fn signing_hash(&self) -> B256 {
        typed::DkgFoldAttestation {
            registry: self.registry,
            e3Id: self.e3.number,
            partyId: U256::from(self.party_id),
            skAggCommit: self.sk_agg_commit,
            esmAggCommit: self.esm_agg_commit,
        }
        .eip712_signing_hash(&contract_domain(
            "InterfoldDkgFoldAttestation",
            self.e3.chain_id,
            self.verifier,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Signature;

    #[test]
    fn a_signature_from_the_current_node_recovers_to_its_signer() {
        let attestation = FoldAttestation {
            e3: E3Id {
                chain_id: 31337,
                number: U256::from(42),
            },
            verifier: "0x9999999999999999999999999999999999999999"
                .parse()
                .unwrap(),
            registry: "0x8888888888888888888888888888888888888888"
                .parse()
                .unwrap(),
            party_id: 3,
            sk_agg_commit: B256::repeat_byte(0x33),
            esm_agg_commit: B256::repeat_byte(0x44),
        };
        let signature = Signature::try_from(
            &hex::decode("3e8f8e9401fa1d64808d537090acd518d471361649a5919a0f3562ca412b7e3d1386d925cc1c09ff96fea4898784bd815a09a9160d722627dda862642fe693241c").unwrap()[..],
        )
        .unwrap();
        assert_eq!(
            signature
                .recover_address_from_prehash(&attestation.signing_hash())
                .unwrap(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse::<Address>()
                .unwrap()
        );
    }
}
