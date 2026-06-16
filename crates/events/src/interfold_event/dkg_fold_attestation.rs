// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ECDSA attestation binding a node's [`CircuitName::NodeFold`] output to its committee address.
//!
//! Used to close the attribution gap between `party_ids[i]` in the DKG aggregator and the
//! operator that produced fold row `i`: the aggregator cannot permute folds without valid
//! signatures from each claimed party.

use crate::E3id;
use alloy::primitives::{keccak256, Address, U256};
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol_types::SolValue;
use anyhow::{anyhow, Result};
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};

/// Commitments surfaced from a [`CircuitName::NodeFold`] proof (C4 aggregate outputs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgFoldAggCommits {
    pub sk_agg_commit: [u8; 32],
    pub esm_agg_commit: [u8; 32],
}

/// Canonical EIP-712 payload signed after `NodeDkgFold` completes.
///
/// `chainId` and `verifying_contract` (the `DkgFoldAttestationVerifier`) are
/// part of the EIP-712 domain; `e3_id`, `party_id`, and the commitments are the
/// struct fields. Must stay aligned with `DkgFoldAttestationLib` in
/// `packages/interfold-contracts`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgFoldAttestationPayload {
    pub e3_id: E3id,
    /// Address of the on-chain `DkgFoldAttestationVerifier` (EIP-712 `verifyingContract`).
    pub verifying_contract: Address,
    /// Sortition / committee slot id (index into on-chain `topNodes` when ids are dense).
    pub party_id: u64,
    pub agg_commits: DkgFoldAggCommits,
}

impl DkgFoldAttestationPayload {
    /// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    pub fn domain_typehash() -> [u8; 32] {
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .into()
    }

    /// `keccak256("InterfoldDkgFoldAttestation")`.
    pub fn domain_name_hash() -> [u8; 32] {
        keccak256("InterfoldDkgFoldAttestation").into()
    }

    /// `keccak256("1")`.
    pub fn domain_version_hash() -> [u8; 32] {
        keccak256("1").into()
    }

    /// `keccak256("DkgFoldAttestation(uint256 e3Id,uint256 partyId,bytes32 skAggCommit,bytes32 esmAggCommit)")`.
    pub fn typehash() -> [u8; 32] {
        keccak256(
            "DkgFoldAttestation(uint256 e3Id,uint256 partyId,bytes32 skAggCommit,bytes32 esmAggCommit)",
        )
        .into()
    }

    /// EIP-712 domain separator for this payload's chain + verifier.
    pub fn domain_separator(&self) -> [u8; 32] {
        let encoded = (
            Self::domain_typehash(),
            Self::domain_name_hash(),
            Self::domain_version_hash(),
            U256::from(self.e3_id.chain_id()),
            self.verifying_contract,
        )
            .abi_encode();
        keccak256(&encoded).into()
    }

    /// EIP-712 `hashStruct(DkgFoldAttestation)`.
    pub fn struct_hash(&self) -> Result<[u8; 32]> {
        let e3_id_u256: U256 = self
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("E3id cannot be converted to U256"))?;
        let encoded = (
            Self::typehash(),
            e3_id_u256,
            U256::from(self.party_id),
            self.agg_commits.sk_agg_commit,
            self.agg_commits.esm_agg_commit,
        )
            .abi_encode();
        Ok(keccak256(&encoded).into())
    }

    /// EIP-712 typed-data hash: `keccak256("\x19\x01" || domainSeparator || structHash)`.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let domain = self.domain_separator();
        let struct_hash = self.struct_hash()?;
        let mut buf = Vec::with_capacity(2 + 32 + 32);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(&domain);
        buf.extend_from_slice(&struct_hash);
        Ok(keccak256(&buf).into())
    }
}

/// EIP-712 typed-data signature over [`DkgFoldAttestationPayload::digest`].
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct SignedDkgFoldAttestation {
    pub payload: DkgFoldAttestationPayload,
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub signature: ArcBytes,
}

impl SignedDkgFoldAttestation {
    pub fn sign(payload: DkgFoldAttestationPayload, signer: &PrivateKeySigner) -> Result<Self> {
        let digest = payload.digest()?;
        // `sign_hash_sync` signs the raw 32-byte hash without EIP-191
        // wrapping, which is what EIP-712 requires (`digest` is already
        // the `\x19\x01 || domainSeparator || structHash` hash).
        let sig = signer
            .sign_hash_sync(&digest.into())
            .map_err(|e| anyhow!("Failed to sign DkgFoldAttestation: {e}"))?;
        Ok(Self {
            payload,
            signature: ArcBytes::from_bytes(&sig.as_bytes()),
        })
    }

    pub fn recover_address(&self) -> Result<Address> {
        use alloy::primitives::Signature;
        let sig = Signature::try_from(&self.signature[..])
            .map_err(|e| anyhow!("Invalid DkgFoldAttestation signature: {e}"))?;
        let digest = self.payload.digest()?;
        sig.recover_address_from_prehash(&digest.into())
            .map_err(|e| anyhow!("Failed to recover DkgFoldAttestation signer: {e}"))
    }

    pub fn verify_signer(&self, expected: &Address) -> Result<bool> {
        Ok(self.recover_address()? == *expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;

    #[test]
    fn sign_and_recover_roundtrip() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let payload = DkgFoldAttestationPayload {
            e3_id: E3id::new("0", 1),
            verifying_contract: Address::from([0x11u8; 20]),
            party_id: 1,
            agg_commits: DkgFoldAggCommits {
                sk_agg_commit: [7u8; 32],
                esm_agg_commit: [9u8; 32],
            },
        };
        let signed = SignedDkgFoldAttestation::sign(payload, &signer).unwrap();
        assert_eq!(signed.recover_address().unwrap(), signer.address());
    }
}
