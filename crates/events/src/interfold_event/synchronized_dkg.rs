// SPDX-License-Identifier: LGPL-3.0-only

//! Synchronized publication consent, deliberately separate from SS fold/ESM attestations.

use crate::E3id;
use actix::Message;
use alloy::{
    primitives::{keccak256, Address, Signature, B256, U256},
    signers::{local::PrivateKeySigner, SignerSync},
    sol_types::SolValue,
};
use anyhow::{ensure, Result};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

mod proof;
pub use proof::*;

pub const SYNCHRONIZED_DKG_CONTEXT_SCHEMA_VERSION: u8 = 1;

/// Facts frozen by the controller/registry when the request is made, not a peer's proposed domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedDkgContext {
    pub registry: Address,
    pub verifying_contract: Address,
    pub crypto_config_id: [u8; 32],
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SynchronizedDkgContextEstablished {
    pub schema_version: u8,
    pub e3_id: E3id,
    pub context: SynchronizedDkgContext,
}

/// Public setup rows returned by the proof worker after contextual/cryptographic verification.
/// The actor still owns source/correlation admission; these values alone are not a proof verdict.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedSetupAnchors {
    pub binding: [u128; 2],
    pub recipient: u32,
    pub dealers: Vec<u32>,
    pub threshold_keys: Vec<[u8; 32]>,
    pub dealer_batch: [u8; 32],
    pub sk_commitment: [u8; 32],
    pub key_bundle: [u8; 32],
}

/// Local dealer join accepted from the correlated proof worker. This is not a peer-authenticated
/// setup, recipient consent, or canonical publication.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SynchronizedDealerProofReady {
    pub e3_id: E3id,
    pub context: crate::SynchronizedProofContext,
    pub proof: crate::Proof,
}

impl Display for SynchronizedDealerProofReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, dealer: {}",
            self.e3_id, self.context.party_id
        )
    }
}

impl Display for SynchronizedDkgContextEstablished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, registry: {}, verifier: {}",
            self.e3_id, self.context.registry, self.context.verifying_contract
        )
    }
}

/// Hash exactly `abi.encode(uint256[] partyIds)`, without sorting or packed encoding.
pub fn synchronized_dkg_roster_hash(party_ids: &[u32]) -> [u8; 32] {
    let ids: Vec<U256> = party_ids.iter().copied().map(U256::from).collect();
    keccak256(ids.abi_encode()).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedDkgAttestationPayload {
    pub e3_id: E3id,
    pub context: SynchronizedDkgContext,
    pub setup_binding: [u8; 32],
    pub roster_hash: [u8; 32],
    pub dealer_batch: [u8; 32],
    pub pk_commitment: [u8; 32],
    pub party_id: u32,
    pub sk_agg_commit: [u8; 32],
    pub key_bundle_commit: [u8; 32],
}

impl SynchronizedDkgAttestationPayload {
    pub fn digest(&self) -> Result<[u8; 32]> {
        let domain = keccak256((
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("InterfoldSynchronizedDkgAttestation"),
            keccak256("1"),
            U256::from(self.e3_id.chain_id()),
            self.context.verifying_contract,
        ).abi_encode());
        let id: U256 = self.e3_id.clone().try_into()?;
        let statement = keccak256(
            (
                keccak256(concat!(
                "SynchronizedDkgAttestation(address registry,uint256 e3Id,bytes32 cryptoConfigId,",
                "bytes32 setupBinding,bytes32 rosterHash,bytes32 dealerBatch,bytes32 pkCommitment,",
                "uint256 partyId,bytes32 skAggCommit,bytes32 keyBundleCommit)"
            )),
                self.context.registry,
                id,
                B256::from(self.context.crypto_config_id),
                B256::from(self.setup_binding),
                B256::from(self.roster_hash),
                B256::from(self.dealer_batch),
                B256::from(self.pk_commitment),
                U256::from(self.party_id),
                B256::from(self.sk_agg_commit),
                B256::from(self.key_bundle_commit),
            )
                .abi_encode(),
        );
        Ok(keccak256([&[0x19, 0x01][..], domain.as_slice(), statement.as_slice()].concat()).into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedSynchronizedDkgAttestation {
    pub payload: SynchronizedDkgAttestationPayload,
    pub signature: ArcBytes,
}

/// Authenticated consent for one selected recipient. Transport authentication alone does not
/// authorize its slot; the publication owner checks the frozen context, roster and exact anchors.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SynchronizedDkgConsentPublished {
    pub attestation: SignedSynchronizedDkgAttestation,
}

impl Display for SynchronizedDkgConsentPublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, recipient: {}",
            self.attestation.payload.e3_id, self.attestation.payload.party_id
        )
    }
}

impl SignedSynchronizedDkgAttestation {
    /// Callers must first admit the exact setup and independently expected native key/anchors.
    pub fn sign(
        payload: SynchronizedDkgAttestationPayload,
        signer: &PrivateKeySigner,
    ) -> Result<Self> {
        let signature = signer.sign_hash_sync(&payload.digest()?.into())?;
        Ok(Self {
            payload,
            signature: ArcBytes::from_bytes(&signature.as_bytes()),
        })
    }

    pub fn recover_address(&self) -> Result<Address> {
        ensure!(
            self.signature.len() == 65,
            "synchronized consent requires a 65-byte ECDSA signature"
        );
        let signature = Signature::try_from(&self.signature[..])?;
        // Match Solidity ECDSA.recover: reject high-S and non-27/28 parity encodings, not normalize.
        ensure!(
            signature.normalize_s().is_none() && self.signature[..] == signature.as_bytes()[..],
            "noncanonical synchronized consent signature"
        );
        Ok(signature.recover_address_from_prehash(&self.payload.digest()?.into())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{b256, hex};

    fn payload() -> SynchronizedDkgAttestationPayload {
        let field = |value| U256::from(value).to_be_bytes::<32>();
        SynchronizedDkgAttestationPayload {
            e3_id: E3id::new(
                "1606938044258990275541962092341162602522202993782792835301385",
                31337,
            ),
            context: SynchronizedDkgContext {
                registry: Address::repeat_byte(0x22),
                verifying_contract: Address::repeat_byte(0x11),
                crypto_config_id: field(1),
            },
            setup_binding: field(2),
            roster_hash: synchronized_dkg_roster_hash(&[0, 2]),
            dealer_batch: field(3),
            pk_commitment: field(4),
            party_id: 2,
            sk_agg_commit: field(5),
            key_bundle_commit: field(6),
        }
    }

    #[test]
    fn ethers_typed_data_vector_retains_full_e3_id_and_exact_roster_encoding() -> Result<()> {
        // Independently calculated with ethers AbiCoder/TypedDataEncoder/signTypedData.
        let payload = payload();
        assert_eq!(
            payload.roster_hash,
            b256!("4d3ddd1d5447f3d66587b8324dcba0a57e95504638b2380a3a46b98f3246a581").0
        );
        assert_ne!(payload.roster_hash, synchronized_dkg_roster_hash(&[2, 0]));
        assert_eq!(
            payload.digest()?,
            b256!("b8780046efe73c2f8045c89c86b0b245737062d217d3a5615b0dfd734df53e61").0
        );
        let signer: PrivateKeySigner =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
        let signed = SignedSynchronizedDkgAttestation::sign(payload.clone(), &signer)?;
        assert_eq!(signed.signature[..], hex!(
            "77b852605272d58757dc1b210b05d0952e60bd351fff5c0d950318d1f71e8e7b7341bc3b2fb9f3f064c8f506010ea983ed7bd218f77146189f6762be224f36b41b"
        ));
        assert_eq!(signed.recover_address()?, signer.address());
        let mut truncated = payload;
        truncated.e3_id = E3id::new("9", 31337);
        assert_ne!(signed.payload.digest()?, truncated.digest()?);
        Ok(())
    }

    #[test]
    fn consent_rejects_non_evm_signature_encodings_and_ss_domain_reuse() -> Result<()> {
        let signer: PrivateKeySigner =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
        let signed = SignedSynchronizedDkgAttestation::sign(payload(), &signer)?;
        let mut bytes = signed.signature[..].to_vec();
        bytes[64] -= 27;
        let mut changed = signed.clone();
        changed.signature = ArcBytes::from_bytes(&bytes);
        assert!(changed.recover_address().is_err());
        changed.signature = ArcBytes::from_bytes(&bytes[..64]);
        assert!(changed.recover_address().is_err());
        let mut high_s = signed.signature.to_vec();
        let order = U256::from_be_bytes(hex!(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        let s = U256::from_be_slice(&high_s[32..64]);
        high_s[32..64].copy_from_slice(&(order - s).to_be_bytes::<32>());
        high_s[64] = 27 + 1 - (high_s[64] - 27);
        changed.signature = ArcBytes::from_bytes(&high_s);
        assert!(changed.recover_address().is_err());
        let ss = crate::SignedDkgFoldAttestation::sign(
            crate::DkgFoldAttestationPayload {
                e3_id: signed.payload.e3_id.clone(),
                registry: signed.payload.context.registry,
                verifying_contract: signed.payload.context.verifying_contract,
                party_id: 2,
                agg_commits: crate::DkgFoldAggCommits {
                    sk_agg_commit: signed.payload.sk_agg_commit,
                    esm_agg_commit: signed.payload.key_bundle_commit,
                },
            },
            &signer,
        )?;
        changed.signature = ss.signature;
        assert_ne!(changed.recover_address()?, signer.address());
        Ok(())
    }
}
