// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, SignedProofPayload};
use actix::Message;
use alloy::primitives::{keccak256, Address, Signature, U256};
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol_types::SolValue;
use anyhow::Result;
use derivative::Derivative;
use e3_trbfv::shares::BfvEncryptedShares;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    sync::Arc,
};

/// BFV-encrypted shares list for a party in the DKG.
///
/// Each party broadcasts their encrypted shares to all other parties.
/// Each recipient can only decrypt the share meant for them using their
/// BFV secret key.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct ThresholdShare {
    /// The publisher's party_id
    pub party_id: u64,
    /// The publisher's TrBFV public key share
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pk_share: ArcBytes,
    /// BFV-encrypted sk_sss - each recipient can decrypt their share
    pub sk_sss: BfvEncryptedShares,
    /// BFV-encrypted esi_sss - one per secret key (sk), each recipient can decrypt their share
    pub esi_sss: Vec<BfvEncryptedShares>,
}

impl ThresholdShare {
    /// Extract only the shares meant for a specific party.
    pub fn extract_for_party(&self, recipient_party_id: usize) -> Option<Self> {
        let sk_sss = self.sk_sss.extract_for_party(recipient_party_id)?;
        let esi_sss: Option<Vec<_>> = self
            .esi_sss
            .iter()
            .map(|shares| shares.extract_for_party(recipient_party_id))
            .collect();

        esi_sss.map(|esi_sss| Self {
            party_id: self.party_id,
            pk_share: self.pk_share.clone(),
            sk_sss,
            esi_sss,
        })
    }

    pub fn num_parties(&self) -> usize {
        self.sk_sss.len()
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ThresholdShareCreated {
    pub e3_id: E3id,
    pub share: Arc<ThresholdShare>,
    pub target_party_id: u64,
    pub external: bool,
    /// Signed C2a proof (sk share computation) from the sender.
    pub signed_c2a_proof: Option<SignedProofPayload>,
    /// Signed C2b proof (e_sm share computation) from the sender.
    pub signed_c2b_proof: Option<SignedProofPayload>,
    /// Signed C3a proofs (sk share encryption per modulus row) for this recipient.
    pub signed_c3a_proofs: Vec<SignedProofPayload>,
    /// Signed C3b proofs (e_sm share encryption per modulus row) for this recipient.
    pub signed_c3b_proofs: Vec<SignedProofPayload>,
    /// Dealer signature over the E3, sender, recipient, shares, and complete proof bundle.
    pub signature: ArcBytes,
}

impl ThresholdShareCreated {
    pub fn sign(mut self, signer: &PrivateKeySigner) -> Result<Self> {
        let signature = signer.sign_hash_sync(&self.digest()?.into())?;
        self.signature = ArcBytes::from_bytes(&signature.as_bytes());
        Ok(self)
    }

    pub fn recover_address(&self) -> Result<Address> {
        let signature = Signature::try_from(&self.signature[..])?;
        Ok(signature.recover_address_from_prehash(&self.digest()?.into())?)
    }

    /// Transport origin is excluded because receipt changes `external`.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let proofs = bincode::serialize(&(
            &self.signed_c2a_proof,
            &self.signed_c2b_proof,
            &self.signed_c3a_proofs,
            &self.signed_c3b_proofs,
        ))?;
        Ok(keccak256(
            (
                keccak256("InterfoldThresholdShare(bytes32 e3IdHash,uint256 dealer,uint256 recipient,bytes32 shareHash,bytes32 proofsHash)"),
                keccak256(bincode::serialize(&self.e3_id)?),
                U256::from(self.share.party_id),
                U256::from(self.target_party_id),
                keccak256(bincode::serialize(&self.share)?),
                keccak256(proofs),
            )
                .abi_encode(),
        )
        .into())
    }
}

impl Display for ThresholdShareCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
