// SPDX-License-Identifier: LGPL-3.0-only

//! Peer join authentication, separate from the Solidity fault-attribution proof-role namespace.

use super::*;
use crate::{CircuitName, Proof, SynchronizedProofContext};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SynchronizedDkgProofRole {
    Dealer,
    Recipient,
}

impl SynchronizedDkgProofRole {
    pub fn circuit(self) -> CircuitName {
        match self {
            Self::Dealer => CircuitName::NodeFold,
            Self::Recipient => CircuitName::NodesFold,
        }
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SynchronizedDkgProofPublished {
    pub e3_id: E3id,
    pub context: SynchronizedProofContext,
    pub role: SynchronizedDkgProofRole,
    pub proof: Proof,
    pub signature: ArcBytes,
}

impl SynchronizedDkgProofPublished {
    pub fn digest(&self) -> Result<[u8; 32]> {
        ensure!(
            self.proof.circuit == self.role.circuit(),
            "wrong synchronized join role"
        );
        let domain = keccak256((
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("InterfoldSynchronizedDkgProof"),
            keccak256("1"),
            U256::from(self.e3_id.chain_id()),
            self.context.setup.interfold_address,
        ).abi_encode());
        let id: U256 = self.e3_id.clone().try_into()?;
        let role = match self.role {
            SynchronizedDkgProofRole::Dealer => 0u8,
            SynchronizedDkgProofRole::Recipient => 1u8,
        };
        let statement = keccak256(
            (
                keccak256(concat!(
                "SynchronizedDkgProof(uint256 e3Id,bytes32 committeeHash,bytes32 cryptoConfigId,",
                "uint256 partyId,uint8 role,bytes32 proofHash,bytes32 publicSignalsHash)"
            )),
                id,
                self.context.setup.committee_hash,
                self.context.setup.crypto_config_id,
                U256::from(self.context.party_id),
                U256::from(role),
                keccak256(&*self.proof.data),
                keccak256(&*self.proof.public_signals),
            )
                .abi_encode(),
        );
        Ok(keccak256([&[0x19, 0x01][..], domain.as_slice(), statement.as_slice()].concat()).into())
    }

    /// The owner must admit the correlated local result before signing.
    pub fn sign(
        e3_id: E3id,
        context: SynchronizedProofContext,
        role: SynchronizedDkgProofRole,
        proof: Proof,
        signer: &PrivateKeySigner,
    ) -> Result<Self> {
        let mut message = Self {
            e3_id,
            context,
            role,
            proof,
            signature: ArcBytes::from_bytes(&[]),
        };
        message.signature =
            ArcBytes::from_bytes(&signer.sign_hash_sync(&message.digest()?.into())?.as_bytes());
        Ok(message)
    }

    /// Authentication is not committee authorization or cryptographic proof verification.
    pub fn recover_address(&self) -> Result<Address> {
        ensure!(
            self.signature.len() == 65,
            "invalid synchronized join signature length"
        );
        let signature = Signature::try_from(&self.signature[..])?;
        ensure!(
            signature.normalize_s().is_none() && self.signature[..] == signature.as_bytes()[..],
            "noncanonical synchronized join signature"
        );
        Ok(signature.recover_address_from_prehash(&self.digest()?.into())?)
    }
}

impl Display for SynchronizedDkgProofPublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, party: {}, role: {:?}",
            self.e3_id, self.context.party_id, self.role
        )
    }
}

/// Local keyshare intent, produced only after native C4 planning fixes the accepted roster.
/// C2 statements come from the verified share batch; neither peers nor join results supply them.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SynchronizedRecipientInputsReady {
    pub e3_id: E3id,
    pub params_profile: e3_fhe_params::BfvProfile,
    pub committee_size: e3_committee::CiphernodesCommitteeSize,
    pub context: SynchronizedProofContext,
    pub dealers: Vec<u32>,
    pub transport_key: [u8; 32],
    pub sk_commitment: [u8; 32],
    pub key_bundle: [u8; 32],
    pub c2_statements: std::collections::BTreeMap<u32, ArcBytes>,
}

impl Display for SynchronizedRecipientInputsReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, recipient: {}",
            self.e3_id, self.context.party_id
        )
    }
}

/// Local, correlated recipient result. Peer setup messages cannot substitute for this verdict.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SynchronizedRecipientProofReady {
    pub e3_id: E3id,
    pub context: SynchronizedProofContext,
    pub proof: Proof,
    pub setup: SynchronizedSetupAnchors,
}

impl Display for SynchronizedRecipientProofReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, recipient: {}",
            self.e3_id, self.context.party_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{b256, hex};

    fn signed() -> Result<(PrivateKeySigner, SynchronizedDkgProofPublished)> {
        let signer: PrivateKeySigner =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
        let message = SynchronizedDkgProofPublished::sign(
            E3id::new(
                "1606938044258990275541962092341162602522202993782792835301385",
                31337,
            ),
            SynchronizedProofContext {
                party_id: 2,
                setup: e3_committee_hash::DkgSetupContext {
                    interfold_address: Address::repeat_byte(0x11),
                    committee_hash: [0x22; 32].into(),
                    crypto_config_id: [0x33; 32].into(),
                },
            },
            SynchronizedDkgProofRole::Dealer,
            Proof::new(
                CircuitName::NodeFold,
                ArcBytes::from_bytes(&[1, 2, 3]),
                ArcBytes::from_bytes(&[4, 5, 6]),
            ),
            &signer,
        )?;
        Ok((signer, message))
    }

    #[test]
    fn synchronized_join_matches_independent_ethers_typed_data() -> Result<()> {
        let (signer, message) = signed()?;
        assert_eq!(
            message.digest()?,
            b256!("a443667a286647f147afd601a2283035ee819fe590da0b150c5dd4a9f0ef4e21").0
        );
        assert_eq!(message.signature[..], hex!("731ce58396e3fae928f49548acaba5604b153c86d922b7dbbc733bc3ddec9b1d22ea1b4f41f6f3439a96cb3cf0619d93d80bc11deafeb3b426bda5bec4dbacc01c"));
        assert_eq!(message.recover_address()?, signer.address());
        Ok(())
    }

    #[test]
    fn synchronized_join_authenticates_every_domain_identity_and_proof_byte() -> Result<()> {
        let (signer, original) = signed()?;
        for mutation in 0..10 {
            let mut message = original.clone();
            match mutation {
                0 => message.e3_id = E3id::new("9", 31337),
                1 => message.e3_id = E3id::new(original.e3_id.e3_id(), 1),
                2 => message.context.setup.interfold_address = Address::repeat_byte(1),
                3 => message.context.setup.committee_hash = [1; 32].into(),
                4 => message.context.setup.crypto_config_id = [1; 32].into(),
                5 => message.context.party_id = 1,
                6 => {
                    message.role = SynchronizedDkgProofRole::Recipient;
                    message.proof.circuit = CircuitName::NodesFold;
                }
                7 => message.proof.data = ArcBytes::from_bytes(&[1, 2, 4]),
                8 => message.proof.public_signals = ArcBytes::from_bytes(&[4, 5, 7]),
                _ => {
                    message.proof.circuit = CircuitName::NodesFold;
                }
            }
            assert!(!message
                .recover_address()
                .is_ok_and(|address| address == signer.address()));
        }
        let mut message = original.clone();
        let mut signature = message.signature.to_vec();
        signature[64] -= 27;
        message.signature = ArcBytes::from_bytes(&signature);
        assert!(message.recover_address().is_err());
        signature = original.signature.to_vec();
        let order = U256::from_be_bytes(hex!(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        let s = U256::from_be_slice(&signature[32..64]);
        signature[32..64].copy_from_slice(&(order - s).to_be_bytes::<32>());
        signature[64] = 27 + 1 - (signature[64] - 27);
        message.signature = ArcBytes::from_bytes(&signature);
        assert!(message.recover_address().is_err());
        Ok(())
    }
}
