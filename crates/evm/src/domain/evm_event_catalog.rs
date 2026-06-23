// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Signatures emitted by the four contracts watched by the ciphernode.
//!
//! Protocol-driving events still have dedicated typed decoders. This catalog
//! names every other event in the current implementation ABIs so raw audit
//! records remain understandable without creating dozens of actor messages.

use alloy::primitives::{keccak256, B256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvmEventDefinition {
    pub name: &'static str,
    pub signature: &'static str,
    /// Position in the complete topics array (`topic0` is the signature).
    pub e3_id_topic: Option<usize>,
}

impl EvmEventDefinition {
    const fn new(name: &'static str, signature: &'static str, e3_id_topic: Option<usize>) -> Self {
        Self {
            name,
            signature,
            e3_id_topic,
        }
    }
}

pub(crate) fn find(contract: &str, topic0: B256) -> Option<&'static EvmEventDefinition> {
    catalog(contract)
        .iter()
        .find(|event| keccak256(event.signature.as_bytes()) == topic0)
}

fn catalog(contract: &str) -> &'static [EvmEventDefinition] {
    match contract {
        "Interfold" => INTERFOLD,
        "BondingRegistry" => BONDING_REGISTRY,
        "CiphernodeRegistry" => CIPHERNODE_REGISTRY,
        "SlashingManager" => SLASHING_MANAGER,
        _ => &[],
    }
}

const INTERFOLD: &[EvmEventDefinition] = &[
    EvmEventDefinition::new("BondingRegistrySet", "BondingRegistrySet(address)", None),
    EvmEventDefinition::new("CiphernodeRegistrySet", "CiphernodeRegistrySet(address)", None),
    EvmEventDefinition::new(
        "CiphertextOutputPublished",
        "CiphertextOutputPublished(uint256,bytes)",
        Some(1),
    ),
    EvmEventDefinition::new("CommitteeFinalized", "CommitteeFinalized(uint256)", Some(1)),
    EvmEventDefinition::new("CommitteeFormed", "CommitteeFormed(uint256)", Some(1)),
    EvmEventDefinition::new(
        "CommitteeThresholdsUpdated",
        "CommitteeThresholdsUpdated(uint8,uint32[2])",
        None,
    ),
    EvmEventDefinition::new("E3Failed", "E3Failed(uint256,uint8,uint8)", Some(1)),
    EvmEventDefinition::new(
        "E3FailureProcessed",
        "E3FailureProcessed(uint256,uint256,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new("E3ProgramRegistered", "E3ProgramRegistered(address)", None),
    EvmEventDefinition::new("E3RefundManagerSet", "E3RefundManagerSet(address)", None),
    EvmEventDefinition::new(
        "E3Requested",
        "E3Requested(uint256,(uint256,uint8,uint256,uint256[2],bytes32,address,uint8,bytes,address,address,bytes32,bytes32,bytes,address,bool),address)",
        None,
    ),
    EvmEventDefinition::new("E3StageChanged", "E3StageChanged(uint256,uint8,uint8)", Some(1)),
    EvmEventDefinition::new(
        "EncryptionSchemeDisabled",
        "EncryptionSchemeDisabled(bytes32)",
        None,
    ),
    EvmEventDefinition::new(
        "EncryptionSchemeEnabled",
        "EncryptionSchemeEnabled(bytes32)",
        None,
    ),
    EvmEventDefinition::new("FeeTokenAllowed", "FeeTokenAllowed(address,bool)", None),
    EvmEventDefinition::new("FeeTokenSet", "FeeTokenSet(address)", None),
    EvmEventDefinition::new("Initialized", "Initialized(uint64)", None),
    EvmEventDefinition::new(
        "InputPublished",
        "InputPublished(uint256,bytes,uint256,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "MarkFailedGracePeriodSet",
        "MarkFailedGracePeriodSet(uint256)",
        None,
    ),
    EvmEventDefinition::new("MaxDurationSet", "MaxDurationSet(uint256)", None),
    EvmEventDefinition::new(
        "OwnershipTransferStarted",
        "OwnershipTransferStarted(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "OwnershipTransferred",
        "OwnershipTransferred(address,address)",
        None,
    ),
    EvmEventDefinition::new("ParamSetRegistered", "ParamSetRegistered(uint8,bytes)", None),
    EvmEventDefinition::new("ParamSetUpdated", "ParamSetUpdated(uint8,bytes,bytes)", None),
    EvmEventDefinition::new("PkVerifierSet", "PkVerifierSet(bytes32,address)", None),
    EvmEventDefinition::new(
        "PlaintextOutputPublished",
        "PlaintextOutputPublished(uint256,bytes,bytes)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "PricingConfigUpdated",
        "PricingConfigUpdated((uint256,uint256,uint256,uint256,uint256,uint256,uint256,address,uint16,uint16,uint16,uint16,uint16,uint32,uint32))",
        None,
    ),
    EvmEventDefinition::new(
        "RewardClaimed",
        "RewardClaimed(uint256,address,address,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "RewardCredited",
        "RewardCredited(uint256,address,address,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "RewardsDistributed",
        "RewardsDistributed(uint256,address[],uint256[])",
        Some(1),
    ),
    EvmEventDefinition::new(
        "SlashedFundsEscrowed",
        "SlashedFundsEscrowed(uint256,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new("SlashingManagerSet", "SlashingManagerSet(address)", None),
    EvmEventDefinition::new(
        "TimeoutConfigUpdated",
        "TimeoutConfigUpdated((uint256,uint256,uint256))",
        None,
    ),
    EvmEventDefinition::new(
        "TreasuryClaimed",
        "TreasuryClaimed(address,address,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "TreasuryCredited",
        "TreasuryCredited(uint256,address,address,uint256)",
        Some(1),
    ),
];

const BONDING_REGISTRY: &[EvmEventDefinition] = &[
    EvmEventDefinition::new(
        "AssetsClaimed",
        "AssetsClaimed(address,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "AssetsQueuedForExit",
        "AssetsQueuedForExit(address,uint256,uint256,uint64)",
        None,
    ),
    EvmEventDefinition::new(
        "CiphernodeDeregistrationRequested",
        "CiphernodeDeregistrationRequested(address,uint64)",
        None,
    ),
    EvmEventDefinition::new(
        "ConfigurationUpdated",
        "ConfigurationUpdated(bytes32,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new("Initialized", "Initialized(uint64)", None),
    EvmEventDefinition::new(
        "LicenseBondUpdated",
        "LicenseBondUpdated(address,int256,uint256,bytes32)",
        None,
    ),
    EvmEventDefinition::new("LicenseTokenSet", "LicenseTokenSet(address)", None),
    EvmEventDefinition::new(
        "LicenseTransferShortfall",
        "LicenseTransferShortfall(address,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "OperatorActivationChanged",
        "OperatorActivationChanged(address,bool)",
        None,
    ),
    EvmEventDefinition::new(
        "OwnershipTransferStarted",
        "OwnershipTransferStarted(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "OwnershipTransferred",
        "OwnershipTransferred(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "PendingAssetsSlashed",
        "PendingAssetsSlashed(address,uint256,uint256,bool)",
        None,
    ),
    EvmEventDefinition::new("RegistrySet", "RegistrySet(address)", None),
    EvmEventDefinition::new(
        "RewardDistributorUpdated",
        "RewardDistributorUpdated(address,bool)",
        None,
    ),
    EvmEventDefinition::new(
        "SlashedFundsTreasurySet",
        "SlashedFundsTreasurySet(address)",
        None,
    ),
    EvmEventDefinition::new(
        "SlashedFundsWithdrawn",
        "SlashedFundsWithdrawn(address,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "SlashingManagerUpdated",
        "SlashingManagerUpdated(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "TicketBalanceUpdated",
        "TicketBalanceUpdated(address,int256,uint256,bytes32)",
        None,
    ),
    EvmEventDefinition::new("TicketTokenSet", "TicketTokenSet(address)", None),
];

const CIPHERNODE_REGISTRY: &[EvmEventDefinition] = &[
    EvmEventDefinition::new(
        "AccusationVoteValidityProposalCancelled",
        "AccusationVoteValidityProposalCancelled(uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "AccusationVoteValidityProposed",
        "AccusationVoteValidityProposed(uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "AccusationVoteValiditySet",
        "AccusationVoteValiditySet(uint256)",
        None,
    ),
    EvmEventDefinition::new("BondingRegistrySet", "BondingRegistrySet(address)", None),
    EvmEventDefinition::new(
        "CiphernodeAdded",
        "CiphernodeAdded(address,uint256,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "CiphernodeRemoved",
        "CiphernodeRemoved(address,uint256,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "CommitteeActivationChanged",
        "CommitteeActivationChanged(uint256,bool)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteeFormationFailed",
        "CommitteeFormationFailed(uint256,uint256,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteeMemberExpelled",
        "CommitteeMemberExpelled(uint256,address,bytes32,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteePublished",
        "CommitteePublished(uint256,address[],bytes,bytes32,bytes)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteeRequested",
        "CommitteeRequested(uint256,uint256,uint32[2],uint256,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteeViabilityUpdated",
        "CommitteeViabilityUpdated(uint256,uint256,uint256,bool)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "DkgFoldAttestationVerifierProposalCancelled",
        "DkgFoldAttestationVerifierProposalCancelled(address)",
        None,
    ),
    EvmEventDefinition::new(
        "DkgFoldAttestationVerifierProposed",
        "DkgFoldAttestationVerifierProposed(address,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "DkgFoldAttestationVerifierUpdated",
        "DkgFoldAttestationVerifierUpdated(address)",
        None,
    ),
    EvmEventDefinition::new("Initialized", "Initialized(uint64)", None),
    EvmEventDefinition::new("InterfoldSet", "InterfoldSet(address)", None),
    EvmEventDefinition::new(
        "OwnershipTransferStarted",
        "OwnershipTransferStarted(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "OwnershipTransferred",
        "OwnershipTransferred(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "RegistrySlashingManagerSet",
        "RegistrySlashingManagerSet(address)",
        None,
    ),
    EvmEventDefinition::new("SlashingManagerSet", "SlashingManagerSet(address)", None),
    EvmEventDefinition::new(
        "SortitionCommitteeFinalized",
        "SortitionCommitteeFinalized(uint256,address[],uint256[])",
        Some(1),
    ),
    EvmEventDefinition::new(
        "SortitionSubmissionWindowSet",
        "SortitionSubmissionWindowSet(uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "TicketSubmitted",
        "TicketSubmitted(uint256,address,uint256,uint256)",
        Some(1),
    ),
];

const SLASHING_MANAGER: &[EvmEventDefinition] = &[
    EvmEventDefinition::new(
        "AppealFiled",
        "AppealFiled(uint256,address,bytes32,string)",
        None,
    ),
    EvmEventDefinition::new(
        "AppealResolved",
        "AppealResolved(uint256,address,bool,address,string)",
        None,
    ),
    EvmEventDefinition::new("BanCancelled", "BanCancelled(address,address)", None),
    EvmEventDefinition::new("BanProposed", "BanProposed(address,bytes32,address)", None),
    EvmEventDefinition::new("BondingRegistrySet", "BondingRegistrySet(address)", None),
    EvmEventDefinition::new(
        "BondingRegistryUpdated",
        "BondingRegistryUpdated(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "CiphernodeRegistrySet",
        "CiphernodeRegistrySet(address)",
        None,
    ),
    EvmEventDefinition::new(
        "CiphernodeRegistryUpdated",
        "CiphernodeRegistryUpdated(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "DefaultAdminDelayChangeCanceled",
        "DefaultAdminDelayChangeCanceled()",
        None,
    ),
    EvmEventDefinition::new(
        "DefaultAdminDelayChangeScheduled",
        "DefaultAdminDelayChangeScheduled(uint48,uint48)",
        None,
    ),
    EvmEventDefinition::new(
        "DefaultAdminTransferCanceled",
        "DefaultAdminTransferCanceled()",
        None,
    ),
    EvmEventDefinition::new(
        "DefaultAdminTransferScheduled",
        "DefaultAdminTransferScheduled(address,uint48)",
        None,
    ),
    EvmEventDefinition::new("E3RefundManagerSet", "E3RefundManagerSet(address)", None),
    EvmEventDefinition::new(
        "E3RefundManagerUpdated",
        "E3RefundManagerUpdated(address,address)",
        None,
    ),
    EvmEventDefinition::new("EIP712DomainChanged", "EIP712DomainChanged()", None),
    EvmEventDefinition::new("InterfoldSet", "InterfoldSet(address)", None),
    EvmEventDefinition::new(
        "InterfoldUpdated",
        "InterfoldUpdated(address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "NodeBanUpdated",
        "NodeBanUpdated(address,bool,bytes32,address)",
        None,
    ),
    EvmEventDefinition::new(
        "RoleAdminChanged",
        "RoleAdminChanged(bytes32,bytes32,bytes32)",
        None,
    ),
    EvmEventDefinition::new("RoleGranted", "RoleGranted(bytes32,address,address)", None),
    EvmEventDefinition::new("RoleRevoked", "RoleRevoked(bytes32,address,address)", None),
    EvmEventDefinition::new("RoutingFailed", "RoutingFailed(uint256,uint256)", Some(1)),
    EvmEventDefinition::new(
        "SlashExecuted",
        "SlashExecuted(uint256,uint256,address,bytes32,uint256,uint256,bool,uint8)",
        None,
    ),
    EvmEventDefinition::new(
        "SlashPolicyUpdated",
        "SlashPolicyUpdated(bytes32,(uint256,uint256,bool,address,bool,uint256,bool,bool,uint8))",
        None,
    ),
    EvmEventDefinition::new(
        "SlashProposed",
        "SlashProposed(uint256,uint256,address,bytes32,uint256,uint256,uint256,address,uint8)",
        Some(2),
    ),
    EvmEventDefinition::new(
        "SlashedFundsEscrowedToRefund",
        "SlashedFundsEscrowedToRefund(uint256,uint256)",
        Some(1),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_contract_catalog_has_unique_topics() {
        for contract in [
            "Interfold",
            "BondingRegistry",
            "CiphernodeRegistry",
            "SlashingManager",
        ] {
            let mut topics = HashSet::new();
            for event in catalog(contract) {
                assert!(
                    topics.insert(keccak256(event.signature.as_bytes())),
                    "duplicate event topic for {contract}: {}",
                    event.signature
                );
            }
        }
    }

    #[test]
    fn resolves_current_admin_and_e3_events() {
        let ownership = keccak256("OwnershipTransferred(address,address)");
        assert_eq!(
            find("BondingRegistry", ownership).map(|event| event.name),
            Some("OwnershipTransferred")
        );

        let treasury = keccak256("TreasuryCredited(uint256,address,address,uint256)");
        let definition = find("Interfold", treasury).unwrap();
        assert_eq!(definition.name, "TreasuryCredited");
        assert_eq!(definition.e3_id_topic, Some(1));
    }
}
