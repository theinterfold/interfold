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
        .chain(retired_catalog(contract).iter())
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

/// Signatures that the current ABIs no longer emit, kept so already-mined logs stay readable.
///
/// Renaming a Solidity event changes its `topic0`, but the contracts sit behind proxies: the
/// address survives the upgrade and so does everything it has already emitted. Without these,
/// a node syncing from before the rename would fail to decode its own history.
///
/// Deliberately separate from [`catalog`], which is asserted to match the current ABIs exactly.
/// Entries here are append-only — a signature that was once on chain is on chain forever.
fn retired_catalog(contract: &str) -> &'static [EvmEventDefinition] {
    match contract {
        "Interfold" => RETIRED_INTERFOLD,
        "BondingRegistry" => RETIRED_BONDING_REGISTRY,
        _ => &[],
    }
}

const RETIRED_INTERFOLD: &[EvmEventDefinition] = &[EvmEventDefinition::new(
    "FeeAssetConfigUpdated",
    "FeeAssetConfigUpdated(address,uint8,(uint256,uint256,uint256,uint256,uint256,uint256,uint256,address,uint16,uint16,uint16,uint16,uint16,uint32,uint32))",
    None,
)];

const RETIRED_BONDING_REGISTRY: &[EvmEventDefinition] = &[
    // Renamed to `CiphernodeBondUpdated`. Same field layout, so the decoded record is identical;
    // only the name the signature hashes from changed.
    EvmEventDefinition::new(
        "CiphernodeBondUpdated",
        "LicenseBondUpdated(address,int256,uint256,bytes32)",
        None,
    ),
];

const INTERFOLD: &[EvmEventDefinition] = &[
    EvmEventDefinition::new("BondingRegistrySet", "BondingRegistrySet(address)", None),
    EvmEventDefinition::new("CiphernodeRegistrySet", "CiphernodeRegistrySet(address)", None),
    EvmEventDefinition::new(
        "CiphertextOutputPublished",
        "CiphertextOutputPublished(uint256,bytes,bytes32)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CiphertextOutputReferencePublished",
        "CiphertextOutputReferencePublished(uint256,bytes32,bytes32,uint32,uint128)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CiphertextVerifierSet",
        "CiphertextVerifierSet(bytes32,address)",
        None,
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
    EvmEventDefinition::new(
        "E3ProgramUnregistered",
        "E3ProgramUnregistered(address)",
        None,
    ),
    EvmEventDefinition::new("E3RefundManagerSet", "E3RefundManagerSet(address)", None),
    EvmEventDefinition::new(
        "E3Requested",
        "E3Requested(uint256,(uint256,uint8,uint256,uint256[2],bytes32,address,uint8,bytes,address,address,bytes32,bytes32,bytes,address,bytes32),bytes32)",
        None,
    ),
    EvmEventDefinition::new("E3StageChanged", "E3StageChanged(uint256,uint8,uint8)", Some(1)),
    EvmEventDefinition::new(
        "EncryptionSchemeEnabled",
        "EncryptionSchemeEnabled(bytes32)",
        None,
    ),
    EvmEventDefinition::new("FeeTokenAllowed", "FeeTokenAllowed(address,bool)", None),
    EvmEventDefinition::new(
        "FeeAssetConfigUpdated",
        "FeeAssetConfigUpdated(address,uint8,(uint256,uint256,uint256,uint256,uint256,uint256,uint256,address,uint16,uint16,uint16,uint16,uint16,uint32,uint32,uint192))",
        None,
    ),
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
        "NodeReleaseRegistrySet",
        "NodeReleaseRegistrySet(address)",
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
    EvmEventDefinition::new("ParamSetRegistered", "ParamSetRegistered(uint8,bytes)", None),
    EvmEventDefinition::new("PkVerifierSet", "PkVerifierSet(bytes32,address)", None),
    EvmEventDefinition::new(
        "PlaintextOutputPublished",
        "PlaintextOutputPublished(uint256,bytes,bytes)",
        Some(1),
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
    EvmEventDefinition::new("RequestsPausedSet", "RequestsPausedSet(bool)", None),
    EvmEventDefinition::new(
        "SlashedFundsEscrowed",
        "SlashedFundsEscrowed(uint256,address,uint256)",
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
        "BondedCheckpointsSet",
        "BondedCheckpointsSet(address)",
        None,
    ),
    EvmEventDefinition::new(
        "BondedCheckpointsDetached",
        "BondedCheckpointsDetached(address)",
        None,
    ),
    EvmEventDefinition::new(
        "BondingAssetConfigUpdated",
        "BondingAssetConfigUpdated(address,address,uint256,uint256,uint8,uint8,uint64)",
        None,
    ),
    EvmEventDefinition::new("BondOwnerSet", "BondOwnerSet(address,address)", None),
    EvmEventDefinition::new(
        "BondOwnerTransferProposed",
        "BondOwnerTransferProposed(address,address,address)",
        None,
    ),
    EvmEventDefinition::new(
        "CiphernodeDeregistrationRequested",
        "CiphernodeDeregistrationRequested(address,uint64)",
        None,
    ),
    EvmEventDefinition::new(
        "CommitteeObligationUpdated",
        "CommitteeObligationUpdated(uint256,address,address,bool)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "ConfigurationUpdated",
        "ConfigurationUpdated(bytes32,uint256,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "EligibilityConfigurationVersionUpdated",
        "EligibilityConfigurationVersionUpdated(uint256)",
        None,
    ),
    EvmEventDefinition::new("Initialized", "Initialized(uint64)", None),
    EvmEventDefinition::new(
        "CiphernodeBondUpdated",
        "CiphernodeBondUpdated(address,int256,uint256,bytes32)",
        None,
    ),
    EvmEventDefinition::new(
        "CiphernodeBondSurplusSwept",
        "CiphernodeBondSurplusSwept(address,address,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "ManagerBanUpdated",
        "ManagerBanUpdated(address,address,bool)",
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
        "ReservedSlashedTicketFundsRouted",
        "ReservedSlashedTicketFundsRouted(address,uint256,address,uint256)",
        None,
    ),
    EvmEventDefinition::new(
        "RewardDistributorUpdated",
        "RewardDistributorUpdated(address,bool)",
        None,
    ),
    EvmEventDefinition::new(
        "SlashLockUpdated",
        "SlashLockUpdated(address,uint256,address,bool)",
        None,
    ),
    EvmEventDefinition::new(
        "SlashRouteDestinationReleased",
        "SlashRouteDestinationReleased(address,uint256)",
        Some(2),
    ),
    EvmEventDefinition::new(
        "SlashRouteDestinationSnapshotted",
        "SlashRouteDestinationSnapshotted(address,uint256,address)",
        Some(2),
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
        "SlashedTicketFundsReserved",
        "SlashedTicketFundsReserved(address,uint256,uint256,address,uint256)",
        Some(3),
    ),
    EvmEventDefinition::new(
        "SlashingManagerAuthorizationUpdated",
        "SlashingManagerAuthorizationUpdated(address,bool)",
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
        "CiphernodeTreeCapacityWarning",
        "CiphernodeTreeCapacityWarning(uint256,uint256)",
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
        "CommitteeProofPublished",
        "CommitteeProofPublished(uint256,address[],bytes32,bytes)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteeRandomnessRequested",
        "CommitteeRandomnessRequested(uint256,uint256,address,uint256)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteePublished",
        "CommitteePublished(uint256,address[],bytes,bytes32,bytes)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteePublicKeyChunkPublished",
        "CommitteePublicKeyChunkPublished(uint256,address,bytes32,address[],bytes32,uint16,uint16,uint32,bytes)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "CommitteeRequested",
        "CommitteeRequested(uint256,uint256,uint32[2],uint256,uint256,uint256)",
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
        "RandomnessProviderSet",
        "RandomnessProviderSet(address)",
        None,
    ),
    EvmEventDefinition::new(
        "RandomnessCircuitBreakerTripped",
        "RandomnessCircuitBreakerTripped(uint256,uint256,address)",
        Some(1),
    ),
    EvmEventDefinition::new(
        "RandomnessRequestTimeoutSet",
        "RandomnessRequestTimeoutSet(uint256)",
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
        "DkgFoldAttestationContextEstablished",
        "DkgFoldAttestationContextEstablished(uint256,address,address)",
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
        "E3DependenciesReleased",
        "E3DependenciesReleased(uint256)",
        Some(1),
    ),
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
        "SlashRouteCompleted",
        "SlashRouteCompleted(uint256,uint256,address,uint256)",
        Some(2),
    ),
    EvmEventDefinition::new(
        "SlashRoutePending",
        "SlashRoutePending(uint256,uint256,address,uint256)",
        Some(2),
    ),
    EvmEventDefinition::new(
        "SlashedFundsEscrowedToRefund",
        "SlashedFundsEscrowedToRefund(uint256,address,uint256)",
        Some(1),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;

    const CONTRACT_ARTIFACTS: &[(&str, &str)] = &[
        (
            "Interfold",
            "artifacts/contracts/Interfold.sol/Interfold.json",
        ),
        (
            "BondingRegistry",
            "artifacts/contracts/registry/BondingRegistry.sol/BondingRegistry.json",
        ),
        (
            "CiphernodeRegistry",
            "artifacts/contracts/registry/CiphernodeRegistryOwnable.sol/CiphernodeRegistryOwnable.json",
        ),
        (
            "SlashingManager",
            "artifacts/contracts/slashing/SlashingManager.sol/SlashingManager.json",
        ),
    ];

    fn artifact_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/interfold-contracts")
            .join(relative)
    }

    fn canonical_type(input: &Value) -> String {
        let abi_type = input["type"].as_str().expect("ABI input type");
        let Some(tuple_suffix) = abi_type.strip_prefix("tuple") else {
            return abi_type.to_owned();
        };
        let components = input["components"]
            .as_array()
            .expect("tuple ABI components")
            .iter()
            .map(canonical_type)
            .collect::<Vec<_>>()
            .join(",");
        format!("({components}){tuple_suffix}")
    }

    fn artifact_events(relative: &str) -> HashMap<String, Option<usize>> {
        let artifact: Value =
            serde_json::from_str(&fs::read_to_string(artifact_path(relative)).unwrap()).unwrap();
        artifact["abi"]
            .as_array()
            .expect("artifact ABI")
            .iter()
            .filter(|item| item["type"] == "event")
            .map(|event| {
                let inputs = event["inputs"].as_array().expect("event inputs");
                let signature = format!(
                    "{}({})",
                    event["name"].as_str().expect("event name"),
                    inputs
                        .iter()
                        .map(canonical_type)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let mut topic_position = 1;
                let mut e3_id_topic = None;
                for input in inputs {
                    if !input["indexed"].as_bool().unwrap_or(false) {
                        continue;
                    }
                    if input["name"].as_str() == Some("e3Id") {
                        e3_id_topic = Some(topic_position);
                    }
                    topic_position += 1;
                }
                (signature, e3_id_topic)
            })
            .collect()
    }

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

    /// A rename changes `topic0`, but the contracts are proxies — the address and everything it
    /// already emitted survive the upgrade. A node syncing from before the rename must still be
    /// able to read its own history.
    #[test]
    fn retired_signatures_still_decode_to_their_current_name() {
        let old_fee_config = keccak256(
            "FeeAssetConfigUpdated(address,uint8,(uint256,uint256,uint256,uint256,uint256,uint256,uint256,address,uint16,uint16,uint16,uint16,uint16,uint32,uint32))",
        );
        assert_eq!(
            find("Interfold", old_fee_config).map(|event| event.name),
            Some("FeeAssetConfigUpdated"),
            "pre-VRF pricing logs must still decode"
        );

        let retired = keccak256("LicenseBondUpdated(address,int256,uint256,bytes32)");
        assert_eq!(
            find("BondingRegistry", retired).map(|event| event.name),
            Some("CiphernodeBondUpdated"),
            "pre-rename logs must still decode"
        );

        // The current signature resolves to the same record, so both eras read alike.
        let current = keccak256("CiphernodeBondUpdated(address,int256,uint256,bytes32)");
        assert_eq!(
            find("BondingRegistry", current).map(|event| event.name),
            Some("CiphernodeBondUpdated")
        );
    }

    /// Retired entries must never collide with a live one, or a current log would decode as the
    /// wrong event.
    #[test]
    fn retired_signatures_never_shadow_a_live_one() {
        for contract in [
            "Interfold",
            "BondingRegistry",
            "CiphernodeRegistry",
            "SlashingManager",
        ] {
            let live: HashSet<B256> = catalog(contract)
                .iter()
                .map(|event| keccak256(event.signature.as_bytes()))
                .collect();
            for event in retired_catalog(contract) {
                assert!(
                    !live.contains(&keccak256(event.signature.as_bytes())),
                    "{contract}: retired signature {} is still live",
                    event.signature
                );
            }
        }
    }

    #[test]
    fn every_watched_contract_catalog_matches_its_current_abi() {
        for (contract, artifact) in CONTRACT_ARTIFACTS {
            let expected = artifact_events(artifact);
            let actual = catalog(contract)
                .iter()
                .map(|event| (event.signature.to_owned(), event.e3_id_topic))
                .collect::<HashMap<_, _>>();
            assert_eq!(
                actual, expected,
                "{contract} event catalog drifted from {artifact}"
            );
        }
    }
}
