// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the chain asks of this node's release. The registries count an operator active only once
//! it acknowledged a release the chain accepts.

use crate::{Call, Contracts, RpcError};
use alloy::providers::Provider;
use alloy_primitives::{Address, B256};
use alloy_sol_types::SolCall;
use e3_evm_contracts::{IBondingRegistry, IInterfold, INodeReleaseRegistry};

/// The node release this build is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub id: B256,
    pub protocol_version: u32,
    pub node_generation: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "the chain requires protocol {protocol} and node generation {generation} or later; this node \
     is protocol {ours_protocol}, generation {ours_generation}"
)]
pub struct Unsupported {
    pub protocol: u32,
    pub generation: u32,
    pub ours_protocol: u32,
    pub ours_generation: u32,
}

/// Where the operator stands with a release.
#[derive(Debug, PartialEq, Eq)]
pub enum Standing {
    /// Nothing to send: the operator acknowledged the release and is active, or is not registered.
    Current,
    /// The operator has to send this acknowledgement.
    Unacknowledged(Box<Call>),
    /// A chain that requires another protocol, or a later generation, cannot run this node.
    Unsupported(Unsupported),
}

/// `operator`'s standing with `release` on the chain behind `provider`.
pub async fn standing<P: Provider>(
    provider: &P,
    contracts: &Contracts,
    release: Release,
    operator: Address,
) -> Result<Standing, RpcError> {
    let address = IInterfold::new(contracts.interfold, provider)
        .nodeReleaseRegistry()
        .call()
        .await
        .map_err(RpcError::new)?;
    let registry = INodeReleaseRegistry::new(address, provider);
    let protocol = registry
        .requiredProtocolVersion()
        .call()
        .await
        .map_err(RpcError::new)?;
    let generation = registry
        .requiredNodeGeneration()
        .call()
        .await
        .map_err(RpcError::new)?;
    if protocol != release.protocol_version || release.node_generation < generation {
        return Ok(Standing::Unsupported(Unsupported {
            protocol,
            generation,
            ours_protocol: release.protocol_version,
            ours_generation: release.node_generation,
        }));
    }
    let acknowledged = registry
        .operatorNodeRelease(operator)
        .call()
        .await
        .map_err(RpcError::new)?;
    let bonding = IBondingRegistry::new(contracts.bonding, provider);
    let registered = bonding
        .isRegistered(operator)
        .call()
        .await
        .map_err(RpcError::new)?;
    let active = bonding
        .isActive(operator)
        .call()
        .await
        .map_err(RpcError::new)?;
    let current = acknowledged.releaseId == release.id
        && acknowledged.protocolVersion == release.protocol_version
        && acknowledged.nodeGeneration == release.node_generation;
    if current && (!registered || active) {
        return Ok(Standing::Current);
    }
    Ok(Standing::Unacknowledged(Box::new(Call {
        label: "acknowledgeNodeRelease",
        to: address,
        data: INodeReleaseRegistry::acknowledgeNodeReleaseCall {
            releaseId: release.id,
            protocolVersion: release.protocol_version,
            nodeGeneration: release.node_generation,
        }
        .abi_encode()
        .into(),
        gas_multiplier: 2,
    })))
}
