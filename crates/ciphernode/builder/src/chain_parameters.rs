// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The chain configuration that the protocol extensions read at startup.

use super::CiphernodeBuilder;
use anyhow::Result;
use e3_events::DkgFoldAttestationContext;
use e3_evm::{fetch_accusation_vote_validity, Chains, EnabledChain};
use e3_sync::NodeRole;
use std::collections::HashMap;
use tracing::{info, warn};

/// Chain configuration that the protocol extensions read at startup.
#[derive(Default)]
pub(super) struct ChainParameters {
    /// DKG fold attestation contexts from static configuration, by chain ID.
    pub dkg_fold_context_by_chain: HashMap<u64, Option<DkgFoldAttestationContext>>,
    /// `CiphernodeRegistry.accusationVoteValidity()` in seconds, by chain ID.
    pub accusation_vote_validity_by_chain: HashMap<u64, u64>,
}

impl CiphernodeBuilder {
    /// Read the DKG fold attestation verifiers and the accusation vote validity of the configured
    /// chains.
    pub(super) async fn fetch_chain_parameters(&self, chains: &Chains) -> Result<ChainParameters> {
        // A bootstrap node runs no keyshare, aggregation, or accusation work, so it reads neither.
        if self.role() == NodeRole::Bootstrap {
            return Ok(ChainParameters::default());
        }
        let mut dkg_fold_context_by_chain = HashMap::new();
        let mut accusation_vote_validity_by_chain = HashMap::new();

        // Synthetic runs have no committee-finalized log to carry request-time addresses.
        // Use static configuration only when the chain itself is disabled.
        for chain in chains.disabled() {
            let Some(chain_id) = chain.chain_id else {
                continue;
            };
            if let Some(contract) = &chain.contracts.dkg_fold_attestation_verifier {
                if let (Ok(registry), Ok(verifying_contract)) = (
                    chain.contracts.ciphernode_registry.address(),
                    contract.address(),
                ) {
                    dkg_fold_context_by_chain.entry(chain_id).or_insert(Some(
                        DkgFoldAttestationContext {
                            registry,
                            verifying_contract,
                        },
                    ));
                }
            }
        }

        for chain in chains.enabled() {
            accusation_vote_validity_by_chain.insert(
                chain.chain_id,
                fetch_accusation_vote_validity_secs(chain).await?,
            );
        }

        Ok(ChainParameters {
            dkg_fold_context_by_chain,
            accusation_vote_validity_by_chain,
        })
    }
}

/// Fetch `CiphernodeRegistry.accusationVoteValidity()` for one chain (off-chain
/// vote freshness window in seconds). Returns `0` when the registry has
/// disabled slashing (governance emergency stop). The actor will then refuse
/// to stamp votes that would be rejected on chain.
///
/// The `u256` returned by the registry is clamped to `u64`. The contract
/// has no upper bound but `u64::MAX` seconds is already ~5.8 × 10¹¹ years —
/// any value that doesn't fit in `u64` is treated as "effectively infinite"
/// by saturating at `u64::MAX`, matching the on-chain `block.timestamp`
/// comparison.
async fn fetch_accusation_vote_validity_secs(chain: &EnabledChain) -> Result<u64> {
    let registry = chain.config.contracts.ciphernode_registry.address()?;
    let validity = fetch_accusation_vote_validity(chain.provider.provider(), registry).await?;
    let secs = match validity {
        Some(v) => {
            let clamped: u64 = v.try_into().unwrap_or(u64::MAX);
            info!(
                chain = %chain.config.name,
                registry = %registry,
                accusation_vote_validity_secs = clamped,
                "loaded accusationVoteValidity from CiphernodeRegistry"
            );
            clamped
        }
        None => {
            warn!(
                chain = %chain.config.name,
                registry = %registry,
                "CiphernodeRegistry.accusationVoteValidity is 0; the off-chain \
                 accusation manager will not produce votes (governance-disabled \
                 or pre-initialized registry)"
            );
            0
        }
    };
    Ok(secs)
}
