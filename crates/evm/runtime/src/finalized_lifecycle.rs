// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Read the lifecycle of E3s at the finalized block.

use crate::{contracts::IInterfold, helpers::EthProvider};
use alloy::{
    eips::BlockId,
    primitives::{Address, U256},
    providers::Provider,
};
use anyhow::{Context, Result};
use e3_events::{E3Stage, E3id, FailureReason};

/// The lifecycle of one E3 at the finalized block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizedE3Lifecycle {
    /// The finalized block has the E3 at this stage. A failed E3 carries its failure reason.
    Finalized {
        stage: E3Stage,
        failure_reason: Option<FailureReason>,
    },
    /// Chain head has the E3, but the finalized block does not have it yet.
    AwaitingFinality,
    /// Chain head does not have the E3.
    Unknown,
}

/// Read the lifecycle of each E3 from one Interfold contract at the finalized block.
pub async fn read_finalized_e3_lifecycles<P: Provider + Clone>(
    provider: &EthProvider<P>,
    contract_address: Address,
    e3_ids: &[E3id],
) -> Result<Vec<(E3id, FinalizedE3Lifecycle)>> {
    let finalized = BlockId::finalized();
    let contract = IInterfold::new(contract_address, provider.provider());
    // A contract that is not deployed at the finalized block has no finalized E3.
    let deployed_at_finalized = !provider
        .provider()
        .get_code_at(contract_address)
        .block_id(finalized)
        .await
        .context("could not read the Interfold contract code at the finalized block")?
        .is_empty();
    let mut lifecycles = Vec::with_capacity(e3_ids.len());
    for e3_id in e3_ids {
        let id: U256 = e3_id.clone().try_into()?;
        let stage = if deployed_at_finalized {
            E3Stage::try_from(contract.getE3Stage(id).block(finalized).call().await?)?
        } else {
            E3Stage::None
        };
        let lifecycle = match stage {
            E3Stage::None => match E3Stage::try_from(contract.getE3Stage(id).call().await?)? {
                E3Stage::None => FinalizedE3Lifecycle::Unknown,
                _ => FinalizedE3Lifecycle::AwaitingFinality,
            },
            E3Stage::Failed => {
                let reason = contract
                    .getFailureReason(id)
                    .block(finalized)
                    .call()
                    .await?;
                FinalizedE3Lifecycle::Finalized {
                    stage,
                    failure_reason: Some(FailureReason::try_from(reason)?),
                }
            }
            stage => FinalizedE3Lifecycle::Finalized {
                stage,
                failure_reason: None,
            },
        };
        lifecycles.push((e3_id.clone(), lifecycle));
    }
    Ok(lifecycles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::Bytes, providers::ProviderBuilder, sol_types::SolValue,
        transports::mock::Asserter,
    };

    const CODE: &str = "0x6080";

    async fn mocked() -> Result<(Asserter, EthProvider<impl Provider + Clone>)> {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider =
            EthProvider::new(ProviderBuilder::new().connect_mocked_client(asserter.clone()))
                .await?;
        Ok((asserter, provider))
    }

    fn word(value: u8) -> Bytes {
        Bytes::from(U256::from(value).abi_encode())
    }

    #[tokio::test]
    async fn reads_terminal_and_active_stages_at_the_finalized_block() -> Result<()> {
        let (asserter, provider) = mocked().await?;
        asserter.push_success(&CODE);
        asserter.push_success(&word(5));
        asserter.push_success(&word(6));
        asserter.push_success(&word(5));
        asserter.push_success(&word(3));
        let ids = [E3id::new("1", 1), E3id::new("2", 1), E3id::new("3", 1)];

        let lifecycles = read_finalized_e3_lifecycles(&provider, Address::ZERO, &ids).await?;

        let finalized = |stage, failure_reason| FinalizedE3Lifecycle::Finalized {
            stage,
            failure_reason,
        };
        assert_eq!(
            lifecycles,
            vec![
                (ids[0].clone(), finalized(E3Stage::Complete, None)),
                (
                    ids[1].clone(),
                    finalized(E3Stage::Failed, Some(FailureReason::NoInputsReceived))
                ),
                (ids[2].clone(), finalized(E3Stage::KeyPublished, None)),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_e3_only_at_chain_head_awaits_finality() -> Result<()> {
        let (asserter, provider) = mocked().await?;
        asserter.push_success(&CODE);
        asserter.push_success(&word(0));
        asserter.push_success(&word(1));
        let id = E3id::new("4", 1);

        let lifecycles =
            read_finalized_e3_lifecycles(&provider, Address::ZERO, std::slice::from_ref(&id))
                .await?;

        assert_eq!(
            lifecycles,
            vec![(id, FinalizedE3Lifecycle::AwaitingFinality)]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_contract_absent_at_the_finalized_block_reads_chain_head() -> Result<()> {
        let (asserter, provider) = mocked().await?;
        asserter.push_success(&"0x");
        asserter.push_success(&word(2));
        asserter.push_success(&word(0));
        let ids = [E3id::new("5", 1), E3id::new("6", 1)];

        let lifecycles = read_finalized_e3_lifecycles(&provider, Address::ZERO, &ids).await?;

        assert_eq!(
            lifecycles,
            vec![
                (ids[0].clone(), FinalizedE3Lifecycle::AwaitingFinality),
                (ids[1].clone(), FinalizedE3Lifecycle::Unknown),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failure_reason_only_at_chain_head_is_not_used() -> Result<()> {
        use alloy::{node_bindings::Anvil, primitives::bytes, providers::ext::AnvilApi};

        let anvil = Anvil::new().try_spawn()?;
        let chain_head = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let interfold = Address::repeat_byte(0x42);
        // The finalized block answers 6: the Failed stage and the ComputeTimeout reason. Chain head
        // answers 2: the InsufficientCommitteeMembers reason. Anvil's finalized block trails chain
        // head by 64 blocks.
        chain_head
            .anvil_set_code(interfold, bytes!("600660005260206000f3"))
            .await?;
        chain_head.anvil_mine(Some(70), None).await?;
        chain_head
            .anvil_set_code(interfold, bytes!("600260005260206000f3"))
            .await?;
        chain_head.anvil_mine(Some(1), None).await?;
        let provider = EthProvider::new(chain_head).await?;
        let id = E3id::new("1", anvil.chain_id());

        let lifecycles =
            read_finalized_e3_lifecycles(&provider, interfold, std::slice::from_ref(&id)).await?;

        assert_eq!(
            lifecycles,
            vec![(
                id,
                FinalizedE3Lifecycle::Finalized {
                    stage: E3Stage::Failed,
                    failure_reason: Some(FailureReason::ComputeTimeout),
                }
            )]
        );
        Ok(())
    }
}
