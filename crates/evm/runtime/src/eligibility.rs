// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{contracts::IBondingRegistry, helpers::ProviderFactory};
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
};
use anyhow::anyhow;
use e3_sortition::EligibilityReader;
use futures_util::future::try_join_all;
use std::{collections::HashMap, sync::Arc};

/// Adapt enabled-chain provider factories and bonding registries into the reader that sortition
/// uses under a required identity policy. Each read connects anew, as the chain time reader does,
/// and asks `eligibilityAt` for every candidate at the request's T-1.
pub fn bonding_eligibility_reader<P>(
    chains: HashMap<u64, (ProviderFactory<P>, Address)>,
) -> EligibilityReader
where
    P: Provider + Clone + 'static,
{
    Arc::new(move |chain_id, operators, timepoint| {
        let chain = chains.get(&chain_id).cloned();
        Box::pin(async move {
            let (factory, bonding_registry) =
                chain.ok_or_else(|| anyhow!("No RPC provider configured for chain {chain_id}"))?;
            let provider = factory().await?;
            let bonding = IBondingRegistry::new(bonding_registry, provider.provider().clone());
            let reads = operators.iter().map(|operator| {
                let call = bonding.eligibilityAt(*operator, U256::from(timepoint));
                async move { call.call().await }
            });
            let eligibility = try_join_all(reads).await?;
            Ok(operators
                .into_iter()
                .zip(eligibility)
                .filter_map(|(operator, eligibility)| eligibility.active.then_some(operator))
                .collect())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{ConcreteReadProvider, EthProvider};
    use alloy::{
        primitives::Bytes, providers::ProviderBuilder, sol_types::SolValue,
        transports::mock::Asserter,
    };
    use anyhow::Result;
    use std::collections::HashSet;

    /// A provider whose `eligibilityAt` answers are `active`, in request order.
    fn factory(active: Vec<bool>) -> ProviderFactory<ConcreteReadProvider> {
        Arc::new(move || {
            let active = active.clone();
            Box::pin(async move {
                let asserter = Asserter::new();
                asserter.push_success(&"0x1");
                let provider = EthProvider::new(
                    ProviderBuilder::new().connect_mocked_client(asserter.clone()),
                )
                .await?;
                for active in active {
                    let answer = (active, U256::from(3)).abi_encode_params();
                    asserter.push_success(&Bytes::from(answer));
                }
                Ok(provider)
            })
        })
    }

    #[tokio::test]
    async fn keeps_the_operators_that_eligibility_at_finds_active() -> Result<()> {
        let operators = vec![
            Address::repeat_byte(1),
            Address::repeat_byte(2),
            Address::repeat_byte(3),
        ];
        let reader = bonding_eligibility_reader(HashMap::from([(
            1,
            (factory(vec![true, false, true]), Address::repeat_byte(9)),
        )]));
        assert_eq!(
            reader(1, operators, 100).await?,
            HashSet::from([Address::repeat_byte(1), Address::repeat_byte(3)])
        );
        assert!(reader(2, vec![], 100)
            .await
            .unwrap_err()
            .to_string()
            .contains("chain 2"));
        Ok(())
    }
}
