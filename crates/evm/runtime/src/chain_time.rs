// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::helpers::{get_current_timestamp_from_provider, ProviderFactory};
use alloy::providers::Provider;
use anyhow::anyhow;
use e3_sortition::CommitteeChainTimeReader;
use std::{collections::HashMap, sync::Arc};

/// Adapt enabled-chain provider factories without retaining a connected provider across attempts.
pub fn committee_chain_time_reader<P>(
    providers: HashMap<u64, ProviderFactory<P>>,
) -> CommitteeChainTimeReader
where
    P: Provider + Clone + 'static,
{
    Arc::new(move |chain_id| {
        let factory = providers.get(&chain_id).cloned();
        Box::pin(async move {
            let factory = factory
                .ok_or_else(|| anyhow!("No RPC provider configured for chain {chain_id}"))?;
            // A WebSocket past its reconnect budget stays dead: reconnect on every attempt.
            get_current_timestamp_from_provider(factory().await?).await
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{ConcreteReadProvider, EthProvider};
    use alloy::{providers::ProviderBuilder, rpc::types::Block, transports::mock::Asserter};
    use anyhow::Result;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn factory(
        chain_id: u64,
        calls: Arc<AtomicUsize>,
        fail_first: bool,
    ) -> ProviderFactory<ConcreteReadProvider> {
        Arc::new(move || {
            let attempt = calls.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move {
                if fail_first && attempt == 1 {
                    anyhow::bail!("connection failed");
                }
                let asserter = Asserter::new();
                asserter.push_success(&format!("0x{chain_id:x}"));
                let provider = EthProvider::new(
                    ProviderBuilder::new().connect_mocked_client(asserter.clone()),
                )
                .await?;
                let mut block: Block = Block::default();
                block.header.inner.timestamp = chain_id * 1_000 + attempt as u64;
                asserter.push_success(&block);
                Ok(provider)
            })
        })
    }

    #[tokio::test]
    async fn reconnects_after_failure_and_after_success_without_caching_time() -> Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader =
            committee_chain_time_reader(HashMap::from([(2, factory(2, calls.clone(), true))]));
        let first = reader(2);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "reader started an unowned connection"
        );
        assert!(first
            .await
            .unwrap_err()
            .to_string()
            .contains("connection failed"));
        assert_eq!(reader(2).await?, 2_002);
        assert_eq!(reader(2).await?, 2_003);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[tokio::test]
    async fn routes_by_chain_and_does_not_fallback_for_an_unknown_chain() -> Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = committee_chain_time_reader(HashMap::from([
            (2, factory(2, calls.clone(), false)),
            (7, factory(7, calls.clone(), false)),
        ]));
        assert_eq!(reader(7).await?, 7_001);
        assert_eq!(reader(2).await?, 2_002);
        assert!(reader(9).await.unwrap_err().to_string().contains("chain 9"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn missing_latest_block_and_rpc_errors_remain_errors() -> Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let factory: ProviderFactory<ConcreteReadProvider> = Arc::new(move || {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let asserter = Asserter::new();
                asserter.push_success(&"0x2");
                let provider = EthProvider::new(
                    ProviderBuilder::new().connect_mocked_client(asserter.clone()),
                )
                .await?;
                if attempt == 0 {
                    asserter.push_success(&Option::<Block>::None);
                } else {
                    asserter.push_failure_msg("timestamp RPC unavailable");
                }
                Ok(provider)
            })
        });
        let reader = committee_chain_time_reader(HashMap::from([(2, factory)]));
        assert!(reader(2)
            .await
            .unwrap_err()
            .to_string()
            .contains("Latest block not found"));
        let error = reader(2).await.unwrap_err();
        assert!(format!("{error:#}").contains("timestamp RPC unavailable"));
        Ok(())
    }

    #[tokio::test]
    async fn reads_anvils_latest_mined_timestamp() -> Result<()> {
        use alloy::{node_bindings::Anvil, providers::ext::AnvilApi};
        let anvil = Anvil::new().try_spawn()?;
        let url = anvil.endpoint_url();
        let factory: ProviderFactory<ConcreteReadProvider> = Arc::new(move || {
            let url = url.clone();
            Box::pin(
                async move { EthProvider::new(ProviderBuilder::new().connect_http(url)).await },
            )
        });
        let reader = committee_chain_time_reader(HashMap::from([(anvil.chain_id(), factory)]));
        let head = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let first = reader(anvil.chain_id()).await?;
        head.anvil_set_next_block_timestamp(first + 60).await?;
        head.anvil_mine(Some(1), None).await?;
        assert_eq!(reader(anvil.chain_id()).await?, first + 60);
        Ok(())
    }
}
