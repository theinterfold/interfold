// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{network::Ethereum, providers::Provider, rpc::types::Header};
use eyre::Result;
use futures::stream::StreamExt;
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;

type BlockHandler =
    Box<dyn Fn(&Header) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

#[derive(Clone)]
pub struct BlockListener {
    provider: Arc<dyn Provider<Ethereum>>,
    block_handlers: Arc<RwLock<Vec<BlockHandler>>>,
}

impl BlockListener {
    pub fn new(provider: Arc<dyn Provider<Ethereum>>) -> Self {
        Self {
            provider,
            block_handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn add_block_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(&Header) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        info!("add_block_handler");
        self.block_handlers
            .write()
            .await
            .push(Box::new(move |h: &Header| Box::pin(handler(h))));
    }

    pub async fn listen(&self) -> Result<()> {
        let mut stream = self.provider.subscribe_blocks().await?.into_stream();
        while let Some(block) = stream.next().await {
            let handlers = self.block_handlers.read().await;
            for handler in handlers.iter() {
                let fut = handler(&block);
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        eprintln!("Error processing block: {:?}", e);
                    }
                });
            }
        }
        Ok(())
    }
}
