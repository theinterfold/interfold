// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::marker::PhantomData;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::DataStore;

/// A value that an actor records before it dispatches the work that the value describes, and that
/// stays until the actor settles it. `record` and `settle` write the store directly and flush it.
/// No snapshot batch writes this key, so a queued batch cannot overwrite it, and a crash after
/// `record` returns cannot lose it.
#[derive(Debug)]
pub struct DurableIntent<T> {
    store: DataStore,
    _p: PhantomData<T>,
}

impl<T> Clone for DurableIntent<T> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            _p: PhantomData,
        }
    }
}

impl<T> DurableIntent<T>
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq,
{
    /// The intent stored at `store`'s scope.
    pub fn new(store: DataStore) -> Self {
        Self {
            store,
            _p: PhantomData,
        }
    }

    /// Record `intent`, durably. Recording the intent that is already recorded does nothing more
    /// than make it durable. A different one fails, so a recorded intent is never replaced.
    pub async fn record(&self, intent: &T) -> Result<()> {
        if self.store.write_if_absent_sync(intent).await? {
            return Ok(());
        }
        match self.restore().await? {
            // Another `record` of the same intent can have inserted it without flushing yet: the
            // caller dispatches the work once this returns, so the intent must be on disk first.
            Some(recorded) if &recorded == intent => self.store.flush_sync().await,
            Some(_) => bail!("a different intent is already recorded"),
            None => bail!("the recorded intent was removed while another was recorded"),
        }
    }

    /// The recorded intent. A failed read, or a record that does not decode, is an error.
    pub async fn restore(&self) -> Result<Option<T>> {
        self.store.read_checked().await
    }

    /// Remove the intent, durably, once its work is done.
    pub async fn settle(&self) -> Result<()> {
        self.store.remove_sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::DurableIntent;
    use crate::{DataStore, InMemStore};
    use actix::Actor;

    #[actix::test]
    async fn an_intent_is_recorded_once_and_never_replaced() -> anyhow::Result<()> {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start()).scope("intent");
        let intent = DurableIntent::<(u64, String)>::new(store.clone());
        assert_eq!(intent.restore().await?, None);

        intent.record(&(1, "roster a".into())).await?;
        intent.record(&(1, "roster a".into())).await?;
        assert!(intent.record(&(2, "roster b".into())).await.is_err());
        assert_eq!(intent.restore().await?, Some((1, "roster a".into())));

        // Another handle over the same key sees the same intent.
        let other = DurableIntent::<(u64, String)>::new(store);
        assert_eq!(other.restore().await?, Some((1, "roster a".into())));

        intent.settle().await?;
        assert_eq!(other.restore().await?, None);
        other.record(&(2, "roster b".into())).await?;
        assert_eq!(intent.restore().await?, Some((2, "roster b".into())));
        Ok(())
    }

    /// Counts the flushes that reach the store.
    struct CountFlushes {
        store: actix::Addr<InMemStore>,
        count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Actor for CountFlushes {
        type Context = actix::Context<Self>;
    }

    impl actix::Handler<e3_events::Flush> for CountFlushes {
        type Result = actix::ResponseFuture<anyhow::Result<()>>;

        fn handle(&mut self, flush: e3_events::Flush, _: &mut Self::Context) -> Self::Result {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let store = self.store.clone();
            Box::pin(async move { store.send(flush).await? })
        }
    }

    /// Recording the intent that is already recorded flushes the store too: another `record` of
    /// the same intent can have inserted it without flushing yet, and the caller dispatches the
    /// work once `record` returns.
    #[actix::test]
    async fn recording_the_recorded_intent_again_flushes_it() -> anyhow::Result<()> {
        let store = InMemStore::new(false).start();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flushes = CountFlushes {
            store: store.clone(),
            count: count.clone(),
        }
        .start();
        let intent = DurableIntent::<(u64, String)>::new(
            DataStore::from_in_mem(&store)
                .with_flush_recipient(flushes.recipient())
                .scope("intent"),
        );

        intent.record(&(1, "roster a".into())).await?;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        intent.record(&(1, "roster a".into())).await?;
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the second record flushes the intent that the first inserted"
        );
        Ok(())
    }

    #[actix::test]
    async fn a_record_that_does_not_decode_is_an_error() -> anyhow::Result<()> {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start()).scope("intent");
        store.write_sync(vec![0xff_u8; 3]).await?;
        let intent = DurableIntent::<(u64, String)>::new(store);
        assert!(intent.restore().await.is_err());
        assert!(intent.record(&(1, "roster a".into())).await.is_err());
        Ok(())
    }
}
