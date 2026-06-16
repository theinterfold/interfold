// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use crate::Repository;
use actix::Recipient;
use anyhow::*;
use async_trait::async_trait;
use e3_events::{EventContext, EventContextManager, Get, Insert, Remove, Sequenced};
use serde::{de::DeserializeOwned, Serialize};

pub trait PersistableData: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}
impl<T> PersistableData for T where T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}

/// AutoPersist enables a repository to generate a persistable container. This is not a database and
/// should not be thought of as a database. This is for creating actor snapshots.
#[async_trait]
pub trait AutoPersist<T>
where
    T: PersistableData,
{
    /// Load the data from the source into an auto persist container
    async fn load(&self) -> Result<Persistable<T>>;
    /// Create a new auto persist container and set some data on it to send back to the source
    fn send(&self, data: Option<T>) -> Persistable<T>;
    /// Load the data from the source into an auto persist container. If there is no persisted data then persist the given default data  
    async fn load_or_default(&self, default: T) -> Result<Persistable<T>>;
    /// Load the data from the source into an auto persist container. If there is no persisted data then persist the given default data  
    async fn load_or_else<F>(&self, f: F) -> Result<Persistable<T>>
    where
        F: Send + FnOnce() -> Result<T>;
}

#[async_trait]
impl<T> AutoPersist<T> for Repository<T>
where
    T: PersistableData,
{
    async fn load(&self) -> Result<Persistable<T>> {
        self.to_connector().load().await
    }

    fn send(&self, data: Option<T>) -> Persistable<T> {
        self.to_connector().send(data)
    }

    async fn load_or_default(&self, default: T) -> Result<Persistable<T>> {
        self.to_connector().load_or_default(default).await
    }

    async fn load_or_else<F>(&self, f: F) -> Result<Persistable<T>>
    where
        F: Send + FnOnce() -> Result<T>,
    {
        self.to_connector().load_or_else(f).await
    }
}

/// Connector to connect to store
#[derive(Clone, Debug)]
pub struct StoreConnector {
    pub key: Vec<u8>,
    pub get: Recipient<Get>,
    pub insert: Recipient<Insert>,
    pub remove: Recipient<Remove>,
}

impl StoreConnector {
    pub fn new(
        key: &[u8],
        get: &Recipient<Get>,
        insert: &Recipient<Insert>,
        remove: &Recipient<Remove>,
    ) -> Self {
        Self {
            key: key.to_owned(),
            get: get.clone(),
            insert: insert.clone(),
            remove: remove.clone(),
        }
    }
}

#[async_trait]
impl<T> AutoPersist<T> for StoreConnector
where
    T: PersistableData,
{
    async fn load(&self) -> Result<Persistable<T>> {
        Persistable::load(self.clone()).await
    }

    fn send(&self, data: Option<T>) -> Persistable<T> {
        Persistable::new(data, self.clone()).save()
    }

    async fn load_or_default(&self, default: T) -> Result<Persistable<T>> {
        Persistable::load_or_default(self.clone(), default).await
    }

    async fn load_or_else<F>(&self, f: F) -> Result<Persistable<T>>
    where
        F: Send + FnOnce() -> Result<T>,
    {
        Persistable::load_or_else(self.clone(), f).await
    }
}

/// A container that automatically persists its content every time it is mutated or changed.
#[derive(Debug)]
pub struct Persistable<T> {
    data: Option<T>,
    connector: StoreConnector,
    ctx: Option<EventContext<Sequenced>>,
    staging_mode: bool,
}

impl<T> Persistable<T>
where
    T: PersistableData,
{
    /// Create a new container with the given data and connector
    pub fn new(data: Option<T>, connector: StoreConnector) -> Self {
        Self {
            data,
            connector,
            ctx: None,
            staging_mode: false,
        }
    }

    /// Load data from the store
    pub async fn load(connector: StoreConnector) -> Result<Self> {
        let data = Self::read_from_store(&connector).await?;
        Ok(Self::new(data, connector))
    }

    /// Load the data or save and sync the given default value
    pub async fn load_or_default(connector: StoreConnector, default: T) -> Result<Self> {
        let data = Self::read_from_store(&connector).await?.unwrap_or(default);
        let instance = Self::new(Some(data), connector);
        Ok(instance.save())
    }

    /// Load the data or save and sync the result of the given callback
    pub async fn load_or_else<F>(connector: StoreConnector, f: F) -> Result<Self>
    where
        F: FnOnce() -> Result<T>,
    {
        let data = Self::read_from_store(&connector)
            .await?
            .ok_or_else(|| anyhow!("Not found"))
            .or_else(|_| f())?;
        let instance = Self::new(Some(data), connector);
        Ok(instance.save())
    }

    async fn read_from_store(connector: &StoreConnector) -> Result<Option<T>> {
        let Some(bytes) = connector.get.send(Get::new(&connector.key)).await? else {
            return Ok(None);
        };
        if bytes == [0] {
            return Ok(None);
        }
        Ok(Some(bincode::deserialize(&bytes)?))
    }

    fn write_to_store(&self) {
        if self.staging_mode {
            return;
        }

        let Some(ref data) = self.data else {
            return;
        };
        let Result::Ok(serialized) = bincode::serialize(data) else {
            tracing::error!("Could not serialize value for persistable");
            return;
        };

        let msg = if let Some(ctx) = self.ctx.clone() {
            Insert::new_with_context(&self.connector.key, serialized, ctx)
        } else {
            Insert::new(&self.connector.key, serialized)
        };
        self.connector.insert.do_send(msg);
    }

    /// Save the data in the container to the store
    pub fn save(self) -> Self {
        self.write_to_store();
        self
    }

    /// Mutate the content if available or return an error
    pub fn try_mutate_without_context<F>(&mut self, mutator: F) -> Result<()>
    where
        F: FnOnce(T) -> Result<T>,
    {
        self.try_mutate_impl(mutator, None)
    }

    pub fn try_mutate<F>(&mut self, ctx: &EventContext<Sequenced>, mutator: F) -> Result<()>
    where
        F: FnOnce(T) -> Result<T>,
    {
        self.try_mutate_impl(mutator, Some(ctx.clone()))
    }

    fn try_mutate_impl<F>(&mut self, mutator: F, ctx: Option<EventContext<Sequenced>>) -> Result<()>
    where
        F: FnOnce(T) -> Result<T>,
    {
        self.ctx = ctx; // Set the context
        let content = self.data.clone().ok_or(anyhow!("Data has not been set"))?;
        self.data = Some(mutator(content)?);
        self.write_to_store();
        Ok(())
    }

    /// Set the data on both the persistable and the store
    pub fn set(&mut self, data: T) {
        self.data = Some(data);
        self.write_to_store();
    }

    /// Clear the data from both the persistable and the store
    pub fn clear(&mut self) {
        self.data = None;
        self.connector
            .remove
            .do_send(Remove::new(&self.connector.key));
    }

    /// Get the data currently stored on the container as an Option<T>
    pub fn get(&self) -> Option<T> {
        self.data.clone()
    }

    /// Get the data from the container or return an error
    pub fn try_get(&self) -> Result<T> {
        self.data
            .clone()
            .ok_or(anyhow!("Data was not set on container."))
    }

    /// Returns true if there is data on the container
    pub fn has(&self) -> bool {
        self.data.is_some()
    }

    /// Enter staging mode - changes held in memory only
    pub fn stage(&mut self) {
        self.staging_mode = true;
    }

    /// Commit mode - writes current state and enables persistence
    pub fn commit(&mut self) {
        self.staging_mode = false;
        self.write_to_store();
    }
}

impl<T> EventContextManager for Persistable<T> {
    fn get_ctx(&self) -> Option<EventContext<Sequenced>> {
        self.ctx.clone()
    }

    fn set_ctx<C>(&mut self, value: C)
    where
        C: Into<EventContext<Sequenced>>,
    {
        self.ctx = Some(value.into().clone())
    }
}

#[cfg(test)]
mod tests {
    use actix::{Actor, Addr, Handler, Message};

    use e3_events::{Get, Insert, Remove};
    use e3_utils::MAILBOX_LIMIT;

    use super::{Persistable, StoreConnector};

    #[derive(Debug, Clone)]
    #[allow(clippy::large_enum_variant)]
    enum Evts {
        Get,
        Insert(Insert),
        Remove,
    }

    struct MockConnector {
        key: Vec<u8>,
        events: Vec<Evts>,
    }
    #[derive(Message)]
    #[rtype("Vec<Evts>")]
    struct GetEvents;

    impl Actor for MockConnector {
        type Context = actix::Context<Self>;
        fn started(&mut self, ctx: &mut Self::Context) {
            ctx.set_mailbox_capacity(MAILBOX_LIMIT)
        }
    }

    impl Handler<GetEvents> for MockConnector {
        type Result = Vec<Evts>;
        fn handle(&mut self, _msg: GetEvents, _ctx: &mut Self::Context) -> Self::Result {
            self.events.clone()
        }
    }

    impl Handler<Get> for MockConnector {
        type Result = Option<Vec<u8>>;
        fn handle(&mut self, _msg: Get, _ctx: &mut Self::Context) -> Self::Result {
            self.events.push(Evts::Get);
            None
        }
    }

    impl Handler<Insert> for MockConnector {
        type Result = ();
        fn handle(&mut self, msg: Insert, _ctx: &mut Self::Context) -> Self::Result {
            self.events.push(Evts::Insert(msg));
        }
    }

    impl Handler<Remove> for MockConnector {
        type Result = ();
        fn handle(&mut self, _msg: Remove, _ctx: &mut Self::Context) -> Self::Result {
            self.events.push(Evts::Remove);
        }
    }

    impl MockConnector {
        fn new(key: impl Into<Vec<u8>>) -> Self {
            Self {
                key: key.into(),
                events: Vec::new(),
            }
        }

        #[allow(clippy::wrong_self_convention)]
        fn to_store_connector(self) -> (Addr<MockConnector>, StoreConnector) {
            let key = self.key.clone();
            let addr = self.start();
            (
                addr.clone(),
                StoreConnector::new(
                    &key,
                    &addr.clone().recipient(),
                    &addr.clone().recipient(),
                    &addr.clone().recipient(),
                ),
            )
        }
    }

    #[actix::test]
    async fn test_persistable_staging() {
        let (addr, connector) = MockConnector::new(b"loc").to_store_connector();
        let mut p = Persistable::new(Some(42i32), connector);

        p.set(100);
        let events = addr.send(GetEvents).await.unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], Evts::Insert(msg) if msg.value() == &bincode::serialize(&100i32).unwrap())
        );

        p.stage();
        p.set(200);
        let events = addr.send(GetEvents).await.unwrap();
        assert_eq!(events.len(), 1);

        p.commit();
        let events = addr.send(GetEvents).await.unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            matches!(&events[1], Evts::Insert(msg) if msg.value() == &bincode::serialize(&200i32).unwrap())
        );
    }
}
