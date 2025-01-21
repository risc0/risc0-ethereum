use crate::{state::WrapStateDb, EvmBlockHeader, GuestEvmEnv};
use alloy_primitives::{Address, Log, Sealed};
use alloy_rpc_types::{Filter, Topic, ValueOrArray};
use alloy_sol_types::SolEvent;
use std::marker::PhantomData;

pub struct Event<S, E> {
    filter: Filter,
    env: E,
    phantom: PhantomData<S>,
}

impl<'a, S: SolEvent, H: EvmBlockHeader> Event<S, &'a GuestEvmEnv<H>> {
    pub fn new(env: &'a GuestEvmEnv<H>) -> Self {
        Self {
            filter: event_filter::<S, H>(env.header()),
            env,
            phantom: PhantomData,
        }
    }

    pub fn query(self) -> Vec<Log<S>> {
        self.try_query().unwrap()
    }

    pub fn try_query(self) -> anyhow::Result<Vec<Log<S>>> {
        let logs = crate::Database::logs(&mut WrapStateDb::new(self.env.db()), &self.filter)?;
        logs.iter()
            .map(|(_, log)| Ok(S::decode_log(log, false)?))
            .collect()
    }
}

impl<S, E> Event<S, E> {
    /// Sets the address to query with this filter.
    ///
    /// See [`Filter::address`].
    pub fn address<A: Into<ValueOrArray<Address>>>(mut self, address: A) -> Self {
        self.filter.address = address.into().into();
        self
    }

    /// Sets the 1st indexed topic
    pub fn topic1<TO: Into<Topic>>(mut self, topic: TO) -> Self {
        self.filter.topics[1] = topic.into();
        self
    }

    /// Sets the 2nd indexed topic
    pub fn topic2<TO: Into<Topic>>(mut self, topic: TO) -> Self {
        self.filter.topics[2] = topic.into();
        self
    }

    /// Sets the 3rd indexed topic
    pub fn topic3<TO: Into<Topic>>(mut self, topic: TO) -> Self {
        self.filter.topics[3] = topic.into();
        self
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::host::HostEvmEnv;
    use anyhow::{anyhow, Result};
    use revm::Database;
    use std::fmt::Display;

    impl<'a, D, H: EvmBlockHeader, C> Event<(), &'a mut HostEvmEnv<D, H, C>>
    where
        D: crate::Database + Send + 'static,
        <D as Database>::Error: Display + Send + 'static,
    {
        pub fn preflight<S: SolEvent>(
            env: &'a mut HostEvmEnv<D, H, C>,
        ) -> Event<S, &'a mut HostEvmEnv<D, H, C>> {
            Event {
                filter: event_filter::<S, H>(env.header()),
                env,
                phantom: PhantomData,
            }
        }
    }

    impl<S: SolEvent, D, H: EvmBlockHeader, C> Event<S, &mut HostEvmEnv<D, H, C>>
    where
        D: crate::Database + Send + 'static,
        <D as Database>::Error: Display + Send + 'static,
    {
        pub async fn query(self) -> Result<Vec<Log<S>>> {
            let logs = self
                .env
                .spawn_with_db(move |db| crate::Database::logs(db, &self.filter))
                .await
                .map_err(|err| anyhow!("querying '{}' failed: {}", S::SIGNATURE, err))?;
            logs.iter()
                .map(|(_, log)| Ok(S::decode_log(log, false)?))
                .collect()
        }
    }
}

fn event_filter<S: SolEvent, H: EvmBlockHeader>(header: &Sealed<H>) -> Filter {
    assert!(!S::ANONYMOUS, "Anonymous events not supported");
    Filter::new()
        .event_signature(S::SIGNATURE_HASH)
        .at_block_hash(header.seal())
}
