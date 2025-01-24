// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Types related to event queries.
pub use alloy_rpc_types::{Topic, ValueOrArray};

use crate::{state::WrapStateDb, EvmBlockHeader, EvmDatabase, GuestEvmEnv};
use alloy_primitives::{Address, Log, Sealed};
use alloy_rpc_types::Filter;
use alloy_sol_types::SolEvent;
use std::marker::PhantomData;

/// Represents an EVM event query.
///
/// ### Usage
/// - **Preflight calls on the Host:** To prepare the event query on the host environment and build
///   the necessary proof, use [Event::preflight].
/// - **Calls in the Guest:** To initialize the event query in the guest, use [Event::new].
///
/// ### Examples
/// ```rust,no_run
/// # use risc0_steel::{ethereum::EthEvmEnv, Event};
/// # use alloy_primitives::address;
/// # use alloy_sol_types::sol;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// let contract_address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
/// sol! {
///     interface IERC20 {
///         event Transfer(address indexed from, address indexed to, uint256 value);
///     }
/// }
///
/// // Host:
/// let url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut env = EthEvmEnv::builder().rpc(url).build().await?;
/// let event = Event::preflight::<IERC20::Transfer>(&mut env).address(contract_address);
/// event.query().await?;
///
/// let evm_input = env.into_input().await?;
///
/// // Guest:
/// let env = evm_input.into_env();
/// let event = Event::new::<IERC20::Transfer>(&env).address(contract_address);
/// let logs = event.query();
///
/// # Ok(())
/// # }
/// ```
///
/// [Contract]: crate::Contract
pub struct Event<S, E> {
    filter: Filter,
    env: E,
    phantom: PhantomData<S>,
}

impl<H: EvmBlockHeader> Event<(), &GuestEvmEnv<H>> {
    /// Constructor for executing an event query for a specific Solidity event.
    pub fn new<S: SolEvent>(env: &GuestEvmEnv<H>) -> Event<S, &GuestEvmEnv<H>> {
        Event {
            filter: event_filter::<S, H>(env.header()),
            env,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "unstable-event")]
impl<S: SolEvent, H: EvmBlockHeader> Event<S, &GuestEvmEnv<H>> {
    /// Executes the query and returns the matching logs and panics on failure.
    ///
    /// A convenience wrapper for [Event::try_query], panicking if the call fails. Useful when
    /// success is expected.
    pub fn query(self) -> Vec<Log<S>> {
        self.try_query().unwrap()
    }

    /// Attempts to execute the query and returns the matching logs or an error.
    pub fn try_query(self) -> anyhow::Result<Vec<Log<S>>> {
        let logs = WrapStateDb::new(self.env.db(), &self.env.header).logs(self.filter)?;
        logs.iter()
            .map(|log| Ok(S::decode_log(log, false)?))
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

    /// Sets the 1st indexed topic.
    pub fn topic1<TO: Into<Topic>>(mut self, topic: TO) -> Self {
        self.filter.topics[1] = topic.into();
        self
    }

    /// Sets the 2nd indexed topic.
    pub fn topic2<TO: Into<Topic>>(mut self, topic: TO) -> Self {
        self.filter.topics[2] = topic.into();
        self
    }

    /// Sets the 3rd indexed topic.
    pub fn topic3<TO: Into<Topic>>(mut self, topic: TO) -> Self {
        self.filter.topics[3] = topic.into();
        self
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::host::HostEvmEnv;
    use anyhow::{Context, Result};
    use revm::Database as RevmDatabase;
    use std::error::Error as StdError;

    impl<D, H: EvmBlockHeader, C> Event<(), &mut HostEvmEnv<D, H, C>>
    where
        D: EvmDatabase + Send + 'static,
        <D as RevmDatabase>::Error: StdError + Send + Sync + 'static,
    {
        /// Constructor for preflighting an event query for a specific EVM event.
        ///
        /// Initializes the environment for event queries, fetching necessary data via the
        /// [Provider], and generating a storage proof for any accessed elements using
        /// [EvmEnv::into_input].
        ///
        /// [EvmEnv::into_input]: crate::EvmEnv::into_input
        /// [EvmEnv]: crate::EvmEnv
        /// [Provider]: alloy::providers::Provider
        pub fn preflight<S: SolEvent>(
            env: &mut HostEvmEnv<D, H, C>,
        ) -> Event<S, &mut HostEvmEnv<D, H, C>> {
            Event {
                filter: event_filter::<S, H>(env.header()),
                env,
                phantom: PhantomData,
            }
        }
    }

    impl<S: SolEvent, D, H: EvmBlockHeader, C> Event<S, &mut HostEvmEnv<D, H, C>>
    where
        D: EvmDatabase + Send + 'static,
        <D as RevmDatabase>::Error: StdError + Send + Sync + 'static,
    {
        /// Executes the event query using an [EvmEnv] constructed with [Event::preflight].
        ///
        /// This uses [tokio::task::spawn_blocking] to run the blocking revm execution.
        ///
        /// [EvmEnv]: crate::EvmEnv
        pub async fn query(self) -> Result<Vec<Log<S>>> {
            log::info!("Executing preflight querying event '{}'", S::SIGNATURE);

            let logs = self
                .env
                .spawn_with_db(move |db| db.logs(self.filter))
                .await
                .with_context(|| format!("querying logs for '{}' failed", S::SIGNATURE))?;
            logs.iter()
                .map(|log| Ok(S::decode_log(log, false)?))
                .collect()
        }
    }
}

/// Creates an event filter for a specific event and block header.
fn event_filter<S: SolEvent, H: EvmBlockHeader>(header: &Sealed<H>) -> Filter {
    assert!(!S::ANONYMOUS, "Anonymous events not supported");
    Filter::new()
        .event_signature(S::SIGNATURE_HASH)
        .at_block_hash(header.seal())
}
