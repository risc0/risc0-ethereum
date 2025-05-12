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

use crate::{state::WrapStateDb, EvmBlockHeader, EvmDatabase, EvmFactory, GuestEvmEnv};
use alloy_primitives::{Address, Bloom, Log, Sealed};
use alloy_rpc_types::{Filter, FilteredParams};
use alloy_sol_types::SolEvent;
use std::marker::PhantomData;

/// Represents an EVM event query.
///
/// This query builder is designed for fetching specific Solidity events that occurred within the
/// block associated with the provided `EvmEnv`.
///
/// ### Filtering Capabilities
/// This `Event` query builder is intentionally designed to mirror the structure and capabilities of
/// the [alloy_rpc_types::Filter] type used in standard Ethereum RPC calls, adapted for the
/// constraints of the RISC Zero zkVM environment.
///
/// You can filter events based on:
/// - **Contract Addresses:** Use the [`.address()`](Event::address) method to specify the event
///   source:
///   - A single address matches only events from this address.
///   - Multiple addresses (pass a `Vec<Address>`) matches events from *any* contract address.
///   - Wildcard (default): If `.address()` is not called, or if an empty `Vec` is provided, it
///     matches events from *any* contract address.
/// - **Indexed Topics:** Use the [`.topic1()`](Event::topic1), [`.topic2()`](Event::topic2) and
///   [`.topic3()`](Event::topic3) to filter by the indexed arguments of the event:
///   - A single value matches only events where the topic has this exact value.
///   - Multiple values (pass a `Vec<B256>`) matches events where the topic matches *any* value in
///     the list.
///   - Wildcard (default): If `.topicX()` is not called or if an empty `Vec` is provided, it
///     matches *any* value for that topic position.
///
/// Certain filtering options available in [alloy_rpc_types::Filter] are not applicable or are
/// fixed within the Steel environment:
/// - **Block Specification:** The block context for the query is determined by the `EvmEnv`
///   (retrieved via `env.header()`) used to create the `Event` query. You cannot specify a block
///   range or a different block hash.
/// - **Topic 0 (Event Signature):** This topic is automatically set based on the `SolEvent` type
///   parameter (`S`) provided to [Event::new] or [Event::preflight] (using `S::SIGNATURE_HASH`). It
///   cannot be altered or set to a wildcard/list. Anonymous events (where `S::ANONYMOUS` is true)
///   are not supported.
///
/// ### Usage
/// The usage pattern mirrors other Steel interactions like [Contract]:
/// - **Preflight calls on the Host:** To prepare the event query on the host environment and build
///   the necessary proof, use [Event::preflight].
/// - **Calls in the Guest:** To initialize the event query in the guest, use [Event::new].
///
/// ### Examples
/// Basic usage with a single contract address:
/// ```rust,no_run
/// # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, Event};
/// # use alloy_primitives::address;
/// # use alloy_sol_types::sol;
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
/// let mut env = EthEvmEnv::builder().rpc(url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
/// let event = Event::preflight::<IERC20::Transfer>(&mut env).address(contract_address);
/// event.query().await?;
///
/// let evm_input = env.into_input().await?;
///
/// // Guest:
/// let env = evm_input.into_env(&ETH_MAINNET_CHAIN_SPEC);
/// let event = Event::new::<IERC20::Transfer>(&env).address(contract_address);
/// let logs = event.query();
///
/// # Ok(())
/// # }
/// ```
///
/// Advanced filtering with multiple addresses and topics:
/// ```rust,no_run
/// # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, Event};
/// # use alloy_primitives::{address, b256, B256, Address};
/// # use alloy_rpc_types::{Topic, ValueOrArray};
/// # use alloy_sol_types::sol;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// // define multiple contract addresses and potential senders
/// let usdt_address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
/// let usdc_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
///
/// sol! {
///     interface IERC20 {
///         event Transfer(address indexed from, address indexed to, uint256 value);
///     }
/// }
///
/// let url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut env = EthEvmEnv::builder().rpc(url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
///
/// // Create an event query for Transfer events from *either* USDT or USDC contract,
/// // originating from *either* sender1 or sender2.
/// let event = Event::preflight::<IERC20::Transfer>(&mut env)
///     // filter by contract address: Match USDT OR USDC
///     .address(vec![usdt_address, usdc_address])
///     // filter by topic 1 (`from`): Match sender1 OR sender2
///     .topic1(vec![
///         address!("0000000000000000000000000000000000000001").into_word(),
///         address!("0000000000000000000000000000000000000002").into_word(),
///     ]);
/// // topic2 (`to`) and topic3 are left as wildcards
///
/// let logs = event.query().await?;
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

impl<F: EvmFactory> Event<(), &GuestEvmEnv<F>> {
    /// Constructor for executing an event query for a specific Solidity event.
    pub fn new<S: SolEvent>(env: &GuestEvmEnv<F>) -> Event<S, &GuestEvmEnv<F>> {
        Event {
            filter: event_filter::<S, F::Header>(env.header()),
            env,
            phantom: PhantomData,
        }
    }
}

impl<S: SolEvent, F: EvmFactory> Event<S, &GuestEvmEnv<F>> {
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
        logs.iter().map(|log| Ok(S::decode_log(log)?)).collect()
    }
}

impl<S, E> Event<S, E> {
    /// Sets the address to query with this filter.
    ///
    /// See [`Filter::address`].
    pub fn address<T: Into<ValueOrArray<Address>>>(mut self, address: T) -> Self {
        self.filter.address = address.into().into();
        self
    }

    /// Sets the 1st indexed topic.
    pub fn topic1<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter.topics[1] = topic.into();
        self
    }

    /// Sets the 2nd indexed topic.
    pub fn topic2<T: Into<Topic>>(mut self, topic: T) -> Self {
        self.filter.topics[2] = topic.into();
        self
    }

    /// Sets the 3rd indexed topic.
    pub fn topic3<T: Into<Topic>>(mut self, topic: T) -> Self {
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

    impl<D, F: EvmFactory, C> Event<(), &mut HostEvmEnv<D, F, C>>
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
            env: &mut HostEvmEnv<D, F, C>,
        ) -> Event<S, &mut HostEvmEnv<D, F, C>> {
            Event {
                filter: event_filter::<S, F::Header>(env.header()),
                env,
                phantom: PhantomData,
            }
        }
    }

    impl<S: SolEvent, D, F: EvmFactory, C> Event<S, &mut HostEvmEnv<D, F, C>>
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
            logs.iter().map(|log| Ok(S::decode_log(log)?)).collect()
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

/// Checks if a bloom filter matches the given filter parameters.
#[inline]
pub(super) fn matches_filter(bloom: Bloom, filter: &Filter) -> bool {
    FilteredParams::matches_address(bloom, &FilteredParams::address_filter(&filter.address))
        && FilteredParams::matches_topics(bloom, &FilteredParams::topics_filter(&filter.topics))
}
