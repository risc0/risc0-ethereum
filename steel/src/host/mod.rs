// Copyright 2024 RISC Zero, Inc.
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

//! Functionality that is only needed for the host and not the guest.
use std::{fmt::Display, marker::PhantomData};

use crate::{
    beacon::BeaconInput,
    block::BlockInput,
    ethereum::{EthBlockHeader, EthEvmEnv},
    EvmBlockHeader, EvmEnv, EvmInput,
};
use alloy::{
    network::{Ethereum, Network},
    providers::{Provider, ProviderBuilder, ReqwestProvider, RootProvider},
    rpc::types::Header as RpcHeader,
    transports::{
        http::{Client, Http},
        Transport,
    },
};
use anyhow::{anyhow, Context, Result};
use db::{AlloyDb, TraceDb};
use url::Url;

pub mod db;

/// A block number (or tag - "latest", "earliest", "pending").
pub type BlockNumberOrTag = alloy::rpc::types::BlockNumberOrTag;

/// Alias for readability, do not make public.
pub(crate) type HostEvmEnv<D, H> = EvmEnv<TraceDb<D>, H>;

impl EthEvmEnv<TraceDb<AlloyDb<Http<Client>, Ethereum, RootProvider<Http<Client>>>>> {
    /// Creates a new provable [EvmEnv] for Ethereum from an HTTP RPC endpoint.
    pub async fn from_rpc(url: Url, number: BlockNumberOrTag) -> Result<Self> {
        EthEvmEnv::builder()
            .rpc(url)
            .block_number_or_tag(number)
            .build()
            .await
    }
}

impl<T, N, P, H> EvmEnv<TraceDb<AlloyDb<T, N, P>>, H>
where
    T: Transport + Clone,
    N: Network,
    P: Provider<T, N>,
    H: EvmBlockHeader + TryFrom<RpcHeader>,
    <H as TryFrom<RpcHeader>>::Error: Display,
{
    /// Creates a new provable [EvmEnv] from an alloy [Provider].
    pub async fn from_provider(provider: P, number: BlockNumberOrTag) -> Result<Self> {
        EvmEnv::builder()
            .provider(provider)
            .block_number_or_tag(number)
            .build()
            .await
    }
}

impl<T, N, P, H> HostEvmEnv<AlloyDb<T, N, P>, H>
where
    T: Transport + Clone,
    N: Network,
    P: Provider<T, N>,
    H: EvmBlockHeader + TryFrom<RpcHeader>,
    <H as TryFrom<RpcHeader>>::Error: Display,
{
    /// Converts the environment into a [EvmInput] committing to a block hash.
    pub async fn into_input(self) -> Result<EvmInput<H>> {
        Ok(EvmInput::Block(BlockInput::from_env(self).await?))
    }
}

impl<T, P> HostEvmEnv<AlloyDb<T, Ethereum, P>, EthBlockHeader>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum>,
{
    /// Converts the environment into a [EvmInput] committing to a Beacon block root.
    pub async fn into_beacon_input(self, url: Url) -> Result<EvmInput<EthBlockHeader>> {
        Ok(EvmInput::Beacon(
            BeaconInput::from_env_and_endpoint(self, url).await?,
        ))
    }
}

impl<H> EvmEnv<(), H> {
    /// Returns a builder for this environment.
    pub fn builder() -> EvmEnvBuilder<NoProvider, H> {
        EvmEnvBuilder::default()
    }
}

/// Builder to construct an [EvmEnv] on the host.
#[derive(Clone, Debug)]
pub struct EvmEnvBuilder<P, H> {
    provider: P,
    block: BlockNumberOrTag,
    phantom: PhantomData<H>,
}

/// First stage of the [EvmEnvBuilder] without a specified [Provider].
pub struct NoProvider;

impl<H> Default for EvmEnvBuilder<NoProvider, H> {
    fn default() -> Self {
        Self {
            provider: NoProvider {},
            block: BlockNumberOrTag::Latest,
            phantom: PhantomData,
        }
    }
}

impl EvmEnvBuilder<NoProvider, EthBlockHeader> {
    /// Sets the Ethereum HTTP RPC endpoint that will be used by the [EvmEnv].
    pub fn rpc(self, url: Url) -> EvmEnvBuilder<ReqwestProvider<Ethereum>, EthBlockHeader> {
        self.provider(ProviderBuilder::new().on_http(url))
    }
}

impl<H: EvmBlockHeader> EvmEnvBuilder<NoProvider, H> {
    /// Sets the [Provider] that will be used by the [EvmEnv].
    pub fn provider<T, N, P>(self, provider: P) -> EvmEnvBuilder<P, H>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<RpcHeader>,
        <H as TryFrom<RpcHeader>>::Error: Display,
    {
        let Self { block, phantom, .. } = self;
        EvmEnvBuilder {
            provider,
            block,
            phantom,
        }
    }
}

impl<P, H> EvmEnvBuilder<P, H> {
    /// Sets the block number.
    pub fn block_number(self, number: u64) -> Self {
        self.block_number_or_tag(BlockNumberOrTag::Number(number))
    }

    /// Sets the block number (or tag - "latest", "earliest", "pending").
    pub fn block_number_or_tag(mut self, block: BlockNumberOrTag) -> Self {
        self.block = block;
        self
    }

    /// Builds the new provable [EvmEnv].
    pub async fn build<T, N>(self) -> Result<EvmEnv<TraceDb<AlloyDb<T, N, P>>, H>>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<RpcHeader>,
        <H as TryFrom<RpcHeader>>::Error: Display,
    {
        let rpc_block = self
            .provider
            .get_block_by_number(self.block, false)
            .await
            .context("eth_getBlockByNumber failed")?
            .with_context(|| format!("block {} not found", self.block))?;
        let header: H = rpc_block
            .header
            .try_into()
            .map_err(|err| anyhow!("header invalid: {}", err))?;
        log::info!("Environment initialized for block {}", header.number());

        let db = TraceDb::new(AlloyDb::new(self.provider, header.number()));

        Ok(EvmEnv::new(db, header.seal_slow()))
    }
}
