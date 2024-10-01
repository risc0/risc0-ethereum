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
    host::db::ProviderDb,
    EvmBlockHeader, EvmEnv, EvmInput,
};
use alloy::{
    network::{BlockResponse, Ethereum, Network},
    providers::{Provider, ProviderBuilder, ReqwestProvider, RootProvider},
    rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
    transports::{
        http::{Client, Http},
        Transport,
    },
};
use anyhow::{anyhow, ensure, Context, Result};
use db::{AlloyDb, ProofDb, ProviderConfig};
use url::Url;

pub mod db;

/// A block number (or tag - "latest", "safe", "finalized").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BlockNumberOrTag {
    /// The most recent block in the canonical chain observed by the client.
    #[default]
    Latest,
    /// The most recent block with a child.
    Parent,
    /// The most recent safe block.
    Safe,
    /// The most recent finalized block.
    Finalized,
    /// Number of a block in the canon chain.
    Number(u64),
}

impl BlockNumberOrTag {
    async fn into_rpc_type<T, N, P>(self, provider: P) -> Result<AlloyBlockNumberOrTag>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
    {
        let number = match self {
            BlockNumberOrTag::Latest => AlloyBlockNumberOrTag::Latest,
            BlockNumberOrTag::Parent => {
                let latest = provider.get_block_number().await?;
                ensure!(latest > 0, "genesis does not have a parent");
                AlloyBlockNumberOrTag::Number(latest - 1)
            }
            BlockNumberOrTag::Safe => AlloyBlockNumberOrTag::Safe,
            BlockNumberOrTag::Finalized => AlloyBlockNumberOrTag::Finalized,
            BlockNumberOrTag::Number(n) => AlloyBlockNumberOrTag::Number(n),
        };
        Ok(number)
    }
}

/// Alias for readability, do not make public.
pub(crate) type HostEvmEnv<D, H> = EvmEnv<ProofDb<D>, H>;

impl EthEvmEnv<ProofDb<AlloyDb<Http<Client>, Ethereum, RootProvider<Http<Client>>>>> {
    /// Creates a new provable [EvmEnv] for Ethereum from an HTTP RPC endpoint.
    #[deprecated(since = "0.12.0", note = "use `EthEvmEnv::builder().rpc()` instead")]
    pub async fn from_rpc(url: Url, number: BlockNumberOrTag) -> Result<Self> {
        EthEvmEnv::builder()
            .rpc(url)
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
    H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
    <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
{
    /// Creates a new provable [EvmEnv] from an alloy [Provider].
    #[deprecated(since = "0.12.0", note = "use `EvmEnv::builder().provider()` instead")]
    pub async fn from_provider(provider: P, number: BlockNumberOrTag) -> Result<Self> {
        EvmEnv::builder()
            .provider(provider)
            .block_number_or_tag(number)
            .build()
            .await
    }

    /// Converts the environment into a [EvmInput] committing to a block hash.
    pub async fn into_input(self) -> Result<EvmInput<H>> {
        Ok(EvmInput::Block(BlockInput::from_env(self).await?))
    }

    /// Returns the provider of the underlying [AlloyDb].
    pub(crate) fn provider(&self) -> &P {
        self.db().inner().provider()
    }
}

impl<T, P> HostEvmEnv<AlloyDb<T, Ethereum, P>, EthBlockHeader>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    /// Converts the environment into a [EvmInput] committing to an Ethereum Beacon block root.
    ///
    /// This function assumes that the
    /// [mainnet](https://github.com/ethereum/consensus-specs/blob/v1.4.0/configs/mainnet.yaml)
    /// preset of the consensus specs is used.
    ///
    /// ```rust,no_run
    /// # use alloy_primitives::{address, Address};
    /// # use risc0_steel::{Contract, ethereum::EthEvmEnv};
    /// # use url::Url;
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> anyhow::Result<()> {
    /// // Create an environment.
    /// let rpc_url = Url::parse("https://ethereum-rpc.publicnode.com")?;
    /// let mut env = EthEvmEnv::builder().rpc(rpc_url).build().await?;
    ///
    /// // Preflight some contract calls...
    /// # let address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
    /// # alloy::sol!( function balanceOf(address account) external view returns (uint); );
    /// # let call = balanceOfCall{ account: Address::ZERO };
    /// Contract::preflight(address, &mut env).call_builder(&call).call().await?;
    ///
    /// // Use EIP-4788 beacon commitments.
    /// let beacon_api_url = Url::parse("https://ethereum-beacon-api.publicnode.com")?;
    /// let input = env.into_beacon_input(beacon_api_url).await?;
    /// # Ok(())
    /// # }
    pub async fn into_beacon_input(self, url: Url) -> Result<EvmInput<EthBlockHeader>> {
        Ok(EvmInput::Beacon(
            BeaconInput::from_env_and_endpoint(self, url).await?,
        ))
    }
}

impl<H> EvmEnv<(), H> {
    /// Creates a builder for building an environment.
    ///
    /// Create an Ethereum environment bast on the latest block:
    /// ```rust,no_run
    /// # use risc0_steel::ethereum::EthEvmEnv;
    /// # use url::Url;
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> anyhow::Result<()> {
    /// # let url = Url::parse("https://ethereum-rpc.publicnode.com")?;
    /// let env = EthEvmEnv::builder().rpc(url).build().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> EvmEnvBuilder<(), H> {
        EvmEnvBuilder {
            provider: (),
            provider_config: ProviderConfig::default(),
            block: BlockNumberOrTag::Latest,
            phantom: PhantomData,
        }
    }
}

/// Builder for building an [EvmEnv] on the host.
///
/// The builder can be created using [EvmEnv::builder()].
#[derive(Clone, Debug)]
pub struct EvmEnvBuilder<P, H> {
    provider: P,
    provider_config: ProviderConfig,
    block: BlockNumberOrTag,
    phantom: PhantomData<H>,
}

impl EvmEnvBuilder<(), EthBlockHeader> {
    /// Sets the Ethereum HTTP RPC endpoint that will be used by the [EvmEnv].
    pub fn rpc(self, url: Url) -> EvmEnvBuilder<ReqwestProvider<Ethereum>, EthBlockHeader> {
        self.provider(ProviderBuilder::new().on_http(url))
    }
}

impl<H: EvmBlockHeader> EvmEnvBuilder<(), H> {
    /// Sets the [Provider] that will be used by the [EvmEnv].
    pub fn provider<T, N, P>(self, provider: P) -> EvmEnvBuilder<P, H>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
        <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        EvmEnvBuilder {
            provider,
            provider_config: self.provider_config,
            block: self.block,
            phantom: self.phantom,
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

    /// Sets the max number of storage keys to request in a single `eth_getProof` call.
    ///
    /// The optimal number depends on the RPC node and its configuration, but the default is 1000.
    pub fn eip1186_proof_chunk_size(mut self, chunk_size: usize) -> Self {
        assert_ne!(chunk_size, 0, "chunk size must be non-zero");
        self.provider_config.eip1186_proof_chunk_size = chunk_size;
        self
    }

    /// Builds the new provable [EvmEnv].
    pub async fn build<T, N>(self) -> Result<EvmEnv<ProofDb<AlloyDb<T, N, P>>, H>>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
        <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        let provider = self.provider;
        let number = self.block.into_rpc_type(&provider).await?;
        let rpc_block = provider
            .get_block_by_number(number, false)
            .await
            .context("eth_getBlockByNumber failed")?
            .with_context(|| format!("block {} not found", number))?;
        let header = rpc_block.header().clone();
        let header: H = header
            .try_into()
            .map_err(|err| anyhow!("header invalid: {}", err))?;
        let sealed_header = header.seal_slow();
        log::info!("Environment initialized for block {}", sealed_header.seal());

        let db = ProofDb::new(AlloyDb::new(
            provider,
            self.provider_config,
            sealed_header.seal(),
        ));

        Ok(EvmEnv::new(db, sealed_header))
    }
}
