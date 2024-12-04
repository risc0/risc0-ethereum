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

use crate::{
    beacon::BeaconCommit,
    block::BlockInput,
    config::ChainSpec,
    ethereum::{EthBlockHeader, EthEvmEnv},
    history::HistoryCommit,
    host::db::ProviderDb,
    ComposeInput, EvmBlockHeader, EvmEnv, EvmInput,
};
use alloy::eips::eip1898::{HexStringMissingPrefixError, ParseBlockNumberError};
use alloy::{
    network::{Ethereum, Network},
    providers::Provider,
    rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
    transports::Transport,
};
use alloy_primitives::B256;
use anyhow::{ensure, Result};
use core::fmt;
use db::{AlloyDb, ProofDb};
use std::fmt::Display;
use std::str::FromStr;
use url::Url;

mod builder;
pub mod db;

pub use builder::EvmEnvBuilder;

/// A block number (or tag - "latest", "safe", "finalized").
/// This enum is used to specify which block to query when interacting with the blockchain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BlockNumberOrTag {
    /// The most recent block in the canonical chain observed by the client.
    #[default]
    Latest,
    /// The parent of the most recent block in the canonical chain observed by the client.
    /// This is equivalent to `Latest - 1`.
    Parent,
    /// The most recent block considered "safe" by the client. This typically refers to a block
    /// that is sufficiently deep in the chain to be considered irreversible.
    Safe,
    /// The most recent finalized block in the chain. Finalized blocks are guaranteed to be
    /// part of the canonical chain.
    Finalized,
    /// A specific block number in the canonical chain.
    Number(u64),
}

impl BlockNumberOrTag {
    /// Converts the `BlockNumberOrTag` into the corresponding RPC type.
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

impl FromStr for BlockNumberOrTag {
    type Err = ParseBlockNumberError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let block = match s {
            "latest" => Self::Latest,
            "parent" => Self::Parent,
            "safe" => Self::Safe,
            "finalized" => Self::Finalized,
            _number => {
                if let Some(hex_val) = s.strip_prefix("0x") {
                    let number = u64::from_str_radix(hex_val, 16);
                    Self::Number(number?)
                } else {
                    return Err(HexStringMissingPrefixError::default().into());
                }
            }
        };
        Ok(block)
    }
}

impl Display for BlockNumberOrTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(x) => write!(f, "0x{x:x}"),
            Self::Latest => f.write_str("latest"),
            Self::Parent => f.write_str("parent"),
            Self::Safe => f.write_str("safe"),
            Self::Finalized => f.write_str("finalized"),
        }
    }
}

/// Alias for readability, do not make public.
pub(crate) type HostEvmEnv<D, H, C> = EvmEnv<ProofDb<D>, H, HostCommit<C>>;
type EthHostEvmEnv<D, C> = EthEvmEnv<ProofDb<D>, HostCommit<C>>;

/// Wrapper for the commit on the host.
pub struct HostCommit<C> {
    inner: C,
    config_id: B256,
}

impl<T, N, P, H> HostEvmEnv<AlloyDb<T, N, P>, H, ()>
where
    T: Transport + Clone,
    N: Network,
    P: Provider<T, N>,
    H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
    <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
{
    /// Converts the environment into a [EvmInput] committing to an execution block hash.
    pub async fn into_input(self) -> Result<EvmInput<H>> {
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::Block(input))
    }
}

impl<D, H: EvmBlockHeader, C> HostEvmEnv<D, H, C> {
    /// Sets the chain ID and specification ID from the given chain spec.
    ///
    /// This will panic when there is no valid specification ID for the current block.
    pub fn with_chain_spec(mut self, chain_spec: &ChainSpec) -> Self {
        self.cfg_env.chain_id = chain_spec.chain_id();
        self.cfg_env.handler_cfg.spec_id = chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self.commit.config_id = chain_spec.digest();

        self
    }
}

impl<T, P> EthHostEvmEnv<AlloyDb<T, Ethereum, P>, BeaconCommit>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum>,
{
    /// Converts the environment into a [EvmInput] committing to a Beacon Chain block root.
    pub async fn into_input(self) -> Result<EvmInput<EthBlockHeader>> {
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::Beacon(ComposeInput::new(
            input,
            self.commit.inner,
        )))
    }
}

impl<T, P> EthHostEvmEnv<AlloyDb<T, Ethereum, P>, HistoryCommit>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum>,
{
    /// Converts the environment into a [EvmInput] recursively committing to multiple Beacon Chain
    /// block roots.
    #[stability::unstable(feature = "history")]
    pub async fn into_input(self) -> Result<EvmInput<EthBlockHeader>> {
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::History(ComposeInput::new(
            input,
            self.commit.inner,
        )))
    }
}

impl<T, P> EthHostEvmEnv<AlloyDb<T, Ethereum, P>, ()>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum>,
{
    /// Converts the environment into a [EvmInput] committing to an Ethereum Beacon block root.
    #[deprecated(
        since = "0.14.0",
        note = "use `EvmEnv::builder().beacon_api()` instead"
    )]
    pub async fn into_beacon_input(self, url: Url) -> Result<EvmInput<EthBlockHeader>> {
        let commit =
            BeaconCommit::from_header(self.header(), self.db().inner().provider(), url).await?;
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::Beacon(ComposeInput::new(input, commit)))
    }
}
