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

//! Functionality that is only needed for the host and not the guest.

use crate::{
    beacon::BeaconCommit,
    block::BlockInput,
    config::ChainSpec,
    ethereum::{EthEvmEnv, EthEvmInput},
    history::HistoryCommit,
    BlockHeaderCommit, Commitment, ComposeInput, EvmBlockHeader, EvmEnv, EvmFactory, EvmInput,
};
use alloy::{
    eips::{
        eip1898::{HexStringMissingPrefixError, ParseBlockNumberError},
        BlockId as AlloyBlockId,
    },
    network::{Ethereum, Network},
    providers::Provider,
    rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
};
use alloy_primitives::{BlockHash, B256};
use anyhow::{ensure, Result};
use db::{ProofDb, ProviderDb};
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

pub use builder::EvmEnvBuilder;

mod builder;
pub mod db;

/// A Block Identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BlockId {
    /// A block hash
    Hash(BlockHash),
    /// A block number or tag (e.g. latest)
    Number(BlockNumberOrTag),
}

impl BlockId {
    /// Converts the `BlockId` into the corresponding RPC type.
    async fn into_rpc_type<N, P>(self, provider: P) -> Result<AlloyBlockId>
    where
        N: Network,
        P: Provider<N>,
    {
        let id = match self {
            BlockId::Hash(hash) => hash.into(),
            BlockId::Number(number) => match number {
                BlockNumberOrTag::Latest => AlloyBlockNumberOrTag::Latest,
                BlockNumberOrTag::Parent => {
                    let latest = provider.get_block_number().await?;
                    ensure!(latest > 0, "genesis does not have a parent");
                    AlloyBlockNumberOrTag::Number(latest - 1)
                }
                BlockNumberOrTag::Safe => AlloyBlockNumberOrTag::Safe,
                BlockNumberOrTag::Finalized => AlloyBlockNumberOrTag::Finalized,
                BlockNumberOrTag::Number(n) => AlloyBlockNumberOrTag::Number(n),
            }
            .into(),
        };
        Ok(id)
    }
}

impl Default for BlockId {
    fn default() -> Self {
        BlockId::Number(BlockNumberOrTag::default())
    }
}

impl Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash(hash) => Display::fmt(&hash, f),
            Self::Number(num) => Display::fmt(&num, f),
        }
    }
}

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

impl FromStr for BlockNumberOrTag {
    type Err = ParseBlockNumberError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let block = match s {
            "latest" => Self::Latest,
            "parent" => Self::Parent,
            "safe" => Self::Safe,
            "finalized" => Self::Finalized,
            _ => {
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
pub(crate) type HostEvmEnv<D, F, C> = EvmEnv<ProofDb<D>, F, HostCommit<C>>;
type EthHostEvmEnv<D, C> = EthEvmEnv<ProofDb<D>, HostCommit<C>>;

/// Wrapper for the commit on the host.
pub struct HostCommit<C> {
    inner: C,
    config_id: B256,
}

impl<C> HostCommit<C> {
    /// Returns the config ID.
    #[inline]
    pub(super) fn config_id(&self) -> B256 {
        self.config_id
    }
}

impl<D, FACTORY: EvmFactory, C> HostEvmEnv<D, FACTORY, C>
where
    D: Send + 'static,
{
    /// Runs the provided closure that requires mutable access to the database on a thread where
    /// blocking is acceptable.
    ///
    /// It panics if the closure panics.
    /// This function is necessary because mutable references to the database cannot be passed
    /// directly to `tokio::task::spawn_blocking`. Instead, the database is temporarily taken out of
    /// the `HostEvmEnv`, moved into the blocking task, and then restored after the task completes.
    pub(crate) async fn spawn_with_db<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut ProofDb<D>) -> R + Send + 'static,
        R: Send + 'static,
    {
        // as mutable references are not possible, the DB must be moved in and out of the task
        let mut db = self.db.take().unwrap();

        let (result, db) = tokio::task::spawn_blocking(move || (f(&mut db), db))
            .await
            .expect("DB execution panicked");

        // restore the DB, so that we never return an env without a DB
        self.db = Some(db);

        result
    }
}

impl<D, F: EvmFactory, C> HostEvmEnv<D, F, C> {
    /// Sets the chain ID and specification ID from the given chain spec.
    ///
    /// This will panic when there is no valid specification ID for the current block.
    pub fn with_chain_spec(mut self, chain_spec: &ChainSpec<F::Spec>) -> Self {
        self.chain_id = chain_spec.chain_id;
        self.spec = *chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self.commit.config_id = chain_spec.digest();

        self
    }

    /// Extends the environment with the contents of another compatible environment.
    ///
    /// ### Errors
    ///
    /// It returns an error if the environments are inconsistent, specifically if:
    /// - The configurations don't match
    /// - The headers don't match
    ///
    /// ### Panics
    ///
    /// It panics if the database states conflict.
    ///
    /// ### Use Cases
    ///
    /// This method is particularly useful for combining results from parallel preflights,
    /// allowing you to execute multiple independent operations and merge their environments.
    ///
    /// ### Example
    /// ```rust,no_run
    /// # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, Contract};
    /// # use alloy_primitives::address;
    /// # use alloy_sol_types::sol;
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> anyhow::Result<()> {
    /// # sol! {
    /// #    interface IERC20 {
    /// #        function balanceOf(address account) external view returns (uint);
    /// #    }
    /// # }
    /// let call =
    ///     IERC20::balanceOfCall { account: address!("F977814e90dA44bFA03b6295A0616a897441aceC") };
    /// # let usdt_addr = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
    /// # let usdc_addr = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    ///
    /// let url = "https://ethereum-rpc.publicnode.com".parse()?;
    /// let builder = EthEvmEnv::builder().rpc(url).chain_spec(&ETH_MAINNET_CHAIN_SPEC);
    ///
    /// let mut env1 = builder.clone().build().await?;
    /// let block_hash = env1.header().seal();
    /// let mut contract1 = Contract::preflight(usdt_addr, &mut env1);
    /// // build second env on the same block
    /// let mut env2 = builder.block_hash(block_hash).build().await?;
    /// let mut contract2 = Contract::preflight(usdc_addr, &mut env2);
    ///
    /// // Perform parallel operations (these would typically modify the state within env1/env2's dbs)
    /// tokio::join!(contract1.call_builder(&call).call(), contract2.call_builder(&call).call());
    ///
    /// let env = env1.merge(env2)?;
    /// let evm_input = env.into_input().await?;
    /// # _ = evm_input.into_env(&ETH_MAINNET_CHAIN_SPEC);
    /// # Ok(())
    /// # }
    /// ```
    pub fn merge(self, mut other: Self) -> Result<Self> {
        let Self {
            mut db,
            chain_id,
            spec,
            header,
            commit,
        } = self;

        ensure!(chain_id == other.chain_id, "configuration mismatch");
        ensure!(spec == other.spec, "configuration mismatch");
        ensure!(
            header.seal() == other.header.seal(),
            "execution header mismatch"
        );
        // the commitments do not need to match as long as the cfg_env is consistent

        // safe unwrap: EvmEnv is never returned without a DB
        let db = db.take().unwrap();
        let db_other = other.db.take().unwrap();

        Ok(Self {
            db: Some(db.merge(db_other)),
            chain_id,
            spec,
            header,
            commit,
        })
    }
}

impl<N, P, F> HostEvmEnv<ProviderDb<N, P>, F, ()>
where
    N: Network,
    P: Provider<N>,
    F: EvmFactory,
    F::Header: TryFrom<<N as Network>::HeaderResponse>,
    <F::Header as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
{
    /// Converts the environment into a [EvmInput] committing to an execution block hash.
    pub async fn into_input(self) -> Result<EvmInput<F>> {
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::Block(input))
    }
}

impl<D, F: EvmFactory, C: Clone + BlockHeaderCommit<F::Header>> HostEvmEnv<D, F, C> {
    /// Returns the [Commitment] used to validate the environment.
    pub fn commitment(&self) -> Commitment {
        self.commit
            .inner
            .clone()
            .commit(&self.header, self.commit.config_id)
    }
}

impl<P> EthHostEvmEnv<ProviderDb<Ethereum, P>, BeaconCommit>
where
    P: Provider<Ethereum>,
{
    /// Converts the environment into a [EvmInput] committing to a Beacon Chain block root.
    pub async fn into_input(self) -> Result<EthEvmInput> {
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::Beacon(ComposeInput::new(
            input,
            self.commit.inner,
        )))
    }
}

impl<P> EthHostEvmEnv<ProviderDb<Ethereum, P>, HistoryCommit>
where
    P: Provider<Ethereum>,
{
    /// Converts the environment into a [EvmInput] recursively committing to multiple Beacon Chain
    /// block roots.
    pub async fn into_input(self) -> Result<EthEvmInput> {
        let input = BlockInput::from_proof_db(self.db.unwrap(), self.header).await?;

        Ok(EvmInput::History(ComposeInput::new(
            input,
            self.commit.inner,
        )))
    }
}
