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

use super::BlockId;
use crate::{
    beacon::BeaconCommit,
    config::ChainSpec,
    ethereum::EthEvmFactory,
    history::HistoryCommit,
    host::{
        db::{ProofDb, ProviderConfig, ProviderDb},
        BlockNumberOrTag, EthHostEvmEnv, HostCommit, HostEvmEnv,
    },
    CommitmentVersion, EvmBlockHeader, EvmEnv, EvmFactory,
};
use alloy::{
    network::{primitives::HeaderResponse, BlockResponse, Ethereum, Network},
    providers::{Provider, ProviderBuilder, RootProvider},
};
use alloy_primitives::{BlockHash, BlockNumber, Sealable, Sealed, B256};
use anyhow::{anyhow, ensure, Context, Result};
use std::{fmt::Display, marker::PhantomData};
use url::Url;

impl<F: EvmFactory> EvmEnv<(), F, ()> {
    /// Creates a builder for building an environment.
    ///
    /// Create an Ethereum environment bast on the latest block:
    /// ```rust,no_run
    /// # use risc0_steel::ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv};
    /// # use url::Url;
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> anyhow::Result<()> {
    /// let url = Url::parse("https://ethereum-rpc.publicnode.com")?;
    /// let env = EthEvmEnv::builder().rpc(url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> EvmEnvBuilder<(), F, (), ()> {
        EvmEnvBuilder {
            provider: (),
            provider_config: ProviderConfig::default(),
            block: BlockId::default(),
            chain_spec: (),
            beacon_config: (),
            phantom: PhantomData,
        }
    }
}

/// Builder for constructing an [EvmEnv] instance on the host.
///
/// The [EvmEnvBuilder] is used to configure and create an [EvmEnv], which is the environment in
/// which the Ethereum Virtual Machine (EVM) operates. This builder provides flexibility in setting
/// up the EVM environment by allowing configuration of RPC endpoints, block numbers, and other
/// parameters.
///
/// # Usage
/// The builder can be created using [EvmEnv::builder()]. Various configurations can be chained to
/// customize the environment before calling the `build` function to create the final [EvmEnv].
#[derive(Clone, Debug)]
pub struct EvmEnvBuilder<P, F, S, B> {
    provider: P,
    provider_config: ProviderConfig,
    block: BlockId,
    chain_spec: S,
    beacon_config: B,
    phantom: PhantomData<F>,
}

impl<S> EvmEnvBuilder<(), EthEvmFactory, S, ()> {
    /// Sets the Ethereum HTTP RPC endpoint that will be used by the [EvmEnv].
    pub fn rpc(self, url: Url) -> EvmEnvBuilder<RootProvider<Ethereum>, EthEvmFactory, S, ()> {
        self.provider(ProviderBuilder::default().connect_http(url))
    }
}

impl<F: EvmFactory, S> EvmEnvBuilder<(), F, S, ()> {
    /// Sets a custom [Provider] that will be used by the [EvmEnv].
    pub fn provider<N, P>(self, provider: P) -> EvmEnvBuilder<P, F, S, ()>
    where
        N: Network,
        P: Provider<N>,
        F::Header: TryFrom<<N as Network>::HeaderResponse>,
        <F::Header as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        EvmEnvBuilder {
            provider,
            provider_config: self.provider_config,
            block: self.block,
            chain_spec: self.chain_spec,
            beacon_config: self.beacon_config,
            phantom: self.phantom,
        }
    }
}

impl<P, F: EvmFactory, B> EvmEnvBuilder<P, F, (), B> {
    /// Sets the [ChainSpec] that will be used by the [EvmEnv].
    pub fn chain_spec(
        self,
        chain_spec: &ChainSpec<F::Spec>,
    ) -> EvmEnvBuilder<P, F, &ChainSpec<F::Spec>, B> {
        EvmEnvBuilder {
            provider: self.provider,
            provider_config: self.provider_config,
            block: self.block,
            chain_spec,
            beacon_config: self.beacon_config,
            phantom: self.phantom,
        }
    }
}

/// Config for commitments to the beacon chain state.
#[derive(Clone, Debug)]
pub struct Beacon {
    url: Url,
    commitment_version: CommitmentVersion,
}

impl<P, S> EvmEnvBuilder<P, EthEvmFactory, S, ()> {
    /// Sets the Beacon API URL for retrieving Ethereum Beacon block root commitments.
    ///
    /// This function configures the [EvmEnv] to interact with an Ethereum Beacon chain.
    /// It assumes the use of the [mainnet](https://github.com/ethereum/consensus-specs/blob/v1.4.0/configs/mainnet.yaml) preset for consensus specs.
    pub fn beacon_api(self, url: Url) -> EvmEnvBuilder<P, EthEvmFactory, S, Beacon> {
        EvmEnvBuilder {
            provider: self.provider,
            provider_config: self.provider_config,
            block: self.block,
            chain_spec: self.chain_spec,
            beacon_config: Beacon {
                url,
                commitment_version: CommitmentVersion::Beacon,
            },
            phantom: self.phantom,
        }
    }
}

impl<P, F, S, B> EvmEnvBuilder<P, F, S, B> {
    /// Sets the block number to be used for the EVM execution.
    pub fn block_number(self, number: u64) -> Self {
        self.block_number_or_tag(BlockNumberOrTag::Number(number))
    }

    /// Sets the block number or block tag ("latest", "earliest", "pending") to be used for the EVM
    /// execution.
    pub fn block_number_or_tag(mut self, block: BlockNumberOrTag) -> Self {
        self.block = BlockId::Number(block);
        self
    }

    /// Sets the block hash to be used for the EVM execution.
    pub fn block_hash(mut self, hash: B256) -> Self {
        self.block = BlockId::Hash(hash);
        self
    }

    /// Sets the chunk size for `eth_getProof` calls (EIP-1186).
    ///
    /// This configures the number of storage keys to request in a single call.
    /// The default is 1000, but this can be adjusted based on the RPC node configuration.
    pub fn eip1186_proof_chunk_size(mut self, chunk_size: usize) -> Self {
        assert_ne!(chunk_size, 0, "chunk size must be non-zero");
        self.provider_config.eip1186_proof_chunk_size = chunk_size;
        self
    }

    /// Returns the [EvmBlockHeader] of the specified block.
    ///
    /// If `block` is `None`, the block based on the current builder configuration is used instead.
    async fn get_header<N>(&self, block: Option<BlockId>) -> Result<Sealed<F::Header>>
    where
        F: EvmFactory,
        N: Network,
        P: Provider<N>,
        F::Header: TryFrom<<N as Network>::HeaderResponse>,
        <F::Header as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        let block = block.unwrap_or(self.block);
        let block = block.into_rpc_type(&self.provider).await?;

        let rpc_block = self
            .provider
            .get_block(block)
            .await
            .context("eth_getBlock1 failed")?
            .with_context(|| format!("block {} not found", block))?;

        let rpc_header = rpc_block.header().clone();
        let header: F::Header = rpc_header
            .try_into()
            .map_err(|err| anyhow!("header invalid: {}", err))?;
        let header = header.seal_slow();
        ensure!(
            header.seal() == rpc_block.header().hash(),
            "computed block hash does not match the hash returned by the API"
        );

        Ok(header)
    }
}

impl<P, F: EvmFactory> EvmEnvBuilder<P, F, &ChainSpec<F::Spec>, ()> {
    /// Builds and returns an [EvmEnv] with the configured settings that commits to a block hash.
    pub async fn build<N>(self) -> Result<HostEvmEnv<ProviderDb<N, P>, F, ()>>
    where
        N: Network,
        P: Provider<N>,
        F::Header: TryFrom<<N as Network>::HeaderResponse>,
        <F::Header as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        let header = self.get_header(None).await?;
        log::info!(
            "Environment initialized with block {} ({})",
            header.number(),
            header.seal()
        );

        let db = ProofDb::new(ProviderDb::new(
            self.provider,
            self.provider_config,
            header.seal(),
        ));
        let commit = HostCommit {
            inner: (),
            config_id: self.chain_spec.digest(),
        };

        Ok(EvmEnv::new(db, self.chain_spec, header, commit))
    }
}

/// Config for separating the execution block from the commitment block.
#[derive(Clone, Debug)]
pub struct History {
    beacon_config: Beacon,
    commitment_block: BlockId,
}

impl<P, S> EvmEnvBuilder<P, EthEvmFactory, S, Beacon> {
    /// Configures the environment builder to generate consensus commitments.
    ///
    /// A consensus commitment contains the beacon block root indexed directly by its slot number.
    /// This is in contrast to the default mechanism, which relies on timestamps for lookups, for
    /// verification using the EIP-4788 beacon root contract deployed at the execution layer.
    ///
    /// The use of slot-based indexing is particularly beneficial for verification methods that have
    /// direct access to the state of the beacon chain, such as systems using beacon light clients.
    /// This allows the commitment to be verified directly against the state of the consensus layer.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use risc0_steel::ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv};
    /// # use alloy_primitives::B256;
    /// # use url::Url;
    /// # use std::str::FromStr;
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> anyhow::Result<()> {
    /// let builder = EthEvmEnv::builder()
    ///     .rpc(Url::parse("https://ethereum-rpc.publicnode.com")?)
    ///     .beacon_api(Url::parse("https://ethereum-beacon-api.publicnode.com")?)
    ///     .chain_spec(&ETH_MAINNET_CHAIN_SPEC)
    ///     // Configure the builder to use slot-indexed consensus commitments.
    ///     .consensus_commitment();
    ///
    /// // The resulting 'env' will be configured to generate a consensus commitment
    /// // (beacon root indexed by slot) when processing blocks or state.
    /// let env = builder.build().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn consensus_commitment(mut self) -> Self {
        self.beacon_config.commitment_version = CommitmentVersion::Consensus;
        self
    }

    /// Sets the block hash for the commitment block, which can be different from the execution
    /// block.
    ///
    /// This allows for historical state execution while maintaining security through a more recent
    /// commitment. The commitment block must be more recent than the execution block.
    ///
    /// Note that this feature requires a Beacon chain RPC provider, as it relies on
    /// [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).
    ///
    /// # Example
    /// ```rust,no_run
    /// # use risc0_steel::ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv};
    /// # use alloy_primitives::B256;
    /// # use url::Url;
    /// # use std::str::FromStr;
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> anyhow::Result<()> {
    /// let commitment_hash = B256::from_str("0x1234...")?;
    /// let builder = EthEvmEnv::builder()
    ///     .rpc(Url::parse("https://ethereum-rpc.publicnode.com")?)
    ///     .beacon_api(Url::parse("https://ethereum-beacon-api.publicnode.com")?)
    ///     .block_number(1_000_000) // execute against historical state
    ///     .commitment_block_hash(commitment_hash) // commit to recent block
    ///     .chain_spec(&ETH_MAINNET_CHAIN_SPEC);
    /// let env = builder.build().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn commitment_block_hash(
        self,
        hash: BlockHash,
    ) -> EvmEnvBuilder<P, EthEvmFactory, S, History> {
        self.commitment_block(BlockId::Hash(hash))
    }

    /// Sets the block number or block tag ("latest", "earliest", "pending")  for the commitment.
    ///
    /// See [EvmEnvBuilder::commitment_block_hash] for detailed documentation.
    pub fn commitment_block_number_or_tag(
        self,
        block: BlockNumberOrTag,
    ) -> EvmEnvBuilder<P, EthEvmFactory, S, History> {
        self.commitment_block(BlockId::Number(block))
    }

    /// Sets the block number for the commitment.
    ///
    /// See [EvmEnvBuilder::commitment_block_hash] for detailed documentation.
    pub fn commitment_block_number(
        self,
        number: BlockNumber,
    ) -> EvmEnvBuilder<P, EthEvmFactory, S, History> {
        self.commitment_block_number_or_tag(BlockNumberOrTag::Number(number))
    }

    fn commitment_block(self, block: BlockId) -> EvmEnvBuilder<P, EthEvmFactory, S, History> {
        EvmEnvBuilder {
            provider: self.provider,
            provider_config: self.provider_config,
            block: self.block,
            chain_spec: self.chain_spec,
            beacon_config: History {
                beacon_config: self.beacon_config,
                commitment_block: block,
            },
            phantom: Default::default(),
        }
    }
}

impl<P> EvmEnvBuilder<P, EthEvmFactory, &ChainSpec<<EthEvmFactory as EvmFactory>::Spec>, Beacon> {
    /// Builds and returns an [EvmEnv] with the configured settings that commits to a beacon root.
    pub async fn build(self) -> Result<EthHostEvmEnv<ProviderDb<Ethereum, P>, BeaconCommit>>
    where
        P: Provider<Ethereum>,
    {
        let header = self.get_header(None).await?;
        log::info!(
            "Environment initialized with block {} ({})",
            header.number(),
            header.seal()
        );

        let beacon_url = self.beacon_config.url;
        let version = self.beacon_config.commitment_version;
        let commit = HostCommit {
            inner: BeaconCommit::from_header(&header, version, &self.provider, beacon_url).await?,
            config_id: self.chain_spec.digest(),
        };
        let db = ProofDb::new(ProviderDb::new(
            self.provider,
            self.provider_config,
            header.seal(),
        ));

        Ok(EvmEnv::new(db, self.chain_spec, header, commit))
    }
}

impl<P> EvmEnvBuilder<P, EthEvmFactory, &ChainSpec<<EthEvmFactory as EvmFactory>::Spec>, History> {
    /// Configures the environment builder to generate consensus commitments.
    ///
    /// See [EvmEnvBuilder<P, EthBlockHeader, Beacon>::consensus_commitment] for more info.
    pub fn consensus_commitment(mut self) -> Self {
        self.beacon_config.beacon_config.commitment_version = CommitmentVersion::Consensus;
        self
    }
    /// Builds and returns an [EvmEnv] with the configured settings, using a dedicated commitment
    /// block that is different from the execution block.
    pub async fn build(self) -> Result<EthHostEvmEnv<ProviderDb<Ethereum, P>, HistoryCommit>>
    where
        P: Provider<Ethereum>,
    {
        let evm_header = self.get_header(None).await?;
        let commitment_header = self
            .get_header(Some(self.beacon_config.commitment_block))
            .await?;
        ensure!(
            evm_header.number() < commitment_header.number(),
            "EVM execution block not before commitment block"
        );

        log::info!(
            "Environment initialized with block {} ({})",
            evm_header.number(),
            evm_header.seal()
        );

        let beacon_url = self.beacon_config.beacon_config.url;
        let commitment_version = self.beacon_config.beacon_config.commitment_version;
        let history_commit = HistoryCommit::from_headers(
            &evm_header,
            &commitment_header,
            commitment_version,
            &self.provider,
            beacon_url,
        )
        .await?;
        let commit = HostCommit {
            inner: history_commit,
            config_id: self.chain_spec.digest(),
        };
        let db = ProofDb::new(ProviderDb::new(
            self.provider,
            self.provider_config,
            evm_header.seal(),
        ));

        Ok(EvmEnv::new(db, self.chain_spec, evm_header, commit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{get_cl_url, get_el_url};
    use crate::{
        ethereum::{EthEvmEnv, ETH_MAINNET_CHAIN_SPEC},
        BlockHeaderCommit, Commitment, CommitmentVersion,
    };
    use test_log::test;

    #[test(tokio::test)]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn build_block_env() {
        let builder = EthEvmEnv::builder()
            .rpc(get_el_url())
            .chain_spec(&ETH_MAINNET_CHAIN_SPEC);
        // the builder should be cloneable
        builder.clone().build().await.unwrap();
    }

    #[test(tokio::test)]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn build_beacon_env() {
        let provider = ProviderBuilder::default().connect_http(get_el_url());

        let builder = EthEvmEnv::builder()
            .provider(&provider)
            .beacon_api(get_cl_url())
            .block_number_or_tag(BlockNumberOrTag::Parent)
            .chain_spec(&ETH_MAINNET_CHAIN_SPEC);
        let env = builder.clone().build().await.unwrap();
        let commit = env.commit.inner.commit(&env.header, env.commit.config_id);

        // the commitment should verify against the parent_beacon_block_root of the child
        let child_block = provider
            .get_block_by_number((env.header.number() + 1).into())
            .await
            .unwrap();
        let header = child_block.unwrap().header;
        assert_eq!(
            commit,
            Commitment::new(
                CommitmentVersion::Beacon as u16,
                header.timestamp,
                header.parent_beacon_block_root.unwrap(),
                ETH_MAINNET_CHAIN_SPEC.digest(),
            )
        );
    }

    #[test(tokio::test)]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn build_history_env() {
        let provider = ProviderBuilder::default().connect_http(get_el_url());

        // initialize the env at latest - 100 while committing to latest - 1
        let latest = provider.get_block_number().await.unwrap();
        let builder = EthEvmEnv::builder()
            .provider(&provider)
            .block_number_or_tag(BlockNumberOrTag::Number(latest - 8191))
            .beacon_api(get_cl_url())
            .commitment_block_number(latest - 1)
            .chain_spec(&ETH_MAINNET_CHAIN_SPEC);
        let env = builder.clone().build().await.unwrap();
        let commit = env.commit.inner.commit(&env.header, env.commit.config_id);

        // the commitment should verify against the parent_beacon_block_root of the latest block
        let child_block = provider.get_block_by_number(latest.into()).await.unwrap();
        let header = child_block.unwrap().header;
        assert_eq!(
            commit,
            Commitment::new(
                CommitmentVersion::Beacon as u16,
                header.timestamp,
                header.parent_beacon_block_root.unwrap(),
                ETH_MAINNET_CHAIN_SPEC.digest(),
            )
        );
    }
}
