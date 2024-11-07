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

use crate::{
    beacon::BeaconCommit,
    config::ChainSpec,
    ethereum::EthBlockHeader,
    history::HistoryCommit,
    host::{
        db::{AlloyDb, ProofDb, ProviderConfig},
        BlockNumberOrTag, EthHostEvmEnv, HostCommit, HostEvmEnv,
    },
    EvmBlockHeader, EvmEnv,
};
use alloy::{
    network::{
        primitives::{BlockTransactionsKind, HeaderResponse},
        BlockResponse, Ethereum, Network,
    },
    providers::{Provider, ProviderBuilder, ReqwestProvider},
    transports::Transport,
};
use alloy_primitives::Sealed;
use anyhow::{anyhow, ensure, Context, Result};
use std::{fmt::Display, marker::PhantomData};
use url::Url;

impl<H> EvmEnv<(), H, ()> {
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
    pub fn builder() -> EvmEnvBuilder<(), H, ()> {
        EvmEnvBuilder {
            provider: (),
            provider_config: ProviderConfig::default(),
            block: BlockNumberOrTag::Latest,
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
///
/// # Type Parameters
/// - `P`: The type of the RPC provider that interacts with the blockchain.
/// - `H`: The type of the block header.
/// - `B`: The type of the configuration to access the Beacon API.
#[derive(Clone, Debug)]
pub struct EvmEnvBuilder<P, H, B> {
    provider: P,
    provider_config: ProviderConfig,
    block: BlockNumberOrTag,
    beacon_config: B,
    phantom: PhantomData<H>,
}

impl EvmEnvBuilder<(), EthBlockHeader, ()> {
    /// Sets the Ethereum HTTP RPC endpoint that will be used by the [EvmEnv].
    pub fn rpc(self, url: Url) -> EvmEnvBuilder<ReqwestProvider<Ethereum>, EthBlockHeader, ()> {
        self.provider(ProviderBuilder::new().on_http(url))
    }
}

impl<H: EvmBlockHeader> EvmEnvBuilder<(), H, ()> {
    /// Sets a custom [Provider] that will be used by the [EvmEnv].
    pub fn provider<T, N, P>(self, provider: P) -> EvmEnvBuilder<P, H, ()>
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
            beacon_config: self.beacon_config,
            phantom: self.phantom,
        }
    }
}

impl<P> EvmEnvBuilder<P, EthBlockHeader, ()> {
    /// Sets the Beacon API URL for retrieving Ethereum Beacon block root commitments.
    ///
    /// This function configures the [EvmEnv] to interact with an Ethereum Beacon chain.
    /// It assumes the use of the [mainnet](https://github.com/ethereum/consensus-specs/blob/v1.4.0/configs/mainnet.yaml) preset for consensus specs.
    pub fn beacon_api(self, url: Url) -> EvmEnvBuilder<P, EthBlockHeader, Url> {
        EvmEnvBuilder {
            provider: self.provider,
            provider_config: self.provider_config,
            block: self.block,
            beacon_config: url,
            phantom: self.phantom,
        }
    }
}

impl<P, H, B> EvmEnvBuilder<P, H, B> {
    /// Sets the block number to be used for the EVM execution.
    pub fn block_number(self, number: u64) -> Self {
        self.block_number_or_tag(BlockNumberOrTag::Number(number))
    }

    /// Sets the block number or block tag ("latest", "earliest", "pending") to be used for the EVM
    /// execution.
    pub fn block_number_or_tag(mut self, block: BlockNumberOrTag) -> Self {
        self.block = block;
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
    async fn get_header<T, N>(&self, block: Option<BlockNumberOrTag>) -> Result<Sealed<H>>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
        <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        let block = block.unwrap_or(self.block);
        let number = block.into_rpc_type(&self.provider).await?;

        let rpc_block = self
            .provider
            .get_block_by_number(number, BlockTransactionsKind::Hashes)
            .await
            .context("eth_getBlockByNumber failed")?
            .with_context(|| format!("block {} not found", number))?;
        let rpc_header = rpc_block.header().clone();
        let header: H = rpc_header
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

impl<P, H> EvmEnvBuilder<P, H, ()> {
    /// Builds and returns an [EvmEnv] with the configured settings that commits to a block hash.
    pub async fn build<T, N>(self) -> Result<HostEvmEnv<AlloyDb<T, N, P>, H, ()>>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
        <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        let header = self.get_header(None).await?;
        log::info!(
            "Environment initialized with block {} ({})",
            header.number(),
            header.seal()
        );

        let db = ProofDb::new(AlloyDb::new(
            self.provider,
            self.provider_config,
            header.seal(),
        ));
        let commit = HostCommit {
            inner: (),
            config_id: ChainSpec::DEFAULT_DIGEST,
        };

        Ok(EvmEnv::new(db, header, commit))
    }
}

/// Config for separating the execution block from the commitment block.
#[stability::unstable(feature = "history")]
#[derive(Clone, Debug)]
pub struct History {
    beacon_url: Url,
    commitment_block: BlockNumberOrTag,
}

impl<P> EvmEnvBuilder<P, EthBlockHeader, Url> {
    /// Sets a dedicated block for the commitment that is different from the execution block.
    ///
    /// The commitment block must be later than the execution block (i.e. the execution block must
    /// be an ancestor of the commitment block). This allows executing smart contracts with
    /// historical state (e.g. 30 days ago) and verifying the results against a more recent
    /// commitment block.
    ///
    /// Note that this feature requires a Beacon chain RPC provider, as it uses EIP-4788.
    #[stability::unstable(feature = "history")]
    pub fn commitment_block(
        self,
        block: BlockNumberOrTag,
    ) -> EvmEnvBuilder<P, EthBlockHeader, History> {
        EvmEnvBuilder {
            provider: self.provider,
            provider_config: self.provider_config,
            block: self.block,
            beacon_config: History {
                beacon_url: self.beacon_config,
                commitment_block: block,
            },
            phantom: Default::default(),
        }
    }

    /// Builds and returns an [EvmEnv] with the configured settings that commits to a beacon root.
    pub async fn build<T>(self) -> Result<EthHostEvmEnv<AlloyDb<T, Ethereum, P>, BeaconCommit>>
    where
        T: Transport + Clone,
        P: Provider<T, Ethereum>,
    {
        let header = self.get_header(None).await?;
        log::info!(
            "Environment initialized with block {} ({})",
            header.number(),
            header.seal()
        );

        let commit = HostCommit {
            inner: BeaconCommit::from_header(&header, &self.provider, self.beacon_config).await?,
            config_id: ChainSpec::DEFAULT_DIGEST,
        };
        let db = ProofDb::new(AlloyDb::new(
            self.provider,
            self.provider_config,
            header.seal(),
        ));

        Ok(EvmEnv::new(db, header, commit))
    }
}

impl<P> EvmEnvBuilder<P, EthBlockHeader, History> {
    /// Builds and returns an [EvmEnv] with the configured settings, using a dedicated commitment
    /// block that is different from the execution block.
    #[stability::unstable(feature = "history")]
    pub async fn build<T>(self) -> Result<EthHostEvmEnv<AlloyDb<T, Ethereum, P>, HistoryCommit>>
    where
        T: Transport + Clone,
        P: Provider<T, Ethereum>,
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

        let beacon_url = self.beacon_config.beacon_url;
        let history_commit = HistoryCommit::from_headers(
            &evm_header,
            &commitment_header,
            &self.provider,
            beacon_url,
        )
        .await?;
        let commit = HostCommit {
            inner: history_commit,
            config_id: ChainSpec::DEFAULT_DIGEST,
        };
        let db = ProofDb::new(AlloyDb::new(
            self.provider,
            self.provider_config,
            evm_header.seal(),
        ));

        Ok(EvmEnv::new(db, evm_header, commit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ChainSpec, ethereum::EthEvmEnv, BlockHeaderCommit, Commitment, CommitmentVersion,
    };
    use test_log::test;

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
    const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

    #[test(tokio::test)]
    #[ignore = "queries actual RPC nodes"]
    async fn build_block_env() {
        let builder = EthEvmEnv::builder().rpc(EL_URL.parse().unwrap());
        // the builder should be cloneable
        builder.clone().build().await.unwrap();
    }

    #[test(tokio::test)]
    #[ignore = "queries actual RPC nodes"]
    async fn build_beacon_env() {
        let provider = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        let builder = EthEvmEnv::builder()
            .provider(&provider)
            .beacon_api(CL_URL.parse().unwrap())
            .block_number_or_tag(BlockNumberOrTag::Parent);
        let env = builder.clone().build().await.unwrap();
        let commit = env.commit.inner.commit(&env.header, env.commit.config_id);

        // the commitment should verify against the parent_beacon_block_root of the child
        let child_block = provider
            .get_block_by_number(
                (env.header.number() + 1).into(),
                BlockTransactionsKind::Hashes,
            )
            .await
            .unwrap();
        let header = child_block.unwrap().header;
        assert_eq!(
            commit,
            Commitment::new(
                CommitmentVersion::Beacon as u16,
                header.timestamp,
                header.parent_beacon_block_root.unwrap(),
                ChainSpec::DEFAULT_DIGEST,
            )
        );
    }

    #[test(tokio::test)]
    #[ignore = "queries actual RPC nodes"]
    async fn build_history_env() {
        let provider = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // initialize the env at latest - 100 while committing to latest - 1
        let latest = provider.get_block_number().await.unwrap();
        let builder = EthEvmEnv::builder()
            .provider(&provider)
            .block_number_or_tag(BlockNumberOrTag::Number(latest - 100))
            .beacon_api(CL_URL.parse().unwrap())
            .commitment_block(BlockNumberOrTag::Number(latest - 1));
        let env = builder.clone().build().await.unwrap();
        let commit = env.commit.inner.commit(&env.header, env.commit.config_id);

        // the commitment should verify against the parent_beacon_block_root of the latest block
        let child_block = provider
            .get_block_by_number(latest.into(), BlockTransactionsKind::Hashes)
            .await
            .unwrap();
        let header = child_block.unwrap().header;
        assert_eq!(
            commit,
            Commitment::new(
                CommitmentVersion::Beacon as u16,
                header.timestamp,
                header.parent_beacon_block_root.unwrap(),
                ChainSpec::DEFAULT_DIGEST,
            )
        );
    }
}
