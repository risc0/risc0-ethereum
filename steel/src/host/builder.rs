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
    host::HostCommit,
    host::{
        db::{AlloyDb, ProofDb, ProviderConfig},
        BlockNumberOrTag, EthHostEvmEnv, HostEvmEnv,
    },
    EvmBlockHeader, EvmEnv,
};
use alloy::{
    network::{BlockResponse, Ethereum, Network},
    providers::{Provider, ProviderBuilder, ReqwestProvider},
    transports::Transport,
};
use alloy_primitives::Sealable;
use anyhow::{anyhow, Context, Result};
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

    /// Retrieves the block header based on the current builder configuration.
    async fn get_header<T, N>(&self) -> Result<H>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N>,
        H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
        <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
    {
        let number = self.block.into_rpc_type(&self.provider).await?;
        let rpc_block = self
            .provider
            .get_block_by_number(number, false)
            .await
            .context("eth_getBlockByNumber failed")?
            .with_context(|| format!("block {} not found", number))?;
        let header = rpc_block.header().clone();
        header
            .try_into()
            .map_err(|err| anyhow!("header invalid: {}", err))
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
        let header = self.get_header().await?.seal_slow();
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

impl<P> EvmEnvBuilder<P, EthBlockHeader, Url> {
    /// Builds and returns an [EvmEnv] with the configured settings that commits to a beacon root.
    pub async fn build<T>(self) -> Result<EthHostEvmEnv<AlloyDb<T, Ethereum, P>, BeaconCommit>>
    where
        T: Transport + Clone,
        P: Provider<T, Ethereum>,
    {
        let header = self.get_header().await?.seal_slow();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChainSpec;
    use crate::{ethereum::EthEvmEnv, BlockHeaderCommit, Commitment, CommitmentVersion};
    use test_log::test;

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
    const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

    #[test(tokio::test)]
    #[ignore] // This queries actual RPC nodes, running only on demand.
    async fn build_block_env() {
        EthEvmEnv::builder()
            .rpc(EL_URL.parse().unwrap())
            .build()
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    #[ignore] // This queries actual RPC nodes, running only on demand.
    async fn build_beacon_env() {
        let provider = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();
        let env = EthEvmEnv::builder()
            .provider(&provider)
            .beacon_api(CL_URL.parse().unwrap())
            .block_number_or_tag(BlockNumberOrTag::Parent)
            .build()
            .await
            .unwrap();
        let commit = env.commit.inner.commit(&env.header, env.commit.config_id);

        // the commitment should verify against the parent_beacon_block_root of the child
        let child_block = provider
            .get_block_by_number((env.header.number() + 1).into(), false)
            .await
            .unwrap();
        let header_block = child_block.unwrap().header;
        assert_eq!(
            commit,
            Commitment::new(
                CommitmentVersion::Beacon as u16,
                header_block.timestamp,
                header_block.parent_beacon_block_root.unwrap(),
                ChainSpec::DEFAULT_DIGEST,
            )
        );
    }
}
