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

//! Types related to commitments to the beacon block root.
use crate::{
    merkle, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput, EvmBlockHeader,
};
use alloy_primitives::{Sealed, B256};
use serde::{Deserialize, Serialize};

/// The generalized Merkle tree index of the `block_hash` field in the `BeaconBlock`
pub const BLOCK_HASH_LEAF_INDEX: merkle::GeneralizedIndex = merkle::GeneralizedIndex::new(6444);

/// Input committing to the corresponding Beacon Chain block root.
pub type BeaconInput<H> = ComposeInput<H, BeaconCommit>;

/// Links the execution block hash to the Beacon block root.
#[derive(Clone, Serialize, Deserialize)]
pub struct BeaconCommit {
    proof: Vec<B256>,
    timestamp: u64,
}

impl BeaconCommit {
    /// Creates a new `BeaconCommit`.
    #[must_use]
    #[inline]
    pub const fn new(proof: Vec<B256>, timestamp: u64) -> Self {
        Self { proof, timestamp }
    }

    /// Disassembles this `BeaconCommit`, returning the underlying Merkle proof and block timestamp.
    #[inline]
    pub fn into_parts(self) -> (Vec<B256>, u64) {
        (self.proof, self.timestamp)
    }

    /// Processes the `BeaconCommit`.
    fn into_commit(self, leaf: B256) -> (u64, B256) {
        let beacon_root = merkle::process_proof(leaf, &self.proof, BLOCK_HASH_LEAF_INDEX)
            .expect("Invalid beacon inclusion proof");
        (self.timestamp, beacon_root)
    }
}

impl<H: EvmBlockHeader> BlockHeaderCommit<H> for BeaconCommit {
    #[inline]
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment {
        let (timestamp, beacon_root) = self.into_commit(header.seal());
        Commitment::new(
            CommitmentVersion::Beacon as u16,
            timestamp,
            beacon_root,
            config_id,
        )
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{
        ethereum::EthBlockHeader,
        host::{db::AlloyDb, HostEvmEnv},
        BlockInput,
    };
    use alloy::{network::Ethereum, providers::Provider, transports::Transport};
    use alloy_primitives::{Sealable, B256};
    use anyhow::{bail, ensure, Context};
    use client::{BeaconClient, GetBlockHeaderResponse};
    use ethereum_consensus::{ssz::prelude::*, types::SignedBeaconBlock, Fork};
    use log::info;
    use proofs::ProofAndWitness;
    use url::Url;

    impl BeaconInput<EthBlockHeader> {
        /// Derives the verifiable input from a [HostEvmEnv] and a Beacon API endpoint.
        pub(crate) async fn from_env_and_endpoint<T, P>(
            env: HostEvmEnv<AlloyDb<T, Ethereum, P>, EthBlockHeader>,
            url: Url,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            P: Provider<T, Ethereum>,
        {
            let block_hash = env.header().hash_slow();
            let block_ts = env.header().timestamp();
            let parent_beacon_block_root = env
                .header()
                .parent_beacon_block_root
                .context("parent_beacon_block_root missing in execution header")?;

            let input = BlockInput::from_env(env)
                .await
                .context("failed to derive block input")?;

            let client = BeaconClient::new(url).context("invalid URL")?;
            let (proof, beacon_root) = create_proof(parent_beacon_block_root, client).await?;
            merkle::verify(block_hash, &proof, BLOCK_HASH_LEAF_INDEX, beacon_root)
                .context("proof derived from API does not verify")?;
            let commit = BeaconCommit::new(proof, block_ts);

            info!(
                "Commitment to beacon block root {} at {}",
                beacon_root, block_ts
            );

            Ok(BeaconInput::new(input, commit))
        }
    }

    mod client {
        use ethereum_consensus::{
            phase0::SignedBeaconBlockHeader, primitives::Root, types::mainnet::SignedBeaconBlock,
            Fork,
        };
        use reqwest::IntoUrl;
        use serde::{Deserialize, Serialize};
        use std::{collections::HashMap, fmt::Display};
        use url::Url;

        /// Errors returned by the [BeaconClient].
        #[derive(Debug, thiserror::Error)]
        pub enum Error {
            #[error("could not parse URL: {0}")]
            Url(#[from] url::ParseError),
            #[error("HTTP request failed: {0}")]
            Http(#[from] reqwest::Error),
            #[error("version field does not match data version")]
            VersionMismatch,
        }

        /// Response returned by the `get_block_header` API.
        #[derive(Debug, Serialize, Deserialize)]
        pub struct GetBlockHeaderResponse {
            pub root: Root,
            pub canonical: bool,
            pub header: SignedBeaconBlockHeader,
        }

        /// Wrapper returned by the API calls.
        #[derive(Serialize, Deserialize)]
        struct Response<T> {
            data: T,
            #[serde(flatten)]
            meta: HashMap<String, serde_json::Value>,
        }

        /// Wrapper returned by the API calls that includes a version.
        #[derive(Serialize, Deserialize)]
        struct VersionedResponse<T> {
            version: Fork,
            #[serde(flatten)]
            inner: Response<T>,
        }

        /// Simple beacon API client for the `mainnet` preset that can query headers and blocks.
        pub struct BeaconClient {
            http: reqwest::Client,
            endpoint: Url,
        }

        impl BeaconClient {
            /// Creates a new beacon endpoint API client.
            pub fn new<U: IntoUrl>(endpoint: U) -> Result<Self, Error> {
                let client = reqwest::Client::new();
                Ok(Self {
                    http: client,
                    endpoint: endpoint.into_url()?,
                })
            }

            async fn http_get<T: serde::de::DeserializeOwned>(
                &self,
                path: &str,
            ) -> Result<T, Error> {
                let target = self.endpoint.join(path)?;
                let resp = self.http.get(target).send().await?;
                let value = resp.error_for_status()?.json().await?;
                Ok(value)
            }

            /// Retrieves block header for given block id.
            pub async fn get_block_header(
                &self,
                block_id: impl Display,
            ) -> Result<GetBlockHeaderResponse, Error> {
                let path = format!("eth/v1/beacon/headers/{block_id}");
                let result: Response<GetBlockHeaderResponse> = self.http_get(&path).await?;
                Ok(result.data)
            }

            /// Retrieves block details for given block id.
            pub async fn get_block(
                &self,
                block_id: impl Display,
            ) -> Result<SignedBeaconBlock, Error> {
                let path = format!("eth/v2/beacon/blocks/{block_id}");
                let result: VersionedResponse<SignedBeaconBlock> = self.http_get(&path).await?;
                if result.version.to_string() != result.inner.data.version().to_string() {
                    return Err(Error::VersionMismatch);
                }
                Ok(result.inner.data)
            }
        }
    }

    /// Creates the [MerkleProof] of `block_hash` in the `BeaconBlock` with the given
    /// `parent_beacon_block_root`.
    async fn create_proof(
        parent_root: B256,
        client: BeaconClient,
    ) -> anyhow::Result<(Vec<B256>, B256)> {
        // first get the header of the parent and then the actual block header
        let parent_beacon_header = client
            .get_block_header(parent_root)
            .await
            .with_context(|| format!("failed to get block header {}", parent_root))?;
        let beacon_header = get_child_beacon_header(&client, parent_beacon_header)
            .await
            .with_context(|| format!("failed to get child of block {}", parent_root))?;

        // get the entire block
        let signed_beacon_block = client
            .get_block(beacon_header.root)
            .await
            .with_context(|| format!("failed to get block {}", beacon_header.root))?;
        // create the inclusion proof of the execution block hash depending on the fork version
        let (proof, beacon_root) = match signed_beacon_block {
            SignedBeaconBlock::Deneb(signed_block) => prove_block_hash(signed_block.message)?,
            _ => {
                bail!(
                    "invalid version of block {}: expected {}; got {}",
                    beacon_header.root,
                    Fork::Deneb,
                    signed_beacon_block.version()
                );
            }
        };

        Ok((
            proof.branch.iter().map(|n| n.0.into()).collect(),
            beacon_root.0.into(),
        ))
    }

    /// Returns the header, with `parent_root` equal to `parent.root`.
    ///
    /// It iteratively tries to fetch headers of successive slots until success.
    // TODO(#242): use `eth/v1/beacon/headers?parent_root` when more clients support it.
    async fn get_child_beacon_header(
        client: &BeaconClient,
        parent: GetBlockHeaderResponse,
    ) -> anyhow::Result<GetBlockHeaderResponse> {
        let parent_slot = parent.header.message.slot;
        let mut request_error = None;
        for slot in (parent_slot + 1)..=(parent_slot + 32) {
            match client.get_block_header(slot).await {
                Err(err) => request_error = Some(err),
                Ok(resp) => {
                    let header = &resp.header.message;
                    ensure!(
                        header.parent_root == parent.root,
                        "block {} has wrong parent_root: expected {}; got {}",
                        resp.root,
                        parent.root,
                        header.parent_root
                    );
                    return Ok(resp);
                }
            }
        }
        // return the last error, if all calls failed
        // safe unwrap: there must have been at least one error when we reach this line
        let err = anyhow::Error::from(request_error.unwrap());
        Err(err.context("no valid response received for the 32 consecutive slots"))
    }

    /// Returns the inclusion proof of `block_hash` in the given `BeaconBlock`.
    fn prove_block_hash<T: SimpleSerialize>(
        beacon_block: T,
    ) -> Result<ProofAndWitness, MerkleizationError> {
        // the `block_hash` is in the ExecutionPayload in the BeaconBlockBody in the BeaconBlock
        beacon_block.prove(&[
            "body".into(),
            "execution_payload".into(),
            "block_hash".into(),
        ])
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy::{eips::BlockNumberOrTag, network::BlockResponse, providers::ProviderBuilder};

        #[tokio::test]
        #[ignore] // This queries actual RPC nodes, running only on demand.
        async fn eth_mainnet_proof() {
            const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
            const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

            let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();
            let cl = BeaconClient::new(CL_URL).unwrap();

            let block = el
                .get_block_by_number(BlockNumberOrTag::Finalized, false)
                .await
                .expect("eth_getBlockByNumber failed")
                .unwrap();
            let header = block.header();

            let (proof, beacon_root) = create_proof(header.parent_beacon_block_root.unwrap(), cl)
                .await
                .expect("proving failed");
            merkle::verify(header.hash, &proof, BLOCK_HASH_LEAF_INDEX, beacon_root).unwrap();
        }
    }
}
