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

use crate::{block::BlockInput, Commitment, CommitmentVersion, EvmBlockHeader, GuestEvmEnv};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Input committing to the corresponding Beacon Chain block root.
#[derive(Clone, Serialize, Deserialize)]
pub struct BeaconInput<H> {
    /// Input committing to an execution block hash.
    input: BlockInput<H>,
    /// Merkle proof linking the execution block hash to the Beacon block root.
    proof: MerkleProof,
}

impl<H: EvmBlockHeader> BeaconInput<H> {
    /// Converts the input into a [EvmEnv] for verifiable state access in the guest.
    ///
    /// [EvmEnv]: crate::EvmEnv
    pub fn into_env(self) -> GuestEvmEnv<H> {
        let mut env = self.input.into_env();

        let beacon_root = self.proof.process(env.header.seal());
        env.commitment = Commitment {
            blockID: Commitment::encode_id(
                env.header().timestamp(),
                CommitmentVersion::Beacon as u16,
            ),
            blockDigest: beacon_root,
        };

        env
    }
}

/// Merkle proof-of-inclusion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path of Merkle nodes to compute the root.
    pub path: Vec<B256>,
    /// Index of the Merkle leaf to prove.
    /// The left-most leaf has index 0 and the right-most leaf 2^depth - 1.
    pub index: u32,
}

impl MerkleProof {
    /// Returns the rebuilt hash obtained by traversing the Merkle tree up from `leaf`.
    #[inline]
    pub fn process(&self, leaf: B256) -> B256 {
        let mut index = self.index;
        let mut computed_hash = leaf;
        let mut hasher = Sha256::new();
        for node in &self.path {
            if index % 2 != 0 {
                hasher.update(node);
                hasher.update(computed_hash);
            } else {
                hasher.update(computed_hash);
                hasher.update(node);
            }
            computed_hash.copy_from_slice(&hasher.finalize_reset());
            index /= 2;
        }

        computed_hash
    }
}

#[cfg(feature = "host")]
mod host {
    use super::{BeaconInput, MerkleProof};
    use crate::{
        block::BlockInput,
        ethereum::EthBlockHeader,
        host::{db::AlloyDb, HostEvmEnv},
        EvmBlockHeader,
    };
    use alloy::{network::Ethereum, providers::Provider, transports::Transport};
    use alloy_primitives::{Sealable, B256};
    use anyhow::{bail, ensure, Context};
    use client::{BeaconClient, GetBlockHeaderResponse};
    use ethereum_consensus::{ssz::prelude::*, types::SignedBeaconBlock, Fork};
    use log::info;
    use proofs::{Proof, ProofAndWitness};
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
                .inner()
                .parent_beacon_block_root
                .context("parent_beacon_block_root missing in execution header")?;

            let input = BlockInput::from_env(env)
                .await
                .context("failed to derive block input")?;

            let client = BeaconClient::new(url).context("invalid URL")?;
            let (proof, beacon_root) = create_proof(parent_beacon_block_root, client).await?;
            ensure!(
                proof.process(block_hash) == beacon_root,
                "proof derived from API does not verify",
            );

            info!(
                "Commitment to beacon block root {} at {}",
                beacon_root, block_ts
            );

            Ok(BeaconInput { input, proof })
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

        /// Simple beacon API client that can be used to query headers and blocks.
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
    ) -> anyhow::Result<(MerkleProof, B256)> {
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
        let proof: MerkleProof = proof
            .try_into()
            .context("proof derived from API is invalid")?;

        Ok((proof, beacon_root.0.into()))
    }

    /// Returns the header, with `parent_root` equal to `parent.root`.
    ///
    /// It iteratively tries to fetch headers of successive slots until success.
    /// TODO: use `eth/v1/beacon/headers?parent_root`, once all the nodes support it.
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

    impl TryFrom<Proof> for MerkleProof {
        type Error = anyhow::Error;

        fn try_from(proof: Proof) -> Result<Self, Self::Error> {
            let depth = proof.index.checked_ilog2().context("index is zero")?;
            let index = proof.index - (1 << depth);
            ensure!(proof.branch.len() == depth as usize, "index is invalid");

            Ok(MerkleProof {
                path: proof.branch.iter().map(|n| n.0.into()).collect(),
                index: index.try_into().context("index too large")?,
            })
        }
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
            assert_eq!(proof.process(header.hash), beacon_root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn process_simple_proof() {
        let leaf = b256!("94159da973dfa9e40ed02535ee57023ba2d06bad1017e451055470967eb71cd5");
        let proof = MerkleProof {
            path: vec![
                b256!("8f594dbb4f4219ad4967f86b9cccdb26e37e44995a291582a431eef36ecba45c"),
                b256!("f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c"),
                b256!("382ba9638ce263e802593b387538faefbaed106e9f51ce793d405f161b105ee6"),
            ],
            index: 2,
        };
        assert_eq!(
            proof.process(leaf),
            b256!("27097c728aade54ff1376d5954681f6d45c282a81596ef19183148441b754abb")
        );
    }
}
