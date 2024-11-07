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

/// The generalized Merkle tree index of the `state_root` field in the `BeaconBlock`.
pub const STATE_ROOT_LEAF_INDEX: usize = 6434;

/// The generalized Merkle tree index of the `block_hash` field in the `BeaconBlock`.
pub const BLOCK_HASH_LEAF_INDEX: usize = 6444;

/// Input committing to the corresponding Beacon Chain block root.
pub type BeaconInput<H> = ComposeInput<H, BeaconCommit>;

/// A commitment that an execution block hash is included in a specific beacon block on the Ethereum
/// blockchain.
///
/// This type represents a commitment that proves the inclusion of an execution block's hash within
/// a particular beacon block on the Ethereum beacon chain. It relies on a Merkle proof to establish
/// this link, ensuring the integrity and verifiability of the connection between the execution
/// block and the beacon chain.
///
/// **Important:** This type currently relies on an underlying implementation that only supports the
/// Deneb fork of the beacon chain. If the beacon chain undergoes a future upgrade, this type's
/// functionality may be affected, potentially requiring updates to handle new block structures or
/// proof generation mechanisms.
///
/// Users should monitor for beacon chain upgrades and ensure they are using a compatible version of
/// this library.
pub type BeaconCommit = GeneralizedBeaconCommit<BLOCK_HASH_LEAF_INDEX>;

/// A commitment to a field of the Beacon block at a specific index in a Merkle tree, along with a
/// timestamp.
///
/// The constant generic parameter `LEAF_INDEX` specifies the generalized Merkle tree index of the
/// leaf node in the Merkle tree corresponding to the field.
#[derive(Clone, Serialize, Deserialize)]
pub struct GeneralizedBeaconCommit<const LEAF_INDEX: usize> {
    proof: Vec<B256>,
    timestamp: u64,
}

impl<const LEAF_INDEX: usize> GeneralizedBeaconCommit<LEAF_INDEX> {
    /// Creates a new `GeneralizedBeaconCommit`.
    ///
    /// It panics if `LEAF_INDEX` is zero, because a Merkle tree cannot have a leaf at index 0.
    #[must_use]
    #[inline]
    pub const fn new(proof: Vec<B256>, timestamp: u64) -> Self {
        assert!(LEAF_INDEX > 0);
        Self { proof, timestamp }
    }

    /// Disassembles this `GeneralizedBeaconCommit`, returning the underlying Merkle proof and block
    /// timestamp.
    #[inline]
    pub fn into_parts(self) -> (Vec<B256>, u64) {
        (self.proof, self.timestamp)
    }

    /// Calculates the root of the Merkle tree containing the given `leaf` hash at `LEAF_INDEX`,
    /// using the provided Merkle proof.
    #[inline]
    pub fn process_proof(&self, leaf: B256) -> Result<B256, merkle::InvalidProofError> {
        merkle::process_proof(leaf, &self.proof, LEAF_INDEX)
    }

    /// Verifies that the given `leaf` hash is present at the `LEAF_INDEX` in the Merkle tree
    /// represented by the `root` hash.
    #[inline]
    pub fn verify(&self, leaf: B256, root: B256) -> Result<(), merkle::InvalidProofError> {
        merkle::verify(leaf, &self.proof, LEAF_INDEX, root)
    }

    pub(crate) fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub(crate) fn into_commit(self, leaf: B256) -> (u64, B256) {
        let beacon_root = self
            .process_proof(leaf)
            .expect("Invalid beacon inclusion proof");
        (self.timestamp(), beacon_root)
    }
}

impl<H: EvmBlockHeader, const LEAF_INDEX: usize> BlockHeaderCommit<H>
    for GeneralizedBeaconCommit<LEAF_INDEX>
{
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
pub(crate) mod host {
    use super::*;
    use crate::ethereum::EthBlockHeader;
    use alloy::{
        network::{primitives::BlockTransactionsKind, Ethereum},
        providers::Provider,
        transports::Transport,
    };
    use alloy_primitives::B256;
    use anyhow::{bail, ensure, Context};
    use client::BeaconClient;
    use ethereum_consensus::{
        ssz::prelude::{proofs::Proof, *},
        types::SignedBeaconBlock,
        Fork,
    };
    use proofs::ProofAndWitness;
    use url::Url;

    pub(crate) mod client {
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

    impl BeaconCommit {
        /// Creates a new `BeaconCommit` for the provided header which proofs the inclusion of the
        /// corresponding block hash in the referenced beacon block.
        pub(crate) async fn from_header<T, P>(
            header: &Sealed<EthBlockHeader>,
            rpc_provider: P,
            beacon_url: Url,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            P: Provider<T, Ethereum>,
        {
            let client = BeaconClient::new(beacon_url).context("invalid URL")?;
            let (commit, beacon_root) =
                create_beacon_commit(header, "block_hash".into(), rpc_provider, &client).await?;
            commit
                .verify(header.seal(), beacon_root)
                .context("proof derived from API does not verify")?;

            log::info!(
                "Committing to parent beacon block: root={},timestamp={}",
                beacon_root,
                commit.timestamp()
            );

            Ok(commit)
        }
    }

    /// Creates a beacon commitment that `field` is contained in the `ExecutionPayload` of the
    /// beacon block corresponding to `header`.
    pub(crate) async fn create_beacon_commit<T, P, H, const LEAF_INDEX: usize>(
        header: &Sealed<H>,
        field: PathElement,
        rpc_provider: P,
        beacon_client: &BeaconClient,
    ) -> anyhow::Result<(GeneralizedBeaconCommit<LEAF_INDEX>, B256)>
    where
        T: Transport + Clone,
        P: Provider<T, Ethereum>,
        H: EvmBlockHeader,
    {
        let child = {
            let child_number = header.number() + 1;
            let block_res = rpc_provider
                .get_block_by_number(child_number.into(), BlockTransactionsKind::Hashes)
                .await
                .context("eth_getBlockByNumber failed")?;
            let block = block_res.with_context(|| {
                format!(
                    "beacon block commitment cannot be created for the most recent block; \
                    use `parent` tag instead: block {} does not have a child",
                    header.number()
                )
            })?;
            block.header
        };
        ensure!(
            child.parent_hash == header.seal(),
            "API returned invalid child block"
        );

        let beacon_root = child
            .parent_beacon_block_root
            .context("parent_beacon_block_root missing in execution header")?;
        let proof = create_execution_payload_proof(field, beacon_root, beacon_client).await?;
        ensure!(proof.index == LEAF_INDEX, "field has the wrong leaf index");

        let commit = GeneralizedBeaconCommit::new(
            proof.branch.iter().map(|n| n.0.into()).collect(),
            child.timestamp,
        );

        Ok((commit, beacon_root))
    }

    /// Creates the Merkle inclusion proof of the element `field` in the `ExecutionPayload` of the
    /// beacon block with the given `beacon_root`.
    async fn create_execution_payload_proof(
        field: PathElement,
        beacon_root: B256,
        client: &BeaconClient,
    ) -> anyhow::Result<Proof> {
        let signed_beacon_block = client
            .get_block(beacon_root)
            .await
            .with_context(|| format!("failed to get block {}", beacon_root))?;
        // create the inclusion proof of the execution block hash depending on the fork version
        let (proof, _) = match signed_beacon_block {
            SignedBeaconBlock::Deneb(signed_block) => {
                prove_execution_payload_field(signed_block.message, field)?
            }
            _ => {
                bail!(
                    "invalid version of block {}: expected {}; got {}",
                    beacon_root,
                    Fork::Deneb,
                    signed_beacon_block.version()
                );
            }
        };

        Ok(proof)
    }

    /// Creates the Merkle inclusion proof of the element `field` in the `ExecutionPayload` in the
    /// given `BeaconBlock`.
    fn prove_execution_payload_field<T: SimpleSerialize>(
        beacon_block: T,
        field: PathElement,
    ) -> Result<ProofAndWitness, MerkleizationError> {
        // the field is in the ExecutionPayload in the BeaconBlockBody in the BeaconBlock
        beacon_block.prove(&["body".into(), "execution_payload".into(), field])
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy::{eips::BlockNumberOrTag, network::BlockResponse, providers::ProviderBuilder};

        #[tokio::test]
        #[ignore = "queries actual RPC nodes"]
        async fn create_execution_payload_proof() {
            const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
            const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

            let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();
            let cl = BeaconClient::new(CL_URL).unwrap();

            let block = el
                .get_block_by_number(BlockNumberOrTag::Latest, BlockTransactionsKind::Hashes)
                .await
                .expect("eth_getBlockByNumber failed")
                .unwrap();
            let beacon_root = block.header().parent_beacon_block_root.unwrap();

            let block_hash = block.header().parent_hash;
            let proof =
                super::create_execution_payload_proof("block_hash".into(), beacon_root, &cl)
                    .await
                    .expect("proving 'block_hash' failed");
            let branch: Vec<B256> = proof.branch.iter().map(|n| n.0.into()).collect();
            merkle::verify(block_hash, &branch, BLOCK_HASH_LEAF_INDEX, beacon_root).unwrap();
        }
    }
}
