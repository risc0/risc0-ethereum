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

//! Types related to commitments to the beacon block root.
use crate::{merkle, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput};
use alloy_primitives::{Sealed, B256};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The generalized Merkle tree index of the `state_root` field in the `BeaconBlock`.
pub const STATE_ROOT_LEAF_INDEX: usize = 6434;

/// The generalized Merkle tree index of the `block_hash` field in the `BeaconBlock`.
pub const BLOCK_HASH_LEAF_INDEX: usize = 6444;

/// Input committing to the corresponding Beacon Chain block root.
pub type BeaconInput<F> = ComposeInput<F, BeaconCommit>;

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

/// A beacon block identifier.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum BeaconBlockId {
    /// Timestamp of the child execution block, to query the beacon block root using the EIP-4788
    /// beacon roots contract.
    Eip4788(u64),
    /// Slot of the beacon block.
    Slot(u64),
}

impl fmt::Display for BeaconBlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BeaconBlockId::Eip4788(timestamp) => {
                write!(f, "eip4788-timestamp: {}", timestamp)
            }
            BeaconBlockId::Slot(slot) => write!(f, "slot: {}", slot),
        }
    }
}

impl BeaconBlockId {
    pub const fn as_version(&self) -> u16 {
        match self {
            BeaconBlockId::Eip4788(_) => CommitmentVersion::Beacon as u16,
            BeaconBlockId::Slot(_) => CommitmentVersion::Consensus as u16,
        }
    }
    pub const fn as_id(&self) -> u64 {
        match self {
            BeaconBlockId::Eip4788(ts) => *ts,
            BeaconBlockId::Slot(slot) => *slot,
        }
    }
}

/// A commitment to a field of the beacon block at a specific index in a Merkle tree, along with a
/// timestamp.
///
/// The constant generic parameter `LEAF_INDEX` specifies the generalized Merkle tree index of the
/// leaf node in the Merkle tree corresponding to the field.
#[derive(Clone, Serialize, Deserialize)]
pub struct GeneralizedBeaconCommit<const LEAF_INDEX: usize> {
    proof: Vec<B256>,
    block_id: BeaconBlockId,
}

impl<const LEAF_INDEX: usize> GeneralizedBeaconCommit<LEAF_INDEX> {
    /// Creates a new `GeneralizedBeaconCommit`.
    ///
    /// It panics if `LEAF_INDEX` is zero, because a Merkle tree cannot have a leaf at index 0.
    #[must_use]
    #[inline]
    pub const fn new(proof: Vec<B256>, block_id: BeaconBlockId) -> Self {
        assert!(LEAF_INDEX > 0);
        Self { proof, block_id }
    }

    /// Disassembles this `GeneralizedBeaconCommit`, returning the underlying Merkle proof and
    /// beacon block identifier.
    #[inline]
    pub fn into_parts(self) -> (Vec<B256>, BeaconBlockId) {
        (self.proof, self.block_id)
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

    /// Returns the beacon block identifier (slot or timestamp).
    pub(crate) fn block_id(&self) -> BeaconBlockId {
        self.block_id
    }

    pub(crate) fn into_commit(self, leaf: B256) -> (BeaconBlockId, B256) {
        let beacon_root = self
            .process_proof(leaf)
            .expect("Invalid beacon inclusion proof");
        (self.block_id(), beacon_root)
    }
}

impl<H, const LEAF_INDEX: usize> BlockHeaderCommit<H> for GeneralizedBeaconCommit<LEAF_INDEX> {
    #[inline]
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment {
        let (block_id, beacon_root) = self.into_commit(header.seal());
        Commitment::new(
            block_id.as_version(),
            block_id.as_id(),
            beacon_root,
            config_id,
        )
    }
}

#[cfg(feature = "host")]
pub(crate) mod host {
    use super::*;
    use crate::{ethereum::EthBlockHeader, EvmBlockHeader};
    use alloy::{network::Ethereum, providers::Provider};
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
        use alloy_primitives::B256;
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
            #[error("response is empty")]
            EmptyResponse,
            #[error("block does not contain an execution payload")]
            NoExecutionPayload,
        }

        /// Response returned by the `get_block_header` API.
        #[derive(Debug, Serialize, Deserialize)]
        pub struct BlockHeaderResponse {
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

            /// Retrieves block details for the given block id.
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

            /// Retrieves block headers with the given parent root.
            pub async fn get_header_for_parent_root(
                &self,
                parent_root: B256,
            ) -> Result<BlockHeaderResponse, Error> {
                let target = self.endpoint.join("eth/v1/beacon/headers")?;
                let params = [("parent_root", parent_root)];
                let resp = self.http.get(target).query(&params).send().await?;
                let mut result: Response<Vec<BlockHeaderResponse>> =
                    resp.error_for_status()?.json().await?;
                result.data.pop().ok_or(Error::EmptyResponse)
            }

            /// Retrieves the execution bock hash for the given block id.
            pub async fn get_execution_payload_block_hash(
                &self,
                block_id: impl Display,
            ) -> Result<B256, Error> {
                let signed_beacon_block = self.get_block(block_id).await?;
                let beacon_block = signed_beacon_block.message();
                let beacon_block_body = beacon_block.body();
                let execution_payload = beacon_block_body
                    .execution_payload()
                    .ok_or(Error::NoExecutionPayload)?;

                Ok(B256::from_slice(execution_payload.block_hash()))
            }
        }
    }

    impl BeaconCommit {
        /// Creates a new `BeaconCommit` for the provided header which proofs the inclusion of the
        /// corresponding block hash in the referenced beacon block.
        pub(crate) async fn from_header<P>(
            header: &Sealed<EthBlockHeader>,
            commitment_version: CommitmentVersion,
            rpc_provider: P,
            beacon_url: Url,
        ) -> anyhow::Result<Self>
        where
            P: Provider<Ethereum>,
        {
            let client = BeaconClient::new(beacon_url).context("invalid URL")?;
            let (commit, beacon_root) = create_beacon_commit(
                header,
                "block_hash".into(),
                commitment_version,
                rpc_provider,
                &client,
            )
            .await?;
            commit
                .verify(header.seal(), beacon_root)
                .context("proof derived from API does not verify")?;

            log::info!(
                "Committing to beacon block: {{ {}, root: {} }}",
                commit.block_id(),
                beacon_root,
            );

            Ok(commit)
        }
    }

    impl<const LEAF_INDEX: usize> GeneralizedBeaconCommit<LEAF_INDEX> {
        pub(crate) async fn from_beacon_root(
            field: PathElement,
            parent_beacon_root: B256,
            beacon_client: &BeaconClient,
            block_id: BeaconBlockId,
        ) -> anyhow::Result<Self> {
            let proof =
                create_execution_payload_proof(field, parent_beacon_root, beacon_client).await?;
            ensure!(proof.index == LEAF_INDEX, "field has the wrong leaf index");

            let commit = GeneralizedBeaconCommit::new(
                proof.branch.iter().map(|n| n.0.into()).collect(),
                block_id,
            );

            Ok(commit)
        }
    }

    /// Creates a beacon commitment that `field` is contained in the `ExecutionPayload` of the
    /// beacon block corresponding to `header` creating a [CommitmentVersion::Beacon] commitment.
    async fn create_eip4788_beacon_commit<P, H, const LEAF_INDEX: usize>(
        header: &Sealed<H>,
        field: PathElement,
        rpc_provider: P,
        beacon_client: &BeaconClient,
    ) -> anyhow::Result<(GeneralizedBeaconCommit<LEAF_INDEX>, B256)>
    where
        P: Provider<Ethereum>,
        H: EvmBlockHeader,
    {
        let child = {
            let child_number = header.number() + 1;
            let block_res = rpc_provider
                .get_block_by_number(child_number.into())
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
        let commit = GeneralizedBeaconCommit::from_beacon_root(
            field,
            beacon_root,
            beacon_client,
            BeaconBlockId::Eip4788(child.timestamp),
        )
        .await?;

        Ok((commit, beacon_root))
    }

    /// Creates a beacon commitment that `field` is contained in the `ExecutionPayload` of the
    /// beacon block corresponding to `header` creating a [CommitmentVersion::Consensus] commitment.
    async fn create_slot_beacon_commit<P, H, const LEAF_INDEX: usize>(
        header: &Sealed<H>,
        field: PathElement,
        rpc_provider: P,
        beacon_client: &BeaconClient,
    ) -> anyhow::Result<(GeneralizedBeaconCommit<LEAF_INDEX>, B256)>
    where
        P: Provider<Ethereum>,
        H: EvmBlockHeader,
    {
        // query the beacon block corresponding to the given execution header
        let (beacon_root, beacon_header) = {
            // first, retrieve the corresponding full execution header
            let execution_header = rpc_provider
                .get_block_by_hash(header.seal())
                .await
                .context("eth_getBlockByHash failed")?
                .with_context(|| format!("block {} not found", header.seal()))?
                .header;
            let parent_root = execution_header
                .parent_beacon_block_root
                .context("parent_beacon_block_root missing in execution header")?;
            // then, retrieve the beacon header that contains the same parent root
            let response = beacon_client
                .get_header_for_parent_root(parent_root)
                .await
                .with_context(|| format!("failed to get header for parent root {}", parent_root))?;
            ensure!(
                response.header.message.parent_root.0 == parent_root.0,
                "API returned invalid beacon header"
            );
            (B256::from(response.root.0), response.header.message)
        };
        let commit = GeneralizedBeaconCommit::from_beacon_root(
            field,
            beacon_root,
            beacon_client,
            BeaconBlockId::Slot(beacon_header.slot),
        )
        .await?;

        Ok((commit, beacon_root))
    }

    /// Creates a beacon commitment that `field` is contained in the `ExecutionPayload` of the
    /// beacon block corresponding to `header`.
    pub(crate) async fn create_beacon_commit<P, H, const LEAF_INDEX: usize>(
        header: &Sealed<H>,
        field: PathElement,
        commitment_version: CommitmentVersion,
        rpc_provider: P,
        beacon_client: &BeaconClient,
    ) -> anyhow::Result<(GeneralizedBeaconCommit<LEAF_INDEX>, B256)>
    where
        P: Provider<Ethereum>,
        H: EvmBlockHeader,
    {
        match commitment_version {
            CommitmentVersion::Beacon => {
                create_eip4788_beacon_commit(header, field, rpc_provider, beacon_client).await
            }
            CommitmentVersion::Consensus => {
                create_slot_beacon_commit(header, field, rpc_provider, beacon_client).await
            }
            _ => bail!("invalid commitment version"),
        }
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

        const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
        const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

        #[tokio::test]
        #[ignore = "queries actual RPC nodes"]
        async fn create_eip4788_beacon_commit() {
            let el = ProviderBuilder::new().connect(EL_URL).await.unwrap();
            let cl = BeaconClient::new(CL_URL).unwrap();

            let block = el
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await
                .expect("eth_getBlockByNumber failed")
                .unwrap();

            let timestamp = block.header().timestamp;
            let parent_beacon_root = block.header().parent_beacon_block_root.unwrap();

            let block = el
                .get_block_by_hash(block.header().parent_hash)
                .await
                .expect("eth_getBlockByNumber failed")
                .unwrap();
            let header: Sealed<EthBlockHeader> = Sealed::new(block.header.try_into().unwrap());

            let (commit, _): (BeaconCommit, B256) =
                super::create_eip4788_beacon_commit(&header, "block_hash".into(), &el, &cl)
                    .await
                    .unwrap();

            // verify the commitment by querying the beacon client
            let (block_id, block_root) = dbg!(commit.into_commit(header.seal()));
            assert_eq!(block_id.as_id(), timestamp);
            assert_eq!(block_root, parent_beacon_root);
        }

        #[tokio::test]
        #[ignore = "queries actual RPC nodes"]
        async fn create_slot_beacon_commit() {
            let el = ProviderBuilder::new().connect(EL_URL).await.unwrap();
            let cl = BeaconClient::new(CL_URL).unwrap();

            let block = el
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await
                .expect("eth_getBlockByNumber failed")
                .unwrap();
            let header: Sealed<EthBlockHeader> = Sealed::new(block.header.try_into().unwrap());

            let (commit, _): (BeaconCommit, B256) =
                super::create_slot_beacon_commit(&header, "block_hash".into(), &el, &cl)
                    .await
                    .unwrap();

            // verify the commitment by querying the beacon client
            let (block_id, block_root) = dbg!(commit.into_commit(header.seal()));
            let beacon_block = cl.get_block(block_id.as_id()).await.unwrap();
            assert_eq!(
                block_root.to_string(),
                beacon_block.message().hash_tree_root().unwrap().to_string()
            );
        }
    }
}
