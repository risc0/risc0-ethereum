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

use super::*;
use crate::{ethereum::EthBlockHeader, EvmBlockHeader};
use alloy::{network::Ethereum, providers::Provider};
use alloy_primitives::B256;
use anyhow::{bail, ensure, Context};
use client::BeaconClient;
use consensus::{
    mainnet::SignedBeaconBlock,
    ssz::prelude::{proofs::Proof, *},
    Fork,
};
use proofs::ProofAndWitness;
use url::Url;

pub(crate) mod client;
mod consensus;

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
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_) => {
            bail!(
                "invalid version of block {}: expected >= {}; got {}",
                beacon_root,
                Fork::Deneb,
                signed_beacon_block.version()
            );
        }
        SignedBeaconBlock::Deneb(signed_block) => {
            prove_execution_payload_field(signed_block.message, field)?
        }
        SignedBeaconBlock::Electra(signed_block) => {
            prove_execution_payload_field(signed_block.message, field)?
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
    use crate::test_utils::{get_cl_url, get_el_url};
    use alloy::{eips::BlockNumberOrTag, network::BlockResponse, providers::ProviderBuilder};

    #[tokio::test]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn create_eip4788_beacon_commit() {
        let el = ProviderBuilder::new().connect_http(get_el_url());
        let cl = BeaconClient::new(get_cl_url()).unwrap();

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
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn create_slot_beacon_commit() {
        let el = ProviderBuilder::new().connect_http(get_el_url());
        let cl = BeaconClient::new(get_cl_url()).unwrap();

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
        assert_eq!(block_root, beacon_block.root().unwrap());
    }
}
