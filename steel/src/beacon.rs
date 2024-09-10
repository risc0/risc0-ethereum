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
    /// Converts the input into a [EvmEnv] for a verifiable state access in the guest.
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
    };
    use alloy::{network::Ethereum, providers::Provider, transports::Transport};
    use alloy_primitives::Sealable;
    use anyhow::{bail, ensure, Context};
    use beacon_api_client::{mainnet::Client as BeaconClient, BeaconHeaderSummary, BlockId};
    use ethereum_consensus::{ssz::prelude::*, types::SignedBeaconBlock, Fork};
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
            let parent_beacon_block_root = env
                .header()
                .inner()
                .parent_beacon_block_root
                .context("parent_beacon_block_root missing in execution header")?;

            let input = BlockInput::from_env(env)
                .await
                .context("failed to derive block input")?;
            let client = BeaconClient::new(url);

            // first get the header of the parent and then the actual block header
            let parent_beacon_header = client
                .get_beacon_header(BlockId::Root(parent_beacon_block_root.0.into()))
                .await
                .with_context(|| {
                    format!("failed to get block header {}", parent_beacon_block_root)
                })?;
            let beacon_header = get_child_beacon_header(&client, parent_beacon_header)
                .await
                .with_context(|| {
                    format!("failed to get child of block {}", parent_beacon_block_root)
                })?;

            // get the entire block
            let signed_beacon_block = client
                .get_beacon_block(BlockId::Root(beacon_header.root))
                .await
                .with_context(|| format!("failed to get block {}", beacon_header.root))?;
            // create the inclusion proof of the execution block hash depending on the fork version
            let (proof, beacon_root) = match signed_beacon_block {
                SignedBeaconBlock::Deneb(signed_block) => {
                    prove_block_hash_inclusion(signed_block.message)?
                }
                _ => {
                    bail!(
                        "invalid version of block {}: expected {}; got {}",
                        beacon_header.root,
                        Fork::Deneb,
                        signed_beacon_block.version()
                    );
                }
            };

            // convert and verify the proof
            let proof: MerkleProof = proof
                .try_into()
                .context("proof derived from API is invalid")?;
            ensure!(
                proof.process(block_hash).0 == beacon_root.0,
                "proof derived from API does not verify",
            );

            Ok(BeaconInput { input, proof })
        }
    }

    /// Returns the inclusion proof of `block_hash` in the given `BeaconBlock`.
    fn prove_block_hash_inclusion<T: SimpleSerialize>(
        beacon_block: T,
    ) -> Result<ProofAndWitness, MerkleizationError> {
        // the `block_hash` is in the ExecutionPayload in the BeaconBlockBody in the BeaconBlock
        beacon_block.prove(&[
            "body".into(),
            "execution_payload".into(),
            "block_hash".into(),
        ])
    }

    /// Returns the header, with `parent_root` equal to `parent.root`.
    ///
    /// It iteratively tries to fetch headers of successive slots until success.
    /// TODO: use [BeaconClient::get_beacon_header_for_parent_root], once the nodes add support.
    async fn get_child_beacon_header(
        client: &BeaconClient,
        parent: BeaconHeaderSummary,
    ) -> anyhow::Result<BeaconHeaderSummary> {
        let parent_slot = parent.header.message.slot;
        let mut request_error = None;
        for slot in (parent_slot + 1)..=(parent_slot + 32) {
            match client.get_beacon_header(BlockId::Slot(slot)).await {
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
}

#[cfg(test)]
pub(crate) mod tests {
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
