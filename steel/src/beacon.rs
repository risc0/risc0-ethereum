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

use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EvmBlockHeader, EvmInput, GuestEvmEnv, SolCommitment};

#[cfg(feature = "host")]
pub mod provider {
    use super::{EvmBeaconInput, Proof};
    use crate::{ethereum::EthBlockHeader, EvmInput};

    use alloy_primitives::Sealable;
    use anyhow::Context;
    use beacon_api_client::{mainnet::Client, BeaconHeaderSummary, BlockId};
    use ethereum_consensus::ssz::prelude::*;
    use url::Url;

    impl EvmBeaconInput<EthBlockHeader> {
        pub async fn from_rpc(
            beacon_rpc_url: Url,
            input: EvmInput<EthBlockHeader>,
        ) -> anyhow::Result<EvmBeaconInput<EthBlockHeader>> {
            let client = Client::new(beacon_rpc_url);

            let block_hash = input.header.hash_slow();
            let parent_beacon_block_root = input
                .header
                .inner()
                .parent_beacon_block_root
                .context("parent_beacon_block_root missing")?;

            // first get the parent and then the actual block
            let resp = client
                .get_beacon_header(BlockId::Root(parent_beacon_block_root))
                .await
                .with_context(|| format!("failed to get header {}", parent_beacon_block_root))?;
            let parent_beacon_header = resp.header.message;
            let beacon_header = get_beacon_header_of_child(&client, parent_beacon_header.slot)
                .await
                .with_context(|| {
                    format!("failed to get child of block {}", parent_beacon_block_root)
                })?;

            let resp = client
                .get_beacon_block(BlockId::Root(beacon_header.root))
                .await
                .with_context(|| format!("failed to get block {}", beacon_header.root))?;
            let block = &resp.deneb().context("no Daneb block")?.message;

            // create the inclusion proof of the block hash
            let (proof, beacon_root) = block.prove(&[
                "body".into(),
                "execution_payload".into(),
                "block_hash".into(),
            ])?;
            debug_assert_eq!(proof.leaf, block_hash);
            debug_assert_eq!(beacon_root, block.hash_tree_root().unwrap());

            let proof = Proof {
                path: proof.branch,
                generalized_index: proof.index.try_into().context("proof index too large")?,
            };
            assert_eq!(
                proof.process(block_hash),
                beacon_root,
                "Proof verification failed"
            );

            Ok(EvmBeaconInput { proof, input })
        }
    }

    async fn get_beacon_header_of_child(
        client: &Client,
        slot: u64,
    ) -> anyhow::Result<BeaconHeaderSummary> {
        let mut request_error = None;
        for slot in (slot + 1)..=(slot + 12) {
            match client.get_beacon_header(BlockId::Slot(slot)).await {
                Err(err) => request_error = Some(err),
                Ok(header) => return Ok(header),
            }
        }
        Err(request_error.unwrap().into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EvmBeaconInput<H> {
    proof: Proof,
    input: EvmInput<H>,
}

impl<H: EvmBlockHeader> EvmBeaconInput<H> {
    pub fn into_env(self) -> GuestEvmEnv<H> {
        let mut env = self.input.into_env();

        let beacon_root = self.proof.process(env.header.seal());
        env.commitment = SolCommitment {
            blockNumber: U256::from(env.header().timestamp()),
            blockHash: beacon_root,
        };

        env
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub path: Vec<B256>,
    pub generalized_index: u32,
}

impl Proof {
    /// Returns the rebuilt hash obtained by traversing a Merkle tree up from `leaf` using `path`.
    #[inline]
    pub fn process(&self, leaf: B256) -> B256 {
        let depth = self.generalized_index.ilog2();
        let mut index = self.generalized_index - (1 << depth);

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn process_simple_proof() {
        let leaf = b256!("94159da973dfa9e40ed02535ee57023ba2d06bad1017e451055470967eb71cd5");
        let proof = Proof {
            path: vec![
                b256!("8f594dbb4f4219ad4967f86b9cccdb26e37e44995a291582a431eef36ecba45c"),
                b256!("f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c"),
                b256!("382ba9638ce263e802593b387538faefbaed106e9f51ce793d405f161b105ee6"),
            ],
            generalized_index: 2u32.pow(3) + 2,
        };
        assert_eq!(
            proof.process(leaf),
            b256!("27097c728aade54ff1376d5954681f6d45c282a81596ef19183148441b754abb")
        );
    }
}
