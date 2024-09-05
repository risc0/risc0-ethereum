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

use crate::{state::StateDb, EvmBlockHeader, EvmEnv, GuestEvmEnv, MerkleTrie};
use ::serde::{Deserialize, Serialize};
use alloy_primitives::Bytes;
use revm::primitives::HashMap;

/// Input committing to the corresponding execution block hash.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockInput<H> {
    header: H,
    state_trie: MerkleTrie,
    storage_tries: Vec<MerkleTrie>,
    contracts: Vec<Bytes>,
    ancestors: Vec<H>,
}

impl<H: EvmBlockHeader> BlockInput<H> {
    /// Converts the input into a [EvmEnv] for a verifiable state access in the guest.
    pub fn into_env(self) -> GuestEvmEnv<H> {
        // verify that the state root matches the state trie
        let state_root = self.state_trie.hash_slow();
        assert_eq!(self.header.state_root(), &state_root, "State root mismatch");

        // seal the header to compute its block hash
        let header = self.header.seal_slow();

        // validate that ancestor headers form a valid chain
        let mut block_hashes = HashMap::with_capacity(self.ancestors.len() + 1);
        block_hashes.insert(header.number(), header.seal());

        let mut previous_header = header.inner();
        for ancestor in &self.ancestors {
            let ancestor_hash = ancestor.hash_slow();
            assert_eq!(
                previous_header.parent_hash(),
                &ancestor_hash,
                "Invalid ancestor chain: block {} is not the parent of block {}",
                ancestor.number(),
                previous_header.number()
            );
            block_hashes.insert(ancestor.number(), ancestor_hash);
            previous_header = ancestor;
        }

        // TODO(victor): When do we check that the storage tries are ok?
        let db = StateDb::new(
            self.state_trie,
            self.storage_tries,
            self.contracts,
            block_hashes,
        );

        EvmEnv::new(db, header)
    }
}

#[cfg(feature = "host")]
pub mod host {
    use std::fmt::Display;

    use super::BlockInput;
    use crate::{
        host::{db::AlloyDb, HostEvmEnv},
        state::StateAccount,
        EvmBlockHeader, MerkleTrie,
    };
    use alloy::{
        network::Network, providers::Provider, rpc::types::Header as RpcHeader,
        transports::Transport,
    };
    use alloy_primitives::{keccak256, StorageKey};
    use anyhow::{anyhow, ensure, Context};
    use log::debug;
    use revm::primitives::HashMap;

    impl<H: EvmBlockHeader> BlockInput<H> {
        /// Derives the verifiable input from a [HostEvmEnv].
        pub(crate) async fn from_env<T, N, P>(
            env: HostEvmEnv<AlloyDb<T, N, P>, H>,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            N: Network,
            P: Provider<T, N>,
            H: EvmBlockHeader + TryFrom<RpcHeader>,
            <H as TryFrom<RpcHeader>>::Error: Display,
        {
            let db = &env.db.unwrap();

            // use the same provider as the database
            let provider = db.inner().provider();
            let block_hash = db.inner().block_hash();
            assert_eq!(block_hash, env.header.seal(), "DB block mismatch");

            // retrieve EIP-1186 proofs for all accounts
            let mut proofs = Vec::new();
            for (address, storage_keys) in db.accounts() {
                let proof = provider
                    .get_proof(
                        *address,
                        storage_keys.iter().map(|v| StorageKey::from(*v)).collect(),
                    )
                    .hash(block_hash)
                    .await
                    .context("eth_getProof failed")?;
                proofs.push(proof);
            }

            // build the sparse MPT for the state and verify it against the header
            let state_nodes = proofs.iter().flat_map(|p| p.account_proof.iter());
            let state_trie =
                MerkleTrie::from_rlp_nodes(state_nodes).context("accountProof invalid")?;
            ensure!(
                env.header.state_root() == &state_trie.hash_slow(),
                "accountProof root does not match header's stateRoot"
            );

            // build the sparse MPT for account storages and filter duplicates
            let mut storage_tries = HashMap::new();
            for proof in proofs {
                // skip non-existing accounts or accounts where no storage slots were requested
                if proof.storage_proof.is_empty() || proof.storage_hash.is_zero() {
                    continue;
                }

                // build the sparse MPT for that account's storage by iterating over all storage
                // proofs
                let storage_nodes = proof.storage_proof.iter().flat_map(|p| p.proof.iter());
                let storage_trie =
                    MerkleTrie::from_rlp_nodes(storage_nodes).context("storageProof invalid")?;
                let storage_root_hash = storage_trie.hash_slow();
                // verify it against the state trie
                let account: StateAccount = state_trie
                    .get_rlp(keccak256(proof.address))
                    .with_context(|| {
                        format!("invalid RLP value in state trie for {}", proof.address)
                    })?
                    .unwrap_or_default();
                ensure!(
                    account.storage_root == storage_root_hash,
                    "storageProof of {} does not match storageRoot in the state",
                    proof.address
                );

                storage_tries.insert(storage_root_hash, storage_trie);
            }
            let storage_tries: Vec<_> = storage_tries.into_values().collect();

            // collect the bytecode of all referenced contracts
            let contracts: Vec<_> = db.contracts().values().cloned().collect();

            // retrieve ancestor block headers
            let mut ancestors = Vec::new();
            if let Some(&block_hash_min_number) = db.block_hash_numbers().iter().min() {
                let block_number = env.header.number();
                for number in (block_hash_min_number..block_number).rev() {
                    let rpc_block = provider
                        .get_block_by_number(number.into(), false)
                        .await
                        .context("eth_getBlockByNumber failed")?
                        .with_context(|| format!("block {} not found", number))?;
                    let header: H = rpc_block
                        .header
                        .try_into()
                        .map_err(|err| anyhow!("header invalid: {}", err))?;
                    ancestors.push(header);
                }
            }

            debug!("state size: {}", state_trie.size());
            debug!("storage tries: {}", storage_tries.len());
            debug!(
                "total storage size: {}",
                storage_tries.iter().map(|t| t.size()).sum::<usize>()
            );
            debug!("contracts: {}", contracts.len());
            debug!("ancestor blocks: {}", ancestors.len());

            let input = BlockInput {
                header: env.header.into_inner(),
                state_trie,
                storage_tries,
                contracts,
                ancestors,
            };

            Ok(input)
        }
    }
}
