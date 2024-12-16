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
    config::ChainSpec, state::StateDb, Commitment, CommitmentVersion, EvmBlockHeader, EvmEnv,
    GuestEvmEnv, MerkleTrie,
};
use ::serde::{Deserialize, Serialize};
use alloy_primitives::{map::HashMap, Bytes};

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
    /// Converts the input into a [EvmEnv] for verifiable state access in the guest.
    pub fn into_env(self) -> GuestEvmEnv<H> {
        // verify that the state root matches the state trie
        let state_root = self.state_trie.hash_slow();
        assert_eq!(self.header.state_root(), &state_root, "State root mismatch");

        // seal the header to compute its block hash
        let header = self.header.seal_slow();

        // validate that ancestor headers form a valid chain
        let mut block_hashes =
            HashMap::with_capacity_and_hasher(self.ancestors.len() + 1, Default::default());
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

        let db = StateDb::new(
            self.state_trie,
            self.storage_tries,
            self.contracts,
            block_hashes,
        );
        let commit = Commitment::new(
            CommitmentVersion::Block as u16,
            header.number(),
            header.seal(),
            ChainSpec::DEFAULT_DIGEST,
        );

        EvmEnv::new(db, header, commit)
    }
}

#[cfg(feature = "host")]
pub mod host {
    use std::fmt::Display;

    use super::BlockInput;
    use crate::{
        host::db::{AlloyDb, ProofDb, ProviderDb},
        EvmBlockHeader,
    };
    use alloy::{network::Network, providers::Provider, transports::Transport};
    use alloy_primitives::Sealed;
    use anyhow::{anyhow, ensure};
    use log::debug;

    impl<H: EvmBlockHeader> BlockInput<H> {
        /// Creates the `BlockInput` containing the necessary EVM state that can be verified against
        /// the block hash.
        pub(crate) async fn from_proof_db<T, N, P>(
            mut db: ProofDb<AlloyDb<T, N, P>>,
            header: Sealed<H>,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            N: Network,
            P: Provider<T, N>,
            H: EvmBlockHeader + TryFrom<<N as Network>::HeaderResponse>,
            <H as TryFrom<<N as Network>::HeaderResponse>>::Error: Display,
        {
            assert_eq!(db.inner().block_hash(), header.seal(), "DB block mismatch");

            let (state_trie, storage_tries) = db.state_proof().await?;
            ensure!(
                header.state_root() == &state_trie.hash_slow(),
                "accountProof root does not match header's stateRoot"
            );

            // collect the bytecode of all referenced contracts
            let contracts: Vec<_> = db.contracts().values().cloned().collect();

            // retrieve ancestor block headers
            let mut ancestors = Vec::new();
            for rlp_header in db.ancestor_proof(header.number()).await? {
                let header: H = rlp_header
                    .try_into()
                    .map_err(|err| anyhow!("header invalid: {}", err))?;
                ancestors.push(header);
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
                header: header.into_inner(),
                state_trie,
                storage_tries,
                contracts,
                ancestors,
            };

            Ok(input)
        }
    }
}
