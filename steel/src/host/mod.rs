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

//! Functionality that is only needed for the host and not the guest.

use self::{
    db::ProofDb,
    provider::{EthersProvider, Provider},
};
use crate::{ethereum::EthEvmEnv, EvmBlockHeader, EvmEnv, EvmInput, MerkleTrie};
use alloy_primitives::{Sealable, B256};
use anyhow::{ensure, Context};
use ethers_providers::{Http, RetryClient};
use log::debug;
use revm::primitives::HashMap;

pub mod db;
pub mod provider;

/// Alias for readability, do not make public.
pub(crate) type HostEvmEnv<P, H> = EvmEnv<ProofDb<P>, H>;

/// The Ethers client type.
pub type EthersClient = ethers_providers::Provider<RetryClient<Http>>;

impl EthEvmEnv<ProofDb<EthersProvider<EthersClient>>> {
    /// Creates a new provable [EvmEnv] for Ethereum from an RPC endpoint.
    pub fn from_rpc(url: &str, block_number: Option<u64>) -> anyhow::Result<Self> {
        let client = EthersClient::new_client(url, 3, 500)?;
        let provider = EthersProvider::new(client);

        // get the latest block number if none is provided
        let block_number = match block_number {
            Some(n) => n,
            None => provider.get_block_number()?,
        };

        EvmEnv::from_provider(provider, block_number)
    }
}

impl<P: Provider> EvmEnv<ProofDb<P>, P::Header> {
    /// Creates a new provable [EvmEnv] from a [Provider].
    pub fn from_provider(provider: P, block_number: u64) -> anyhow::Result<Self> {
        let header = provider
            .get_block_header(block_number)?
            .with_context(|| format!("block {block_number} not found"))?;

        // create a new database backed by the provider
        let db = ProofDb::new(provider, block_number);

        Ok(EvmEnv::new(db, header.seal_slow()))
    }
}

impl<P: Provider> EvmEnv<ProofDb<P>, P::Header> {
    /// Converts the environment into a [EvmInput].
    ///
    /// The resulting input contains inclusion proofs for all the required chain state data. It can
    /// therefore be used to execute the same calls in a verifiable way in the zkVM.
    pub fn into_input(self) -> anyhow::Result<EvmInput<P::Header>> {
        let db = &self.db;

        // use the same provider as the database
        let provider = db.provider();

        // retrieve EIP-1186 proofs for all accounts
        let mut proofs = Vec::new();
        for (address, storage_keys) in db.accounts() {
            let proof = provider.get_proof(
                *address,
                storage_keys.iter().map(|v| B256::from(*v)).collect(),
                db.block_number(),
            )?;
            proofs.push(proof);
        }

        // build the sparse MPT for the state and verify against the header
        let state_nodes = proofs.iter().flat_map(|p| p.account_proof.iter());
        let state_trie =
            MerkleTrie::from_rlp_nodes(state_nodes).context("invalid account proof")?;
        ensure!(
            self.header.state_root() == &state_trie.hash_slow(),
            "root of the state trie does not match the header"
        );

        // build the sparse MPT for account storages and filter duplicates
        let mut storage_tries = HashMap::new();
        for proof in proofs {
            // skip non-existing accounts or accounts where no storage slots were requested
            if proof.storage_proof.is_empty() || proof.storage_hash.is_zero() {
                continue;
            }

            let storage_nodes = proof.storage_proof.iter().flat_map(|p| p.proof.iter());
            let storage_trie =
                MerkleTrie::from_rlp_nodes(storage_nodes).context("invalid storage proof")?;
            storage_tries.insert(storage_trie.hash_slow(), storage_trie);
        }
        let storage_tries: Vec<_> = storage_tries.into_values().collect();

        // collect the bytecode of all referenced contracts
        let contracts: Vec<_> = db.contracts().values().cloned().collect();

        // retrieve ancestor block headers
        let mut ancestors = Vec::new();
        if let Some(block_hash_min_number) = db.block_hash_numbers().iter().min() {
            let block_hash_min_number: u64 = block_hash_min_number.to();
            for number in (block_hash_min_number..db.block_number()).rev() {
                let header = provider
                    .get_block_header(number)?
                    .with_context(|| format!("block {number} not found"))?;
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
        debug!("blocks: {}", ancestors.len());

        let header = self.header.into_inner();
        Ok(EvmInput {
            header,
            state_trie,
            storage_tries,
            contracts,
            ancestors,
        })
    }
}
