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
use std::fmt::Display;

use crate::{
    ethereum::EthEvmEnv, state::StateAccount, EvmBlockHeader, EvmEnv, EvmInput, MerkleTrie,
};
use alloy::{
    network::{Ethereum, Network},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Header as RpcHeader,
    transports::{
        http::{Client, Http},
        Transport,
    },
};
use alloy_primitives::{keccak256, StorageKey};
use anyhow::{anyhow, ensure, Context};
use db::{AlloyDb, TraceDb};
use log::debug;
use revm::primitives::HashMap;
use url::Url;

pub mod db;

/// A block number (or tag - "latest", "earliest", "pending").
pub type BlockNumberOrTag = alloy::rpc::types::BlockNumberOrTag;

/// Alias for readability, do not make public.
pub(crate) type HostEvmEnv<D, H> = EvmEnv<TraceDb<D>, H>;

impl EthEvmEnv<TraceDb<AlloyDb<Http<Client>, Ethereum, RootProvider<Http<Client>>>>> {
    /// Creates a new provable [EvmEnv] for Ethereum from an HTTP RPC endpoint.
    pub async fn from_rpc(url: Url, number: BlockNumberOrTag) -> anyhow::Result<Self> {
        let provider = ProviderBuilder::new().on_http(url);
        EvmEnv::from_provider(provider, number).await
    }
}

impl<T, N, P, H> EvmEnv<TraceDb<AlloyDb<T, N, P>>, H>
where
    T: Transport + Clone,
    N: Network,
    P: Provider<T, N>,
    H: EvmBlockHeader + TryFrom<RpcHeader>,
    <H as TryFrom<RpcHeader>>::Error: Display,
{
    /// Creates a new provable [EvmEnv] from an alloy [Provider].
    pub async fn from_provider(provider: P, number: BlockNumberOrTag) -> anyhow::Result<Self> {
        let rpc_block = provider
            .get_block_by_number(number, false)
            .await
            .context("eth_getBlockByNumber failed")?
            .with_context(|| format!("block {} not found", number))?;
        let header: H = try_into_header(rpc_block.header)?;
        log::info!("Environment initialized for block {}", header.number());

        let db = TraceDb::new(AlloyDb::new(provider, header.number()));

        Ok(EvmEnv::new(db, header.seal_slow()))
    }
}

impl<T, N, P, H> EvmEnv<TraceDb<AlloyDb<T, N, P>>, H>
where
    T: Transport + Clone,
    N: Network,
    P: Provider<T, N>,
    H: EvmBlockHeader + TryFrom<RpcHeader>,
    <H as TryFrom<RpcHeader>>::Error: Display,
{
    /// Converts the environment into a [EvmInput].
    ///
    /// The resulting input contains inclusion proofs for all the required chain state data. It can
    /// therefore be used to execute the same calls in a verifiable way in the zkVM.
    pub async fn into_input(self) -> anyhow::Result<EvmInput<H>> {
        let db = &self.db.unwrap();

        // use the same provider as the database
        let provider = db.inner().provider();
        let block_number = db.inner().block_number();

        // retrieve EIP-1186 proofs for all accounts
        let mut proofs = Vec::new();
        for (address, storage_keys) in db.accounts() {
            let proof = provider
                .get_proof(
                    *address,
                    storage_keys.iter().map(|v| StorageKey::from(*v)).collect(),
                )
                .number(block_number)
                .await
                .context("eth_getProof failed")?;
            proofs.push(proof);
        }

        // build the sparse MPT for the state and verify it against the header
        let state_nodes = proofs.iter().flat_map(|p| p.account_proof.iter());
        let state_trie = MerkleTrie::from_rlp_nodes(state_nodes).context("accountProof invalid")?;
        ensure!(
            self.header.state_root() == &state_trie.hash_slow(),
            "accountProof root does not match header's stateRoot"
        );

        // build the sparse MPT for account storages and filter duplicates
        let mut storage_tries = HashMap::new();
        for proof in proofs {
            // skip non-existing accounts or accounts where no storage slots were requested
            if proof.storage_proof.is_empty() || proof.storage_hash.is_zero() {
                continue;
            }

            // build the sparse MPT for that account's storage by iterating over all storage proofs
            let storage_nodes = proof.storage_proof.iter().flat_map(|p| p.proof.iter());
            let storage_trie =
                MerkleTrie::from_rlp_nodes(storage_nodes).context("storageProof invalid")?;
            let storage_root_hash = storage_trie.hash_slow();
            // verify it against the state trie
            let account: StateAccount = state_trie
                .get_rlp(keccak256(proof.address))
                .with_context(|| format!("invalid RLP value in state trie for {}", proof.address))?
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
        if let Some(block_hash_min_number) = db.block_hash_numbers().iter().min() {
            let block_hash_min_number: u64 = block_hash_min_number.to();
            for number in (block_hash_min_number..block_number).rev() {
                let rpc_block = provider
                    .get_block_by_number(number.into(), false)
                    .await
                    .context("eth_getBlockByNumber failed")?
                    .with_context(|| format!("block {} not found", number))?;
                let header: H = try_into_header(rpc_block.header)?;
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

        let input = EvmInput {
            header: self.header.into_inner(),
            state_trie,
            storage_tries,
            contracts,
            ancestors,
        };

        Ok(input)
    }
}

fn try_into_header<H: EvmBlockHeader + TryFrom<RpcHeader>>(
    rpc_header: RpcHeader,
) -> anyhow::Result<H>
where
    <H as TryFrom<RpcHeader>>::Error: Display,
{
    rpc_header
        .try_into()
        .map_err(|err| anyhow!("header invalid: {}", err))
}
