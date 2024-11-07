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

use super::{provider::ProviderDb, AlloyDb};
use crate::MerkleTrie;
use alloy::{
    eips::eip2930::{AccessList, AccessListItem},
    network::{primitives::BlockTransactionsKind, BlockResponse, Network},
    providers::Provider,
    rpc::types::EIP1186AccountProofResponse,
    transports::Transport,
};
use alloy_primitives::{
    map::{hash_map, AddressHashMap, B256HashMap, B256HashSet, HashSet},
    Address, BlockNumber, Bytes, StorageKey, StorageValue, B256, U256,
};
use anyhow::{ensure, Context, Result};
use revm::{
    primitives::{AccountInfo, Bytecode},
    Database,
};

/// A simple revm [Database] wrapper that records all DB queries.
pub struct ProofDb<D> {
    accounts: AddressHashMap<B256HashSet>,
    contracts: B256HashMap<Bytes>,
    block_hash_numbers: HashSet<BlockNumber>,
    proofs: AddressHashMap<AccountProof>,
    inner: D,
}

struct AccountProof {
    /// The inclusion proof for this account.
    account_proof: Vec<Bytes>,
    /// The MPT inclusion proofs for several storage slots.
    storage_proofs: B256HashMap<StorageProof>,
}

struct StorageProof {
    /// The value that this key holds.
    value: StorageValue,
    /// In MPT inclusion proof for this particular slot.
    proof: Vec<Bytes>,
}

impl<D: Database> ProofDb<D> {
    /// Creates a new ProofDb instance, with a [Database].
    pub fn new(db: D) -> Self {
        Self {
            accounts: Default::default(),
            contracts: Default::default(),
            block_hash_numbers: Default::default(),
            proofs: Default::default(),
            inner: db,
        }
    }

    /// Adds a new response for EIP-1186 account proof `eth_getProof`.
    ///
    /// The proof data will be used for lookups of the referenced storage keys.
    pub fn add_proof(&mut self, proof: EIP1186AccountProofResponse) -> Result<()> {
        add_proof(&mut self.proofs, proof)
    }

    /// Returns the referenced contracts
    pub fn contracts(&self) -> &B256HashMap<Bytes> {
        &self.contracts
    }

    /// Returns the underlying [Database].
    pub fn inner(&self) -> &D {
        &self.inner
    }
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> ProofDb<AlloyDb<T, N, P>> {
    /// Fetches all the EIP-1186 storage proofs from the `access_list` and stores them in the DB.
    pub async fn add_access_list(&mut self, access_list: AccessList) -> Result<()> {
        for AccessListItem {
            address,
            storage_keys,
        } in access_list.0
        {
            let storage_keys: Vec<_> = storage_keys
                .into_iter()
                .filter(filter_existing_keys(self.proofs.get(&address)))
                .collect();

            if !storage_keys.is_empty() {
                log::trace!("PROOF: address={}, #keys={}", address, storage_keys.len());
                let proof = self
                    .inner
                    .get_eip1186_proof(address, storage_keys)
                    .await
                    .context("eth_getProof failed")?;
                self.add_proof(proof)
                    .context("invalid eth_getProof response")?;
            }
        }

        Ok(())
    }

    /// Returns the proof (hash chain) of all `blockhash` calls recorded by the [Database].
    pub async fn ancestor_proof(
        &self,
        block_number: BlockNumber,
    ) -> Result<Vec<<N as Network>::HeaderResponse>> {
        let mut ancestors = Vec::new();
        if let Some(&block_hash_min_number) = self.block_hash_numbers.iter().min() {
            assert!(block_hash_min_number <= block_number);

            let provider = self.inner.provider();
            for number in (block_hash_min_number..block_number).rev() {
                let rpc_block = provider
                    .get_block_by_number(number.into(), BlockTransactionsKind::Hashes)
                    .await
                    .context("eth_getBlockByNumber failed")?
                    .with_context(|| format!("block {} not found", number))?;
                ancestors.push(rpc_block.header().clone());
            }
        }

        Ok(ancestors)
    }

    /// Returns the merkle proofs (sparse [MerkleTrie]) for the state and all storage queries
    /// recorded by the [Database].
    pub async fn state_proof(&mut self) -> Result<(MerkleTrie, Vec<MerkleTrie>)> {
        ensure!(
            !self.accounts.is_empty(),
            "no accounts accessed: use Contract::preflight"
        );

        let proofs = &mut self.proofs;
        for (address, storage_keys) in &self.accounts {
            let account_proof = proofs.get(address);
            let storage_keys: Vec<_> = storage_keys
                .iter()
                .cloned()
                .filter(filter_existing_keys(account_proof))
                .collect();

            if account_proof.is_none() || !storage_keys.is_empty() {
                log::trace!("PROOF: address={}, #keys={}", address, storage_keys.len());
                let proof = self
                    .inner
                    .get_eip1186_proof(*address, storage_keys)
                    .await
                    .context("eth_getProof failed")?;
                ensure!(
                    &proof.address == address,
                    "eth_getProof response does not match request"
                );
                add_proof(proofs, proof).context("invalid eth_getProof response")?;
            }
        }

        let state_nodes = self
            .accounts
            .keys()
            .filter_map(|address| proofs.get(address))
            .flat_map(|proof| proof.account_proof.iter());
        let state_trie = MerkleTrie::from_rlp_nodes(state_nodes).context("accountProof invalid")?;

        let mut storage_tries = B256HashMap::default();
        for (address, storage_keys) in &self.accounts {
            // if no storage keys have been accessed, we don't need to prove anything
            if storage_keys.is_empty() {
                continue;
            }

            // safe unwrap: added a proof for each account in the previous loop
            let storage_proofs = &proofs.get(address).unwrap().storage_proofs;

            let storage_nodes = storage_keys
                .iter()
                .filter_map(|key| storage_proofs.get(key))
                .flat_map(|proof| proof.proof.iter());
            let storage_trie =
                MerkleTrie::from_rlp_nodes(storage_nodes).context("storageProof invalid")?;
            let storage_root_hash = storage_trie.hash_slow();

            storage_tries.insert(storage_root_hash, storage_trie);
        }
        let storage_tries = storage_tries.into_values().collect();

        Ok((state_trie, storage_tries))
    }
}

impl<DB: Database> Database for ProofDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        log::trace!("BASIC: address={}", address);
        self.accounts.entry(address).or_default();

        // eth_getProof also returns an account object. However, since the returned data is not
        // always consistent, it is just simpler to forward the query to the underlying DB.
        // See https://github.com/ethereum/go-ethereum/issues/28441
        self.inner.basic(address)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        log::trace!("CODE: hash={}", hash);
        let code = self.inner.code_by_hash(hash)?;
        self.contracts.insert(hash, code.original_bytes());

        Ok(code)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let key = StorageKey::from(index);
        self.accounts.entry(address).or_default().insert(key);

        // try to get the storage value from the loaded proofs before querying the underlying DB
        match self
            .proofs
            .get(&address)
            .and_then(|account| account.storage_proofs.get(&key))
        {
            Some(storage_proof) => Ok(storage_proof.value),
            None => {
                log::trace!("STORAGE: address={}, index={}", address, key);
                self.inner.storage(address, index)
            }
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        log::trace!("BLOCK: number={}", number);
        self.block_hash_numbers.insert(number);

        self.inner.block_hash(number)
    }
}

fn filter_existing_keys(account_proof: Option<&AccountProof>) -> impl Fn(&StorageKey) -> bool + '_ {
    move |key| {
        !account_proof
            .map(|p| p.storage_proofs.contains_key(key))
            .unwrap_or_default()
    }
}

fn add_proof(
    proofs: &mut AddressHashMap<AccountProof>,
    proof_response: EIP1186AccountProofResponse,
) -> Result<()> {
    // convert the response into a StorageProof
    let storage_proofs = proof_response
        .storage_proof
        .into_iter()
        .map(|proof| {
            (
                proof.key.as_b256(),
                StorageProof {
                    value: proof.value,
                    proof: proof.proof,
                },
            )
        })
        .collect();

    match proofs.entry(proof_response.address) {
        hash_map::Entry::Occupied(mut entry) => {
            let account_proof = entry.get_mut();
            ensure!(
                account_proof.account_proof == proof_response.account_proof,
                "account_proof does not match"
            );
            account_proof.storage_proofs.extend(storage_proofs);
        }
        hash_map::Entry::Vacant(entry) => {
            entry.insert(AccountProof {
                account_proof: proof_response.account_proof,
                storage_proofs,
            });
        }
    }

    Ok(())
}
