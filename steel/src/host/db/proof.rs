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

use std::collections::{hash_map::Entry, HashMap, HashSet};

use super::AlloyDb;
use crate::MerkleTrie;
use alloy::{
    eips::eip2930::AccessList,
    network::Network,
    providers::Provider,
    rpc::types::{EIP1186AccountProofResponse, Header},
    transports::Transport,
};
use alloy_primitives::{Address, Bytes, StorageKey, StorageValue, B256, U256};
use anyhow::Context;
use revm::{
    primitives::{AccountInfo, Bytecode},
    Database,
};

#[derive(Clone)]
struct AccountProof {
    /// The hash of the storage of the account.
    storage_hash: B256,
    /// The account proof.
    account_proof: Vec<Bytes>,
    /// The storage proof.
    storage_proofs: HashMap<StorageKey, StorageProof>,
}

#[derive(Clone)]
struct StorageProof {
    /// Value that the key holds
    value: StorageValue,
    /// proof for the pair
    proof: Vec<Bytes>,
}

/// A simple revm [Database] wrapper that records all DB queries.
pub struct ProofDb<D> {
    accounts: HashMap<Address, HashSet<StorageKey>>,
    contracts: HashMap<B256, Bytes>,
    block_hash_numbers: HashSet<u64>,

    proofs: HashMap<Address, AccountProof>,

    inner: D,
}

impl<D: Database> ProofDb<D> {
    /// Creates a new ProofDb instance, with a [Database].
    pub fn new(db: D) -> Self {
        Self {
            accounts: HashMap::new(),
            contracts: HashMap::new(),
            block_hash_numbers: HashSet::new(),

            proofs: HashMap::new(),
            inner: db,
        }
    }

    /// Adds a new response for EIP-1186 account proof `eth_getProof`.
    ///
    /// The proof data will be used for lookups of the referenced storage keys.
    #[inline]
    pub fn add_proof(&mut self, proof: EIP1186AccountProofResponse) {
        add_proof(&mut self.proofs, proof)
    }

    /// Returns the referenced contracts
    pub fn contracts(&self) -> &HashMap<B256, Bytes> {
        return &self.contracts;
    }
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> ProofDb<AlloyDb<T, N, P>> {
    /// Max number of storage keys to request in a single `eth_getProof` call.
    pub const STORAGE_KEY_CHUNK_SIZE: usize = 1000;

    pub async fn add_access_list(&mut self, access_list: AccessList) -> anyhow::Result<()> {
        for item in access_list.0 {
            let proof = self
                .get_eip1186_proof(item.address, item.storage_keys)
                .await
                .with_context(|| format!("eth_getProof failed for {}", item.address))?;
            self.add_proof(proof);
        }

        Ok(())
    }

    /// Returns the proof (hash chain) of all `blockhash` calls recorded by the [Database].
    pub async fn ancestor_proof(&self) -> anyhow::Result<Vec<Header>> {
        let mut ancestors = Vec::new();
        if let Some(&block_hash_min_number) = self.block_hash_numbers.iter().min() {
            let provider = self.inner.provider();
            let block_number = self.inner.block_number();

            for number in (block_hash_min_number..block_number).rev() {
                let rpc_block = provider
                    .get_block_by_number(number.into(), false)
                    .await
                    .context("eth_getBlockByNumber failed")?
                    .with_context(|| format!("block {} not found", number))?;
                ancestors.push(rpc_block.header);
            }
        }

        Ok(ancestors)
    }

    /// Returns the proof (sparse [MerkleTrie]) of all account and storage queries recorded by the [Database].
    pub async fn state_proof(&self) -> anyhow::Result<(MerkleTrie, Vec<MerkleTrie>)> {
        let mut proofs = self.proofs.clone();

        for (address, storage_keys) in &self.accounts {
            match proofs.get(address) {
                None => {
                    let foo = self
                        .get_eip1186_proof(*address, storage_keys.iter().cloned().collect())
                        .await
                        .context("eth_getProof failed")?;
                    add_proof(&mut proofs, foo);
                }
                Some(proof) => {
                    let storage_proofs = &proof.storage_proofs;
                    let keys: Vec<_> = storage_keys
                        .iter()
                        .filter(|key| !storage_proofs.contains_key(*key))
                        .cloned()
                        .collect();
                    if !keys.is_empty() {
                        let foo = self
                            .get_eip1186_proof(*address, keys)
                            .await
                            .context("eth_getProof failed")?;
                        add_proof(&mut proofs, foo);
                    }
                }
            }
        }

        let state_nodes = self
            .accounts
            .iter()
            .flat_map(|(address, _)| proofs.get(address).unwrap().account_proof.iter());
        let state_trie = MerkleTrie::from_rlp_nodes(state_nodes).context("accountProof invalid")?;

        let mut storage_tries = HashMap::new();
        for (address, storage_keys) in &self.accounts {
            if storage_keys.is_empty() {
                continue;
            }

            let storage_proofs = &proofs.get(address).unwrap().storage_proofs;

            let storage_nodes = storage_keys
                .iter()
                .flat_map(|key| storage_proofs.get(key).unwrap().proof.iter());
            let storage_trie =
                MerkleTrie::from_rlp_nodes(storage_nodes).context("storageProof invalid")?;
            let storage_root_hash = storage_trie.hash_slow();

            storage_tries.insert(storage_root_hash, storage_trie);
        }
        let storage_tries = storage_tries.into_values().collect();

        Ok((state_trie, storage_tries))
    }

    async fn get_eip1186_proof(
        &self,
        address: Address,
        keys: Vec<StorageKey>,
    ) -> anyhow::Result<EIP1186AccountProofResponse> {
        let provider = self.inner.provider();
        let number = self.inner.block_number();

        let mut iter = keys.chunks(Self::STORAGE_KEY_CHUNK_SIZE);
        let mut account_proof = provider
            .get_proof(address, iter.next().unwrap_or_default().into())
            .number(number)
            .await?;
        while let Some(keys) = iter.next() {
            let proof = provider
                .get_proof(address, keys.into())
                .number(number)
                .await?;
            account_proof.storage_proof.extend(proof.storage_proof);
        }

        Ok(account_proof)
    }
}

impl<DB: Database> Database for ProofDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        log::trace!("BASIC: address={}", address);
        self.accounts.entry(address).or_default();

        self.inner.basic(address)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        log::trace!("CODE: hash={}", hash);
        let code = self.inner.code_by_hash(hash)?;
        self.contracts.insert(hash, code.original_bytes());

        Ok(code)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        log::trace!(
            "STORAGE: address={}, index={}",
            address,
            StorageKey::from(index)
        );
        self.accounts
            .entry(address)
            .or_default()
            .insert(StorageKey::from(index));

        match self
            .proofs
            .get(&address)
            .and_then(|account| account.storage_proofs.get(&StorageKey::from(index)))
        {
            Some(storage_proof) => Ok(storage_proof.value),
            None => self.inner.storage(address, index),
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        log::trace!("BLOCK: number={}", number);
        self.block_hash_numbers.insert(number);

        self.inner.block_hash(number)
    }
}

fn add_proof(proofs: &mut HashMap<Address, AccountProof>, proof: EIP1186AccountProofResponse) {
    match proofs.entry(proof.address) {
        Entry::Vacant(entry) => entry.insert(AccountProof {
            account_proof: proof.account_proof,
            storage_hash: proof.storage_hash,
            storage_proofs: proof
                .storage_proof
                .into_iter()
                .map(|proof| {
                    (
                        proof.key.0,
                        StorageProof {
                            value: proof.value,
                            proof: proof.proof,
                        },
                    )
                })
                .collect(),
        }),
        Entry::Occupied(mut entry) => {
            let account_proof = entry.get_mut();
            assert_eq!(account_proof.account_proof, proof.account_proof);
            assert_eq!(account_proof.storage_hash, proof.storage_hash);
            for storage_proof in proof.storage_proof {
                account_proof.storage_proofs.insert(
                    storage_proof.key.0,
                    StorageProof {
                        value: storage_proof.value,
                        proof: storage_proof.proof,
                    },
                );
            }

            account_proof
        }
    };
}
