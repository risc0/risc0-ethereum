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

use crate::{event, host::db::ProviderDb, mpt::EMPTY_ROOT_HASH, MerkleTrie, StateAccount};
use alloy::{
    consensus::BlockHeader,
    eips::eip2930::{AccessList, AccessListItem},
    network::{BlockResponse, Network},
    providers::Provider,
    rpc::types::EIP1186AccountProofResponse,
};
use alloy_consensus::ReceiptEnvelope;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    map::{hash_map, AddressHashMap, B256HashMap, B256HashSet, Entry, HashMap, HashSet},
    Address, BlockNumber, Bytes, Log, StorageKey, StorageValue, B256, U256,
};
use alloy_rpc_types::{Filter, TransactionReceipt};
use anyhow::{ensure, Context, Result};
use revm::{
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
    Database as RevmDatabase,
};
use std::{
    fmt::Debug,
    hash::{BuildHasher, Hash},
};

/// A simple revm [RevmDatabase] wrapper that records all DB queries.
pub struct ProofDb<D> {
    accounts: AddressHashMap<B256HashSet>,
    contracts: B256HashMap<Bytes>,
    block_hash_numbers: HashSet<BlockNumber>,
    log_filters: Vec<Filter>,
    proofs: AddressHashMap<AccountProof>,
    inner: D,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountProof {
    /// The account information as stored in the account trie.
    account: StateAccount,
    /// The inclusion proof for this account.
    account_proof: Vec<Bytes>,
    /// The MPT inclusion proofs for several storage slots.
    storage_proofs: B256HashMap<StorageProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StorageProof {
    /// The value that this key holds.
    value: StorageValue,
    /// In MPT inclusion proof for this particular slot.
    proof: Vec<Bytes>,
}

impl<D> ProofDb<D> {
    /// Creates a new ProofDb instance, with a [RevmDatabase].
    pub(crate) fn new(db: D) -> Self
    where
        D: RevmDatabase,
    {
        Self {
            accounts: Default::default(),
            contracts: Default::default(),
            block_hash_numbers: Default::default(),
            log_filters: Default::default(),
            proofs: Default::default(),
            inner: db,
        }
    }

    /// Adds a new response for EIP-1186 account proof `eth_getProof`.
    ///
    /// The proof data will be used for lookups of the referenced storage keys.
    pub(crate) fn add_proof(&mut self, proof: EIP1186AccountProofResponse) -> Result<()> {
        add_proof(&mut self.proofs, proof)
    }

    /// Returns the referenced contracts
    pub(crate) fn contracts(&self) -> &B256HashMap<Bytes> {
        &self.contracts
    }

    /// Returns the underlying [RevmDatabase].
    pub(crate) fn inner(&self) -> &D {
        &self.inner
    }

    /// Merges this `ProofDb` with another, consuming both and returning a new one.
    ///
    /// It Panics if inconsistent data is found between `self` and `other`.
    #[must_use = "merge consumes self and returns a new ProofDb"]
    pub(crate) fn merge(self, other: Self) -> Self {
        let accounts = merge_checked_maps(self.accounts, other.accounts);
        let contracts = merge_checked_maps(self.contracts, other.contracts);
        let proofs = merge_checked_maps(self.proofs, other.proofs);
        // HashSet::extend naturally handles duplicates
        let mut block_hash_numbers = self.block_hash_numbers;
        block_hash_numbers.extend(other.block_hash_numbers);
        // use a HashSet to remove duplicates, the order does not matter for filters
        let log_filters = self
            .log_filters
            .into_iter()
            .chain(other.log_filters)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // construct the new ProofDb using the struct literal for compile-time safety
        ProofDb {
            accounts,
            contracts,
            block_hash_numbers,
            log_filters,
            proofs,
            inner: self.inner,
        }
    }
}

impl<N: Network, P: Provider<N>> ProofDb<ProviderDb<N, P>> {
    /// Fetches all the EIP-1186 storage proofs from the `access_list` and stores them in the DB.
    pub(crate) async fn add_access_list(&mut self, access_list: AccessList) -> Result<()> {
        for AccessListItem {
            address,
            storage_keys,
        } in access_list.0
        {
            let storage_keys: Vec<_> = storage_keys
                .into_iter()
                .filter(filter_existing_keys(self.proofs.get(&address)))
                .collect();

            let proof = self.get_proof(address, storage_keys).await?;
            self.add_proof(proof)
                .context("invalid eth_getProof response")?;
        }

        Ok(())
    }

    /// Returns the StateAccount information for the given address.
    pub(crate) async fn state_account(&mut self, address: Address) -> Result<StateAccount> {
        log::trace!("ACCOUNT: address={}", address);
        self.accounts.entry(address).or_default();

        if !self.proofs.contains_key(&address) {
            let proof = self.get_proof(address, vec![]).await?;
            self.add_proof(proof)
                .context("invalid eth_getProof response")?;
        }
        let proof = self.proofs.get(&address).unwrap();

        Ok(proof.account)
    }

    /// Returns the proof (hash chain) of all `blockhash` calls recorded by the [RevmDatabase].
    pub(crate) async fn ancestor_proof(
        &self,
        block_number: BlockNumber,
    ) -> Result<Vec<<N as Network>::HeaderResponse>> {
        let mut ancestors = Vec::new();
        if let Some(&block_hash_min_number) = self.block_hash_numbers.iter().min() {
            assert!(block_hash_min_number <= block_number);

            let provider = self.inner.provider();
            for number in (block_hash_min_number..block_number).rev() {
                let rpc_block = provider
                    .get_block_by_number(number.into())
                    .await
                    .context("eth_getBlockByNumber failed")?
                    .with_context(|| format!("block {} not found", number))?;
                ancestors.push(rpc_block.header().clone());
            }
        }

        Ok(ancestors)
    }

    /// Returns the merkle proofs (sparse [MerkleTrie]) for the state and all storage queries
    /// recorded by the [RevmDatabase].
    pub(crate) async fn state_proof(&mut self) -> Result<(MerkleTrie, Vec<MerkleTrie>)> {
        ensure!(
            !self.accounts.is_empty()
                || !self.block_hash_numbers.is_empty()
                || !self.log_filters.is_empty(),
            "no accounts accessed: use Contract::preflight"
        );

        // if no accounts were accessed, use the state root of the corresponding block as is
        if self.accounts.is_empty() {
            let hash = self.inner.block();
            let block = self
                .inner
                .provider()
                .get_block_by_hash(hash)
                .await
                .context("eth_getBlockByHash failed")?
                .with_context(|| format!("block {} not found", hash))?;

            return Ok((
                MerkleTrie::from_digest(block.header().state_root()),
                Vec::default(),
            ));
        }

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
                    .get_proof(*address, storage_keys)
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

        let mut storage_tries: B256HashMap<MerkleTrie> = B256HashMap::default();
        for (address, storage_keys) in &self.accounts {
            // if no storage keys have been accessed, we don't need to prove anything
            if storage_keys.is_empty() {
                continue;
            }

            // safe unwrap: added a proof for each account in the previous loop
            let proof = proofs.get(address).unwrap();

            let storage_nodes = storage_keys
                .iter()
                .filter_map(|key| proof.storage_proofs.get(key))
                .flat_map(|proof| proof.proof.iter());
            let storage_root = proof.account.storage_root;

            match storage_tries.entry(storage_root) {
                Entry::Occupied(mut entry) => {
                    // add nodes to existing trie for this root
                    entry
                        .get_mut()
                        .hydrate_from_rlp_nodes(storage_nodes)
                        .with_context(|| {
                            format!("invalid storage proof for address {}", address)
                        })?;
                    ensure!(
                        entry.get().hash_slow() == storage_root,
                        "storage root mismatch"
                    );
                }
                Entry::Vacant(entry) => {
                    // create a new trie for this root
                    let storage_trie =
                        MerkleTrie::from_rlp_nodes(storage_nodes).with_context(|| {
                            format!("invalid storage proof for address {}", address)
                        })?;
                    ensure!(
                        storage_trie.hash_slow() == storage_root,
                        "storage root mismatch"
                    );
                    entry.insert(storage_trie);
                }
            }
        }
        let storage_tries = storage_tries.into_values().collect();

        Ok((state_trie, storage_tries))
    }

    pub async fn receipt_proof(&self) -> Result<Option<Vec<ReceiptEnvelope>>> {
        if self.log_filters.is_empty() {
            return Ok(None);
        }

        let provider = self.inner.provider();
        let block_hash = self.inner.block();

        let block = provider
            .get_block_by_hash(block_hash)
            .await
            .context("eth_getBlockByHash failed")?
            .with_context(|| format!("block {} not found", block_hash))?;
        let header = block.header();

        // we don't need to include any receipts, if the Bloom filter proves the exclusion
        let bloom_match = self
            .log_filters
            .iter()
            .any(|filter| event::matches_filter(header.logs_bloom(), filter));
        if !bloom_match {
            return Ok(None);
        }

        let rpc_receipts = provider
            .get_block_receipts(block_hash.into())
            .await
            .context("eth_getBlockReceipts failed")?
            .with_context(|| format!("block {} not found", block_hash))?;

        // convert the receipts so that they can be RLP-encoded
        let receipts = convert_rpc_receipts::<N>(rpc_receipts, header.receipts_root())
            .context("invalid receipts; inconsistent API response or incompatible response type")?;

        Ok(Some(receipts))
    }

    async fn get_proof(
        &self,
        address: Address,
        storage_keys: Vec<StorageKey>,
    ) -> Result<EIP1186AccountProofResponse> {
        log::trace!("PROOF: address={}, #keys={}", address, storage_keys.len());
        let proof = self
            .inner
            .get_proof(address, storage_keys)
            .await
            .context("eth_getProof failed")?;
        ensure!(
            proof.address == address,
            "eth_getProof response does not match request"
        );

        Ok(proof)
    }
}

impl<DB: RevmDatabase> RevmDatabase for ProofDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        log::trace!("BASIC: address={}", address);
        self.accounts.entry(address).or_default();

        // Because RevmDatabase requires that basic is always called before code_by_hash, it is just
        // simpler to forward the query to the underlying DB.
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

impl<DB: crate::EvmDatabase> crate::EvmDatabase for ProofDb<DB> {
    fn logs(&mut self, filter: Filter) -> Result<Vec<Log>, <Self as RevmDatabase>::Error> {
        log::trace!("LOGS: filter={:?}", &filter);
        let logs = self.inner.logs(filter.clone())?;

        self.log_filters.push(filter);

        Ok(logs)
    }
}

/// Merges two HashMaps, checking for consistency on overlapping keys.
/// Panics if values for the same key are different. Consumes both maps.
fn merge_checked_maps<K, V, S, T>(mut map: HashMap<K, V, S>, iter: T) -> HashMap<K, V, S>
where
    K: Eq + Hash + Debug,
    V: PartialEq + Debug,
    S: BuildHasher,
    T: IntoIterator<Item = (K, V)>,
{
    let iter = iter.into_iter();
    let (lower_bound, _) = iter.size_hint();
    map.reserve(lower_bound);

    for (key, value2) in iter {
        match map.entry(key) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(value2);
            }
            hash_map::Entry::Occupied(entry) => {
                let value1 = entry.get();
                if value1 != &value2 {
                    panic!(
                        "mismatching values for key {:?}: existing={:?}, other={:?}",
                        entry.key(),
                        value1,
                        value2
                    );
                }
            }
        }
    }

    map
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

    // eth_getProof returns an account object. However, the returned data is not always consistent.
    // See https://github.com/ethereum/go-ethereum/issues/28441
    let account = StateAccount {
        nonce: proof_response.nonce,
        balance: proof_response.balance,
        storage_root: default_if_zero(proof_response.storage_hash, EMPTY_ROOT_HASH),
        code_hash: default_if_zero(proof_response.code_hash, KECCAK_EMPTY),
    };

    match proofs.entry(proof_response.address) {
        hash_map::Entry::Occupied(mut entry) => {
            let account_proof = entry.get_mut();
            ensure!(
                account_proof.account == account
                    && account_proof.account_proof == proof_response.account_proof,
                "inconsistent proof response"
            );
            account_proof.storage_proofs = merge_checked_maps(
                std::mem::take(&mut account_proof.storage_proofs),
                storage_proofs,
            );
        }
        hash_map::Entry::Vacant(entry) => {
            entry.insert(AccountProof {
                account,
                account_proof: proof_response.account_proof,
                storage_proofs,
            });
        }
    }

    Ok(())
}

fn default_if_zero(hash: B256, default: B256) -> B256 {
    if hash.is_zero() {
        default
    } else {
        hash
    }
}

/// Converts an API ReceiptResponse into a vector of ReceiptEnvelope.
fn convert_rpc_receipts<N: Network>(
    rpc_receipts: impl IntoIterator<Item = <N as Network>::ReceiptResponse>,
    receipts_root: B256,
) -> Result<Vec<ReceiptEnvelope>> {
    let receipts = rpc_receipts
        .into_iter()
        .map(|rpc_receipt| {
            // Unfortunately ReceiptResponse does not implement ReceiptEnvelope, so we have to
            // manually convert it. We convert to a TransactionReceipt which is the default and
            // works for Ethereum-compatible networks.
            // Use serde here for the conversion as it is much safer than mem::transmute.
            // TODO(https://github.com/alloy-rs/alloy/issues/854): use ReceiptEnvelope directly
            let json = serde_json::to_value(rpc_receipt).context("failed to serialize")?;
            let tx_receipt: TransactionReceipt = serde_json::from_value(json)
                .context("failed to parse as Ethereum transaction receipt")?;

            Ok(tx_receipt.inner.into_primitives_receipt())
        })
        .collect::<Result<Vec<_>>>()?;

    // in case the conversion did not work correctly, we check the receipts root in the header
    let root =
        alloy_trie::root::ordered_trie_root_with_encoder(&receipts, |r, out| r.encode_2718(out));
    ensure!(root == receipts_root, "receipts root mismatch");

    Ok(receipts)
}
