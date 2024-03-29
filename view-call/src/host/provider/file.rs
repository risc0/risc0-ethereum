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

use super::{EIP1186Proof, NullProvider, Provider};
use crate::{ethereum::EthBlockHeader, EvmHeader};
use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, TxNumber, B256, U256};
use anyhow::Context;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, BTreeSet, HashMap},
    fs::{self, File},
    io::{BufReader, BufWriter},
    marker::PhantomData,
    path::PathBuf,
};

/// A provider that caches responses from an underlying provider in a JSON file.
/// Queries are first checked against the cache, and if not found, the provider is invoked.
/// The cache is saved when the provider is dropped.
pub struct CachedProvider<P: Provider>
where
    P::Header: Clone + Serialize + DeserializeOwned,
{
    inner: P,
    cache: RefCell<JsonCache<P::Header>>,
}

impl<P: Provider> CachedProvider<P>
where
    P::Header: Clone + Serialize + DeserializeOwned,
{
    /// Creates a new [CachedProvider]. If the cache file exists, it will be read and deserialized.
    /// Otherwise, a new file will be created when dropped.
    pub fn new(cache_path: PathBuf, provider: P) -> anyhow::Result<Self> {
        let cache = match JsonCache::from_file(cache_path.clone()) {
            Ok(cache) => cache,
            Err(err) => match err.downcast_ref::<std::io::Error>() {
                Some(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                    // create the file and directory if it doesn't exist
                    if let Some(parent) = cache_path.parent() {
                        fs::create_dir_all(parent).context("failed to create directory")?;
                    }
                    JsonCache::empty(cache_path)
                }
                _ => return Err(err),
            },
        };

        Ok(Self {
            inner: provider,
            cache: RefCell::new(cache),
        })
    }
}

/// [FileProvider] for Ethereum.
pub type EthFileProvider = FileProvider<EthBlockHeader>;

/// A provider returning responses cached in a file.
/// It panics if queries are not found in the cache.
pub type FileProvider<H> = CachedProvider<NullProvider<H>>;

impl<H> FileProvider<H>
where
    H: EvmHeader + Clone + Serialize + DeserializeOwned,
{
    /// Creates a new [FileProvider] loading the given file.
    pub fn from_file(file_path: &PathBuf) -> anyhow::Result<Self> {
        let cache = JsonCache::load(file_path)?;
        Ok(Self {
            inner: NullProvider(PhantomData),
            cache: RefCell::new(cache),
        })
    }
}

impl<P: Provider> Provider for CachedProvider<P>
where
    P::Header: Clone + Serialize + DeserializeOwned,
{
    type Error = P::Error;
    type Header = P::Header;

    fn get_block_header(&self, block: BlockNumber) -> Result<Option<Self::Header>, Self::Error> {
        match self
            .cache
            .borrow_mut()
            .partial_blocks
            .entry(BlockQuery { block_no: block })
        {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => Ok(entry.insert(self.inner.get_block_header(block)?).clone()),
        }
    }

    fn get_transaction_count(
        &self,
        address: Address,
        block: BlockNumber,
    ) -> Result<TxNumber, Self::Error> {
        match self
            .cache
            .borrow_mut()
            .transaction_count
            .entry(AccountQuery {
                block_no: block,
                address,
            }) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let count = self.inner.get_transaction_count(address, block)?;
                Ok(*entry.insert(count))
            }
        }
    }

    fn get_balance(&self, address: Address, block: BlockNumber) -> Result<U256, Self::Error> {
        match self.cache.borrow_mut().balance.entry(AccountQuery {
            block_no: block,
            address,
        }) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let balance = self.inner.get_balance(address, block)?;
                Ok(*entry.insert(balance))
            }
        }
    }

    fn get_code(&self, address: Address, block: BlockNumber) -> Result<Bytes, Self::Error> {
        match self.cache.borrow_mut().code.entry(AccountQuery {
            block_no: block,
            address,
        }) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let code = self.inner.get_code(address, block)?;
                Ok(entry.insert(code).clone())
            }
        }
    }

    fn get_storage_at(
        &self,
        address: Address,
        storage_slot: StorageKey,
        block: BlockNumber,
    ) -> Result<B256, Self::Error> {
        match self.cache.borrow_mut().storage.entry(StorageQuery {
            block_no: block,
            address,
            index: storage_slot,
        }) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let storage = self.inner.get_storage_at(address, storage_slot, block)?;
                Ok(*entry.insert(storage))
            }
        }
    }

    fn get_proof(
        &self,
        address: Address,
        storage_slots: Vec<StorageKey>,
        block: BlockNumber,
    ) -> Result<EIP1186Proof, Self::Error> {
        match self.cache.borrow_mut().proofs.entry(ProofQuery {
            block_no: block,
            address,
            indices: storage_slots.iter().cloned().collect(),
        }) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let proof = self.inner.get_proof(address, storage_slots, block)?;
                Ok(entry.insert(proof).clone())
            }
        }
    }
}

/// A simple JSON cache for storing responses from a provider.
#[derive(Debug, Deserialize, Serialize)]
struct JsonCache<H: DeserializeOwned + Serialize> {
    #[serde(skip)]
    file_path: Option<PathBuf>,

    #[serde(with = "ordered_map")]
    partial_blocks: HashMap<BlockQuery, Option<H>>,
    #[serde(with = "ordered_map")]
    proofs: HashMap<ProofQuery, EIP1186Proof>,
    #[serde(with = "ordered_map")]
    transaction_count: HashMap<AccountQuery, TxNumber>,
    #[serde(with = "ordered_map")]
    balance: HashMap<AccountQuery, U256>,
    #[serde(with = "ordered_map")]
    code: HashMap<AccountQuery, Bytes>,
    #[serde(with = "ordered_map")]
    storage: HashMap<StorageQuery, B256>,
}

impl<H: DeserializeOwned + Serialize> JsonCache<H> {
    /// Creates a new empty cache. It will be saved to the given file when dropped.
    fn empty(file_path: PathBuf) -> Self {
        Self {
            file_path: Some(file_path),
            partial_blocks: HashMap::new(),
            proofs: HashMap::new(),
            transaction_count: HashMap::new(),
            balance: HashMap::new(),
            code: HashMap::new(),
            storage: HashMap::new(),
        }
    }

    /// Creates a new cache backed by the given file. It updates the file when dropped.
    fn from_file(file_path: PathBuf) -> anyhow::Result<Self> {
        Self::load(&file_path).map(|mut cache| {
            cache.file_path = Some(file_path);
            cache
        })
    }

    /// Loads a cache from a file. Nothing is saved when the cache is dropped.
    fn load(file_path: &PathBuf) -> anyhow::Result<Self> {
        let file = File::open(file_path).context("failed to open cache file")?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).context("failed to deserialize cache")
    }

    /// Saves the cache to the file.
    fn save(&self) -> anyhow::Result<()> {
        if let Some(file_path) = &self.file_path {
            let file = File::create(file_path).context("failed to create cache file")?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, self).context("failed to serialize cache")?;
        }
        Ok(())
    }
}

impl<H: DeserializeOwned + Serialize> Drop for JsonCache<H> {
    fn drop(&mut self) {
        self.save().expect("failed to save cache");
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
struct AccountQuery {
    block_no: BlockNumber,
    address: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
struct BlockQuery {
    block_no: BlockNumber,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
struct ProofQuery {
    block_no: BlockNumber,
    address: Address,
    indices: BTreeSet<B256>,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
struct StorageQuery {
    block_no: BlockNumber,
    address: Address,
    index: B256,
}

/// A serde helper to serialize a HashMap into a vector sorted by key
mod ordered_map {
    use std::{collections::HashMap, hash::Hash};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, K, V>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Ord + Serialize,
        V: Serialize,
    {
        let mut vec: Vec<(_, _)> = map.iter().collect();
        vec.sort_unstable_by_key(|&(k, _)| k);
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
    where
        D: Deserializer<'de>,
        K: Eq + Hash + Deserialize<'de>,
        V: Deserialize<'de>,
    {
        let vec = Vec::<(_, _)>::deserialize(deserializer)?;
        Ok(vec.into_iter().collect())
    }
}
