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

pub use alloy_consensus::Account as StateAccount;

use crate::{event, mpt::MerkleTrie};
use alloy_primitives::{
    keccak256,
    map::{AddressHashMap, B256HashMap, HashMap},
    Address, Bytes, Log, Sealed, B256, U256,
};
use revm::{
    state::{AccountInfo, Bytecode},
    Database as RevmDatabase,
};
use std::{convert::Infallible, rc::Rc};

/// A simple MPT-based read-only EVM database implementation.
///
/// It is backed by a single [MerkleTrie] for the accounts and one [MerkleTrie] each for the
/// accounts' stores. It panics when querying data not contained in the tries. This design allows
/// storage keys to be queried by storage trie root hash, but not by account, which is required to
/// implement [DatabaseRef]. Thus, in order to use [StateDb] in revm, a wrapper must be
/// used, which caches the appropriate storage trie root for each basic account query, thus
/// requiring mutability.
///
/// [DatabaseRef]: revm::DatabaseRef
pub struct StateDb {
    /// State MPT.
    state_trie: MerkleTrie,
    /// Storage MPTs to their root hash.
    /// [Rc] is used for MPT deduplication.
    storage_tries: B256HashMap<Rc<MerkleTrie>>,
    /// Contracts by their hash.
    contracts: B256HashMap<Bytes>,
    /// Block hashes by their number.
    block_hashes: HashMap<u64, B256>,
    /// All the logs for this block.
    logs: Option<Vec<Log>>,
}

impl StateDb {
    /// Creates a new state database from the given tries.
    pub fn new(
        state_trie: MerkleTrie,
        storage_tries: impl IntoIterator<Item = MerkleTrie>,
        contracts: impl IntoIterator<Item = Bytes>,
        block_hashes: HashMap<u64, B256>,
        logs: Option<Vec<Log>>,
    ) -> Self {
        let contracts = contracts
            .into_iter()
            .map(|code| (keccak256(&code), code))
            .collect();
        let storage_tries = storage_tries
            .into_iter()
            .map(|trie| (trie.hash_slow(), Rc::new(trie)))
            .collect();

        Self {
            state_trie,
            contracts,
            storage_tries,
            block_hashes,
            logs,
        }
    }

    #[inline]
    pub(crate) fn account(&self, address: Address) -> Option<StateAccount> {
        self.state_trie
            .get_rlp(keccak256(address))
            .expect("Invalid encoded state trie value")
    }

    #[inline]
    pub(crate) fn code_by_hash(&self, hash: B256) -> &Bytes {
        self.contracts
            .get(&hash)
            .unwrap_or_else(|| panic!("No code with hash: {}", hash))
    }

    #[inline]
    pub(crate) fn block_hash(&self, number: u64) -> B256 {
        let hash = self
            .block_hashes
            .get(&number)
            .unwrap_or_else(|| panic!("No block with number: {}", number));
        *hash
    }

    #[inline]
    pub(crate) fn storage_trie(&self, root: &B256) -> Option<&Rc<MerkleTrie>> {
        self.storage_tries.get(root)
    }
}

/// A simple wrapper for [StateDb] to implement the [Database] trait.
///
/// In addition to translating the actual [Database] queries into MPT calls, it also maps account
/// addresses to their respective storage trie when the account is first accessed. This works
/// because [Database::basic] must always be called before any [Database::storage] calls for that
/// account.
pub struct WrapStateDb<'a, H> {
    inner: &'a StateDb,
    header: &'a Sealed<H>,
    account_storage: AddressHashMap<Option<Rc<MerkleTrie>>>,
}

impl<'a, H> WrapStateDb<'a, H> {
    /// Creates a new [Database] from the given [StateDb].
    pub fn new(inner: &'a StateDb, header: &'a Sealed<H>) -> Self {
        Self {
            inner,
            header,
            account_storage: Default::default(),
        }
    }
}

impl<H> RevmDatabase for WrapStateDb<'_, H> {
    /// The [StateDb] does not return any errors.
    type Error = Infallible;

    /// Get basic account information.
    #[inline]
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let account = self.inner.account(address);
        match account {
            Some(account) => {
                // link storage trie to the account, if it exists
                if let Some(storage_trie) = self.inner.storage_trie(&account.storage_root) {
                    self.account_storage
                        .insert(address, Some(storage_trie.clone()));
                }

                Ok(Some(AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    code: None, // we don't need the code here, `code_by_hash` will be used instead
                }))
            }
            None => {
                self.account_storage.insert(address, None);

                Ok(None)
            }
        }
    }

    /// Get account code by its hash.
    #[inline]
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let code = self.inner.code_by_hash(code_hash);
        Ok(Bytecode::new_raw(code.clone()))
    }

    /// Get storage value of address at index.
    #[inline]
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage = self
            .account_storage
            .get(&address)
            .unwrap_or_else(|| panic!("No storage trie with root: {}", address));
        match storage {
            Some(storage) => {
                let val = storage
                    .get_rlp(keccak256(index.to_be_bytes::<32>()))
                    .expect("Invalid encoded storage value");
                Ok(val.unwrap_or_default())
            }
            None => Ok(U256::ZERO),
        }
    }

    /// Get block hash by block number.
    #[inline]
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.inner.block_hash(number))
    }
}

impl<H: crate::EvmBlockHeader> crate::EvmDatabase for WrapStateDb<'_, H> {
    fn logs(
        &mut self,
        filter: alloy_rpc_types::Filter,
    ) -> Result<Vec<Log>, <Self as RevmDatabase>::Error> {
        assert_eq!(filter.get_block_hash(), Some(self.header.seal()));

        let Some(logs) = self.inner.logs.as_ref() else {
            // if no logs are stored in the DB, check that the Bloom filter proves non-existence
            assert!(
                !event::matches_filter(*self.header.logs_bloom(), &filter),
                "No logs for matching filter"
            );
            return Ok(vec![]);
        };

        let params = alloy_rpc_types::FilteredParams::new(Some(filter));
        let filtered = logs
            .iter()
            .filter(|log| params.filter_address(&log.address) && params.filter_topics(log.topics()))
            .cloned()
            .collect();

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
    #[test]
    fn default_account() {
        let account: StateAccount = Default::default();
        assert_eq!(account.storage_root, EMPTY_ROOT_HASH);
        assert_eq!(account.code_hash, KECCAK_EMPTY);
    }
}
