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

use std::{convert::Infallible, fmt::Debug, rc::Rc};

use crate::mpt::{MerkleTrie, EMPTY_ROOT_HASH};
use alloy_primitives::{
    keccak256,
    map::{AddressHashMap, B256HashMap, HashMap},
    Address, Bytes, TxNumber, B256, U256,
};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable};
use revm::{
    primitives::{AccountInfo, Bytecode, KECCAK_EMPTY},
    Database,
};

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
    /// [Rc] is used fore MPT deduplication.
    storage_tries: B256HashMap<Rc<MerkleTrie>>,
    /// Contracts by their hash.
    contracts: B256HashMap<Bytes>,
    /// Block hashes by their number.
    block_hashes: HashMap<u64, B256>,
}

impl StateDb {
    /// Creates a new state database from the given tries.
    pub fn new(
        state_trie: MerkleTrie,
        storage_tries: impl IntoIterator<Item = MerkleTrie>,
        contracts: impl IntoIterator<Item = Bytes>,
        block_hashes: HashMap<u64, B256>,
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
        }
    }

    #[inline]
    fn account(&self, address: Address) -> Option<StateAccount> {
        self.state_trie
            .get_rlp(keccak256(address))
            .expect("Invalid encoded state trie value")
    }

    #[inline]
    fn code_by_hash(&self, hash: B256) -> &Bytes {
        self.contracts
            .get(&hash)
            .unwrap_or_else(|| panic!("No code with hash: {}", hash))
    }

    #[inline]
    fn block_hash(&self, number: u64) -> B256 {
        let hash = self
            .block_hashes
            .get(&number)
            .unwrap_or_else(|| panic!("No block with number: {}", number));
        *hash
    }

    #[inline]
    fn storage_trie(&self, root: &B256) -> Option<&Rc<MerkleTrie>> {
        self.storage_tries.get(root)
    }
}

/// A simple wrapper for [StateDb] to implement the [Database] trait.
///
/// In addition to translating the actual [Database] queries into MPT calls, it also maps account
/// addresses to their respective storage trie when the account is first accessed. This works
/// because [Database::basic] must always be called before any [Database::storage] calls for that
/// account.
pub struct WrapStateDb<'a> {
    inner: &'a StateDb,
    account_storage: AddressHashMap<Option<Rc<MerkleTrie>>>,
}

impl<'a> WrapStateDb<'a> {
    /// Creates a new [Database] from the given [StateDb].
    pub fn new(inner: &'a StateDb) -> Self {
        Self {
            inner,
            account_storage: Default::default(),
        }
    }
}

impl Database for WrapStateDb<'_> {
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

/// Represents an account within the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct StateAccount {
    /// The number of transactions sent from this account's address.
    pub nonce: TxNumber,
    /// The number of Wei owned by this account's address.
    pub balance: U256,
    /// The root of the account's storage trie.
    pub storage_root: B256,
    /// The hash of the EVM code of this account.
    pub code_hash: B256,
}

impl Default for StateAccount {
    /// Provides default values for a [StateAccount].
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        }
    }
}
