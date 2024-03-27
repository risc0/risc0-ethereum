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

use alloy_primitives::{Address, B256, U256};
use revm::{
    primitives::{hash_map::Entry, AccountInfo, Bytecode, HashMap},
    Database,
};

type Account = (AccountInfo, HashMap<U256, U256>);

/// A simple revm [Database] caching the result of another [Database].
pub struct CacheDb<D: Database> {
    accounts: HashMap<Address, Option<Account>>,
    contracts: HashMap<B256, Bytecode>,
    block_hashes: HashMap<U256, B256>,

    inner: D,
}

impl<D: Database> CacheDb<D> {
    pub fn new(db: D) -> Self {
        Self {
            accounts: HashMap::new(),
            contracts: HashMap::new(),
            block_hashes: HashMap::new(),
            inner: db,
        }
    }

    pub fn inner(&self) -> &D {
        &self.inner
    }
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: Database> Database for CacheDb<D> {
    type Error = D::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let account = match self.accounts.entry(address) {
            Entry::Occupied(entry) => entry.into_mut().as_ref(),
            Entry::Vacant(entry) => {
                let account = self.inner.basic(address)?.map(new_account);
                entry.insert(account).as_ref()
            }
        };
        Ok(account.map(|(a, _)| a.clone()))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.contracts.entry(code_hash) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let code = self.inner.code_by_hash(code_hash)?;
                entry.insert(code.clone());
                Ok(code)
            }
        }
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let account = match self.accounts.entry(address) {
            Entry::Occupied(entry) => entry.into_mut().as_mut(),
            Entry::Vacant(entry) => {
                let account = self.inner.basic(address)?.map(new_account);
                entry.insert(account).as_mut()
            }
        };
        match account {
            Some((_, storage)) => match storage.entry(index) {
                Entry::Occupied(entry) => Ok(*entry.get()),
                Entry::Vacant(entry) => {
                    let value = self.inner.storage(address, index)?;
                    entry.insert(value);
                    Ok(value)
                }
            },
            None => Ok(U256::ZERO),
        }
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        match self.block_hashes.entry(number) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let hash = self.inner.block_hash(number)?;
                entry.insert(hash);
                Ok(hash)
            }
        }
    }
}

fn new_account(info: AccountInfo) -> Account {
    (info, HashMap::new())
}
