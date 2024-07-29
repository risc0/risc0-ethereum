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

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::{
    primitives::{AccountInfo, Bytecode, HashMap, HashSet},
    Database,
};

/// A simple revm [Database] wrapper that records all DB queries.
pub struct TraceDb<D> {
    accounts: HashMap<Address, HashSet<U256>>,
    contracts: HashMap<B256, Bytes>,
    block_hash_numbers: HashSet<U256>,

    inner: D,
}

impl<D: Database> TraceDb<D> {
    pub fn new(db: D) -> Self {
        Self {
            accounts: HashMap::new(),
            contracts: HashMap::new(),
            block_hash_numbers: HashSet::new(),
            inner: db,
        }
    }

    /// Returns all the queried account addresses with their queried storage keys.
    pub fn accounts(&self) -> &HashMap<Address, HashSet<U256>> {
        &self.accounts
    }
    /// Returns a map of the bytecode of the contracts queried by their code hash.
    pub fn contracts(&self) -> &HashMap<B256, Bytes> {
        &self.contracts
    }
    /// Returns all the queried block numbers.
    pub fn block_hash_numbers(&self) -> &HashSet<U256> {
        &self.block_hash_numbers
    }

    pub fn inner(&self) -> &D {
        &self.inner
    }
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<DB: Database> Database for TraceDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        log::trace!("BASIC: address={}", address);
        let basic = self.inner.basic(address)?;
        self.accounts.entry(address).or_default();

        Ok(basic)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        log::trace!("CODE: hash={}", hash);
        let code = self.inner.code_by_hash(hash)?;
        self.contracts.insert(hash, code.original_bytes());

        Ok(code)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        log::trace!("STORAGE: address={}, index={}", address, index);
        let storage = self.inner.storage(address, index)?;
        self.accounts.entry(address).or_default().insert(index);

        Ok(storage)
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        log::trace!("BLOCK: number={}", number);
        let block_hash = self.inner.block_hash(number)?;
        self.block_hash_numbers.insert(number);

        Ok(block_hash)
    }
}
