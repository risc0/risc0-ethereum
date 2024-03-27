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

use super::provider::Provider;
use crate::db::CacheDb;
use alloy_primitives::{Address, Bytes, Sealable, B256, U256};
use revm::{
    primitives::{AccountInfo, Bytecode, HashMap, HashSet, KECCAK_EMPTY},
    Database,
};
use std::fmt::Debug;
use thiserror::Error;

/// Error type for the [ProviderDb].
#[derive(Error, Debug)]
pub enum ProviderDbError<E: std::error::Error> {
    #[error("provider error")]
    Provider(#[from] E),
    #[error("invalid block number: {0}")]
    InvalidBlockNumber(U256),
    #[error("hash missing for block: {0}")]
    BlockHashMissing(U256),
}

/// A revm [Database] backed by a [Provider].
pub struct ProviderDb<P: Provider> {
    provider: P,
    block_number: u64,

    /// Cache for code hashes to contract addresses.
    code_hashes: HashMap<B256, Address>,
}

impl<P: Provider> ProviderDb<P> {
    /// Creates a new [ProviderDb] with the given provider and block number.
    pub fn new(provider: P, block_number: u64) -> Self {
        Self {
            provider,
            block_number,
            code_hashes: HashMap::new(),
        }
    }
}

impl<P: Provider> Database for ProviderDb<P> {
    type Error = ProviderDbError<P::Error>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // use `eth_getProof` to get all the account info with a single call
        let proof = self
            .provider
            .get_proof(address, vec![], self.block_number)?;
        // for non-existent accounts, the code hash is zero
        // see https://github.com/ethereum/go-ethereum/issues/28441
        if proof.code_hash == B256::ZERO {
            return Ok(None);
        }
        // cache the code hash to address mapping, so we can later retrieve the code
        self.code_hashes
            .insert(proof.code_hash.0.into(), proof.address);

        Ok(Some(AccountInfo {
            nonce: proof.nonce,
            balance: proof.balance,
            code_hash: proof.code_hash,
            code: None,
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // avoid querying the RPC if the code hash is empty
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }

        // this works because we always call `basic_ref` first
        let contract_address = *self
            .code_hashes
            .get(&code_hash)
            .expect("`basic` must be called first for the corresponding account");
        let code = self
            .provider
            .get_code(contract_address, self.block_number)
            .map_err(ProviderDbError::Provider)?;

        Ok(Bytecode::new_raw(code.0.into()))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage = self
            .provider
            .get_storage_at(address, index.into(), self.block_number)
            .map_err(ProviderDbError::Provider)?;

        Ok(storage.into())
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        let block_number: u64 = number
            .try_into()
            .map_err(|_| ProviderDbError::InvalidBlockNumber(number))?;
        let header = self
            .provider
            .get_block_header(block_number)?
            .ok_or(ProviderDbError::InvalidBlockNumber(number))?;

        Ok(header.hash_slow())
    }
}

/// A revm [Database] backed by a [Provider] that caches all queries needed for a state proof.
pub struct ProofDb<P: Provider> {
    accounts: HashMap<Address, HashSet<U256>>,
    contracts: HashMap<B256, Bytes>,
    block_hash_numbers: HashSet<U256>,

    db: CacheDb<ProviderDb<P>>,
}

impl<P: Provider> ProofDb<P> {
    pub fn new(provider: P, block_number: u64) -> Self {
        Self {
            accounts: HashMap::new(),
            contracts: HashMap::new(),
            block_hash_numbers: HashSet::new(),
            db: CacheDb::new(ProviderDb::new(provider, block_number)),
        }
    }

    pub fn provider(&self) -> &P {
        &self.db.inner().provider
    }
    pub fn block_number(&self) -> u64 {
        self.db.inner().block_number
    }
    pub fn accounts(&self) -> &HashMap<Address, HashSet<U256>> {
        &self.accounts
    }
    pub fn contracts(&self) -> &HashMap<B256, Bytes> {
        &self.contracts
    }
    pub fn block_hash_numbers(&self) -> &HashSet<U256> {
        &self.block_hash_numbers
    }
}

impl<P: Provider> Database for ProofDb<P> {
    type Error = <ProviderDb<P> as Database>::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let basic = self.db.basic(address)?;
        self.accounts.entry(address).or_default();

        Ok(basic)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let code = self.db.code_by_hash(code_hash)?;
        self.contracts.insert(code_hash, code.original_bytes());

        Ok(code)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage = self.db.storage(address, index)?;
        self.accounts.entry(address).or_default().insert(index);

        Ok(storage)
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        let block_hash = self.db.block_hash(number)?;
        self.block_hash_numbers.insert(number);

        Ok(block_hash)
    }
}
