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

use std::{future::IntoFuture, marker::PhantomData};

use alloy::{
    network::Network,
    providers::Provider,
    transports::{Transport, TransportError},
};
use alloy_primitives::{Address, BlockNumber, B256, U256};
use revm::{
    primitives::{AccountInfo, Bytecode, HashMap, KECCAK_EMPTY},
    Database,
};
use tokio::runtime::Handle;

/// A revm [Database] backed by an alloy [Provider].
///
/// When accessing the database, it'll use the given provider to fetch the corresponding account's
/// data. It will block the current thread to execute provider calls, Therefore, its methods
/// must *not* be executed inside an async runtime, or it will panic when trying to block. If the
/// immediate context is only synchronous, but a transitive caller is async, use
/// [tokio::task::spawn_blocking] around the calls that need to be blocked.
pub struct AlloyDb<T: Transport + Clone, N: Network, P: Provider<T, N>> {
    /// Provider to fetch the data from.
    provider: P,
    /// Block number on which the queries will be based on.
    block_number: BlockNumber,
    /// Handle to the Tokio runtime.
    handle: Handle,
    /// Bytecode cache to allow querying bytecode by hash instead of address.
    contracts: HashMap<B256, Bytecode>,

    phantom: PhantomData<fn() -> (T, N)>,
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> AlloyDb<T, N, P> {
    /// Create a new AlloyDb instance, with a [Provider] and a block.
    ///
    /// This will panic if called outside the context of a Tokio runtime.
    pub fn new(provider: P, block_number: BlockNumber) -> Self {
        Self {
            provider,
            block_number,
            handle: Handle::current(),
            contracts: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Returns the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Returns the block number used for the queries.
    pub fn block_number(&self) -> BlockNumber {
        self.block_number
    }
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> Database for AlloyDb<T, N, P> {
    type Error = TransportError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let f = async {
            let get_nonce = self
                .provider
                .get_transaction_count(address)
                .number(self.block_number);
            let get_balance = self.provider.get_balance(address).number(self.block_number);
            let get_code = self.provider.get_code_at(address).number(self.block_number);

            tokio::join!(
                get_nonce.into_future(),
                get_balance.into_future(),
                get_code.into_future()
            )
        };
        let (nonce, balance, code) = self.handle.block_on(f);

        let nonce = nonce?;
        let balance = balance?;
        let code = Bytecode::new_raw(code?.0.into());

        // if the account is empty return None
        // in the EVM emptiness is treated as equivalent to nonexistence
        if nonce == 0 && balance.is_zero() && code.is_empty() {
            return Ok(None);
        }

        // cache the code hash to address mapping, so we can later retrieve the code
        let code_hash = code.hash_slow();
        self.contracts.insert(code_hash, code);

        Ok(Some(AccountInfo {
            nonce,
            balance,
            code_hash,
            code: None, // will be queried later using code_by_hash
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // avoid querying the RPC if the code hash is empty
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }

        // this works because we always call `basic` first
        let code = self
            .contracts
            .get(&code_hash)
            .expect("`basic` must be called first for the corresponding account");

        Ok(code.clone())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage = self.handle.block_on(
            self.provider
                .get_storage_at(address, index)
                .number(self.block_number)
                .into_future(),
        )?;

        Ok(storage)
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        // SAFETY: We know number <= u64::MAX, so we can safely convert it to u64
        let block = self.handle.block_on(
            self.provider
                .get_block_by_number(number.to::<u64>().into(), false),
        )?;
        let header = block.unwrap().header;
        Ok(header.hash.unwrap())
    }
}
