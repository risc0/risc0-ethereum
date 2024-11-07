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

use super::provider::{ProviderConfig, ProviderDb};
use alloy::{
    network::{
        primitives::{BlockTransactionsKind, HeaderResponse},
        BlockResponse, Network,
    },
    providers::Provider,
    transports::{Transport, TransportError},
};
use alloy_primitives::{map::B256HashMap, Address, BlockHash, B256, U256};
use revm::{
    primitives::{AccountInfo, Bytecode},
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
    /// Configuration of the provider.
    provider_config: ProviderConfig,
    /// Hash of the block on which the queries will be based.
    block_hash: BlockHash,
    /// Handle to the Tokio runtime.
    handle: Handle,
    /// Bytecode cache to allow querying bytecode by hash instead of address.
    contracts: B256HashMap<Bytecode>,

    phantom: PhantomData<fn() -> (T, N)>,
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> AlloyDb<T, N, P> {
    /// Creates a new AlloyDb instance, with a [Provider] and a block.
    ///
    /// This will panic if called outside the context of a Tokio runtime.
    pub fn new(provider: P, config: ProviderConfig, block_hash: BlockHash) -> Self {
        Self {
            provider,
            provider_config: config,
            block_hash,
            handle: Handle::current(),
            contracts: Default::default(),
            phantom: PhantomData,
        }
    }
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> ProviderDb<T, N, P> for AlloyDb<T, N, P> {
    fn config(&self) -> &ProviderConfig {
        &self.provider_config
    }

    fn provider(&self) -> &P {
        &self.provider
    }

    fn block_hash(&self) -> BlockHash {
        self.block_hash
    }
}

/// Errors returned by the [AlloyDb].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} failed")]
    Rpc(&'static str, #[source] TransportError),
    #[error("block not found")]
    BlockNotFound,
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> Database for AlloyDb<T, N, P> {
    type Error = Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let f = async {
            let get_nonce = self
                .provider
                .get_transaction_count(address)
                .hash(self.block_hash);
            let get_balance = self.provider.get_balance(address).hash(self.block_hash);
            let get_code = self.provider.get_code_at(address).hash(self.block_hash);

            tokio::join!(
                get_nonce.into_future(),
                get_balance.into_future(),
                get_code.into_future()
            )
        };
        let (nonce, balance, code) = self.handle.block_on(f);

        let nonce = nonce.map_err(|err| Error::Rpc("eth_getTransactionCount", err))?;
        let balance = balance.map_err(|err| Error::Rpc("eth_getBalance", err))?;
        let code = code.map_err(|err| Error::Rpc("eth_getCode", err))?;
        let bytecode = Bytecode::new_raw(code.0.into());

        // if the account is empty return None
        // in the EVM, emptiness is treated as equivalent to nonexistence
        if nonce == 0 && balance.is_zero() && bytecode.is_empty() {
            return Ok(None);
        }

        // index the code by its hash, so that we can later use code_by_hash
        let code_hash = bytecode.hash_slow();
        self.contracts.insert(code_hash, bytecode);

        Ok(Some(AccountInfo {
            nonce,
            balance,
            code_hash,
            code: None, // will be queried later using code_by_hash
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // this works because `basic` is always called first
        let code = self
            .contracts
            .get(&code_hash)
            .expect("`basic` must be called first for the corresponding account");

        Ok(code.clone())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage = self
            .handle
            .block_on(
                self.provider
                    .get_storage_at(address, index)
                    .hash(self.block_hash)
                    .into_future(),
            )
            .map_err(|err| Error::Rpc("eth_getStorageAt", err))?;

        Ok(storage)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        let block_response = self
            .handle
            .block_on(
                self.provider
                    .get_block_by_number(number.into(), BlockTransactionsKind::Hashes),
            )
            .map_err(|err| Error::Rpc("eth_getBlockByNumber", err))?;
        let block = block_response.ok_or(Error::BlockNotFound)?;

        Ok(block.header().hash())
    }
}
