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
use tokio::runtime::{self, Handle, Runtime};

/// A revm [Database] backed by an alloy [Provider].
///
/// When accessing the database, it'll use the given provider to fetch the corresponding account's
/// data. It will block the current thread to execute provider calls, Therefore, its methods
/// must *not* be executed inside an async runtime, or it will panic when trying to block. If the
/// immediate context is only synchronous, but a transitive caller is async, use
/// [tokio::task::spawn_blocking] around the calls that need to be blocked.
pub struct AlloyDb<T: Transport + Clone, N: Network, P: Provider<T, N>> {
    /// The provider to fetch the data from.
    provider: P,
    /// The block number on which the queries will be based on.
    block_number: BlockNumber,
    /// handle to the tokio runtime
    runtime_handle: HandleOrRuntime,
    /// Cache for code hashes to contract addresses.
    code_hashes: HashMap<B256, Address>,

    _marker: PhantomData<fn() -> (T, N)>,
}

/// Holds a tokio runtime handle or full runtime
#[derive(Debug)]
enum HandleOrRuntime {
    Handle(Handle),
    Runtime(Runtime),
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> AlloyDb<T, N, P> {
    pub fn new(provider: P, block_number: BlockNumber) -> Self {
        let runtime_handle = match Handle::try_current() {
            Ok(handle) => HandleOrRuntime::Handle(handle),
            Err(_) => {
                let runtime = runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                HandleOrRuntime::Runtime(runtime)
            }
        };

        Self {
            provider,
            block_number,
            runtime_handle,
            code_hashes: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn provider(&self) -> &P {
        &self.provider
    }
    pub(crate) fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// internal utility function to call tokio feature and wait for output
    #[inline]
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        match &self.runtime_handle {
            HandleOrRuntime::Handle(handle) => handle.block_on(f),
            HandleOrRuntime::Runtime(rt) => rt.block_on(f),
        }
    }
}

impl<T: Transport + Clone, N: Network, P: Provider<T, N>> Database for AlloyDb<T, N, P> {
    type Error = TransportError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // use `eth_getProof` to get all the account info with a single call
        let proof = self.block_on(
            self.provider
                .get_proof(address, vec![])
                .number(self.block_number)
                .into_future(),
        )?;
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

        // this works because we always call `basic` first
        let contract_address = *self
            .code_hashes
            .get(&code_hash)
            .expect("`basic` must be called first for the corresponding account");
        let code = self.block_on(
            self.provider
                .get_code_at(contract_address)
                .number(self.block_number)
                .into_future(),
        )?;

        Ok(Bytecode::new_raw(code.0.into()))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let storage = self.block_on(
            self.provider
                .get_storage_at(address, index)
                .number(self.block_number)
                .into_future(),
        )?;

        Ok(storage)
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        // SAFETY: We know number <= u64::MAX, so we can safely convert it to u64
        let block = self.block_on(
            self.provider
                .get_block_by_number(number.to::<u64>().into(), false),
        )?;
        let header = block.unwrap().header;
        Ok(header.hash.unwrap())
    }
}
