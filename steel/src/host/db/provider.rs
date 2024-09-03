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

use alloy::{
    network::Network, providers::Provider, rpc::types::EIP1186AccountProofResponse,
    transports::Transport,
};
use alloy_primitives::{Address, BlockNumber, StorageKey};
use anyhow::{ensure, Result};
use revm::Database;

/// A [Database] backed by a [Provider].
pub trait ProviderDb<T, N, P>: Database
where
    T: Transport + Clone,
    N: Network,
    P: Provider<T, N>,
{
    /// Max number of storage keys to request in a single `eth_getProof` call.
    const STORAGE_KEY_CHUNK_SIZE: usize = 1000;

    /// Returns the [Provider].
    fn provider(&self) -> &P;

    /// Returns the block number used for the queries.
    fn block_number(&self) -> BlockNumber;

    /// Get the EIP-1186 account and storage merkle proofs.
    async fn get_eip1186_proof(
        &self,
        address: Address,
        mut keys: Vec<StorageKey>,
    ) -> Result<EIP1186AccountProofResponse> {
        let number = self.block_number();

        // for certain RPC nodes it seemed beneficial when the keys are in the correct order
        keys.sort_unstable();

        let mut iter = keys.chunks(Self::STORAGE_KEY_CHUNK_SIZE);
        // always make at least one call even if the keys are empty
        let mut account_proof = self
            .provider()
            .get_proof(address, iter.next().unwrap_or_default().into())
            .number(number)
            .await?;
        while let Some(keys) = iter.next() {
            let proof = self
                .provider()
                .get_proof(address, keys.into())
                .number(number)
                .await?;
            // only the keys have changed, the account proof should not change
            ensure!(
                proof.account_proof == account_proof.account_proof,
                "account_proof not consistent between calls"
            );

            account_proof.storage_proof.extend(proof.storage_proof);
        }

        Ok(account_proof)
    }
}
