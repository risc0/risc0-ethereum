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

use crate::{MerkleTrie, StateAccount};
use alloy_primitives::{address, b256, keccak256, uint, Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Enum representing possible errors that can occur within the `BeaconRootsContract`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error indicating that the contract is not deployed at the expected address.
    #[error("wrong or no contract deployed")]
    NoContract,
    /// Error indicating an inconsistency in the contract's state.
    #[error("inconsistent state")]
    InvalidState,
    /// Error indicating that the state contains improperly encoded data.
    #[error("state contains invalid encoded data")]
    InvalidEncoding(#[from] alloy_rlp::Error),
    /// Error indicating that the contract execution was reverted.
    #[error("execution reverted")]
    Reverted,
}

/// The `State` struct represents the state of the contract.
#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    /// EVM (global) state trie with path to the contract account.
    state_trie: MerkleTrie,
    /// Storage trie containing the state of the beacon root contract.
    storage_trie: MerkleTrie,
}

impl State {
    /// Computes the state root.
    #[inline]
    pub fn root(&self) -> B256 {
        self.state_trie.hash_slow()
    }
}

/// The `BeaconRootsContract` is responsible for storing and retrieving historical beacon roots.
///
/// It is an exact reimplementation of the beacon roots contract as defined in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).
/// It is deployed at the address `000F3df6D732807Ef1319fB7B8bB8522d0Beac02` and has the
/// following storage layout:
/// - `timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH`: Stores the timestamp at this index.
/// - `root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH`: Stores the beacon root at this index.
pub struct BeaconRootsContract {
    storage: MerkleTrie,
}

impl BeaconRootsContract {
    /// The length of the buffer that stores historical entries, i.e., the number of stored
    /// timestamps and roots.
    pub const HISTORY_BUFFER_LENGTH: U256 = uint!(8191_U256);
    /// Address where the contract is deployed.
    #[allow(dead_code)]
    pub const ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

    /// Hash of the contract's address, where the contract is deployed.
    const ADDRESS_HASH: B256 =
        b256!("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42");
    /// Hash of the deployed EVM bytecode.
    const CODE_HASH: B256 =
        b256!("f57acd40259872606d76197ef052f3d35588dadf919ee1f0e3cb9b62d3f4b02c");

    /// Creates a new instance of the `BeaconRootsContract` by verifying the provided state.
    pub fn new(state: State) -> Result<Self, Error> {
        // retrieve the account data from the state trie using the contract's address hash
        let account: StateAccount = state
            .state_trie
            .get_rlp(Self::ADDRESS_HASH)?
            .unwrap_or_default();
        // validate the account's code hash and storage root
        if account.code_hash != Self::CODE_HASH {
            return Err(Error::NoContract);
        }
        let storage = state.storage_trie;
        if storage.hash_slow() != account.storage_root {
            return Err(Error::InvalidState);
        }

        Ok(Self { storage })
    }

    /// Retrieves the root associated with the provided `calldata` (timestamp).
    ///
    /// This behaves exactly like the EVM bytecode defined in EIP-4788.
    pub fn get(&self, calldata: U256) -> Result<B256, Error> {
        if calldata.is_zero() {
            return Err(Error::Reverted);
        }

        let timestamp_idx = calldata % Self::HISTORY_BUFFER_LENGTH;
        let timestamp = self.storage_get(timestamp_idx)?;

        if timestamp != calldata {
            return Err(Error::Reverted);
        }

        let root_idx = timestamp_idx + Self::HISTORY_BUFFER_LENGTH;
        let root = self.storage_get(root_idx)?;

        Ok(root.into())
    }

    /// Retrieves the root from a given `State` based on the provided `calldata` (timestamp).
    #[inline]
    pub fn get_from_state(state: State, calldata: U256) -> Result<B256, Error> {
        Self::new(state)?.get(calldata)
    }

    /// Retrieves a value from the contract's storage at the given index.
    fn storage_get(&self, index: U256) -> Result<U256, Error> {
        Ok(self
            .storage
            .get_rlp(keccak256(index.to_be_bytes::<32>()))?
            .unwrap_or_default())
    }

    /// Prepares and retrieves the beacon root from an RPC provider by constructing the
    /// necessary proof.
    ///
    /// It fetches the minimal set of Merkle proofs (for the contract's state and storage)
    /// required to verify and retrieve the beacon root associated with the given `calldata`
    /// (timestamp). It leverages the Ethereum `eth_getProof` RPC to get the account and
    /// storage proofs needed to validate the contract's state and storage.
    #[cfg(feature = "host")]
    pub async fn preflight_get<T, N, P>(
        calldata: U256,
        provider: P,
        block_id: alloy::eips::BlockId,
    ) -> anyhow::Result<(B256, State)>
    where
        T: alloy::transports::Transport + Clone,
        N: alloy::network::Network,
        P: alloy::providers::Provider<T, N>,
    {
        use anyhow::{anyhow, Context};

        // compute the keys of the two storage slots that will be accessed
        let timestamp_idx = calldata % Self::HISTORY_BUFFER_LENGTH;
        let root_idx = timestamp_idx + Self::HISTORY_BUFFER_LENGTH;

        // derive the minimal state needed to query and validate
        let proof = provider
            .get_proof(Self::ADDRESS, vec![timestamp_idx.into(), root_idx.into()])
            .block_id(block_id)
            .await
            .context("eth_getProof failed")?;
        let state = State {
            state_trie: MerkleTrie::from_rlp_nodes(proof.account_proof)
                .context("accountProof invalid")?,
            storage_trie: MerkleTrie::from_rlp_nodes(
                proof.storage_proof.iter().flat_map(|p| &p.proof),
            )
            .context("storageProof invalid")?,
        };

        // validate the returned state and compute the return value
        match Self::get_from_state(state.clone(), calldata) {
            Ok(returns) => Ok((returns, state)),
            Err(err) => match err {
                Error::Reverted => Err(anyhow!("BeaconRootsContract({}) reverted", calldata)),
                err => Err(err).context("API returned invalid state"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        network::{primitives::BlockTransactionsKind, BlockResponse},
        providers::{Provider, ProviderBuilder},
        rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
    };
    use test_log::test;

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";

    #[test(tokio::test)]
    #[ignore = "queries actual RPC nodes"]
    async fn beacon_roots_contract() {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // get the latest header
        let latest = el
            .get_block_by_number(AlloyBlockNumberOrTag::Latest, BlockTransactionsKind::Hashes)
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = latest.header();

        // query the contract for the latest timestamp, this should return parent_beacon_block_root
        let calldata = U256::from(header.timestamp);
        let (preflight, state) =
            BeaconRootsContract::preflight_get(calldata, el, header.hash.into())
                .await
                .expect("preflighting BeaconRootsContract failed");
        assert_eq!(state.root(), header.state_root);
        assert_eq!(preflight, header.parent_beacon_block_root.unwrap());

        // executing the contract from the exact state should return the same value
        assert_eq!(
            preflight,
            dbg!(BeaconRootsContract::get_from_state(state, calldata)).unwrap()
        );
    }
}
