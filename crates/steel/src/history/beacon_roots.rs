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

use crate::{MerkleTrie, StateAccount};
use alloy_primitives::{address, b256, keccak256, uint, Address, B256, U256};
use revm::{
    database::DBErrorMarker,
    state::{AccountInfo, Bytecode},
    Database,
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

/// Address where the contract is deployed.
pub const ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

/// The length of the buffer that stores historical entries, i.e., the number of stored
/// timestamps and roots.
const HISTORY_BUFFER_LENGTH: U256 = uint!(8191_U256);
/// Hash of the contract's address, where the contract is deployed.
const ADDRESS_HASH: B256 =
    b256!("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42");
/// Hash of the deployed EVM bytecode.
const CODE_HASH: B256 = b256!("f57acd40259872606d76197ef052f3d35588dadf919ee1f0e3cb9b62d3f4b02c");

/// Enum representing possible errors that can occur within the `BeaconRootsContract`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// Unspecified error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DBErrorMarker for Error {}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

#[cfg(feature = "host")]
impl From<crate::host::db::provider::Error> for Error {
    fn from(value: crate::host::db::provider::Error) -> Self {
        anyhow::Error::new(value).into()
    }
}

/// A simplified MPT-based read-only EVM database implementation only containing the state of the
/// beacon roots contract.
#[derive(Clone, Serialize, Deserialize)]
pub struct BeaconRootsState {
    /// EVM (global) state trie with path to the beacon roots contract.
    state_trie: MerkleTrie,
    /// Storage trie containing the state of the beacon roots contract.
    storage_trie: MerkleTrie,
}

/// Returns the timestamp stored in the slot which corresponds to the given `calldata` (timestamp).
#[cfg(feature = "host")]
pub(super) async fn get_timestamp<N, P>(
    calldata: U256,
    provider: P,
    block_id: alloy::eips::BlockId,
) -> anyhow::Result<U256>
where
    N: alloy::network::Network,
    P: alloy::providers::Provider<N>,
{
    // compute the key of the storage slot
    let timestamp_idx = calldata % HISTORY_BUFFER_LENGTH;
    // return its value
    anyhow::Context::context(
        provider
            .get_storage_at(ADDRESS, timestamp_idx)
            .block_id(block_id)
            .await,
        "eth_getStorageAt failed",
    )
}

impl BeaconRootsState {
    /// Computes the state root.
    #[inline]
    pub fn root(&self) -> B256 {
        self.state_trie.hash_slow()
    }

    /// Prepares the [BeaconRootsState] by retrieving the beacon root from an RPC provider and
    /// constructing the necessary proofs.
    ///
    /// It fetches the minimal set of Merkle proofs (for the contract's state and storage) required
    /// to verify and retrieve the beacon root associated with the given `calldata` (timestamp).
    #[cfg(feature = "host")]
    pub async fn preflight_get<N, P>(
        calldata: U256,
        provider: P,
        block_id: alloy::eips::BlockId,
    ) -> anyhow::Result<(B256, BeaconRootsState)>
    where
        N: alloy::network::Network,
        P: alloy::providers::Provider<N>,
    {
        use anyhow::{anyhow, Context};

        // compute the keys of the two storage slots that will be accessed
        let timestamp_idx = calldata % HISTORY_BUFFER_LENGTH;
        let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH;

        // derive the minimal state needed to query and validate
        let proof = provider
            .get_proof(ADDRESS, vec![timestamp_idx.into(), root_idx.into()])
            .block_id(block_id)
            .await
            .context("eth_getProof failed")?;
        let mut state = BeaconRootsState {
            state_trie: MerkleTrie::from_rlp_nodes(proof.account_proof)
                .context("accountProof invalid")?,
            storage_trie: MerkleTrie::from_rlp_nodes(
                proof.storage_proof.iter().flat_map(|p| &p.proof),
            )
            .context("storageProof invalid")?,
        };

        // validate the returned state and compute the return value
        match BeaconRootsContract::get_from_db(&mut state, calldata) {
            Ok(returns) => Ok((returns, state)),
            Err(err) => match err {
                Error::Reverted => Err(anyhow!("BeaconRootsContract({}) reverted", calldata)),
                err => Err(err).context("RPC error"),
            },
        }
    }
}

/// Implements the Database trait, but only for the account of the beacon roots contract.
impl Database for BeaconRootsState {
    type Error = Error;

    #[inline(always)]
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // only allow accessing the beacon roots contract's address
        assert_eq!(address, ADDRESS);
        let account: StateAccount = self.state_trie.get_rlp(ADDRESS_HASH)?.unwrap_or_default();
        // and the account storage must match the storage trie
        if account.storage_root != self.storage_trie.hash_slow() {
            return Err(Error::InvalidState);
        }

        Ok(Some(AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            code: None,
        }))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // should never be called.
        unimplemented!()
    }

    #[inline(always)]
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        // only allow accessing the beacon roots contract's address
        assert_eq!(address, ADDRESS);
        Ok(self
            .storage_trie
            .get_rlp(keccak256(index.to_be_bytes::<32>()))?
            .unwrap_or_default())
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        // should never be called.
        unimplemented!()
    }
}

/// The `BeaconRootsContract` is responsible for storing and retrieving historical beacon roots.
///
/// It is an exact reimplementation of the beacon roots contract as defined in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).
/// It is deployed at the address `000F3df6D732807Ef1319fB7B8bB8522d0Beac02` and has the
/// following storage layout:
/// - `timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH`: Stores the timestamp at this index.
/// - `root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH`: Stores the beacon root at this index.
pub struct BeaconRootsContract<D> {
    db: D,
}

impl<D> BeaconRootsContract<D>
where
    D: Database,
    Error: From<<D as Database>::Error>,
{
    /// Creates a new instance of the `BeaconRootsContract` from the given db.
    pub fn new(mut db: D) -> Result<Self, Error> {
        // retrieve the account data from the state trie using the contract's address hash
        let account = db.basic(ADDRESS)?.unwrap_or_default();
        // validate the account's code hash
        if account.code_hash != CODE_HASH {
            return Err(Error::NoContract);
        }

        Ok(Self { db })
    }

    /// Retrieves the root associated with the provided `calldata` (timestamp).
    ///
    /// This behaves exactly like the EVM bytecode defined in EIP-4788.
    pub fn get(&mut self, calldata: U256) -> Result<B256, Error> {
        if calldata.is_zero() {
            return Err(Error::Reverted);
        }

        let timestamp_idx = calldata % HISTORY_BUFFER_LENGTH;
        let timestamp = self.db.storage(ADDRESS, timestamp_idx)?;

        if timestamp != calldata {
            return Err(Error::Reverted);
        }

        let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH;
        let root = self.db.storage(ADDRESS, root_idx)?;

        Ok(root.into())
    }

    /// Retrieves the root associated with the provided `calldata` (timestamp) from the given `db`.
    #[inline]
    pub fn get_from_db(db: D, calldata: U256) -> Result<B256, Error> {
        Self::new(db)?.get(calldata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_el_url;
    use alloy::{
        network::BlockResponse,
        providers::{Provider, ProviderBuilder},
        rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
    };
    use test_log::test;

    #[test(tokio::test)]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn beacon_roots_contract() {
        let el = ProviderBuilder::new().connect_http(get_el_url());

        // get the latest header
        let latest = el
            .get_block_by_number(AlloyBlockNumberOrTag::Latest)
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = latest.header();

        // query the contract for the latest timestamp, this should return parent_beacon_block_root
        let calldata = U256::from(header.timestamp);
        let (preflight, mut state) =
            BeaconRootsState::preflight_get(calldata, el, header.hash.into())
                .await
                .expect("preflighting BeaconRootsContract failed");
        assert_eq!(state.root(), header.state_root);
        assert_eq!(preflight, header.parent_beacon_block_root.unwrap());

        // executing the contract from the exact state should return the same value
        assert_eq!(
            preflight,
            dbg!(BeaconRootsContract::get_from_db(&mut state, calldata)).unwrap()
        );
    }
}
