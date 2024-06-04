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

#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_primitives::{
    b256, keccak256, Address, BlockNumber, Bytes, Sealable, Sealed, TxNumber, B256, U256,
};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable};

use revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg, HashMap, SpecId};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, rc::Rc};

pub mod config;
mod contract;
pub mod ethereum;
#[cfg(feature = "host")]
pub mod host;
mod mpt;

pub use contract::{CallBuilder, Contract};
pub use mpt::MerkleTrie;

/// The serializable input to derive and validate a [EvmEnv].
#[derive(Debug, Serialize, Deserialize)]
pub struct EvmInput<H> {
    pub header: H,
    pub state_trie: MerkleTrie,
    pub storage_tries: Vec<MerkleTrie>,
    pub contracts: Vec<Bytes>,
    pub ancestors: Vec<H>,
}

impl<H: EvmBlockHeader> EvmInput<H> {
    /// Converts the input into a [EvmEnv] for execution.
    ///
    /// This method verifies that the state matches the state root in the header and panics if not.
    pub fn into_env(self) -> GuestEvmEnv<H> {
        // verify that the state root matches the state trie
        let state_root = self.state_trie.hash_slow();
        assert_eq!(self.header.state_root(), &state_root, "State root mismatch");

        // seal the header to compute its block hash
        let header = self.header.seal_slow();

        // validate that ancestor headers form a valid chain
        let mut block_hashes = HashMap::with_capacity(self.ancestors.len() + 1);
        block_hashes.insert(header.number(), header.seal());

        let mut previous_header = header.inner();
        for ancestor in &self.ancestors {
            let ancestor_hash = ancestor.hash_slow();
            assert_eq!(
                previous_header.parent_hash(),
                &ancestor_hash,
                "Invalid chain: block {} is not the parent of block {}",
                ancestor.number(),
                previous_header.number()
            );
            block_hashes.insert(ancestor.number(), ancestor_hash);
            previous_header = ancestor;
        }

        let db = StateDb::new(
            self.state_trie,
            self.storage_tries,
            self.contracts,
            block_hashes,
        );

        EvmEnv::new(db, header)
    }
}

// Keep everything in the Steel library private except the commitment.
mod private {
    alloy_sol_types::sol!("../contracts/src/steel/Steel.sol");
}

/// Solidity struct representing the committed block used for validation.
pub use private::Steel::Commitment as SolCommitment;

/// Alias for readability, do not make public.
pub(crate) type GuestEvmEnv<H> = EvmEnv<StateDb, H>;

/// The environment to execute the contract calls in.
pub struct EvmEnv<D, H> {
    db: D,
    cfg_env: CfgEnvWithHandlerCfg,
    header: Sealed<H>,
}

impl<D, H: EvmBlockHeader> EvmEnv<D, H> {
    /// Creates a new environment.
    /// It uses the default configuration for the latest specification.
    pub fn new(db: D, header: Sealed<H>) -> Self {
        let cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(Default::default(), SpecId::LATEST);

        Self {
            db,
            cfg_env,
            header,
        }
    }

    /// Sets the chain ID and specification ID from the given chain spec.
    pub fn with_chain_spec(mut self, chain_spec: &config::ChainSpec) -> Self {
        self.cfg_env.chain_id = chain_spec.chain_id();
        self.cfg_env.handler_cfg.spec_id = chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self
    }

    /// Returns the [SolCommitment] used to validate the environment.
    pub fn block_commitment(&self) -> SolCommitment {
        SolCommitment {
            blockHash: self.header.seal(),
            blockNumber: U256::from(self.header.number()),
        }
    }

    /// Returns the header of the environment.
    pub fn header(&self) -> &H {
        self.header.inner()
    }
}

/// A simple read-only EVM database.
///
/// It is backed by a single [MerkleTrie] for the accounts and one [MerkleTrie] each for the
/// accounts' storages. It panics when data is queried that is not contained in the tries.
pub struct StateDb {
    state_trie: MerkleTrie,
    storage_tries: HashMap<B256, Rc<MerkleTrie>>,
    contracts: HashMap<B256, Bytes>,
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

    fn account(&self, address: Address) -> Option<StateAccount> {
        self.state_trie
            .get_rlp(keccak256(address))
            .expect("invalid state value")
    }

    fn code_by_hash(&self, hash: B256) -> &Bytes {
        self.contracts
            .get(&hash)
            .unwrap_or_else(|| panic!("code not found: {}", hash))
    }

    fn block_hash(&self, number: U256) -> B256 {
        // block number is never bigger then u64::MAX
        let number: u64 = number.to();
        let hash = self
            .block_hashes
            .get(&number)
            .unwrap_or_else(|| panic!("block not found: {}", number));
        *hash
    }

    fn storage_trie(&self, root: &B256) -> Option<&Rc<MerkleTrie>> {
        self.storage_tries.get(root)
    }
}

/// Hash of an empty byte array, i.e. `keccak256([])`.
pub const KECCAK_EMPTY: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// Represents an account within the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct StateAccount {
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
            storage_root: mpt::EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        }
    }
}

/// An EVM abstraction of a block header.
pub trait EvmBlockHeader: Sealable {
    /// Returns the hash of the parent block's header.
    fn parent_hash(&self) -> &B256;
    /// Returns the block number.
    fn number(&self) -> BlockNumber;
    /// Returns the block timestamp.
    fn timestamp(&self) -> u64;
    /// Returns the state root hash.
    fn state_root(&self) -> &B256;

    /// Fills the EVM block environment with the header's data.
    fn fill_block_env(&self, blk_env: &mut BlockEnv);
}
