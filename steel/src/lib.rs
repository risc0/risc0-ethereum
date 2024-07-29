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

use std::fmt::Debug;

use ::serde::{Deserialize, Serialize};
use alloy_primitives::{BlockNumber, Bytes, Sealable, Sealed, B256, U256};
use revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg, HashMap, SpecId};

pub mod config;
mod contract;
pub mod ethereum;
#[cfg(feature = "host")]
pub mod host;
mod mpt;
pub mod serde;
mod state;

pub use contract::{CallBuilder, Contract};
pub use mpt::MerkleTrie;

/// The serializable input to derive and validate a [EvmEnv].
#[derive(Debug, Serialize, Deserialize)]
pub struct EvmInput<H> {
    header: H,
    state_trie: MerkleTrie,
    storage_tries: Vec<MerkleTrie>,
    contracts: Vec<Bytes>,
    ancestors: Vec<H>,
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
    alloy_sol_types::sol! {
        #![sol(all_derives)]
        /// A Commitment struct representing a block number and its block hash.
        struct Commitment {
            uint256 blockNumber; // Block number at which the commitment was made.
            bytes32 blockHash; // Hash of the block at the specified block number.
        }
    }
}

/// Solidity struct representing the committed block used for validation.
pub use private::Commitment as SolCommitment;
use state::StateDb;

/// Alias for readability, do not make public.
pub(crate) type GuestEvmEnv<H> = EvmEnv<StateDb, H>;

/// The environment to execute the contract calls in.
pub struct EvmEnv<D, H> {
    db: Option<D>,
    cfg_env: CfgEnvWithHandlerCfg,
    header: Sealed<H>,
}

impl<D, H: EvmBlockHeader> EvmEnv<D, H> {
    /// Creates a new environment.
    /// It uses the default configuration for the latest specification.
    pub fn new(db: D, header: Sealed<H>) -> Self {
        let cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(Default::default(), SpecId::LATEST);

        Self {
            db: Some(db),
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
    #[inline]
    pub fn header(&self) -> &H {
        self.header.inner()
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
