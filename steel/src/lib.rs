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

use ::serde::{Deserialize, Serialize};
use alloy_primitives::{uint, BlockNumber, Sealable, Sealed, B256, U256};
use alloy_sol_types::SolValue;
use revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg, SpecId};

pub mod beacon;
mod block;
pub mod config;
mod contract;
pub mod ethereum;
#[cfg(feature = "host")]
pub mod host;
mod merkle;
mod mpt;
pub mod serde;
mod state;

pub use beacon::BeaconInput;
pub use block::BlockInput;
pub use contract::{CallBuilder, Contract};
pub use mpt::MerkleTrie;
pub use state::{StateAccount, StateDb};

/// The serializable input to derive and validate an [EvmEnv] from.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub enum EvmInput<H> {
    /// Input committing to the corresponding execution block hash.
    Block(BlockInput<H>),
    /// Input committing to the corresponding Beacon Chain block root.
    Beacon(BeaconInput<H>),
}

impl<H: EvmBlockHeader> EvmInput<H> {
    /// Converts the input into a [EvmEnv] for execution.
    ///
    /// This method verifies that the state matches the state root in the header and panics if not.
    #[inline]
    pub fn into_env(self) -> GuestEvmEnv<H> {
        match self {
            EvmInput::Block(input) => input.into_env(),
            EvmInput::Beacon(input) => input.into_env(),
        }
    }
}

/// A trait linking the block header to a commitment.
pub trait BlockHeaderCommit<H: EvmBlockHeader> {
    /// Creates a verifiable [Commitment] of the `header`.
    fn commit(self, header: &Sealed<H>) -> Commitment;
}

/// A generalized input type consisting of a block based input and a commitment wrapper.
#[derive(Clone, Serialize, Deserialize)]
pub struct ComposeInput<H, C> {
    input: BlockInput<H>,
    commit: C,
}

impl<H: EvmBlockHeader, C: BlockHeaderCommit<H>> ComposeInput<H, C> {
    /// Creates a new composed input from a [BlockInput] and a [BlockHeaderCommit].
    pub const fn new(input: BlockInput<H>, commit: C) -> Self {
        Self { input, commit }
    }

    /// Disassembles this `ComposeInput`, returning the underlying input and commitment creator.
    pub fn into_parts(self) -> (BlockInput<H>, C) {
        (self.input, self.commit)
    }

    /// Converts the input into a [EvmEnv] for verifiable state access in the guest.
    pub fn into_env(self) -> GuestEvmEnv<H> {
        let mut env = self.input.into_env();
        env.commitment = self.commit.commit(&env.header);

        env
    }
}

/// Alias for readability, do not make public.
pub(crate) type GuestEvmEnv<H> = EvmEnv<StateDb, H>;

/// The environment to execute the contract calls in.
pub struct EvmEnv<D, H> {
    db: Option<D>,
    cfg_env: CfgEnvWithHandlerCfg,
    header: Sealed<H>,
    commitment: Commitment,
}

impl<D, H: EvmBlockHeader> EvmEnv<D, H> {
    /// Creates a new environment.
    ///
    /// It uses the default configuration for the latest specification.
    pub(crate) fn new(db: D, header: Sealed<H>) -> Self {
        let cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(Default::default(), SpecId::LATEST);
        let commitment = Commitment::new(
            CommitmentVersion::Block as u16,
            header.number(),
            header.seal(),
        );

        Self {
            db: Some(db),
            cfg_env,
            header,
            commitment,
        }
    }

    /// Sets the chain ID and specification ID from the given chain spec.
    ///
    /// This will panic when there is no valid specification ID for the current block.
    pub fn with_chain_spec(mut self, chain_spec: &config::ChainSpec) -> Self {
        self.cfg_env.chain_id = chain_spec.chain_id();
        self.cfg_env.handler_cfg.spec_id = chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self
    }

    /// Returns the sealed header of the environment.
    #[inline]
    pub fn header(&self) -> &Sealed<H> {
        &self.header
    }

    /// Returns the [Commitment] used to validate the environment.
    #[inline]
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Consumes and returns the [Commitment] used to validate the environment.
    #[inline]
    pub fn into_commitment(self) -> Commitment {
        self.commitment
    }

    fn db(&self) -> &D {
        // safe unwrap: self cannot be borrowed without a DB
        self.db.as_ref().unwrap()
    }

    #[allow(dead_code)]
    fn db_mut(&mut self) -> &mut D {
        // safe unwrap: self cannot be borrowed without a DB
        self.db.as_mut().unwrap()
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

// Keep everything in the Steel library private except the commitment.
mod private {
    alloy_sol_types::sol! {
        #![sol(all_derives)]
        /// Solidity struct representing the Steel commitment used for validation.
        struct Commitment {
            /// Encodes both the block identifier (block number or timestamp) and the version.
            uint256 blockID;
            /// The block hash or beacon block root, used for validation.
            bytes32 blockDigest;
        }
    }
}

pub use private::Commitment;

/// The different versions of a [Commitment].
#[repr(u16)]
enum CommitmentVersion {
    Block,
    Beacon,
}

impl Commitment {
    /// Constructs a new commitment.
    #[inline]
    pub const fn new(version: u16, id: u64, digest: B256) -> Commitment {
        Self {
            blockID: Commitment::encode_id(id, version),
            blockDigest: digest,
        }
    }

    /// ABI-encodes the commitment.
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        SolValue::abi_encode(self)
    }

    /// Returns the block identifier without the commitment version.
    #[inline]
    pub fn block_id(&self) -> u64 {
        Self::decode_id(self.blockID).0.try_into().unwrap()
    }

    /// Encodes an ID and version into a single [U256] value.
    #[inline]
    pub(crate) const fn encode_id(id: u64, version: u16) -> U256 {
        U256::from_limbs([id, 0, 0, (version as u64) << 48])
    }

    /// Decodes an ID and version from a single [U256] value.
    #[inline]
    pub(crate) fn decode_id(id: U256) -> (U256, u16) {
        let decoded =
            id & uint!(0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256);
        let version = (id.as_limbs()[3] >> 48) as u16;
        (decoded, version)
    }
}

#[cfg(test)]
mod tests {
    use super::Commitment;

    #[test]
    fn versioned_id() {
        let tests = vec![(u64::MAX, u16::MAX), (u64::MAX, 0), (0, u16::MAX), (0, 0)];
        for test in tests {
            let id = Commitment::encode_id(test.0, test.1);
            let (id, version) = Commitment::decode_id(id);
            assert_eq!((id.to(), version), test);
        }
    }
}
