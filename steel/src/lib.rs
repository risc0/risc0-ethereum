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
use config::ChainSpec;
use revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg, SpecId};

pub mod beacon;
mod block;
pub mod config;
mod contract;
pub mod ethereum;
#[cfg(feature = "host")]
pub mod host;
pub mod merkle;
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
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment;
}

/// A generalized input type consisting of a block-based input and a commitment wrapper.
/// The `commit` field provides a mechanism to generate a commitment to the block header
/// contained within the `input` field.
#[derive(Clone, Serialize, Deserialize)]
pub struct ComposeInput<H, C> {
    input: BlockInput<H>,
    commit: C,
}

impl<H: EvmBlockHeader, C: BlockHeaderCommit<H>> ComposeInput<H, C> {
    /// Creates a new composed input from a [BlockInput] and a [BlockHeaderCommit].
    #[must_use]
    #[inline]
    pub const fn new(input: BlockInput<H>, commit: C) -> Self {
        Self { input, commit }
    }

    /// Disassembles this `ComposeInput`, returning the underlying input and commitment creator.
    #[inline]
    pub fn into_parts(self) -> (BlockInput<H>, C) {
        (self.input, self.commit)
    }

    /// Converts the input into a [EvmEnv] for verifiable state access in the guest.
    pub fn into_env(self) -> GuestEvmEnv<H> {
        let mut env = self.input.into_env();
        env.commitment = self.commit.commit(&env.header, env.commitment.configID);

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
            ChainSpec::DEFAULT_DIGEST,
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
    pub fn with_chain_spec(mut self, chain_spec: &ChainSpec) -> Self {
        self.cfg_env.chain_id = chain_spec.chain_id();
        self.cfg_env.handler_cfg.spec_id = chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self.commitment.configID = chain_spec.digest();

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
        /// A Solidity struct representing a commitment used for validation.
        ///
        /// This struct is used to commit to a specific claim, such as the hash of an execution block
        /// or a beacon chain state. It includes a version, an identifier, the claim itself, and a
        /// configuration ID to ensure the commitment is valid for the intended network.
        #[derive(Default, PartialEq, Eq, Hash)]
        struct Commitment {
            /// Commitment ID.
            ///
            /// This ID combines the version and the actual identifier of the claim, such as the block number.
            uint256 id;
            /// The cryptographic claim.
            ///
            /// This is the core of the commitment, representing the data being committed to,
            /// e.g., the hash of the execution block.
            bytes32 claim;
            /// The cryptographic digest of the network configuration.
            ///
            /// This ID ensures that the commitment is valid only for the specific network configuration
            /// it was created for.
            bytes32 configID;
        }
    }
}

pub use private::Commitment;

/// Version of a [`Commitment`].
#[repr(u16)]
#[derive(Debug, PartialEq, Eq)]
pub enum CommitmentVersion {
    /// Commitment to an execution block.
    Block,
    /// Commitment to a beacon chain state.
    Beacon,
}

impl Commitment {
    /// The size in bytes of the ABI-encoded commitment.
    pub const ABI_ENCODED_SIZE: usize = 3 * 32;

    /// Creates a new commitment.
    #[inline]
    pub const fn new(version: u16, id: u64, claim: B256, config_id: B256) -> Commitment {
        Self {
            id: Commitment::encode_id(id, version),
            claim,
            configID: config_id,
        }
    }

    /// Decodes the `id` field into the claim ID and the commitment version.
    #[inline]
    pub fn decode_id(&self) -> (U256, u16) {
        let decoded = self.id
            & uint!(0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256);
        let version = (self.id.as_limbs()[3] >> 48) as u16;
        (decoded, version)
    }

    /// ABI-encodes the commitment.
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        SolValue::abi_encode(self)
    }

    /// Encodes an ID and version into a single [U256] value.
    const fn encode_id(id: u64, version: u16) -> U256 {
        U256::from_limbs([id, 0, 0, (version as u64) << 48])
    }
}

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (id, version) = self.decode_id();
        f.debug_struct("Commitment")
            .field("version", &version)
            .field("id", &id)
            .field("claim", &self.claim)
            .field("configID", &self.configID)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn size() {
        let tests = vec![
            Commitment::default(),
            Commitment::new(
                u16::MAX,
                u64::MAX,
                B256::repeat_byte(0xFF),
                B256::repeat_byte(0xFF),
            ),
        ];
        for test in tests {
            assert_eq!(test.abi_encode().len(), Commitment::ABI_ENCODED_SIZE);
        }
    }

    #[test]
    fn versioned_id() {
        let tests = vec![(u64::MAX, u16::MAX), (u64::MAX, 0), (0, u16::MAX), (0, 0)];
        for test in tests {
            let commit = Commitment::new(test.1, test.0, B256::default(), B256::default());
            let (id, version) = commit.decode_id();
            assert_eq!((id.to(), version), test);
        }
    }
}
