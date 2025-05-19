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

#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// Re-export of [alloy], provided to ensure that the correct version of the types used in the
/// public API are available in case multiple versions of [alloy] are in use.
///
/// Because [alloy] is a v0.x crate, it is not covered under the semver policy of this crate.
#[cfg(feature = "host")]
pub use alloy;

use ::serde::{de::DeserializeOwned, Deserialize, Serialize};
use alloy_evm::{Database, Evm, EvmError, IntoTxEnv};
use alloy_primitives::{
    uint, Address, BlockNumber, Bloom, Bytes, ChainId, Log, Sealable, Sealed, B256, U256,
};
use alloy_rpc_types::Filter;
use alloy_sol_types::SolValue;
use config::ChainSpec;
use revm::{
    context::{result::HaltReasonTr, BlockEnv},
    Database as RevmDatabase,
};
use std::{error::Error, fmt, fmt::Debug};

pub mod account;
pub mod beacon;
mod block;
pub mod config;
mod contract;
pub mod ethereum;
pub mod event;
pub mod history;
#[cfg(feature = "host")]
pub mod host;
mod merkle;
mod mpt;
pub mod serde;
mod state;
#[cfg(test)]
mod test_utils;
mod verifier;

pub use account::Account;
pub use beacon::BeaconInput;
pub use block::BlockInput;
pub use contract::{CallBuilder, Contract};
pub use event::Event;
pub use history::HistoryInput;
pub use mpt::MerkleTrie;
pub use state::{StateAccount, StateDb};
pub use verifier::SteelVerifier;

/// The serializable input to derive and validate an [EvmEnv] from.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub enum EvmInput<F: EvmFactory> {
    /// Input committing to the corresponding execution block hash.
    Block(BlockInput<F>),
    /// Input committing to the corresponding Beacon Chain block root.
    Beacon(BeaconInput<F>),
    /// Input recursively committing to multiple Beacon Chain block root.
    History(HistoryInput<F>),
}

impl<F: EvmFactory> EvmInput<F> {
    /// Converts the input into a [EvmEnv] for execution.
    ///
    /// This method verifies that the state matches the state root in the header and panics if not.
    #[inline]
    pub fn into_env(self, chain_spec: &ChainSpec<F::Spec>) -> GuestEvmEnv<F> {
        match self {
            EvmInput::Block(input) => input.into_env(chain_spec),
            EvmInput::Beacon(input) => input.into_env(chain_spec),
            EvmInput::History(input) => input.into_env(chain_spec),
        }
    }
}

/// A trait linking the block header to a commitment.
pub trait BlockHeaderCommit<H> {
    /// Creates a verifiable [Commitment] of the `header`.
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment;
}

/// A generalized input type consisting of a block-based input and a commitment wrapper.
///
/// The `commit` field provides a mechanism to generate a commitment to the block header
/// contained within the `input` field.
#[derive(Clone, Serialize, Deserialize)]
pub struct ComposeInput<F: EvmFactory, C> {
    input: BlockInput<F>,
    commit: C,
}

impl<F: EvmFactory, C: BlockHeaderCommit<F::Header>> ComposeInput<F, C> {
    /// Creates a new composed input from a [BlockInput] and a [BlockHeaderCommit].
    pub const fn new(input: BlockInput<F>, commit: C) -> Self {
        Self { input, commit }
    }

    /// Disassembles this `ComposeInput`, returning the underlying input and commitment creator.
    pub fn into_parts(self) -> (BlockInput<F>, C) {
        (self.input, self.commit)
    }

    /// Converts the input into a [EvmEnv] for verifiable state access in the guest.
    pub fn into_env(self, chain_spec: &ChainSpec<F::Spec>) -> GuestEvmEnv<F> {
        let mut env = self.input.into_env(chain_spec);
        env.commit = self.commit.commit(&env.header, env.commit.configID);

        env
    }
}

/// A database abstraction for the Steel EVM.
pub trait EvmDatabase: RevmDatabase {
    /// Retrieves all the logs matching the given [Filter].
    ///
    /// It returns an error, if the corresponding logs cannot be retrieved from DB.
    /// The filter must match the block hash corresponding to the DB, it will panic otherwise.
    fn logs(&mut self, filter: Filter) -> Result<Vec<Log>, <Self as RevmDatabase>::Error>;
}

/// Alias for readability, do not make public.
pub(crate) type GuestEvmEnv<F> = EvmEnv<StateDb, F, Commitment>;

/// Abstracts the creation and configuration of a specific EVM implementation.
///
/// This trait acts as a factory pattern, allowing generic code (like `Contract` and `CallBuilder`)
/// to operate with different underlying EVM engines (e.g., `revm`) without being
/// tightly coupled to a specific implementation. Implementors define the concrete types
/// associated with their chosen EVM and provide the logic to instantiate it.
pub trait EvmFactory {
    /// The concrete EVM execution environment type created by this factory.
    type Evm<DB: Database>: Evm<
        DB = DB,
        Tx = Self::Tx,
        HaltReason = Self::HaltReason,
        Error = Self::Error<DB::Error>,
        Spec = Self::Spec,
    >;
    /// The transaction environment type compatible with `Self::Evm`.
    type Tx: IntoTxEnv<Self::Tx> + Send + Sync + 'static;
    /// The error type returned by `Self::Evm` during execution.
    type Error<DBError: Error + Send + Sync + 'static>: EvmError;
    /// The type representing reasons why `Self::Evm` might halt execution.
    type HaltReason: HaltReasonTr + Send + Sync + 'static;
    /// The EVM specification identifier (e.g., Shanghai, Cancun) used by `Self::Evm`.
    type Spec: Ord + Serialize + Debug + Copy + Send + Sync + 'static;
    /// The block header type providing execution context (e.g., timestamp, number, basefee).
    type Header: EvmBlockHeader<Spec = Self::Spec>
        + Clone
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static;

    /// Creates a new transaction environment instance for a basic call.
    ///
    /// Implementors should create an instance of `Self::Tx`,
    /// populate it with the target `address` and input `data`, and apply appropriate
    /// defaults for other transaction fields (like caller, value, gas limit, etc.)
    /// required by the specific EVM implementation.
    fn new_tx(address: Address, data: Bytes) -> Self::Tx;

    /// Creates a new instance of the EVM defined by `Self::Evm`.
    fn create_evm<DB: Database>(
        db: DB,
        chain_id: ChainId,
        spec: Self::Spec,
        header: &Self::Header,
    ) -> Self::Evm<DB>;
}

/// Represents the complete execution environment for EVM contract calls.
///
/// This struct encapsulates all necessary components to configure and run an EVM instance
/// compatible with the specified [EvmFactory]. It serves as the primary context object passed
/// around during EVM execution setup and interaction, both on the host (for preflight) and in the
/// guest.
pub struct EvmEnv<D, F: EvmFactory, C> {
    /// The database instance providing EVM state (accounts, storage).
    ///
    /// This is wrapped in an `Option` because ownership might need to be temporarily
    /// transferred during certain operations, particularly when moving execution into
    /// a blocking task or thread on the host during preflight simulation.
    db: Option<D>,
    /// The Chain ID of the EVM network (EIP-155).
    chain_id: ChainId,
    /// The EVM specification identifier, representing the active hardfork (e.g., Shanghai,
    /// Cancun).
    spec: F::Spec,
    /// The sealed block header providing context for the current transaction execution.
    header: Sealed<F::Header>,
    /// Auxiliary context or commitment handler.
    commit: C,
}

impl<D, F: EvmFactory, C> EvmEnv<D, F, C> {
    /// Creates a new environment.
    pub(crate) fn new(
        db: D,
        chain_spec: &ChainSpec<F::Spec>,
        header: Sealed<F::Header>,
        commit: C,
    ) -> Self {
        let spec = *chain_spec
            .active_fork(header.number(), header.timestamp())
            .unwrap();
        Self {
            db: Some(db),
            chain_id: chain_spec.chain_id,
            spec,
            header,
            commit,
        }
    }

    /// Returns the sealed header of the environment.
    #[inline]
    pub fn header(&self) -> &Sealed<F::Header> {
        &self.header
    }

    pub(crate) fn db(&self) -> &D {
        // safe unwrap: self cannot be borrowed without a DB
        self.db.as_ref().unwrap()
    }

    #[cfg(feature = "host")]
    pub(crate) fn db_mut(&mut self) -> &mut D {
        // safe unwrap: self cannot be borrowed without a DB
        self.db.as_mut().unwrap()
    }
}

impl<D, F: EvmFactory> EvmEnv<D, F, Commitment> {
    /// Returns the [Commitment] used to validate the environment.
    #[inline]
    pub fn commitment(&self) -> &Commitment {
        &self.commit
    }

    /// Consumes and returns the [Commitment] used to validate the environment.
    #[inline]
    pub fn into_commitment(self) -> Commitment {
        self.commit
    }
}

/// An EVM abstraction of a block header.
pub trait EvmBlockHeader: Sealable {
    /// Associated type for the EVM specification (e.g., London, Shanghai)
    type Spec: Copy;

    /// Returns the hash of the parent block's header.
    fn parent_hash(&self) -> &B256;
    /// Returns the block number.
    fn number(&self) -> BlockNumber;
    /// Returns the block timestamp.
    fn timestamp(&self) -> u64;
    /// Returns the state root hash.
    fn state_root(&self) -> &B256;
    /// Returns the receipts root hash of the block.
    fn receipts_root(&self) -> &B256;
    /// Returns the logs bloom filter of the block
    fn logs_bloom(&self) -> &Bloom;

    /// Returns the EVM block environment equivalent to this block header.
    fn to_block_env(&self, spec: Self::Spec) -> BlockEnv;
}

// Keep everything in the Steel library private except the commitment.
mod private {
    alloy_sol_types::sol! {
        /// A Solidity struct representing a commitment used for validation within Steel proofs.
        ///
        /// This struct is used to commit to a specific claim, such as the hash of an execution block
        /// or a beacon chain state root. It includes an identifier combining the claim type (version)
        /// and a specific instance identifier (e.g., block number), the claim digest itself, and a
        /// configuration ID to ensure the commitment is valid for the intended network configuration.
        /// This structure is designed to be ABI-compatible with Solidity for on-chain verification.
        #[derive(Default, PartialEq, Eq, Hash)]
        struct Commitment {
            /// Packed commitment identifier and version.
            ///
            /// This field encodes two distinct pieces of information into a single 256-bit unsigned integer:
            /// 1.  **Version (Top 16 bits):** Bits `[255..240]` store a `u16` representing the type or version
            ///     of the claim being made. See [CommitmentVersion] for defined values like
            ///     `Block` or `Beacon`.
            /// 2.  **Identifier (Bottom 64 bits):** Bits `[63..0]` store a `u64` value that uniquely identifies
            ///     the specific instance of the claim. For example, for a `Block` commitment, this
            ///     would be the block number. For a `Beacon` commitment, it would be the slot number.
            ///
            /// Use [Commitment::decode_id] to unpack this field into its constituent parts in Rust code.
            /// The packing scheme ensures efficient storage and retrieval while maintaining compatibility
            /// with Solidity's `uint256`.
            ///
            /// [CommitmentVersion]: crate::CommitmentVersion
            uint256 id;

            /// The cryptographic digest representing the core claim data.
            ///
            /// This is the actual data being attested to. The exact meaning depends on the `version` specified in the `id` field.
            bytes32 digest;

            /// A cryptographic digest identifying the network and prover configuration.
            ///
            /// This ID acts as a fingerprint of the context in which the commitment was generated,
            /// including details like the Ethereum chain ID, active hard forks (part of the chain spec),
            /// and potentially prover-specific settings. Verification must ensure this `configID`
            /// matches the verifier's current environment configuration to prevent cross-chain or
            /// misconfigured proof validation.
            bytes32 configID;
        }
    }
}

// Publicly export only the Commitment struct definition generated by the sol! macro.
pub use private::Commitment;

/// Version identifier for a [Commitment], indicating the type of claim.
///
/// This enum defines the valid types of commitments that can be created and verified.
/// The raw `u16` value of the enum variant is stored in the top 16 bits of the
/// [Commitment::id] field.
#[derive(Debug, Copy, Clone, PartialEq, Eq, enumn::N)]
#[repr(u16)]
#[non_exhaustive]
pub enum CommitmentVersion {
    /// Version 0: Commitment to an execution block hash indexed by its block number.
    Block = 0,
    /// Version 1: Commitment to a beacon block root indexed by its EIP-4788 child timestamp.
    Beacon = 1,
    /// Version 2: Commitment to a beacon block root indexed by its slot.
    Consensus = 2,
}

impl Commitment {
    /// The size in bytes of the ABI-encoded commitment (3 fields * 32 bytes/field = 96 bytes).
    pub const ABI_ENCODED_SIZE: usize = 3 * 32;

    /// Creates a new [Commitment] by packing the version and identifier into the `id` field.
    #[inline]
    pub const fn new(version: u16, id: u64, digest: B256, config_id: B256) -> Commitment {
        Self {
            id: Commitment::encode_id(id, version), // pack id and version
            digest,
            configID: config_id,
        }
    }

    /// Decodes the packed `Commitment.id` field into the identifier part and the version.
    ///
    /// This function extracts the version from the top 16 bits and returns the remaining part of
    /// the `id` field (which contains the instance identifier in its lower 64 bits) along with the
    /// `u16` version.
    #[inline]
    pub fn decode_id(&self) -> (U256, u16) {
        // define a mask to isolate the lower 240 bits (zeroing out the top 16 version bits)
        let id_mask =
            uint!(0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256);
        let id_part = self.id & id_mask;

        // extract the version by right-shifting the most significant limb (limbs[3]) by 48 bits
        let version = (self.id.as_limbs()[3] >> 48) as u16;

        (id_part, version)
    }

    /// ABI-encodes the commitment into a byte vector according to Solidity ABI specifications.
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        SolValue::abi_encode(self)
    }

    /// Packs a `u64` identifier and a `u16` version into a single `U256` value.
    const fn encode_id(id: u64, version: u16) -> U256 {
        U256::from_limbs([id, 0, 0, (version as u64) << 48])
    }
}

impl Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (id, version_code) = self.decode_id();
        let version = match CommitmentVersion::n(version_code) {
            Some(v) => format!("{:?}", v),
            None => format!("Unknown({:x})", version_code),
        };

        f.debug_struct("Commitment")
            .field("version", &version)
            .field("id", &id)
            .field("digest", &self.digest)
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
