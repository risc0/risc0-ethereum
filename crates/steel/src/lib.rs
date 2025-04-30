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
use alloy_rpc_types::{Filter, FilteredParams};
use alloy_sol_types::SolValue;
use config::ChainSpec;
use revm::{
    context::{result::HaltReasonTr, BlockEnv},
    Database as RevmDatabase,
};
use std::{error::Error, fmt::Debug};

pub mod account;
pub mod beacon;
mod block;
pub mod config;
mod contract;
pub mod ethereum;
#[cfg(feature = "unstable-event")]
pub mod event;
#[cfg(feature = "unstable-history")]
pub mod history;
#[cfg(not(feature = "unstable-history"))]
mod history;
#[cfg(feature = "host")]
pub mod host;
mod merkle;
mod mpt;
pub mod serde;
mod state;
#[cfg(feature = "unstable-verifier")]
mod verifier;

pub use account::Account;
pub use beacon::BeaconInput;
pub use block::BlockInput;
pub use contract::{CallBuilder, Contract};
pub use mpt::MerkleTrie;
pub use state::{StateAccount, StateDb};

#[cfg(feature = "unstable-event")]
pub use event::Event;
#[cfg(feature = "unstable-history")]
pub use history::HistoryInput;
#[cfg(not(feature = "unstable-history"))]
pub(crate) use history::HistoryInput;
#[cfg(feature = "unstable-verifier")]
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
    pub fn into_env(self) -> GuestEvmEnv<F> {
        match self {
            EvmInput::Block(input) => input.into_env(),
            EvmInput::Beacon(input) => input.into_env(),
            EvmInput::History(input) => input.into_env(),
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
    pub fn into_env(self) -> GuestEvmEnv<F> {
        let mut env = self.input.into_env();
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

/// Checks if a bloom filter matches the given filter parameters.
// TODO: Move to `event` once no longer unstable
#[allow(dead_code)]
#[inline]
pub(crate) fn matches_filter(bloom: Bloom, filter: &Filter) -> bool {
    FilteredParams::matches_address(bloom, &FilteredParams::address_filter(&filter.address))
        && FilteredParams::matches_topics(bloom, &FilteredParams::topics_filter(&filter.topics))
}

/// Alias for readability, do not make public.
pub(crate) type GuestEvmEnv<F> = EvmEnv<StateDb, F, Commitment>;

/// Represents types constructible from basic call data
pub trait FromCallData: Sized {
    /// Creates a new instance from a target address and input data.
    /// This typically initializes a transaction environment with the minimum
    /// required fields for a simple contract call.
    fn new(address: Address, data: Bytes) -> Self;
}

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
    ///
    /// Must implement [`FromCallData`] to allow construction from basic call info (address, data).
    type Tx: IntoTxEnv<Self::Tx> + FromCallData + Send + Sync + 'static;
    /// The error type returned by `Self::Evm` during execution.
    type Error<DBError: Error + Send + Sync + 'static>: EvmError;
    /// The type representing reasons why `Self::Evm` might halt execution.
    type HaltReason: HaltReasonTr + Send + Sync + 'static;
    /// The EVM specification identifier (e.g., Shanghai, Cancun) used by `Self::Evm`.
    type Spec: Default + Ord + ToString + Debug + Copy + Send + Sync + 'static;
    /// The block header type providing execution context (e.g., timestamp, number, basefee).
    type Header: EvmBlockHeader<Spec = Self::Spec>
        + Clone
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static;

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
    ///
    /// It uses the default configuration for the latest specification.
    pub(crate) fn new(db: D, header: Sealed<F::Header>, commit: C) -> Self {
        Self {
            db: Some(db),
            chain_id: 1,
            spec: F::Spec::default(),
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
    /// Sets the chain ID and specification ID from the given chain spec.
    ///
    /// This will panic when there is no valid specification ID for the current block.
    pub fn with_chain_spec(mut self, chain_spec: &ChainSpec<F::Spec>) -> Self {
        self.chain_id = chain_spec.chain_id();
        self.spec = *chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self.commit.configID = chain_spec.digest();

        self
    }

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
    #[cfg(feature = "unstable-event")]
    /// Returns the receipts root hash of the block.
    fn receipts_root(&self) -> &B256;
    #[cfg(feature = "unstable-event")]
    /// Returns the logs bloom filter of the block
    fn logs_bloom(&self) -> &Bloom;

    /// Returns the EVM block environment equivalent to this block header.
    fn to_block_env(&self, spec: Self::Spec) -> BlockEnv;
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
            /// The cryptographic digest of the commitment.
            ///
            /// This is the core of the commitment, representing the data being committed to,
            /// e.g., the hash of the execution block.
            bytes32 digest;
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
    pub const fn new(version: u16, id: u64, digest: B256, config_id: B256) -> Commitment {
        Self {
            id: Commitment::encode_id(id, version),
            digest,
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
