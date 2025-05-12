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

//! Types related to commitments to the beacon block root.
use crate::{merkle, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput};
use alloy_primitives::{Sealed, B256};
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "host")]
pub(crate) mod host;

/// The generalized Merkle tree index of the `state_root` field in the `BeaconBlock`.
pub const STATE_ROOT_LEAF_INDEX: usize = 6434;

/// The generalized Merkle tree index of the `block_hash` field in the `BeaconBlock`.
pub const BLOCK_HASH_LEAF_INDEX: usize = 6444;

/// Input committing to the corresponding Beacon Chain block root.
pub type BeaconInput<F> = ComposeInput<F, BeaconCommit>;

/// A commitment that an execution block hash is included in a specific beacon block on the Ethereum
/// blockchain.
///
/// This type represents a commitment that proves the inclusion of an execution block's hash within
/// a particular beacon block on the Ethereum beacon chain. It relies on a Merkle proof to establish
/// this link, ensuring the integrity and verifiability of the connection between the execution
/// block and the beacon chain.
///
/// **Important:** This type currently relies on an underlying implementation that only supports the
/// Deneb fork of the beacon chain. If the beacon chain undergoes a future upgrade, this type's
/// functionality may be affected, potentially requiring updates to handle new block structures or
/// proof generation mechanisms.
///
/// Users should monitor for beacon chain upgrades and ensure they are using a compatible version of
/// this library.
pub type BeaconCommit = GeneralizedBeaconCommit<BLOCK_HASH_LEAF_INDEX>;

/// A beacon block identifier.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum BeaconBlockId {
    /// Timestamp of the child execution block, to query the beacon block root using the EIP-4788
    /// beacon roots contract.
    Eip4788(u64),
    /// Slot of the beacon block.
    Slot(u64),
}

impl fmt::Display for BeaconBlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BeaconBlockId::Eip4788(timestamp) => {
                write!(f, "eip4788-timestamp: {}", timestamp)
            }
            BeaconBlockId::Slot(slot) => write!(f, "slot: {}", slot),
        }
    }
}

impl BeaconBlockId {
    pub const fn as_version(&self) -> u16 {
        match self {
            BeaconBlockId::Eip4788(_) => CommitmentVersion::Beacon as u16,
            BeaconBlockId::Slot(_) => CommitmentVersion::Consensus as u16,
        }
    }
    pub const fn as_id(&self) -> u64 {
        match self {
            BeaconBlockId::Eip4788(ts) => *ts,
            BeaconBlockId::Slot(slot) => *slot,
        }
    }
}

/// A commitment to a field of the beacon block at a specific index in a Merkle tree, along with a
/// timestamp.
///
/// The constant generic parameter `LEAF_INDEX` specifies the generalized Merkle tree index of the
/// leaf node in the Merkle tree corresponding to the field.
#[derive(Clone, Serialize, Deserialize)]
pub struct GeneralizedBeaconCommit<const LEAF_INDEX: usize> {
    proof: Vec<B256>,
    block_id: BeaconBlockId,
}

impl<const LEAF_INDEX: usize> GeneralizedBeaconCommit<LEAF_INDEX> {
    /// Creates a new `GeneralizedBeaconCommit`.
    ///
    /// It panics if `LEAF_INDEX` is zero, because a Merkle tree cannot have a leaf at index 0.
    #[must_use]
    #[inline]
    pub const fn new(proof: Vec<B256>, block_id: BeaconBlockId) -> Self {
        assert!(LEAF_INDEX > 0);
        Self { proof, block_id }
    }

    /// Disassembles this `GeneralizedBeaconCommit`, returning the underlying Merkle proof and
    /// beacon block identifier.
    #[inline]
    pub fn into_parts(self) -> (Vec<B256>, BeaconBlockId) {
        (self.proof, self.block_id)
    }

    /// Calculates the root of the Merkle tree containing the given `leaf` hash at `LEAF_INDEX`,
    /// using the provided Merkle proof.
    #[inline]
    pub fn process_proof(&self, leaf: B256) -> Result<B256, merkle::InvalidProofError> {
        merkle::process_proof(leaf, &self.proof, LEAF_INDEX)
    }

    /// Verifies that the given `leaf` hash is present at the `LEAF_INDEX` in the Merkle tree
    /// represented by the `root` hash.
    #[inline]
    pub fn verify(&self, leaf: B256, root: B256) -> Result<(), merkle::InvalidProofError> {
        merkle::verify(leaf, &self.proof, LEAF_INDEX, root)
    }

    /// Returns the beacon block identifier (slot or timestamp).
    pub(crate) fn block_id(&self) -> BeaconBlockId {
        self.block_id
    }

    pub(crate) fn into_commit(self, leaf: B256) -> (BeaconBlockId, B256) {
        let beacon_root = self
            .process_proof(leaf)
            .expect("Invalid beacon inclusion proof");
        (self.block_id(), beacon_root)
    }
}

impl<H, const LEAF_INDEX: usize> BlockHeaderCommit<H> for GeneralizedBeaconCommit<LEAF_INDEX> {
    #[inline]
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment {
        let (block_id, beacon_root) = self.into_commit(header.seal());
        Commitment::new(
            block_id.as_version(),
            block_id.as_id(),
            beacon_root,
            config_id,
        )
    }
}
