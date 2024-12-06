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

#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

extern crate alloc;

use alloc::vec::Vec;
use core::borrow::Borrow;

use alloy_primitives::{Keccak256, B256};
use alloy_sol_types::SolValue;
use risc0_binfmt::Digestible;
use risc0_zkvm::{sha, sha::Digest, ReceiptClaim};
use serde::{Deserialize, Serialize};

#[cfg(feature = "verify")]
mod receipt;

#[cfg(feature = "verify")]
pub use receipt::{
    EncodingError, RecursionVerifierParamters, SetInclusionReceipt,
    SetInclusionReceiptVerifierParameters,
    VerificationError,
    /* TODO(#353)
    SET_BUILDER_ELF, SET_BUILDER_ID, SET_BUILDER_PATH,
    */
};

alloy_sol_types::sol! {
    /// Seal of the SetInclusionReceipt.
    #[sol(all_derives)]
    struct Seal {
        /// Merkle path to the leaf.
        bytes32[] path;
        /// Root seal.
        bytes root_seal;
    }
}

/// Input of the aggregation set builder guest.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GuestInput {
    /// Input is a leaf of the Merkle tree.
    Singleton {
        self_image_id: Digest,
        claim: ReceiptClaim,
    },
    /// Input is an inner node of the Merkle tree.
    Join {
        self_image_id: Digest,
        left_set_root: Digest,
        right_set_root: Digest,
    },
}

impl GuestInput {
    #[inline]
    pub fn image_id(&self) -> Digest {
        match self {
            GuestInput::Singleton { self_image_id, .. } => *self_image_id,
            GuestInput::Join { self_image_id, .. } => *self_image_id,
        }
    }

    #[inline]
    pub fn root(&self) -> Digest {
        match self {
            GuestInput::Singleton { claim, .. } => claim.digest::<sha::Impl>(),
            GuestInput::Join {
                left_set_root,
                right_set_root,
                ..
            } => commutative_keccak256(left_set_root, right_set_root),
        }
    }

    /// Creates a [GuestOutput] from the input.
    #[inline]
    pub fn to_output(&self) -> GuestOutput {
        GuestOutput::new(self.image_id(), self.root())
    }
}

/// Calculate the Merkle root for a tree with the given list of digests as leaves.
///
/// Panics if the given list of leaves is empty.
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    match leaves {
        [] => panic!("digest list is empty, cannot compute Merkle root"),
        [digest] => *digest, // If only one digest, return it as the root
        _ => {
            // Split the list into two halves
            let (left, right) = leaves.split_at(leaves.len().next_power_of_two() / 2);
            let left_root = merkle_root(left);
            let right_root = merkle_root(right);
            // Hash the combined roots of the left and right halves
            commutative_keccak256(&left_root, &right_root)
        }
    }
}

// TODO(victor) Should this be assembled into under a struct and impl rather than as discrete
// functions?
/// Calculate the Merkle path proving inclusion of the leaf at the given index in a tree
/// constructed from the given leaves. The leaf and root are not included.
///
/// Panics if the given index is out of bounds.
pub fn merkle_path(leaves: &[Digest], index: usize) -> Vec<Digest> {
    assert!(
        index < leaves.len(),
        "no leaf with index {index} in tree of size {}",
        leaves.len()
    );

    if leaves.len() == 1 {
        return Vec::new(); // If only one digest, return an empty path
    }

    let mut path = Vec::new();
    let mut current_leaves = leaves;
    let mut current_index = index;

    while current_leaves.len() > 1 {
        // Split the list into two halves
        let mid = current_leaves.len().next_power_of_two() / 2;
        let (left, right) = current_leaves.split_at(mid);

        // Descent into the respective half
        if current_index < mid {
            path.push(merkle_root(right));
            current_leaves = left;
        } else {
            path.push(merkle_root(left));
            current_leaves = right;
            current_index -= mid;
        }
    }

    path.reverse();
    path
}

/// Calculate the root of the path assuming the given leaf value.
///
/// NOTE: The result of this function must be checked to be the root of some committed Merkle tree.
pub fn merkle_path_root(
    leaf: &Digest,
    path: impl IntoIterator<Item = impl Borrow<Digest>>,
) -> Digest {
    path.into_iter()
        .fold(*leaf, |a, b| commutative_keccak256(a.borrow(), b.borrow()))
}

/// Computes the hash of a sorted pair of [Digest].
fn commutative_keccak256(a: &Digest, b: &Digest) -> Digest {
    let mut hasher = Keccak256::new();
    if a.as_bytes() < b.as_bytes() {
        hasher.update(a.as_bytes());
        hasher.update(b.as_bytes());
    } else {
        hasher.update(b.as_bytes());
        hasher.update(a.as_bytes());
    }
    hasher.finalize().0.into()
}

alloy_sol_types::sol! {
    /// Journal output of aggregation set builder guest.
    #[sol(all_derives)]
    struct GuestOutput {
        /// Image ID used to verify the assumptions.
        bytes32 id;
        /// Root of the current sub-set.
        bytes32 root;
    }
}

impl GuestOutput {
    // NOTE: We use `impl Into<Digest>` here for the image ID type to accept the image ID constants
    // produced by risc0-build, which are [u8; 32].
    pub fn new(image_id: impl Into<Digest>, root: Digest) -> Self {
        Self {
            id: to_b256(image_id.into()),
            root: to_b256(root),
        }
    }

    /// ABI-encodes the output.
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        SolValue::abi_encode(self)
    }

    #[inline]
    pub fn image_id(&self) -> Digest {
        self.id.0.into()
    }
    #[inline]
    pub fn root(&self) -> Digest {
        self.root.0.into()
    }
}

fn to_b256(digest: Digest) -> B256 {
    <[u8; 32]>::from(digest).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    fn assert_merkle_root(digests: &[Digest], expected_root: Digest) {
        let root = merkle_root(digests);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_root_manual() {
        let digests = vec![
            Digest::from_hex("6a428060b5d51f04583182f2ff1b565f9db661da12ee7bdc003e9ab6d5d91ba9")
                .unwrap(),
            Digest::from_hex("6a428060b5d51f04583182f2ff1b565f9db661da12ee7bdc003e9ab6d5d91ba9")
                .unwrap(),
            Digest::from_hex("6a428060b5d51f04583182f2ff1b565f9db661da12ee7bdc003e9ab6d5d91ba9")
                .unwrap(),
        ];

        assert_merkle_root(
            &digests,
            Digest::from_hex("e004c72e4cb697fa97669508df099edbc053309343772a25e56412fc7db8ebef")
                .unwrap(),
        );
    }

    #[test]
    fn test_merkle_root() {
        let digests = vec![Digest::from([0u8; 32])];
        assert_merkle_root(&digests, digests[0]);

        let digests = vec![
            Digest::from([0u8; 32]),
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
        ];
        assert_merkle_root(
            &digests,
            commutative_keccak256(
                &commutative_keccak256(&digests[0], &digests[1]),
                &digests[2],
            ),
        );

        let digests = vec![
            Digest::from([0u8; 32]),
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
            Digest::from([3u8; 32]),
        ];
        assert_merkle_root(
            &digests,
            commutative_keccak256(
                &commutative_keccak256(&digests[0], &digests[1]),
                &commutative_keccak256(&digests[2], &digests[3]),
            ),
        );
    }

    #[test]
    fn test_consistency() {
        for length in 1..=128 {
            let digests: Vec<Digest> = (0..length)
                .map(|_| rand::random::<[u8; 32]>().into())
                .collect();
            let root = merkle_root(&digests);

            for i in 0..length {
                let path = merkle_path(&digests, i);
                assert_eq!(merkle_path_root(&digests[i], &path), root);
            }
        }
    }
}
