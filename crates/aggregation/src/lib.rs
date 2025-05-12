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

#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

extern crate alloc;

use alloc::vec::Vec;
use core::borrow::Borrow;

use alloy_primitives::{uint, Keccak256, U256};
use risc0_zkvm::{
    sha::{Digest, DIGEST_BYTES},
    ReceiptClaim,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "verify")]
mod receipt;

#[cfg(feature = "verify")]
pub use receipt::{
    decode_set_inclusion_seal, RecursionVerifierParameters, SetInclusionDecodingError,
    /* TODO(#353)
    SET_BUILDER_ELF, SET_BUILDER_ID, SET_BUILDER_PATH,
    */
    SetInclusionEncodingError, SetInclusionReceipt, SetInclusionReceiptVerifierParameters,
    VerificationError,
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
pub struct GuestInput {
    /// State of the incremental set building process. On first run, this will be the initial
    /// state, which does not require verification (it is trivially true that an empty set contains
    /// no false claims). On subsequent runs, it will be set to the state written to the journal by
    /// the last run of the set builder guest.
    pub state: GuestState,
    /// Vector of claims to be verified and added to the set of verified claims committed to by the
    /// [MerkleMountainRange].
    pub claims: Vec<ReceiptClaim>,
    /// Whether or not to finalize the Merkle mountain range at the end of guest execution.
    ///
    /// A finalized [MerkleMountainRange] cannot have additional leaves added, but is guaranteed to
    /// be a single root. The [MerkleMountainRange] should be finalized to obtain the root for use
    /// with the Solidity set verifier contract.
    pub finalize: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuestState {
    /// Image ID of the set builder itself.
    ///
    /// Passed as input since a guest cannot contain its own image ID. All successive calls to the
    /// set builder must use the same image ID, which is propagated to the journal as part of the
    /// guest output.
    pub self_image_id: Digest,
    /// Merkle mountain range representing the state of the iterative tree building process at the
    /// end of guest execution.
    pub mmr: MerkleMountainRange,
}

impl GuestState {
    /// Construct the initial, empty, state for set builder.
    pub fn initial(self_image_id: impl Into<Digest>) -> Self {
        Self {
            self_image_id: self_image_id.into(),
            mmr: MerkleMountainRange::empty(),
        }
    }

    /// Returns true if this is the initial state, for an empty claim set.
    pub fn is_initial(&self) -> bool {
        self.mmr.is_empty()
    }

    /// Encodes the [GuestState] for committing to the journal. Uses a specialized codec.
    /// See [MerkleMountainRange::encode].
    pub fn encode(&self) -> Vec<u8> {
        [self.self_image_id.as_bytes(), &self.mmr.encode()].concat()
    }

    /// Decodes the [GuestState] for the journal. Uses a specialized codec.
    /// See [MerkleMountainRange::encode].
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self, DecodingError> {
        // Read the first 32 bytes as the self_image_id.
        let (chunk, bytes) = bytes
            .as_ref()
            .split_at_checked(U256::BYTES)
            .ok_or(DecodingError::UnexpectedEnd)?;
        let self_image_id = Digest::try_from(chunk).unwrap();
        let mmr = MerkleMountainRange::decode(bytes)?;
        Ok(Self { self_image_id, mmr })
    }

    /// Create a [GuestInput] from this [GuestState]. When run with the guest, the given claims
    /// will be accumulated into the Merkle mountain range, and will be finalized if `finalize` is
    /// set to `true`.
    ///
    /// Will return an error if the [MerkleMountainRange] on the [GuestState] is already
    /// finalized, as no more claims may be added and the guest would reject this input.
    pub fn into_input(
        self,
        claims: Vec<ReceiptClaim>,
        finalize: bool,
    ) -> Result<GuestInput, Error> {
        if self.mmr.is_finalized() {
            return Err(Error::FinalizedError);
        }
        Ok(GuestInput {
            state: self,
            claims,
            finalize,
        })
    }
}

/// Incrementally constructable Merkle mountain range.
///
/// Each entry in the list is a pair of (digest, max-depth), where max-depth tracks an upper bound
/// on the size of the subtree for which the digest is the root. The largest subtree is at index 0,
/// the smallest at index len - 1.
///
/// Note that the max size of the internal vec of digests (peaks) is equal to log_2 n where n is
/// the number of leaves in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct MerkleMountainRange(Vec<Peak>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
struct Peak {
    /// Digest for the root of the Merkle subtree committed to by this peak.
    digest: Digest,
    /// An upper-bound on the depth of the subtree rooted at this peak.
    ///
    /// It is expressed as the total height of the subtree - 1, such that a peak with a single node
    /// (i.e. a leaf) has a max_depth value of 0.
    ///
    /// A finalized [MerkleMountainRange] will have a single peak with max-depth set to `0xff`.
    max_depth: u8,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Merkle mountain range is finalized")]
    FinalizedError,
    #[error("Merkle mountain range is empty")]
    EmptyError,
    #[error("decoding error: {0}")]
    DecodingError(#[from] DecodingError),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodingError {
    #[error("invalid bitmap")]
    InvalidBitmap,
    #[error("unexpected end of byte stream")]
    UnexpectedEnd,
    #[error("trailing bytes")]
    TrailingBytes,
}

impl MerkleMountainRange {
    /// Constructs a new empty Merkle mountain range.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Construct a new [MerkleMountainRange] in a finalized state, given a root.
    pub fn new_finalized(root: Digest) -> Self {
        Self(vec![Peak {
            max_depth: u8::MAX,
            digest: root,
        }])
    }

    /// Push a new value onto the Merkle mountain range.
    pub fn push(&mut self, value: impl Borrow<Digest>) -> Result<(), Error> {
        self.push_peak(Peak {
            digest: hash_leaf(value.borrow()),
            max_depth: 0,
        })
    }

    fn push_peak(&mut self, new_peak: Peak) -> Result<(), Error> {
        // If the peak has a max-depth of 255, then the mountain range is finalized and no new
        // peaks can be pushed to it. Note that this state can only be achieved by calling
        // `finalize` since it is computationally infeasible to push 2^256 nodes onto the MMR,
        // although it is theoretically consistent that if an MMR reached a state of being a
        // single peak with max depth value of 255, it would be naturally finalized.
        if self.is_finalized() {
            return Err(Error::FinalizedError);
        }
        match self.0.last() {
            // If the MerkleMountainRange is empty, push the new peak.
            None => self.0.push(new_peak),
            // If the tail subtree is larger, push the new subtree onto the end.
            Some(peak) if peak.max_depth > new_peak.max_depth => {
                self.0.push(new_peak);
            }
            // If the tail subtree is the same size, combine them and recurse.
            Some(peak) if peak.max_depth == new_peak.max_depth => {
                // Will never panic, since we've already checked that there is at least one peak.
                let peak = self.0.pop().unwrap();
                self.push_peak(Peak {
                    digest: commutative_keccak256(&peak.digest, &new_peak.digest),
                    max_depth: peak.max_depth.checked_add(1).expect(
                        "violation of invariant on the finalization of the Merkle mountain range",
                    ),
                })?;
            }
            Some(_) => {
                unreachable!("violation of ordering invariant in Merkle mountain range builder")
            }
        };
        Ok(())
    }

    /// Finalize the [MerkleMountainRange], combining all peaks into one root. No new nodes can be
    /// added to a finalized commitment.
    pub fn finalize(&mut self) -> Result<(), Error> {
        let root = self.0.iter().rev().fold(None, |root, peak| {
            Some(match root {
                Some(root) => commutative_keccak256(&root, &peak.digest),
                None => peak.digest,
            })
        });
        let Some(root) = root else {
            return Err(Error::EmptyError);
        };
        self.0.clear();
        self.0.push(Peak {
            digest: root,
            max_depth: u8::MAX,
        });
        Ok(())
    }

    /// Finalizes the [MerkleMountainRange] and returns the root, or returns `None` is the
    /// [MerkleMountainRange] is empty.
    pub fn finalized_root(mut self) -> Option<Digest> {
        match self.is_empty() {
            true => None,
            false => {
                // finalize should only fail if the MMR is empty.
                self.finalize().unwrap();
                Some(self.0[0].digest)
            }
        }
    }

    /// Returns true if the [MerkleMountainRange] is finalized. No new nodes can be added to a
    /// finalized [MerkleMountainRange].
    pub fn is_finalized(&self) -> bool {
        // If the peak has a max-depth of 255, then the mountain range is finalized and no new
        // peaks can be pushed to it. Note that this state can only be achieved by calling
        // `finalize` since it is computationally infeasible to push 2^256 nodes onto the MMR,
        // although it is theoretically consistent that if an MMR reached a state of being a
        // single peak with max depth value of 255, it would be naturally finalized.
        self.0.first().is_some_and(|peak| peak.max_depth == u8::MAX)
    }

    /// Returns true if the [MerkleMountainRange] is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A compact encoding for the [MerkleMountainRange] used in encoding the journal designed to
    /// be efficient for use in the EVM, and designed to ensure it is possible to construct the
    /// journal encoding of a finalized [MerkleMountainRange] given only the finalized root.
    pub fn encode(&self) -> Vec<u8> {
        // bitmap encodes the max-depth values present in the MerkleMountainRange. Note that when
        // finalized, the bitmap is guaranteed to be equal to 1 << 255.
        let mut bitmap = U256::ZERO;
        let mut peaks = Vec::<Digest>::with_capacity(self.0.len());
        // Iterate over the peaks from greatest to least max-depth.
        for peak in self.0.iter() {
            bitmap.set_bit(peak.max_depth as usize, true);
            peaks.push(peak.digest);
        }
        [
            &bitmap.to_be_bytes::<{ U256::BYTES }>(),
            bytemuck::cast_slice(&peaks),
        ]
        .concat()
    }

    /// Decode the specialized journal encoding. See [MerkleMountainRange::encode].
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self, DecodingError> {
        // Read the first 32 bytes as the bitmap.
        let (mut chunk, mut bytes) = bytes
            .as_ref()
            .split_at_checked(U256::BYTES)
            .ok_or(DecodingError::UnexpectedEnd)?;
        let bitmap = U256::from_be_slice(chunk);
        if bitmap > (uint!(1_U256 << u8::MAX)) {
            // When the leading bit is set, it must be finalized. Any value above 2^255 is invalid.
            return Err(DecodingError::InvalidBitmap);
        }

        // Read the rest of the bytes as the peaks, with depth specified by the bitmap.
        let mut peaks = Vec::<Peak>::with_capacity(bitmap.count_ones());
        for i in (0..=u8::MAX).rev() {
            if !bitmap.bit(i as usize) {
                continue;
            }
            (chunk, bytes) = bytes
                .split_at_checked(DIGEST_BYTES)
                .ok_or(DecodingError::UnexpectedEnd)?;
            peaks.push(Peak {
                digest: Digest::try_from(chunk).unwrap(),
                max_depth: i,
            });
        }
        if !bytes.is_empty() {
            return Err(DecodingError::TrailingBytes);
        }

        Ok(Self(peaks))
    }
}

impl<D: Borrow<Digest>> Extend<D> for MerkleMountainRange {
    /// Extend a [MerkleMountainRange] from an iterator of digest values.
    fn extend<T: IntoIterator<Item = D>>(&mut self, values: T) {
        for value in values {
            self.push(value)
                .expect("attempted to extend a finalized MerkleMountainRange");
        }
    }
}

impl<D: Borrow<Digest>> FromIterator<D> for MerkleMountainRange {
    /// Construct a [MerkleMountainRange] from an iterator of digest values.
    fn from_iter<T: IntoIterator<Item = D>>(values: T) -> Self {
        let mut mmr = Self::empty();
        mmr.extend(values);
        mmr
    }
}

/// Calculate the Merkle root for a tree with the given list of digests as leaves.
///
/// Panics if the given list of leaves is empty.
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    match leaves {
        [] => panic!("digest list is empty, cannot compute Merkle root"),
        _ => MerkleMountainRange::from_iter(leaves)
            .finalized_root()
            .unwrap(),
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
    leaf_value: impl Borrow<Digest>,
    path: impl IntoIterator<Item = impl Borrow<Digest>>,
) -> Digest {
    let leaf = hash_leaf(leaf_value.borrow());
    path.into_iter()
        .fold(leaf, |a, b| commutative_keccak256(a.borrow(), b.borrow()))
}

/// Domain-separating tag value prepended to a digest before being hashed to form leaf node.
///
/// NOTE: It is explicitly not 32 bytes to avoid any chance of collision with a node value.
const LEAF_TAG: &[u8; 8] = b"LEAF_TAG";

/// Hash the given digest to form a leaf node.
///
/// This adds a tag to the given value and hashes it to ensure it is domain separated from any
/// internal nodes in the tree.
fn hash_leaf(value: &Digest) -> Digest {
    let mut hasher = Keccak256::new();
    hasher.update(LEAF_TAG);
    hasher.update(value.as_bytes());
    hasher.finalize().0.into()
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
            Digest::from_hex("bd792a6858270b233a6b399c1cbc60c5b1046a5b43758b9abc46ba32d23c7352")
                .unwrap(),
        );
    }

    #[test]
    fn test_merkle_root() {
        let digests = vec![Digest::from([0u8; 32])];
        assert_merkle_root(&digests, hash_leaf(&digests[0]));

        let digests = vec![
            Digest::from([0u8; 32]),
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
        ];
        assert_merkle_root(
            &digests,
            commutative_keccak256(
                &commutative_keccak256(&hash_leaf(&digests[0]), &hash_leaf(&digests[1])),
                &hash_leaf(&digests[2]),
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
                &commutative_keccak256(&hash_leaf(&digests[0]), &hash_leaf(&digests[1])),
                &commutative_keccak256(&hash_leaf(&digests[2]), &hash_leaf(&digests[3])),
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
                assert_eq!(merkle_path_root(digests[i], &path), root);
            }
        }
    }

    #[test]
    fn test_encode_decode() {
        for length in 0..=128 {
            let digests: Vec<Digest> = (0..length)
                .map(|_| rand::random::<[u8; 32]>().into())
                .collect();
            let mmr = MerkleMountainRange::from_iter(digests);

            assert_eq!(mmr, MerkleMountainRange::decode(mmr.encode()).unwrap());
        }
    }
}
