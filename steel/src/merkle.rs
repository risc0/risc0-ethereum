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

//! Helpers for verifying Merkle proofs.
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use thiserror::Error as ThisError;

/// Error returned when verifying Merkle proofs.
#[derive(Debug, ThisError)]
#[error("proof verification failed")]
pub struct InvalidProofError;

/// Returns an error if `leaf` cannot be proven to occupy the `index` in the Merkle tree.
#[inline]
pub fn verify(
    leaf: B256,
    branch: &[B256],
    generalized_index: usize,
    root: B256,
) -> Result<(), InvalidProofError> {
    if process_proof(leaf, branch, generalized_index)? != root {
        return Err(InvalidProofError);
    }

    Ok(())
}

/// Returns the rebuilt hash obtained by traversing the Merkle tree up from `leaf`, assuming `leaf`
/// occupies the `generalized_index` in the tree.
#[inline]
pub fn process_proof(
    leaf: B256,
    branch: &[B256],
    generalized_index: usize,
) -> Result<B256, InvalidProofError> {
    let depth = generalized_index.ilog2();
    let mut index = generalized_index - (1 << depth);
    if !usize::try_from(depth)
        .map(|depth| branch.len() == depth)
        .unwrap_or(false)
    {
        return Err(InvalidProofError);
    }

    let mut computed_hash = leaf;
    let mut hasher = Sha256::new();
    for node in branch {
        if index % 2 != 0 {
            hasher.update(node);
            hasher.update(computed_hash);
        } else {
            hasher.update(computed_hash);
            hasher.update(node);
        }
        computed_hash.copy_from_slice(&hasher.finalize_reset());
        index /= 2;
    }

    Ok(computed_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    const LEAF: B256 = b256!("94159da973dfa9e40ed02535ee57023ba2d06bad1017e451055470967eb71cd5");
    const BRANCH: [B256; 3] = [
        b256!("8f594dbb4f4219ad4967f86b9cccdb26e37e44995a291582a431eef36ecba45c"),
        b256!("f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c"),
        b256!("382ba9638ce263e802593b387538faefbaed106e9f51ce793d405f161b105ee6"),
    ];
    const INDEX: usize = (1 << BRANCH.len()) + 2;
    const ROOT: B256 = b256!("27097c728aade54ff1376d5954681f6d45c282a81596ef19183148441b754abb");

    #[test]
    fn valid_proof() {
        assert_eq!(process_proof(LEAF, &BRANCH, INDEX).unwrap(), ROOT);
        verify(LEAF, &BRANCH, INDEX, ROOT).unwrap()
    }

    #[test]
    fn invalid_length() {
        let branch = &BRANCH[..2];
        process_proof(LEAF, branch, INDEX).unwrap_err();
        verify(LEAF, branch, INDEX, ROOT).unwrap_err();
    }

    #[test]
    fn invalid_index() {
        let index: usize = 1 << BRANCH.len();
        assert_ne!(process_proof(LEAF, &BRANCH, index).unwrap(), ROOT);
        verify(LEAF, &BRANCH, index, ROOT).unwrap_err();
    }

    #[test]
    fn invalid_leaf() {
        let leaf = B256::ZERO;
        assert_ne!(process_proof(leaf, &BRANCH, INDEX).unwrap(), ROOT);
        verify(leaf, &BRANCH, INDEX, ROOT).unwrap_err();
    }
}
