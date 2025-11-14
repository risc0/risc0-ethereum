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

//! Functionality to resolve "orphan" nodes occurring during removes.
//!
//! Calling `remove` in sparse Merkle Patricia tries are only safe, if it does not lead to a Branch
//! node with just a single unresolved Digest child. Even though such a sparse trie is perfectly
//! valid to proof inclusion if the trie is not modified.

use crate::{
    mpt::{memoize::Memoization, nibbles::NibbleSlice, node::Node},
    CachedTrie, Trie,
};
use alloy_primitives::{keccak256, map::B256Map};
use alloy_trie::Nibbles;
use std::fmt::Debug;

/// Error returned by the `resolve_orphan` method.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Indicates that the proof does not have a valid RLP encoding.
    #[error("proof RLP encoding error")]
    RlpError(#[from] alloy_rlp::Error),

    /// Indicates that the given proof is an invalid post-removal proof and does not prove the
    /// non-inclusion of the key.
    #[error("invalid proof")]
    InvalidProof,

    /// Indicates that the orphan cannot be resolved using only the provided post-removal proof.
    /// This typically occurs when the removal of a key transforms an `Extension` node into a
    /// `Branch` node, and the proof does not contain sufficient information to reconstruct the
    /// original `Extension` node.
    /// It contains the key prefix that needs to be resolved, to make the removal valid.
    #[error("key prefix `{0:?}` not resolved")]
    Unresolvable(Nibbles),
}

impl Trie {
    /// Attempts to resolve orphaned branch children caused by the removal of a key-value pair.
    ///
    /// When a key-value pair is removed from the trie, it may leave behind "orphaned" nodes that
    /// must be transformed into a different type of node for the trie to remain valid.
    /// This method uses an [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) proof to resolve
    /// these orphans. The proof should represent the state of the trie *after* the removal of the
    /// key-value pair.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` if the orphan was successfully resolved. Returns `Error` if the proof is
    /// invalid or the orphan cannot be resolved with the given proof.
    ///
    /// # Panics
    ///
    /// It panics if the key is not contained in the trie.
    #[inline]
    pub fn resolve_orphan<K, I, T>(&mut self, key: K, proof: I) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.0.resolve_orphan(NibbleSlice::from(&Nibbles::unpack(key)), proof)
    }
}

impl CachedTrie {
    /// Attempts to resolve orphaned branch children caused by removing a key-value pair.
    ///
    /// See [`Trie::resolve_orphan`] for detailed documentation.
    #[inline]
    pub fn resolve_orphan<K, I, T>(&mut self, key: K, proof: I) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.inner.resolve_orphan(NibbleSlice::from(&Nibbles::unpack(key)), proof)
    }
}

impl<M: Memoization + Clone> Node<M> {
    /// Attempts to resolve orphaned branch children caused by removing a key-value pair.
    pub(super) fn resolve_orphan<T: AsRef<[u8]>>(
        &mut self,
        key: NibbleSlice<'_>,
        proof: impl IntoIterator<Item = T>,
    ) -> Result<(), Error> {
        assert!(self.get(key).is_some(), "key not contained");
        let other = Node::from_rlp(proof)?;
        let Some((diverging, unmatched)) = other.diverging(key) else {
            return Ok(());
        };
        let matched = key.strip_suffix(&unmatched).unwrap();

        match diverging {
            Node::Null => {
                // the entire tree has been removed so trivially there can be no orphans
            }
            Node::Leaf(prefix, value, _) => {
                // get the unmatched part of the Leaf-prefix
                let (common, unmatched, _) =
                    NibbleSlice::from(prefix).split_common_prefix(unmatched);
                // split the first nibble which used to belong to the Branch
                let (idx, suffix) = unmatched.split_first().expect("empty unmatched key");
                // this can only be an orphan, if it is currently a Digest child of a Branch
                if !self.is_branch_with_digest(&matched.join(common), idx) {
                    return Ok(());
                }

                // any orphan must be a Leaf with the suffix as a prefix
                let sibling = Node::Leaf(suffix.into(), value.clone(), M::default());
                let rlp = sibling.rlp_encoded();
                self.resolve_digests(&B256Map::from_iter([(keccak256(&rlp), rlp)])).unwrap();
            }
            Node::Extension(prefix, child, _) => {
                // get the unmatched part of the Extension-prefix
                let (common, unmatched, _) =
                    NibbleSlice::from(prefix).split_common_prefix(unmatched);
                // split the first nibble which used to belong to the Branch
                let (idx, suffix) = unmatched.split_first().expect("empty unmatched key");
                // this can only be an orphan, if it is currently a Digest child of a Branch
                if !self.is_branch_with_digest(&matched.join(common), idx) {
                    return Ok(());
                }

                // Extensions cannot have an empty prefix. This means that if the suffix is empty,
                // the orphan is a Branch, and because of the removal, its parent Branch has been
                // converted to an Extension. So to resolve this orphan, we need to know the
                // original Branch.
                if suffix.is_empty() {
                    // if we are lucky, the post-removal proof does not stop at the Extension and
                    // the child still corresponds to the node we are looking for.
                    if !matches!(**child, Node::Digest(_)) {
                        let rlp = child.rlp_encoded();
                        self.resolve_digests(&B256Map::from_iter([(keccak256(&rlp), rlp)]))
                            .unwrap();
                    }
                    // the path to the orphan corresponds exactly to the path of the Extension-child
                    let orphan_prefix = matched.join(prefix);
                    // maybe the trie already contains a node with this prefix
                    if self.contains_prefix(&orphan_prefix) {
                        // in this case, the removal will not fail and nothing needs to be resolved
                        return Ok(());
                    }
                    // otherwise return error that the given prefix needs to be resolved externally
                    return Err(Error::Unresolvable(orphan_prefix));
                }

                // any potential orphan must be an Extension with the (non-empty) suffix as a prefix
                let sibling = Node::Extension(suffix.into(), (*child).clone(), M::default());
                let rlp = sibling.rlp_encoded();
                self.resolve_digests(&B256Map::from_iter([(keccak256(&rlp), rlp)])).unwrap();
            }
            Node::Digest(_) => {
                // the proof is invalid, as it does not proof the non-inclusion of `key`
                return Err(Error::InvalidProof);
            }
            Node::Branch(..) => unreachable!("Branch node with value"),
        }

        Ok(())
    }

    /// Returns the diverging trie node for a key.
    ///
    /// If the key is present in the trie, this method returns `None`. Otherwise, it returns the
    /// node where the search for the key would fail, along with the unmatched portion of the key.
    fn diverging<'a>(&'a self, key: NibbleSlice<'a>) -> Option<(&'a Node<M>, NibbleSlice<'a>)> {
        match self {
            Node::Null => Some((&Node::Null, key)),

            Node::Leaf(prefix, ..) if prefix == key.as_slice() => None,
            Node::Leaf(..) => Some((self, key)),

            Node::Extension(prefix, child, _) => {
                key.strip_prefix(prefix).map_or(Some((self, key)), |tail| child.diverging(tail))
            }

            Node::Branch(children, _) => match key.split_first() {
                Some((idx, tail)) => {
                    let child = children.get(idx);
                    child.map_or(Some((&Node::Null, tail)), |node| node.diverging(tail))
                }
                None => Some((self, key)), // branch nodes don't have values
            },

            Node::Digest(_) => Some((self, key)),
        }
    }

    fn contains_prefix<'a>(&'a self, key: impl Into<NibbleSlice<'a>>) -> bool {
        match self.diverging(key.into()) {
            None => true,                                 // contains the prefix as a key
            Some((Node::Digest(_), _)) => false,          // prefix not resolved
            Some((_, unmatched)) => unmatched.is_empty(), // prefix contained or not
        }
    }

    /// Returns whether the node at key is a Branch which has a Digest child at idx.
    fn is_branch_with_digest<'a>(&'a self, key: impl Into<NibbleSlice<'a>>, idx: u8) -> bool {
        match self.diverging(key.into()) {
            // match only if, the node found is a `Node::Branch` and the *entire* key was consumed
            Some((Node::Branch(children, ..), unmatched)) if unmatched.is_empty() => {
                // if all the above conditions are met, check the specific child
                matches!(children.get(idx), Some(Node::Digest(_)))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Trie;
    use alloy_primitives::{Bytes, B256};
    use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
    use std::{borrow::Borrow, panic};

    fn create_eip1186_proof<K, V>(
        key: K,
        trie: impl IntoIterator<Item = impl Borrow<(K, V)>>,
    ) -> Vec<Bytes>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let hb = HashBuilder::default();
        let mut hb =
            hb.with_proof_retainer(ProofRetainer::new(vec![Nibbles::unpack(key.as_ref())]));

        let mut sorted_data: Vec<_> = trie.into_iter().collect();
        sorted_data.sort_by(|a, b| a.borrow().0.as_ref().cmp(b.borrow().0.as_ref()));
        for (key, val) in sorted_data.iter().map(Borrow::borrow) {
            hb.add_leaf(Nibbles::unpack(key), val.as_ref());
        }
        let _ = hb.root();

        hb.take_proof_nodes().into_nodes_sorted().into_iter().map(|(_, rlp)| rlp).collect()
    }

    #[test]
    fn leaf_orphan() {
        let keys = [vec![0x00], vec![0x11]];
        let key = &keys[0];
        let leaves = keys.iter().map(|k| (k, Bytes::from(B256::ZERO))).collect::<Vec<_>>();

        let proof = create_eip1186_proof(key, &leaves);
        let post_proof = create_eip1186_proof(key, &leaves[1..]);

        let mut trie = Trie::from_rlp(proof).unwrap();
        assert!(trie.get(key).is_some());
        assert!(panic::catch_unwind(|| trie.clone().remove(key)).is_err(), "Removal should panic");

        trie.resolve_orphan(key, post_proof).unwrap();
        trie.remove(key);
    }

    #[test]
    fn extension_orphan() {
        let keys = [vec![0x00], vec![0x10, 0x00], vec![0x10, 0x01]];
        let key = &keys[0];
        let leaves = keys.iter().map(|k| (k, Bytes::from(B256::ZERO))).collect::<Vec<_>>();

        let proof = create_eip1186_proof(key, &leaves);
        let post_proof = create_eip1186_proof(key, &leaves[1..]);

        let mut trie = Trie::from_rlp(proof).unwrap();
        assert!(trie.get(key).is_some());
        assert!(panic::catch_unwind(|| trie.clone().remove(key)).is_err(), "Removal should panic");

        trie.resolve_orphan(key, post_proof).unwrap();
        trie.remove(key);
    }

    #[test]
    fn unresolvable_orphan() {
        let keys = [vec![0x00], vec![0x10], vec![0x11]];
        let key = &keys[0];
        let leaves = keys.iter().map(|k| (k, Bytes::from(B256::ZERO))).collect::<Vec<_>>();

        let proof = create_eip1186_proof(key, &leaves);
        let post_proof = create_eip1186_proof(key, &leaves[1..]);

        let mut trie = Trie::from_rlp(proof).unwrap();
        assert!(trie.get(key).is_some());
        assert!(panic::catch_unwind(|| trie.clone().remove(key)).is_err(), "Removal should panic");

        let err = trie.resolve_orphan(key, post_proof).unwrap_err();
        assert!(matches!(err, Error::Unresolvable(_)));
    }
}
