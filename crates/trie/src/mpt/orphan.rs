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
    /// Indicates that the proof is invalid or not a valid post-removal proof for the specified
    /// key.
    #[error("invalid proof")]
    RlpError(#[from] alloy_rlp::Error),

    /// Indicates that the orphan cannot be resolved using only the provided post-removal proof.
    /// This typically occurs when the removal of a key transforms an `Extension` node into a
    /// `Branch` node, and the proof does not contain sufficient information to reconstruct the
    /// original `Extension` node.
    #[error("not resolvable from proof")]
    Unresolvable(Nibbles),
}

impl Trie {
    /// Attempts to resolve orphaned branch children caused by removing a key-value pair.
    ///
    /// When a key-value pair is removed from the trie, it can leave behind "orphaned" nodes, which
    /// needs to be transformed into a different type for the trie to remain valid.
    /// This method uses an [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) proof to resolve
    /// these orphans. The proof should represent the state of the trie *after* the removal of the
    /// key-value pair.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` if the orphan was successfully resolved. Returns an `Error` if the proof is
    /// invalid or the orphan cannot be resolved using the provided proof.
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
            Node::Null => {}
            Node::Leaf(prefix, value, _) => {
                // get the unmatched part of the Leaf-prefix
                let (_, unmatched, _) = NibbleSlice::from(prefix).split_common_prefix(unmatched);
                // split the first nibble which used to belong to the Branch
                let (_, suffix) = unmatched.split_first().expect("empty unmatched key");

                // the original sibling node of `diverging` is a Leaf with suffix
                let sibling = Node::Leaf(suffix.into(), value.clone(), M::default());
                let rlp = sibling.rlp_encoded();
                self.resolve_digests(&B256Map::from_iter([(keccak256(&rlp), rlp)])).unwrap();
            }
            Node::Extension(prefix, child, _) => {
                // get the unmatched part of the Extension-prefix
                let (_, unmatched, _) = NibbleSlice::from(prefix).split_common_prefix(unmatched);
                // split the first nibble which used to belong to the Branch
                let (_, suffix) = unmatched.split_first().expect("empty unmatched key");
                // there must not be an Extension with empty prefix
                // if this happens, during the removal an Extension got converted into a Branch and
                // we cannot resolve it with the information of the proof
                if suffix.is_empty() {
                    return Err(Error::Unresolvable(matched.join(prefix)));
                }

                // the original sibling node of `diverging` is an Extension with suffix
                let sibling = Node::Extension(suffix.into(), (*child).clone(), M::default());
                let rlp = sibling.rlp_encoded();
                self.resolve_digests(&B256Map::from_iter([(keccak256(&rlp), rlp)])).unwrap();
            }
            Node::Digest(_) => {
                return Err(Error::RlpError(alloy_rlp::Error::Custom("no leaf for key")))
            }
            Node::Branch(..) => unreachable!("Branch node with value"),
        }

        Ok(())
    }

    /// Returns the diverging Merkle Patricia Trie (MPT) node for a key.
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
        let keys = vec![vec![0x00], vec![0x11]];
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
        let keys = vec![vec![0x00], vec![0x10, 0x00], vec![0x10, 0x01]];
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
        let keys = vec![vec![0x00], vec![0x10], vec![0x11]];
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
