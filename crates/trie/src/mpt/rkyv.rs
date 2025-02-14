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

use super::{
    memoize::{Cache, Memoization},
    node::Node,
};
use alloy_primitives::{Bytes, B256};
use alloy_trie::nybbles::Nibbles;
use itertools::Itertools;
use rkyv::{
    rancor::{Fallible, Source},
    ser::{Allocator, Writer},
    vec::{ArchivedVec, VecResolver},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
    Archive, Archived, Deserialize, Place, Serialize,
};

/// Wrapper to encode a [B256] as an `[u8; 32]`.
#[derive(Archive, Serialize, Deserialize)]
#[rkyv(remote = B256)]
pub(super) struct B256Def([u8; B256::len_bytes()]);

impl From<B256Def> for B256 {
    #[inline]
    fn from(B256Def(arr): B256Def) -> Self {
        Self(arr)
    }
}

/// Wrapper to encode [Bytes] as an [`ArchivedVec<u8>`].
pub(super) struct BytesDef;

impl ArchiveWith<Bytes> for BytesDef {
    type Archived = ArchivedVec<u8>;
    type Resolver = VecResolver;

    fn resolve_with(bytes: &Bytes, resolver: Self::Resolver, out: Place<Self::Archived>) {
        ArchivedVec::resolve_from_slice(bytes, resolver, out);
    }
}

impl<S: Fallible + Allocator + Writer + ?Sized> SerializeWith<Bytes, S> for BytesDef {
    fn serialize_with(bytes: &Bytes, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        ArchivedVec::serialize_from_slice(bytes, serializer)
    }
}

impl<D> DeserializeWith<Archived<Vec<u8>>, Bytes, D> for BytesDef
where
    D: Fallible + ?Sized,
    <D as Fallible>::Error: Source,
{
    fn deserialize_with(field: &ArchivedVec<u8>, deserializer: &mut D) -> Result<Bytes, D::Error> {
        let vec = <ArchivedVec<u8> as Deserialize<Vec<u8>, D>>::deserialize(field, deserializer)?;
        Ok(Bytes::from(vec))
    }
}

/// Wrapper to encode [Nibbles] as an [`ArchivedVec<u8>`].
pub(super) struct NibblesDef;

impl ArchiveWith<Nibbles> for NibblesDef {
    type Archived = ArchivedVec<u8>;
    type Resolver = VecResolver;

    fn resolve_with(nibbles: &Nibbles, resolver: Self::Resolver, out: Place<Self::Archived>) {
        ArchivedVec::resolve_from_slice(nibbles, resolver, out);
    }
}

impl<S: Fallible + Allocator + Writer + ?Sized> SerializeWith<Nibbles, S> for NibblesDef {
    fn serialize_with(nibbles: &Nibbles, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        ArchivedVec::serialize_from_slice(nibbles, serializer)
    }
}

impl<D> DeserializeWith<Archived<Vec<u8>>, Nibbles, D> for NibblesDef
where
    D: Fallible + ?Sized,
    <D as Fallible>::Error: Source,
{
    fn deserialize_with(f: &ArchivedVec<u8>, deserializer: &mut D) -> Result<Nibbles, D::Error> {
        let vec = <ArchivedVec<u8> as Deserialize<Vec<u8>, D>>::deserialize(f, deserializer)?;
        Ok(Nibbles::from_vec_unchecked(vec))
    }
}

/// RLP-encodes a cached trie during serialization.
///
/// This has several advantages:
/// - The serialized bytes are fully verified at deserialization.
/// - The trie nodes already have an RLP-encoding when the hash is computed.
#[derive(Archive, Serialize, Deserialize)]
#[rkyv(remote = Node<Cache>)]
pub(super) struct RlpNodes(#[rkyv(getter = rlp_nodes)] Vec<Vec<u8>>);

fn rlp_nodes<M: Memoization>(node: &Node<M>) -> Vec<Vec<u8>> {
    node.rlp_nodes().into_iter().unique().map(Vec::from).collect()
}

impl<M: Memoization> From<RlpNodes> for Node<M> {
    #[inline]
    fn from(RlpNodes(nodes): RlpNodes) -> Self {
        Node::from_rlp(nodes).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::{ArchivedTrie, Trie};
    use alloy_primitives::keccak256;
    use rkyv::rancor::Error;

    const N: usize = 512;

    #[test]
    fn round_trip() {
        let trie: Trie = (0..N)
            .map(|i| (keccak256(i.to_be_bytes()), Bytes::from(alloy_rlp::encode(i))))
            .collect();

        let bytes = rkyv::to_bytes::<Error>(&trie).unwrap();
        let archived = rkyv::access::<ArchivedTrie, Error>(&bytes).unwrap();
        let other = rkyv::deserialize::<Trie, Error>(archived).unwrap();

        assert_eq!(trie, other);
    }

    mod cached {
        use super::*;
        use crate::mpt::{ArchivedCachedTrie, CachedTrie};

        #[test]
        fn round_trip() {
            let mut trie: CachedTrie = (0..N)
                .map(|i| (keccak256(i.to_be_bytes()), Bytes::from(alloy_rlp::encode(i))))
                .collect();
            trie.hash();
            assert!(trie.hash.is_some());

            let bytes = rkyv::to_bytes::<Error>(&trie).unwrap();
            let archived = rkyv::access::<ArchivedCachedTrie, Error>(&bytes).unwrap();
            let other = rkyv::deserialize::<CachedTrie, Error>(archived).unwrap();
            assert!(other.hash.is_none());

            assert_eq!(trie, other);
        }

        #[test]
        fn round_trip_dup() {
            let trie: CachedTrie =
                (0..255).map(|i| (B256::with_last_byte(i), Bytes::from(B256::ZERO))).collect();

            let bytes = rkyv::to_bytes::<Error>(&trie).unwrap();
            let archived = rkyv::access::<ArchivedCachedTrie, Error>(&bytes).unwrap();
            let other = rkyv::deserialize::<CachedTrie, Error>(archived).unwrap();

            assert_eq!(trie, other);
        }
    }
}
