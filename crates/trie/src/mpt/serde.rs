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

/// RLP-encodes a cached trie during serialization.
///
/// This has several advantages:
/// - The serialized bytes are fully verified at deserialization.
/// - The trie nodes already have an RLP-encoding when the hash is computed.
#[cfg(feature = "rlp_serialize")]
pub(crate) mod rlp_nodes {
    use crate::mpt::{memoize::Memoization, node::Node};
    use alloy_primitives::Bytes;
    use itertools::Itertools;
    use serde::{de, ser::SerializeSeq, Deserialize, Deserializer, Serializer};

    #[inline]
    pub(crate) fn serialize<S, M>(trie: &Node<M>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        M: Memoization,
    {
        // deduplicate the RLP nodes
        let nodes: Vec<Bytes> = trie.rlp_nodes().into_iter().unique().collect();

        let mut seq = serializer.serialize_seq(Some(nodes.len()))?;
        for node in &nodes {
            seq.serialize_element(&node[..])?;
        }
        seq.end()
    }

    #[inline]
    pub(crate) fn deserialize<'de, D, M>(deserializer: D) -> Result<Node<M>, D::Error>
    where
        D: Deserializer<'de>,
        M: Memoization,
    {
        let nodes: Vec<&[u8]> = Vec::deserialize(deserializer)?;

        Node::from_rlp(nodes).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::Trie;
    use alloy_primitives::{keccak256, Bytes};

    const N: usize = 512;

    #[test]
    fn round_trip() {
        let trie: Trie = (0..N)
            .map(|i| (keccak256(i.to_be_bytes()), Bytes::from(alloy_rlp::encode(i))))
            .collect();

        let bytes = bincode::serialize(&trie).unwrap();
        let other: Trie = bincode::deserialize(&bytes).unwrap();

        assert_eq!(trie, other);
    }

    mod cached {
        use super::*;
        use crate::CachedTrie;
        use alloy_primitives::B256;

        #[test]
        fn round_trip() {
            let mut trie: CachedTrie = (0..N)
                .map(|i| (keccak256(i.to_be_bytes()), Bytes::from(alloy_rlp::encode(i))))
                .collect();
            trie.hash();
            assert!(trie.hash.is_some());

            let bytes = bincode::serialize(&trie).unwrap();
            let other: CachedTrie = bincode::deserialize(&bytes).unwrap();
            assert!(other.hash.is_none());

            assert_eq!(trie, other);
        }

        #[test]
        fn round_trip_dup() {
            let trie: CachedTrie =
                (0..255).map(|i| (B256::with_last_byte(i), Bytes::from(B256::ZERO))).collect();

            let bytes = bincode::serialize(&trie).unwrap();
            let other: CachedTrie = bincode::deserialize(&bytes).unwrap();

            assert_eq!(trie, other);
        }
    }
}
