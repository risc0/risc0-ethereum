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

use super::Node;
use crate::mpt::memoize::Memoization;
use serde::de;
use serde::{Deserialize, Deserializer};

#[inline]
pub(crate) fn deserialize_and_validate<'de, D, M>(deserializer: D) -> Result<Node<M>, D::Error>
where
    D: Deserializer<'de>,
    M: Memoization,
{
    let node = Node::<M>::deserialize(deserializer)?;
    if !node.is_valid() {
        return Err(de::Error::custom("invalid trie structure"));
    }

    Ok(node)
}

pub(crate) mod nibbles {
    use crate::Nibbles;
    use serde::de::{SeqAccess, Visitor};
    use serde::{ser::SerializeSeq, Deserializer, Serializer};
    use std::fmt;

    #[inline]
    pub(crate) fn serialize<S>(nibbles: &Nibbles, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(nibbles.len()))?;
        for node in &nibbles.pack() {
            seq.serialize_element(node)?;
        }
        seq.end()
    }

    #[inline]
    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Nibbles, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NibblesVisitor;

        impl<'de> Visitor<'de> for NibblesVisitor {
            type Value = Nibbles;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let size = seq.size_hint().unwrap();
                let mut nibbles = Nibbles::with_capacity(size);
                for i in (0..size).step_by(2) {
                    let byte: u8 = seq.next_element()?.unwrap();
                    nibbles.push_unchecked(byte >> 4);
                    if i < size - 1 {
                        nibbles.push_unchecked(byte & 0x0F);
                    }
                }

                Ok(nibbles)
            }
        }

        deserializer.deserialize_seq(NibblesVisitor)
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
