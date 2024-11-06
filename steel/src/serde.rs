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

//! Serde related helpers.
use std::fmt::{self, Debug};

use alloy_primitives::{hex, keccak256, Sealable, Sealed, B256};
use alloy_rlp::{Decodable, Encodable};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// An efficient wrapper for header types that do not support serde serialization.
///
/// It implements deserialization using RLP encoding and does not discard the RLP data after
/// decoding, instead keeping it for faster hash computation.
#[derive(Clone, Debug)]
pub struct RlpHeader<H: Encodable> {
    inner: H,
    rlp: Option<Vec<u8>>,
}

impl<H: Encodable> std::ops::Deref for RlpHeader<H> {
    type Target = H;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<H: Encodable> RlpHeader<H> {
    #[must_use]
    #[inline]
    pub const fn new(inner: H) -> Self {
        Self { inner, rlp: None }
    }
    #[inline]
    pub fn inner(&self) -> &H {
        &self.inner
    }
    #[inline]
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }
}

impl<H: Encodable> Sealable for RlpHeader<H> {
    /// Calculate the seal hash, this may be slow.
    #[inline]
    fn hash_slow(&self) -> B256 {
        match &self.rlp {
            Some(rlp) => keccak256(rlp),
            None => keccak256(alloy_rlp::encode(&self.inner)),
        }
    }

    #[inline]
    fn seal_unchecked(mut self, seal: B256) -> Sealed<Self> {
        self.rlp = None;
        Sealed::new_unchecked(self, seal)
    }
}

impl<H: Encodable> Serialize for RlpHeader<H> {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            hex::serialize(alloy_rlp::encode(&self.inner), serializer)
        } else {
            serializer.serialize_bytes(&alloy_rlp::encode(&self.inner))
        }
    }
}

impl<'de, H: Encodable + Decodable> Deserialize<'de> for RlpHeader<H> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl<'de> de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bytes represented as a hex string, sequence or raw bytes")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                hex::decode(v).map_err(de::Error::custom)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(values)
            }
        }

        // deserialize the byte vector
        let rlp = if deserializer.is_human_readable() {
            deserializer.deserialize_any(BytesVisitor)?
        } else {
            deserializer.deserialize_byte_buf(BytesVisitor)?
        };
        // the RLP-encoding is not malleable, as long as we make sure that there are no additional
        // bytes after the RLP-encoded data
        let inner = alloy_rlp::decode_exact(&rlp).map_err(de::Error::custom)?;

        Ok(RlpHeader {
            inner,
            rlp: Some(rlp),
        })
    }
}

#[cfg(feature = "host")]
impl<H, I> TryFrom<alloy::rpc::types::Header<H>> for RlpHeader<I>
where
    I: Encodable + Decodable + TryFrom<H>,
{
    type Error = <I as TryFrom<H>>::Error;

    #[inline]
    fn try_from(value: alloy::rpc::types::Header<H>) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: value.inner.try_into()?,
            rlp: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::Sealable;

    #[test]
    fn bincode_rlp_header() {
        let value = RlpHeader::new(alloy_consensus::Header::default());
        assert_eq!(value.hash_slow(), value.inner().hash_slow());

        let bin = bincode::serialize(&value).unwrap();
        let de: RlpHeader<alloy_consensus::Header> = bincode::deserialize(&bin).unwrap();
        assert_eq!(de.inner(), value.inner());
        assert_eq!(de.hash_slow(), value.inner().hash_slow());
    }

    #[test]
    fn serde_rlp_header() {
        let value = RlpHeader::new(alloy_consensus::Header::default());
        assert_eq!(value.hash_slow(), value.inner().hash_slow());

        let json = serde_json::to_string(&value).unwrap();
        let de: RlpHeader<alloy_consensus::Header> = serde_json::from_str(&json).unwrap();
        assert_eq!(de.inner(), value.inner());
        assert_eq!(de.hash_slow(), value.inner().hash_slow());
    }
}
