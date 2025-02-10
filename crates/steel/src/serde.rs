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

//! Serde related helpers.
use alloy_eips::{
    eip2718::{Eip2718Envelope, Encodable2718},
    Typed2718,
};
use alloy_primitives::{bytes::BufMut, hex, keccak256, Sealable, Sealed, B256};
use alloy_rlp::{Decodable, Encodable};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug},
    ops,
};

/// An efficient wrapper for header types that do not support serde serialization.
///
/// It implements deserialization using RLP encoding and does not discard the RLP data after
/// decoding, instead keeping it for faster hash computation.
#[derive(Clone, Debug)]
pub struct RlpHeader<H: Encodable> {
    inner: H,
    rlp: Option<Box<[u8]>>,
}

impl<H: Encodable> ops::Deref for RlpHeader<H> {
    type Target = H;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<H: Encodable> RlpHeader<H> {
    #[must_use]
    pub const fn new(inner: H) -> Self {
        Self { inner, rlp: None }
    }

    pub fn inner(&self) -> &H {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }

    pub fn into_inner(self) -> H {
        self.inner
    }
}

impl<H: Encodable> Sealable for RlpHeader<H> {
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
        let encoded = alloy_rlp::encode(&self.inner);
        if serializer.is_human_readable() {
            hex::serialize(&encoded, serializer)
        } else {
            serializer.serialize_bytes(&encoded)
        }
    }
}

impl<'de, H: Encodable + Decodable> Deserialize<'de> for RlpHeader<H> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let rlp = if deserializer.is_human_readable() {
            deserializer.deserialize_any(BytesVisitor)?
        } else {
            deserializer.deserialize_byte_buf(BytesVisitor)?
        };
        let inner = alloy_rlp::decode_exact(&rlp).map_err(de::Error::custom)?;

        Ok(RlpHeader {
            inner,
            rlp: Some(rlp.into_boxed_slice()),
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
        Ok(Self::new(value.inner.try_into()?))
    }
}

/// An efficient wrapper for [Eip2718Envelope] types that do not support serde serialization.
///
/// It implements deserialization using the EIP-2718 RLP encoding and does not discard the RLP data
/// after decoding, instead keeping it for faster RLP encoding of the deserialized type.
#[derive(Clone, Debug)]
pub struct Eip2718Wrapper<T: Eip2718Envelope> {
    inner: T,
    encoding: Option<Box<[u8]>>,
}

impl<T: Eip2718Envelope> Eip2718Wrapper<T> {
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            encoding: None,
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Eip2718Envelope> ops::Deref for Eip2718Wrapper<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Eip2718Envelope> Encodable for Eip2718Wrapper<T> {
    fn encode(&self, out: &mut dyn BufMut) {
        self.encode_2718(out);
    }

    fn length(&self) -> usize {
        self.encode_2718_len()
    }
}

impl<T: Eip2718Envelope> Typed2718 for Eip2718Wrapper<T> {
    fn ty(&self) -> u8 {
        self.inner().ty()
    }
}

impl<T: Eip2718Envelope> Encodable2718 for Eip2718Wrapper<T> {
    fn type_flag(&self) -> Option<u8> {
        self.inner.type_flag()
    }

    fn encode_2718_len(&self) -> usize {
        match &self.encoding {
            None => self.inner.encode_2718_len(),
            Some(bytes) => bytes.len(),
        }
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        match &self.encoding {
            Some(bytes) => out.put_slice(bytes),
            None => self.inner.encode_2718(out),
        }
    }
}

impl<T: Eip2718Envelope> Serialize for Eip2718Wrapper<T> {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = self.inner.encoded_2718();
        if serializer.is_human_readable() {
            hex::serialize(&encoded, serializer)
        } else {
            serializer.serialize_bytes(&encoded)
        }
    }
}

impl<'de, T: Eip2718Envelope> Deserialize<'de> for Eip2718Wrapper<T> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_any(BytesVisitor)?
        } else {
            deserializer.deserialize_byte_buf(BytesVisitor)?
        };
        let mut buf = bytes.as_slice();
        let inner = T::decode_2718(&mut buf).map_err(de::Error::custom)?;
        if !buf.is_empty() {
            return Err(de::Error::custom("unexpected length"));
        }

        Ok(Eip2718Wrapper {
            inner,
            encoding: Some(bytes.into_boxed_slice()),
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, ReceiptEnvelope};
    use alloy_primitives::Sealable;

    #[test]
    fn bincode_rlp_header() {
        let value = RlpHeader::new(Header::default());
        assert_eq!(value.hash_slow(), value.inner().hash_slow());

        let bin = bincode::serialize(&value).unwrap();
        let de: RlpHeader<Header> = bincode::deserialize(&bin).unwrap();
        assert_eq!(de.inner(), value.inner());
        assert_eq!(de.hash_slow(), value.inner().hash_slow());
    }

    #[test]
    fn serde_rlp_header() {
        let value = RlpHeader::new(Header::default());
        assert_eq!(value.hash_slow(), value.inner().hash_slow());

        let json = serde_json::to_string(&value).unwrap();
        let de: RlpHeader<Header> = serde_json::from_str(&json).unwrap();
        assert_eq!(de.inner(), value.inner());
        assert_eq!(de.hash_slow(), value.inner().hash_slow());
    }

    #[test]
    fn bincode_eip2718_wrapper() {
        let value = Eip2718Wrapper::new(ReceiptEnvelope::Eip2930(Default::default()));
        assert_eq!(value.encoded_2718(), value.inner().encoded_2718());

        let bin = bincode::serialize(&value).unwrap();
        let de: Eip2718Wrapper<ReceiptEnvelope> = bincode::deserialize(&bin).unwrap();
        assert_eq!(de.inner(), value.inner());
        assert_eq!(de.encoded_2718(), value.inner().encoded_2718());
    }

    #[test]
    fn serde_eip2718_wrapper() {
        let value = Eip2718Wrapper::new(ReceiptEnvelope::Eip2930(Default::default()));
        assert_eq!(value.encoded_2718(), value.inner().encoded_2718());

        let json = serde_json::to_string(&value).unwrap();
        let de: Eip2718Wrapper<ReceiptEnvelope> = serde_json::from_str(&json).unwrap();
        assert_eq!(de.inner(), value.inner());
        assert_eq!(de.encoded_2718(), value.inner().encoded_2718());
    }
}
