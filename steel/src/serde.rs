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

use alloy_primitives::{keccak256, Sealable, Sealed, B256};
use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod rlp {
    use core::{fmt, marker::PhantomData};

    use alloy_rlp::{Decodable, Encodable};
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    struct RlpVisitor<T>(PhantomData<T>);

    impl<'de, T: Decodable> Visitor<'de> for RlpVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("RLP-encodes bytes")
        }

        #[inline]
        fn visit_bytes<E: Error>(self, mut v: &[u8]) -> Result<Self::Value, E> {
            T::decode(&mut v).map_err(Error::custom)
        }
    }

    pub fn serialize<T, S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encodable,
        S: Serializer,
    {
        let rlp = alloy_rlp::encode(source);
        serializer.serialize_bytes(&rlp)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Decodable,
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(RlpVisitor(PhantomData))
    }
}

/// A simple wrapper to serialize a header using the RLP-encoding.
#[derive(Clone)]
pub struct RlpHeader<H: Encodable + Decodable> {
    inner: H,
    rlp: Option<Box<[u8]>>,
}

impl<H: Encodable + Decodable> RlpHeader<H> {
    pub fn new(inner: H) -> Self {
        Self { inner, rlp: None }
    }
    #[inline]
    pub fn inner(&self) -> &H {
        &self.inner
    }
}

impl<H: Encodable + Decodable> Sealable for RlpHeader<H> {
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

impl<H: Encodable + Decodable> Serialize for RlpHeader<H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let rlp = alloy_rlp::encode(&self.inner).into_boxed_slice();
        rlp.serialize(serializer)
    }
}

impl<'de, H: Encodable + Decodable> Deserialize<'de> for RlpHeader<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let rlp = <Box<[u8]>>::deserialize(deserializer)?;
        let header = H::decode(&mut rlp.as_ref()).map_err(serde::de::Error::custom)?;
        Ok(RlpHeader {
            inner: header,
            rlp: Some(rlp),
        })
    }
}

#[cfg(feature = "host")]
impl<H> TryFrom<alloy::rpc::types::Header> for RlpHeader<H>
where
    H: Encodable + Decodable + TryFrom<alloy::rpc::types::Header>,
{
    type Error = <H as TryFrom<alloy::rpc::types::Header>>::Error;

    fn try_from(value: alloy::rpc::types::Header) -> Result<Self, Self::Error> {
        let header = value.try_into()?;
        Ok(Self {
            inner: header,
            rlp: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use serde::{Deserialize, Serialize};

    use crate::serde::RlpHeader;

    #[test]
    fn serde_with() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct T {
            #[serde(with = "super::rlp")]
            uint: U256,
        }
        let t = T {
            uint: U256::from(42),
        };

        let bin = bincode::serialize(&t).unwrap();
        assert_eq!(bincode::deserialize::<T>(&bin).unwrap(), t);
    }

    #[test]
    fn rlp_header_roundtrip() {
        let value = RlpHeader::new(alloy_consensus::Header::default());

        let bin = bincode::serialize(&value).unwrap();
        assert_eq!(
            bincode::deserialize::<RlpHeader<alloy_consensus::Header>>(&bin)
                .unwrap()
                .inner(),
            value.inner()
        );
    }
}
