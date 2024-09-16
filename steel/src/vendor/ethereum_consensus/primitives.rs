use crate::ethereum_consensus::ssz::prelude::*;
pub use crate::ethereum_consensus::{
    crypto::{PublicKey as BlsPublicKey, Signature as BlsSignature},
    domains::DomainType,
    ssz::prelude::U256,
};

pub type Root = Node;
pub type Slot = u64;
pub type Epoch = u64;

pub type CommitteeIndex = usize;
pub type ValidatorIndex = usize;
pub type WithdrawalIndex = usize;
pub type BlobIndex = usize;
pub type Gwei = u64;
pub type Hash32 = Bytes32;

pub type Version = [u8; 4];
pub type ForkDigest = [u8; 4];
pub type Domain = [u8; 32];

pub type ExecutionAddress = ByteVector<20>;

pub type ChainId = usize;
pub type NetworkId = usize;

pub type RandaoReveal = BlsSignature;
pub type Bytes32 = ByteVector<32>;

pub type ParticipationFlags = u8;

pub type ShuffledIndices = Vec<usize>;

// Coordinate refers to a unique location in the block tree
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Coordinate {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    slot: Slot,
    root: Root,
}

pub const GENESIS_SLOT: Slot = 0;
pub const GENESIS_EPOCH: Epoch = 0;
pub const FAR_FUTURE_EPOCH: Epoch = Epoch::MAX;

pub const BLS_WITHDRAWAL_PREFIX: u8 = 0x00;
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
pub const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        let bytes = Bytes32::default();
        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(
            json,
            "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
        );
        let bytes_roundtrip: Bytes32 = serde_json::from_str(&json).unwrap();
        assert_eq!(bytes, bytes_roundtrip);
    }
}
