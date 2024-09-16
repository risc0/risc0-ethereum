use crate::ethereum_consensus::{
    primitives::{BlsPublicKey, BlsSignature},
    ssz::prelude::*,
};

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SyncAggregate<const SYNC_COMMITTEE_SIZE: usize> {
    pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
    pub sync_committee_signature: BlsSignature,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    #[serde(rename = "pubkeys")]
    pub public_keys: Vector<BlsPublicKey, SYNC_COMMITTEE_SIZE>,
    #[serde(rename = "aggregate_pubkey")]
    pub aggregate_public_key: BlsPublicKey,
}
