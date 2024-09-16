use crate::ethereum_consensus::{
    altair::constants::SYNC_COMMITTEE_SUBNET_COUNT, phase0::networking::ATTESTATION_SUBNET_COUNT,
    ssz::prelude::Bitvector,
};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MetaData {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub seq_number: u64,
    pub attnets: Bitvector<ATTESTATION_SUBNET_COUNT>,
    pub syncnets: Bitvector<SYNC_COMMITTEE_SUBNET_COUNT>,
}
