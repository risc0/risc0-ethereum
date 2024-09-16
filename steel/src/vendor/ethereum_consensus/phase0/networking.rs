use crate::ethereum_consensus::{primitives::Epoch, ssz::prelude::Bitvector};
use std::time::Duration;

pub const ATTESTATION_SUBNET_COUNT: usize = 64;
pub const GOSSIP_MAX_SIZE: usize = 2usize.pow(20);
pub const MAX_REQUEST_BLOCKS: usize = 2usize.pow(10);
pub const MIN_EPOCHS_FOR_BLOCK_REQUESTS: Epoch = 33024;
pub const MAX_CHUNK_SIZE: usize = 2usize.pow(20);
pub const TTFB_TIMEOUT: Duration = Duration::from_secs(5);
pub const RESP_TIMEOUT: Duration = Duration::from_secs(10);
pub const ATTESTATION_PROPAGATION_SLOT_RANGE: usize = 32;
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY: Duration = Duration::from_millis(500);

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MetaData {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub seq_number: u64,
    pub attnets: Bitvector<ATTESTATION_SUBNET_COUNT>,
}
