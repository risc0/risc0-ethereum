use crate::ethereum_consensus::{
    altair::{
        sync::{SyncAggregate, SyncCommittee},
        BeaconBlockHeader,
    },
    primitives::{Bytes32, Slot},
    ssz::prelude::*,
};

pub const FINALIZED_ROOT_INDEX: usize = 105;
pub const FINALIZED_ROOT_INDEX_FLOOR_LOG_2: usize = 6;

pub const CURRENT_SYNC_COMMITTEE_INDEX: usize = 54;
pub const CURRENT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2: usize = 5;

pub const NEXT_SYNC_COMMITTEE_INDEX: usize = 55;
pub const NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2: usize = 5;

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrap<const SYNC_COMMITTEE_SIZE: usize> {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: Vector<Bytes32, CURRENT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2>,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: Vector<Bytes32, NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2>,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_INDEX_FLOOR_LOG_2>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientFinalityUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_INDEX_FLOOR_LOG_2>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientOptimisticUpdate<const SYNC_COMMITTEE_SIZE: usize> {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}
