use crate::ethereum_consensus::{
    altair::light_client::{
        CURRENT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2, FINALIZED_ROOT_INDEX_FLOOR_LOG_2,
        NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2,
    },
    capella::EXECUTION_PAYLOAD_INDEX_FLOOR_LOG_2,
    deneb::{
        execution_payload::ExecutionPayloadHeader, BeaconBlockHeader, SyncAggregate, SyncCommittee,
    },
    primitives::{Bytes32, Slot},
    ssz::prelude::*,
};

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientHeader<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize> {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub execution_branch: Vector<Bytes32, EXECUTION_PAYLOAD_INDEX_FLOOR_LOG_2>,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientBootstrap<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub current_sync_committee_branch: Vector<Bytes32, CURRENT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2>,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientUpdate<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee_branch: Vector<Bytes32, NEXT_SYNC_COMMITTEE_INDEX_FLOOR_LOG_2>,
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_INDEX_FLOOR_LOG_2>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientFinalityUpdate<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finalized_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub finality_branch: Vector<Bytes32, FINALIZED_ROOT_INDEX_FLOOR_LOG_2>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}

#[derive(Default, Debug, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct LightClientOptimisticUpdate<
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub attested_header: LightClientHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
    pub signature_slot: Slot,
}
