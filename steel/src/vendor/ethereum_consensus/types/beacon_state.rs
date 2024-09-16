//! WARNING: This file was derived by the `spec-gen` utility. DO NOT EDIT MANUALLY.
use crate::ethereum_consensus::{
    altair::{beacon_state as altair, sync::SyncCommittee},
    bellatrix::beacon_state as bellatrix,
    capella::beacon_state::{self as capella, HistoricalSummary},
    deneb::beacon_state as deneb,
    phase0::{
        beacon_block::BeaconBlockHeader,
        beacon_state::{self as phase0, Fork},
        operations::{Checkpoint, Eth1Data, PendingAttestation},
        validator::Validator,
        JUSTIFICATION_BITS_LENGTH,
    },
    primitives::{Bytes32, Gwei, ParticipationFlags, Root, Slot, ValidatorIndex, WithdrawalIndex},
    ssz::prelude::*,
    types::execution_payload_header::{ExecutionPayloadHeaderRef, ExecutionPayloadHeaderRefMut},
    Fork as Version,
};
#[derive(Debug, Clone, PartialEq, Eq, Serializable, HashTreeRoot, serde::Serialize)]
#[ssz(transparent)]
#[serde(untagged)]
pub enum BeaconState<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    Phase0(
        phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    ),
    Altair(
        altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
    Bellatrix(
        bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Deneb(
        deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
}
impl<
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    pub fn phase0(
        &self,
    ) -> Option<
        &phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    > {
        match self {
            Self::Phase0(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn phase0_mut(
        &mut self,
    ) -> Option<
        &mut phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    > {
        match self {
            Self::Phase0(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn altair(
        &self,
    ) -> Option<
        &altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    > {
        match self {
            Self::Altair(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn altair_mut(
        &mut self,
    ) -> Option<
        &mut altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    > {
        match self {
            Self::Altair(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix(
        &self,
    ) -> Option<
        &bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix_mut(
        &mut self,
    ) -> Option<
        &mut bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella(
        &self,
    ) -> Option<
        &capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella_mut(
        &mut self,
    ) -> Option<
        &mut capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb(
        &self,
    ) -> Option<
        &deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb_mut(
        &mut self,
    ) -> Option<
        &mut deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn version(&self) -> Version {
        match self {
            Self::Phase0(_) => Version::Phase0,
            Self::Altair(_) => Version::Altair,
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
        }
    }
    pub fn genesis_time(&self) -> u64 {
        match self {
            Self::Phase0(inner) => inner.genesis_time,
            Self::Altair(inner) => inner.genesis_time,
            Self::Bellatrix(inner) => inner.genesis_time,
            Self::Capella(inner) => inner.genesis_time,
            Self::Deneb(inner) => inner.genesis_time,
        }
    }
    pub fn genesis_time_mut(&mut self) -> &mut u64 {
        match self {
            Self::Phase0(inner) => &mut inner.genesis_time,
            Self::Altair(inner) => &mut inner.genesis_time,
            Self::Bellatrix(inner) => &mut inner.genesis_time,
            Self::Capella(inner) => &mut inner.genesis_time,
            Self::Deneb(inner) => &mut inner.genesis_time,
        }
    }
    pub fn genesis_validators_root(&self) -> Root {
        match self {
            Self::Phase0(inner) => inner.genesis_validators_root,
            Self::Altair(inner) => inner.genesis_validators_root,
            Self::Bellatrix(inner) => inner.genesis_validators_root,
            Self::Capella(inner) => inner.genesis_validators_root,
            Self::Deneb(inner) => inner.genesis_validators_root,
        }
    }
    pub fn genesis_validators_root_mut(&mut self) -> &mut Root {
        match self {
            Self::Phase0(inner) => &mut inner.genesis_validators_root,
            Self::Altair(inner) => &mut inner.genesis_validators_root,
            Self::Bellatrix(inner) => &mut inner.genesis_validators_root,
            Self::Capella(inner) => &mut inner.genesis_validators_root,
            Self::Deneb(inner) => &mut inner.genesis_validators_root,
        }
    }
    pub fn slot(&self) -> Slot {
        match self {
            Self::Phase0(inner) => inner.slot,
            Self::Altair(inner) => inner.slot,
            Self::Bellatrix(inner) => inner.slot,
            Self::Capella(inner) => inner.slot,
            Self::Deneb(inner) => inner.slot,
        }
    }
    pub fn slot_mut(&mut self) -> &mut Slot {
        match self {
            Self::Phase0(inner) => &mut inner.slot,
            Self::Altair(inner) => &mut inner.slot,
            Self::Bellatrix(inner) => &mut inner.slot,
            Self::Capella(inner) => &mut inner.slot,
            Self::Deneb(inner) => &mut inner.slot,
        }
    }
    pub fn fork(&self) -> &Fork {
        match self {
            Self::Phase0(inner) => &inner.fork,
            Self::Altair(inner) => &inner.fork,
            Self::Bellatrix(inner) => &inner.fork,
            Self::Capella(inner) => &inner.fork,
            Self::Deneb(inner) => &inner.fork,
        }
    }
    pub fn fork_mut(&mut self) -> &mut Fork {
        match self {
            Self::Phase0(inner) => &mut inner.fork,
            Self::Altair(inner) => &mut inner.fork,
            Self::Bellatrix(inner) => &mut inner.fork,
            Self::Capella(inner) => &mut inner.fork,
            Self::Deneb(inner) => &mut inner.fork,
        }
    }
    pub fn latest_block_header(&self) -> &BeaconBlockHeader {
        match self {
            Self::Phase0(inner) => &inner.latest_block_header,
            Self::Altair(inner) => &inner.latest_block_header,
            Self::Bellatrix(inner) => &inner.latest_block_header,
            Self::Capella(inner) => &inner.latest_block_header,
            Self::Deneb(inner) => &inner.latest_block_header,
        }
    }
    pub fn latest_block_header_mut(&mut self) -> &mut BeaconBlockHeader {
        match self {
            Self::Phase0(inner) => &mut inner.latest_block_header,
            Self::Altair(inner) => &mut inner.latest_block_header,
            Self::Bellatrix(inner) => &mut inner.latest_block_header,
            Self::Capella(inner) => &mut inner.latest_block_header,
            Self::Deneb(inner) => &mut inner.latest_block_header,
        }
    }
    pub fn block_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.block_roots,
            Self::Altair(inner) => &inner.block_roots,
            Self::Bellatrix(inner) => &inner.block_roots,
            Self::Capella(inner) => &inner.block_roots,
            Self::Deneb(inner) => &inner.block_roots,
        }
    }
    pub fn block_roots_mut(&mut self) -> &mut Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &mut inner.block_roots,
            Self::Altair(inner) => &mut inner.block_roots,
            Self::Bellatrix(inner) => &mut inner.block_roots,
            Self::Capella(inner) => &mut inner.block_roots,
            Self::Deneb(inner) => &mut inner.block_roots,
        }
    }
    pub fn state_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.state_roots,
            Self::Altair(inner) => &inner.state_roots,
            Self::Bellatrix(inner) => &inner.state_roots,
            Self::Capella(inner) => &inner.state_roots,
            Self::Deneb(inner) => &inner.state_roots,
        }
    }
    pub fn state_roots_mut(&mut self) -> &mut Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &mut inner.state_roots,
            Self::Altair(inner) => &mut inner.state_roots,
            Self::Bellatrix(inner) => &mut inner.state_roots,
            Self::Capella(inner) => &mut inner.state_roots,
            Self::Deneb(inner) => &mut inner.state_roots,
        }
    }
    pub fn historical_roots(&self) -> &List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.historical_roots,
            Self::Altair(inner) => &inner.historical_roots,
            Self::Bellatrix(inner) => &inner.historical_roots,
            Self::Capella(inner) => &inner.historical_roots,
            Self::Deneb(inner) => &inner.historical_roots,
        }
    }
    pub fn historical_roots_mut(&mut self) -> &mut List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.historical_roots,
            Self::Altair(inner) => &mut inner.historical_roots,
            Self::Bellatrix(inner) => &mut inner.historical_roots,
            Self::Capella(inner) => &mut inner.historical_roots,
            Self::Deneb(inner) => &mut inner.historical_roots,
        }
    }
    pub fn eth1_data(&self) -> &Eth1Data {
        match self {
            Self::Phase0(inner) => &inner.eth1_data,
            Self::Altair(inner) => &inner.eth1_data,
            Self::Bellatrix(inner) => &inner.eth1_data,
            Self::Capella(inner) => &inner.eth1_data,
            Self::Deneb(inner) => &inner.eth1_data,
        }
    }
    pub fn eth1_data_mut(&mut self) -> &mut Eth1Data {
        match self {
            Self::Phase0(inner) => &mut inner.eth1_data,
            Self::Altair(inner) => &mut inner.eth1_data,
            Self::Bellatrix(inner) => &mut inner.eth1_data,
            Self::Capella(inner) => &mut inner.eth1_data,
            Self::Deneb(inner) => &mut inner.eth1_data,
        }
    }
    pub fn eth1_data_votes(&self) -> &List<Eth1Data, ETH1_DATA_VOTES_BOUND> {
        match self {
            Self::Phase0(inner) => &inner.eth1_data_votes,
            Self::Altair(inner) => &inner.eth1_data_votes,
            Self::Bellatrix(inner) => &inner.eth1_data_votes,
            Self::Capella(inner) => &inner.eth1_data_votes,
            Self::Deneb(inner) => &inner.eth1_data_votes,
        }
    }
    pub fn eth1_data_votes_mut(&mut self) -> &mut List<Eth1Data, ETH1_DATA_VOTES_BOUND> {
        match self {
            Self::Phase0(inner) => &mut inner.eth1_data_votes,
            Self::Altair(inner) => &mut inner.eth1_data_votes,
            Self::Bellatrix(inner) => &mut inner.eth1_data_votes,
            Self::Capella(inner) => &mut inner.eth1_data_votes,
            Self::Deneb(inner) => &mut inner.eth1_data_votes,
        }
    }
    pub fn eth1_deposit_index(&self) -> u64 {
        match self {
            Self::Phase0(inner) => inner.eth1_deposit_index,
            Self::Altair(inner) => inner.eth1_deposit_index,
            Self::Bellatrix(inner) => inner.eth1_deposit_index,
            Self::Capella(inner) => inner.eth1_deposit_index,
            Self::Deneb(inner) => inner.eth1_deposit_index,
        }
    }
    pub fn eth1_deposit_index_mut(&mut self) -> &mut u64 {
        match self {
            Self::Phase0(inner) => &mut inner.eth1_deposit_index,
            Self::Altair(inner) => &mut inner.eth1_deposit_index,
            Self::Bellatrix(inner) => &mut inner.eth1_deposit_index,
            Self::Capella(inner) => &mut inner.eth1_deposit_index,
            Self::Deneb(inner) => &mut inner.eth1_deposit_index,
        }
    }
    pub fn validators(&self) -> &List<Validator, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.validators,
            Self::Altair(inner) => &inner.validators,
            Self::Bellatrix(inner) => &inner.validators,
            Self::Capella(inner) => &inner.validators,
            Self::Deneb(inner) => &inner.validators,
        }
    }
    pub fn validators_mut(&mut self) -> &mut List<Validator, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.validators,
            Self::Altair(inner) => &mut inner.validators,
            Self::Bellatrix(inner) => &mut inner.validators,
            Self::Capella(inner) => &mut inner.validators,
            Self::Deneb(inner) => &mut inner.validators,
        }
    }
    pub fn balances(&self) -> &List<Gwei, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.balances,
            Self::Altair(inner) => &inner.balances,
            Self::Bellatrix(inner) => &inner.balances,
            Self::Capella(inner) => &inner.balances,
            Self::Deneb(inner) => &inner.balances,
        }
    }
    pub fn balances_mut(&mut self) -> &mut List<Gwei, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.balances,
            Self::Altair(inner) => &mut inner.balances,
            Self::Bellatrix(inner) => &mut inner.balances,
            Self::Capella(inner) => &mut inner.balances,
            Self::Deneb(inner) => &mut inner.balances,
        }
    }
    pub fn randao_mixes(&self) -> &Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.randao_mixes,
            Self::Altair(inner) => &inner.randao_mixes,
            Self::Bellatrix(inner) => &inner.randao_mixes,
            Self::Capella(inner) => &inner.randao_mixes,
            Self::Deneb(inner) => &inner.randao_mixes,
        }
    }
    pub fn randao_mixes_mut(&mut self) -> &mut Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR> {
        match self {
            Self::Phase0(inner) => &mut inner.randao_mixes,
            Self::Altair(inner) => &mut inner.randao_mixes,
            Self::Bellatrix(inner) => &mut inner.randao_mixes,
            Self::Capella(inner) => &mut inner.randao_mixes,
            Self::Deneb(inner) => &mut inner.randao_mixes,
        }
    }
    pub fn slashings(&self) -> &Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.slashings,
            Self::Altair(inner) => &inner.slashings,
            Self::Bellatrix(inner) => &inner.slashings,
            Self::Capella(inner) => &inner.slashings,
            Self::Deneb(inner) => &inner.slashings,
        }
    }
    pub fn slashings_mut(&mut self) -> &mut Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> {
        match self {
            Self::Phase0(inner) => &mut inner.slashings,
            Self::Altair(inner) => &mut inner.slashings,
            Self::Bellatrix(inner) => &mut inner.slashings,
            Self::Capella(inner) => &mut inner.slashings,
            Self::Deneb(inner) => &mut inner.slashings,
        }
    }
    pub fn previous_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.previous_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn previous_epoch_attestations_mut(
        &mut self,
    ) -> Option<
        &mut List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>,
    > {
        match self {
            Self::Phase0(inner) => Some(&mut inner.previous_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn current_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.current_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn current_epoch_attestations_mut(
        &mut self,
    ) -> Option<
        &mut List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>,
    > {
        match self {
            Self::Phase0(inner) => Some(&mut inner.current_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn justification_bits(&self) -> &Bitvector<JUSTIFICATION_BITS_LENGTH> {
        match self {
            Self::Phase0(inner) => &inner.justification_bits,
            Self::Altair(inner) => &inner.justification_bits,
            Self::Bellatrix(inner) => &inner.justification_bits,
            Self::Capella(inner) => &inner.justification_bits,
            Self::Deneb(inner) => &inner.justification_bits,
        }
    }
    pub fn justification_bits_mut(&mut self) -> &mut Bitvector<JUSTIFICATION_BITS_LENGTH> {
        match self {
            Self::Phase0(inner) => &mut inner.justification_bits,
            Self::Altair(inner) => &mut inner.justification_bits,
            Self::Bellatrix(inner) => &mut inner.justification_bits,
            Self::Capella(inner) => &mut inner.justification_bits,
            Self::Deneb(inner) => &mut inner.justification_bits,
        }
    }
    pub fn previous_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.previous_justified_checkpoint,
            Self::Altair(inner) => &inner.previous_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.previous_justified_checkpoint,
            Self::Capella(inner) => &inner.previous_justified_checkpoint,
            Self::Deneb(inner) => &inner.previous_justified_checkpoint,
        }
    }
    pub fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        match self {
            Self::Phase0(inner) => &mut inner.previous_justified_checkpoint,
            Self::Altair(inner) => &mut inner.previous_justified_checkpoint,
            Self::Bellatrix(inner) => &mut inner.previous_justified_checkpoint,
            Self::Capella(inner) => &mut inner.previous_justified_checkpoint,
            Self::Deneb(inner) => &mut inner.previous_justified_checkpoint,
        }
    }
    pub fn current_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.current_justified_checkpoint,
            Self::Altair(inner) => &inner.current_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.current_justified_checkpoint,
            Self::Capella(inner) => &inner.current_justified_checkpoint,
            Self::Deneb(inner) => &inner.current_justified_checkpoint,
        }
    }
    pub fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        match self {
            Self::Phase0(inner) => &mut inner.current_justified_checkpoint,
            Self::Altair(inner) => &mut inner.current_justified_checkpoint,
            Self::Bellatrix(inner) => &mut inner.current_justified_checkpoint,
            Self::Capella(inner) => &mut inner.current_justified_checkpoint,
            Self::Deneb(inner) => &mut inner.current_justified_checkpoint,
        }
    }
    pub fn finalized_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.finalized_checkpoint,
            Self::Altair(inner) => &inner.finalized_checkpoint,
            Self::Bellatrix(inner) => &inner.finalized_checkpoint,
            Self::Capella(inner) => &inner.finalized_checkpoint,
            Self::Deneb(inner) => &inner.finalized_checkpoint,
        }
    }
    pub fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint {
        match self {
            Self::Phase0(inner) => &mut inner.finalized_checkpoint,
            Self::Altair(inner) => &mut inner.finalized_checkpoint,
            Self::Bellatrix(inner) => &mut inner.finalized_checkpoint,
            Self::Capella(inner) => &mut inner.finalized_checkpoint,
            Self::Deneb(inner) => &mut inner.finalized_checkpoint,
        }
    }
    pub fn previous_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.previous_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.previous_epoch_participation),
            Self::Capella(inner) => Some(&inner.previous_epoch_participation),
            Self::Deneb(inner) => Some(&inner.previous_epoch_participation),
        }
    }
    pub fn previous_epoch_participation_mut(
        &mut self,
    ) -> Option<&mut List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.previous_epoch_participation),
            Self::Bellatrix(inner) => Some(&mut inner.previous_epoch_participation),
            Self::Capella(inner) => Some(&mut inner.previous_epoch_participation),
            Self::Deneb(inner) => Some(&mut inner.previous_epoch_participation),
        }
    }
    pub fn current_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.current_epoch_participation),
            Self::Capella(inner) => Some(&inner.current_epoch_participation),
            Self::Deneb(inner) => Some(&inner.current_epoch_participation),
        }
    }
    pub fn current_epoch_participation_mut(
        &mut self,
    ) -> Option<&mut List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.current_epoch_participation),
            Self::Bellatrix(inner) => Some(&mut inner.current_epoch_participation),
            Self::Capella(inner) => Some(&mut inner.current_epoch_participation),
            Self::Deneb(inner) => Some(&mut inner.current_epoch_participation),
        }
    }
    pub fn inactivity_scores(&self) -> Option<&List<u64, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.inactivity_scores),
            Self::Bellatrix(inner) => Some(&inner.inactivity_scores),
            Self::Capella(inner) => Some(&inner.inactivity_scores),
            Self::Deneb(inner) => Some(&inner.inactivity_scores),
        }
    }
    pub fn inactivity_scores_mut(&mut self) -> Option<&mut List<u64, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.inactivity_scores),
            Self::Bellatrix(inner) => Some(&mut inner.inactivity_scores),
            Self::Capella(inner) => Some(&mut inner.inactivity_scores),
            Self::Deneb(inner) => Some(&mut inner.inactivity_scores),
        }
    }
    pub fn current_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_sync_committee),
            Self::Bellatrix(inner) => Some(&inner.current_sync_committee),
            Self::Capella(inner) => Some(&inner.current_sync_committee),
            Self::Deneb(inner) => Some(&inner.current_sync_committee),
        }
    }
    pub fn current_sync_committee_mut(
        &mut self,
    ) -> Option<&mut SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.current_sync_committee),
            Self::Bellatrix(inner) => Some(&mut inner.current_sync_committee),
            Self::Capella(inner) => Some(&mut inner.current_sync_committee),
            Self::Deneb(inner) => Some(&mut inner.current_sync_committee),
        }
    }
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.next_sync_committee),
            Self::Bellatrix(inner) => Some(&inner.next_sync_committee),
            Self::Capella(inner) => Some(&inner.next_sync_committee),
            Self::Deneb(inner) => Some(&inner.next_sync_committee),
        }
    }
    pub fn next_sync_committee_mut(&mut self) -> Option<&mut SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.next_sync_committee),
            Self::Bellatrix(inner) => Some(&mut inner.next_sync_committee),
            Self::Capella(inner) => Some(&mut inner.next_sync_committee),
            Self::Deneb(inner) => Some(&mut inner.next_sync_committee),
        }
    }
    pub fn latest_execution_payload_header(
        &self,
    ) -> Option<ExecutionPayloadHeaderRef<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(inner) => Some(From::from(&inner.latest_execution_payload_header)),
            Self::Capella(inner) => Some(From::from(&inner.latest_execution_payload_header)),
            Self::Deneb(inner) => Some(From::from(&inner.latest_execution_payload_header)),
        }
    }
    pub fn latest_execution_payload_header_mut(
        &mut self,
    ) -> Option<ExecutionPayloadHeaderRefMut<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(inner) => Some(From::from(&mut inner.latest_execution_payload_header)),
            Self::Capella(inner) => Some(From::from(&mut inner.latest_execution_payload_header)),
            Self::Deneb(inner) => Some(From::from(&mut inner.latest_execution_payload_header)),
        }
    }
    pub fn next_withdrawal_index(&self) -> Option<WithdrawalIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.next_withdrawal_index),
            Self::Deneb(inner) => Some(inner.next_withdrawal_index),
        }
    }
    pub fn next_withdrawal_index_mut(&mut self) -> Option<&mut WithdrawalIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.next_withdrawal_index),
            Self::Deneb(inner) => Some(&mut inner.next_withdrawal_index),
        }
    }
    pub fn next_withdrawal_validator_index(&self) -> Option<ValidatorIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.next_withdrawal_validator_index),
            Self::Deneb(inner) => Some(inner.next_withdrawal_validator_index),
        }
    }
    pub fn next_withdrawal_validator_index_mut(&mut self) -> Option<&mut ValidatorIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.next_withdrawal_validator_index),
            Self::Deneb(inner) => Some(&mut inner.next_withdrawal_validator_index),
        }
    }
    pub fn historical_summaries(&self) -> Option<&List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&inner.historical_summaries),
            Self::Deneb(inner) => Some(&inner.historical_summaries),
        }
    }
    pub fn historical_summaries_mut(
        &mut self,
    ) -> Option<&mut List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.historical_summaries),
            Self::Deneb(inner) => Some(&mut inner.historical_summaries),
        }
    }
}
impl<
        'de,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    > serde::Deserialize<'de>
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Deneb(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Capella(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Bellatrix(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Altair(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Phase0(inner));
        }
        Err(serde::de::Error::custom(
            "no variant could be deserialized from input",
        ))
    }
}
#[derive(Debug, PartialEq, Eq, HashTreeRoot)]
#[ssz(transparent)]
pub enum BeaconStateRef<
    'a,
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    Phase0(
        &'a phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    ),
    Altair(
        &'a altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
    Bellatrix(
        &'a bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        &'a capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Deneb(
        &'a deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    BeaconStateRef<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    pub fn phase0(
        &self,
    ) -> Option<
        &phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    > {
        match self {
            Self::Phase0(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn altair(
        &self,
    ) -> Option<
        &altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    > {
        match self {
            Self::Altair(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix(
        &self,
    ) -> Option<
        &bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella(
        &self,
    ) -> Option<
        &capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb(
        &self,
    ) -> Option<
        &deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn version(&self) -> Version {
        match self {
            Self::Phase0(_) => Version::Phase0,
            Self::Altair(_) => Version::Altair,
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
        }
    }
    pub fn genesis_time(&self) -> u64 {
        match self {
            Self::Phase0(inner) => inner.genesis_time,
            Self::Altair(inner) => inner.genesis_time,
            Self::Bellatrix(inner) => inner.genesis_time,
            Self::Capella(inner) => inner.genesis_time,
            Self::Deneb(inner) => inner.genesis_time,
        }
    }
    pub fn genesis_validators_root(&self) -> Root {
        match self {
            Self::Phase0(inner) => inner.genesis_validators_root,
            Self::Altair(inner) => inner.genesis_validators_root,
            Self::Bellatrix(inner) => inner.genesis_validators_root,
            Self::Capella(inner) => inner.genesis_validators_root,
            Self::Deneb(inner) => inner.genesis_validators_root,
        }
    }
    pub fn slot(&self) -> Slot {
        match self {
            Self::Phase0(inner) => inner.slot,
            Self::Altair(inner) => inner.slot,
            Self::Bellatrix(inner) => inner.slot,
            Self::Capella(inner) => inner.slot,
            Self::Deneb(inner) => inner.slot,
        }
    }
    pub fn fork(&self) -> &Fork {
        match self {
            Self::Phase0(inner) => &inner.fork,
            Self::Altair(inner) => &inner.fork,
            Self::Bellatrix(inner) => &inner.fork,
            Self::Capella(inner) => &inner.fork,
            Self::Deneb(inner) => &inner.fork,
        }
    }
    pub fn latest_block_header(&self) -> &BeaconBlockHeader {
        match self {
            Self::Phase0(inner) => &inner.latest_block_header,
            Self::Altair(inner) => &inner.latest_block_header,
            Self::Bellatrix(inner) => &inner.latest_block_header,
            Self::Capella(inner) => &inner.latest_block_header,
            Self::Deneb(inner) => &inner.latest_block_header,
        }
    }
    pub fn block_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.block_roots,
            Self::Altair(inner) => &inner.block_roots,
            Self::Bellatrix(inner) => &inner.block_roots,
            Self::Capella(inner) => &inner.block_roots,
            Self::Deneb(inner) => &inner.block_roots,
        }
    }
    pub fn state_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.state_roots,
            Self::Altair(inner) => &inner.state_roots,
            Self::Bellatrix(inner) => &inner.state_roots,
            Self::Capella(inner) => &inner.state_roots,
            Self::Deneb(inner) => &inner.state_roots,
        }
    }
    pub fn historical_roots(&self) -> &List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.historical_roots,
            Self::Altair(inner) => &inner.historical_roots,
            Self::Bellatrix(inner) => &inner.historical_roots,
            Self::Capella(inner) => &inner.historical_roots,
            Self::Deneb(inner) => &inner.historical_roots,
        }
    }
    pub fn eth1_data(&self) -> &Eth1Data {
        match self {
            Self::Phase0(inner) => &inner.eth1_data,
            Self::Altair(inner) => &inner.eth1_data,
            Self::Bellatrix(inner) => &inner.eth1_data,
            Self::Capella(inner) => &inner.eth1_data,
            Self::Deneb(inner) => &inner.eth1_data,
        }
    }
    pub fn eth1_data_votes(&self) -> &List<Eth1Data, ETH1_DATA_VOTES_BOUND> {
        match self {
            Self::Phase0(inner) => &inner.eth1_data_votes,
            Self::Altair(inner) => &inner.eth1_data_votes,
            Self::Bellatrix(inner) => &inner.eth1_data_votes,
            Self::Capella(inner) => &inner.eth1_data_votes,
            Self::Deneb(inner) => &inner.eth1_data_votes,
        }
    }
    pub fn eth1_deposit_index(&self) -> u64 {
        match self {
            Self::Phase0(inner) => inner.eth1_deposit_index,
            Self::Altair(inner) => inner.eth1_deposit_index,
            Self::Bellatrix(inner) => inner.eth1_deposit_index,
            Self::Capella(inner) => inner.eth1_deposit_index,
            Self::Deneb(inner) => inner.eth1_deposit_index,
        }
    }
    pub fn validators(&self) -> &List<Validator, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.validators,
            Self::Altair(inner) => &inner.validators,
            Self::Bellatrix(inner) => &inner.validators,
            Self::Capella(inner) => &inner.validators,
            Self::Deneb(inner) => &inner.validators,
        }
    }
    pub fn balances(&self) -> &List<Gwei, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.balances,
            Self::Altair(inner) => &inner.balances,
            Self::Bellatrix(inner) => &inner.balances,
            Self::Capella(inner) => &inner.balances,
            Self::Deneb(inner) => &inner.balances,
        }
    }
    pub fn randao_mixes(&self) -> &Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.randao_mixes,
            Self::Altair(inner) => &inner.randao_mixes,
            Self::Bellatrix(inner) => &inner.randao_mixes,
            Self::Capella(inner) => &inner.randao_mixes,
            Self::Deneb(inner) => &inner.randao_mixes,
        }
    }
    pub fn slashings(&self) -> &Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.slashings,
            Self::Altair(inner) => &inner.slashings,
            Self::Bellatrix(inner) => &inner.slashings,
            Self::Capella(inner) => &inner.slashings,
            Self::Deneb(inner) => &inner.slashings,
        }
    }
    pub fn previous_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.previous_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn current_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.current_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn justification_bits(&self) -> &Bitvector<JUSTIFICATION_BITS_LENGTH> {
        match self {
            Self::Phase0(inner) => &inner.justification_bits,
            Self::Altair(inner) => &inner.justification_bits,
            Self::Bellatrix(inner) => &inner.justification_bits,
            Self::Capella(inner) => &inner.justification_bits,
            Self::Deneb(inner) => &inner.justification_bits,
        }
    }
    pub fn previous_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.previous_justified_checkpoint,
            Self::Altair(inner) => &inner.previous_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.previous_justified_checkpoint,
            Self::Capella(inner) => &inner.previous_justified_checkpoint,
            Self::Deneb(inner) => &inner.previous_justified_checkpoint,
        }
    }
    pub fn current_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.current_justified_checkpoint,
            Self::Altair(inner) => &inner.current_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.current_justified_checkpoint,
            Self::Capella(inner) => &inner.current_justified_checkpoint,
            Self::Deneb(inner) => &inner.current_justified_checkpoint,
        }
    }
    pub fn finalized_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.finalized_checkpoint,
            Self::Altair(inner) => &inner.finalized_checkpoint,
            Self::Bellatrix(inner) => &inner.finalized_checkpoint,
            Self::Capella(inner) => &inner.finalized_checkpoint,
            Self::Deneb(inner) => &inner.finalized_checkpoint,
        }
    }
    pub fn previous_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.previous_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.previous_epoch_participation),
            Self::Capella(inner) => Some(&inner.previous_epoch_participation),
            Self::Deneb(inner) => Some(&inner.previous_epoch_participation),
        }
    }
    pub fn current_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.current_epoch_participation),
            Self::Capella(inner) => Some(&inner.current_epoch_participation),
            Self::Deneb(inner) => Some(&inner.current_epoch_participation),
        }
    }
    pub fn inactivity_scores(&self) -> Option<&List<u64, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.inactivity_scores),
            Self::Bellatrix(inner) => Some(&inner.inactivity_scores),
            Self::Capella(inner) => Some(&inner.inactivity_scores),
            Self::Deneb(inner) => Some(&inner.inactivity_scores),
        }
    }
    pub fn current_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_sync_committee),
            Self::Bellatrix(inner) => Some(&inner.current_sync_committee),
            Self::Capella(inner) => Some(&inner.current_sync_committee),
            Self::Deneb(inner) => Some(&inner.current_sync_committee),
        }
    }
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.next_sync_committee),
            Self::Bellatrix(inner) => Some(&inner.next_sync_committee),
            Self::Capella(inner) => Some(&inner.next_sync_committee),
            Self::Deneb(inner) => Some(&inner.next_sync_committee),
        }
    }
    pub fn latest_execution_payload_header(
        &self,
    ) -> Option<ExecutionPayloadHeaderRef<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(inner) => Some(From::from(&inner.latest_execution_payload_header)),
            Self::Capella(inner) => Some(From::from(&inner.latest_execution_payload_header)),
            Self::Deneb(inner) => Some(From::from(&inner.latest_execution_payload_header)),
        }
    }
    pub fn next_withdrawal_index(&self) -> Option<WithdrawalIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.next_withdrawal_index),
            Self::Deneb(inner) => Some(inner.next_withdrawal_index),
        }
    }
    pub fn next_withdrawal_validator_index(&self) -> Option<ValidatorIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.next_withdrawal_validator_index),
            Self::Deneb(inner) => Some(inner.next_withdrawal_validator_index),
        }
    }
    pub fn historical_summaries(&self) -> Option<&List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&inner.historical_summaries),
            Self::Deneb(inner) => Some(&inner.historical_summaries),
        }
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    >
    for BeaconStateRef<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    ) -> Self {
        Self::Phase0(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    >
    for BeaconStateRef<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    ) -> Self {
        Self::Altair(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    >
    for BeaconStateRef<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Bellatrix(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    >
    for BeaconStateRef<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Capella(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    >
    for BeaconStateRef<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Deneb(value)
    }
}
#[derive(Debug, PartialEq, Eq, HashTreeRoot)]
#[ssz(transparent)]
pub enum BeaconStateRefMut<
    'a,
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    Phase0(
        &'a mut phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    ),
    Altair(
        &'a mut altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
    Bellatrix(
        &'a mut bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        &'a mut capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Deneb(
        &'a mut deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    BeaconStateRefMut<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    pub fn phase0(
        &self,
    ) -> Option<
        &phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    > {
        match self {
            Self::Phase0(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn phase0_mut(
        &mut self,
    ) -> Option<
        &mut phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    > {
        match self {
            Self::Phase0(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn altair(
        &self,
    ) -> Option<
        &altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    > {
        match self {
            Self::Altair(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn altair_mut(
        &mut self,
    ) -> Option<
        &mut altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    > {
        match self {
            Self::Altair(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix(
        &self,
    ) -> Option<
        &bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix_mut(
        &mut self,
    ) -> Option<
        &mut bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella(
        &self,
    ) -> Option<
        &capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella_mut(
        &mut self,
    ) -> Option<
        &mut capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb(
        &self,
    ) -> Option<
        &deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb_mut(
        &mut self,
    ) -> Option<
        &mut deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    > {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn version(&self) -> Version {
        match self {
            Self::Phase0(_) => Version::Phase0,
            Self::Altair(_) => Version::Altair,
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
        }
    }
    pub fn genesis_time(&self) -> u64 {
        match self {
            Self::Phase0(inner) => inner.genesis_time,
            Self::Altair(inner) => inner.genesis_time,
            Self::Bellatrix(inner) => inner.genesis_time,
            Self::Capella(inner) => inner.genesis_time,
            Self::Deneb(inner) => inner.genesis_time,
        }
    }
    pub fn genesis_time_mut(&mut self) -> &mut u64 {
        match self {
            Self::Phase0(inner) => &mut inner.genesis_time,
            Self::Altair(inner) => &mut inner.genesis_time,
            Self::Bellatrix(inner) => &mut inner.genesis_time,
            Self::Capella(inner) => &mut inner.genesis_time,
            Self::Deneb(inner) => &mut inner.genesis_time,
        }
    }
    pub fn genesis_validators_root(&self) -> Root {
        match self {
            Self::Phase0(inner) => inner.genesis_validators_root,
            Self::Altair(inner) => inner.genesis_validators_root,
            Self::Bellatrix(inner) => inner.genesis_validators_root,
            Self::Capella(inner) => inner.genesis_validators_root,
            Self::Deneb(inner) => inner.genesis_validators_root,
        }
    }
    pub fn genesis_validators_root_mut(&mut self) -> &mut Root {
        match self {
            Self::Phase0(inner) => &mut inner.genesis_validators_root,
            Self::Altair(inner) => &mut inner.genesis_validators_root,
            Self::Bellatrix(inner) => &mut inner.genesis_validators_root,
            Self::Capella(inner) => &mut inner.genesis_validators_root,
            Self::Deneb(inner) => &mut inner.genesis_validators_root,
        }
    }
    pub fn slot(&self) -> Slot {
        match self {
            Self::Phase0(inner) => inner.slot,
            Self::Altair(inner) => inner.slot,
            Self::Bellatrix(inner) => inner.slot,
            Self::Capella(inner) => inner.slot,
            Self::Deneb(inner) => inner.slot,
        }
    }
    pub fn slot_mut(&mut self) -> &mut Slot {
        match self {
            Self::Phase0(inner) => &mut inner.slot,
            Self::Altair(inner) => &mut inner.slot,
            Self::Bellatrix(inner) => &mut inner.slot,
            Self::Capella(inner) => &mut inner.slot,
            Self::Deneb(inner) => &mut inner.slot,
        }
    }
    pub fn fork(&self) -> &Fork {
        match self {
            Self::Phase0(inner) => &inner.fork,
            Self::Altair(inner) => &inner.fork,
            Self::Bellatrix(inner) => &inner.fork,
            Self::Capella(inner) => &inner.fork,
            Self::Deneb(inner) => &inner.fork,
        }
    }
    pub fn fork_mut(&mut self) -> &mut Fork {
        match self {
            Self::Phase0(inner) => &mut inner.fork,
            Self::Altair(inner) => &mut inner.fork,
            Self::Bellatrix(inner) => &mut inner.fork,
            Self::Capella(inner) => &mut inner.fork,
            Self::Deneb(inner) => &mut inner.fork,
        }
    }
    pub fn latest_block_header(&self) -> &BeaconBlockHeader {
        match self {
            Self::Phase0(inner) => &inner.latest_block_header,
            Self::Altair(inner) => &inner.latest_block_header,
            Self::Bellatrix(inner) => &inner.latest_block_header,
            Self::Capella(inner) => &inner.latest_block_header,
            Self::Deneb(inner) => &inner.latest_block_header,
        }
    }
    pub fn latest_block_header_mut(&mut self) -> &mut BeaconBlockHeader {
        match self {
            Self::Phase0(inner) => &mut inner.latest_block_header,
            Self::Altair(inner) => &mut inner.latest_block_header,
            Self::Bellatrix(inner) => &mut inner.latest_block_header,
            Self::Capella(inner) => &mut inner.latest_block_header,
            Self::Deneb(inner) => &mut inner.latest_block_header,
        }
    }
    pub fn block_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.block_roots,
            Self::Altair(inner) => &inner.block_roots,
            Self::Bellatrix(inner) => &inner.block_roots,
            Self::Capella(inner) => &inner.block_roots,
            Self::Deneb(inner) => &inner.block_roots,
        }
    }
    pub fn block_roots_mut(&mut self) -> &mut Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &mut inner.block_roots,
            Self::Altair(inner) => &mut inner.block_roots,
            Self::Bellatrix(inner) => &mut inner.block_roots,
            Self::Capella(inner) => &mut inner.block_roots,
            Self::Deneb(inner) => &mut inner.block_roots,
        }
    }
    pub fn state_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.state_roots,
            Self::Altair(inner) => &inner.state_roots,
            Self::Bellatrix(inner) => &inner.state_roots,
            Self::Capella(inner) => &inner.state_roots,
            Self::Deneb(inner) => &inner.state_roots,
        }
    }
    pub fn state_roots_mut(&mut self) -> &mut Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &mut inner.state_roots,
            Self::Altair(inner) => &mut inner.state_roots,
            Self::Bellatrix(inner) => &mut inner.state_roots,
            Self::Capella(inner) => &mut inner.state_roots,
            Self::Deneb(inner) => &mut inner.state_roots,
        }
    }
    pub fn historical_roots(&self) -> &List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.historical_roots,
            Self::Altair(inner) => &inner.historical_roots,
            Self::Bellatrix(inner) => &inner.historical_roots,
            Self::Capella(inner) => &inner.historical_roots,
            Self::Deneb(inner) => &inner.historical_roots,
        }
    }
    pub fn historical_roots_mut(&mut self) -> &mut List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.historical_roots,
            Self::Altair(inner) => &mut inner.historical_roots,
            Self::Bellatrix(inner) => &mut inner.historical_roots,
            Self::Capella(inner) => &mut inner.historical_roots,
            Self::Deneb(inner) => &mut inner.historical_roots,
        }
    }
    pub fn eth1_data(&self) -> &Eth1Data {
        match self {
            Self::Phase0(inner) => &inner.eth1_data,
            Self::Altair(inner) => &inner.eth1_data,
            Self::Bellatrix(inner) => &inner.eth1_data,
            Self::Capella(inner) => &inner.eth1_data,
            Self::Deneb(inner) => &inner.eth1_data,
        }
    }
    pub fn eth1_data_mut(&mut self) -> &mut Eth1Data {
        match self {
            Self::Phase0(inner) => &mut inner.eth1_data,
            Self::Altair(inner) => &mut inner.eth1_data,
            Self::Bellatrix(inner) => &mut inner.eth1_data,
            Self::Capella(inner) => &mut inner.eth1_data,
            Self::Deneb(inner) => &mut inner.eth1_data,
        }
    }
    pub fn eth1_data_votes(&self) -> &List<Eth1Data, ETH1_DATA_VOTES_BOUND> {
        match self {
            Self::Phase0(inner) => &inner.eth1_data_votes,
            Self::Altair(inner) => &inner.eth1_data_votes,
            Self::Bellatrix(inner) => &inner.eth1_data_votes,
            Self::Capella(inner) => &inner.eth1_data_votes,
            Self::Deneb(inner) => &inner.eth1_data_votes,
        }
    }
    pub fn eth1_data_votes_mut(&mut self) -> &mut List<Eth1Data, ETH1_DATA_VOTES_BOUND> {
        match self {
            Self::Phase0(inner) => &mut inner.eth1_data_votes,
            Self::Altair(inner) => &mut inner.eth1_data_votes,
            Self::Bellatrix(inner) => &mut inner.eth1_data_votes,
            Self::Capella(inner) => &mut inner.eth1_data_votes,
            Self::Deneb(inner) => &mut inner.eth1_data_votes,
        }
    }
    pub fn eth1_deposit_index(&self) -> u64 {
        match self {
            Self::Phase0(inner) => inner.eth1_deposit_index,
            Self::Altair(inner) => inner.eth1_deposit_index,
            Self::Bellatrix(inner) => inner.eth1_deposit_index,
            Self::Capella(inner) => inner.eth1_deposit_index,
            Self::Deneb(inner) => inner.eth1_deposit_index,
        }
    }
    pub fn eth1_deposit_index_mut(&mut self) -> &mut u64 {
        match self {
            Self::Phase0(inner) => &mut inner.eth1_deposit_index,
            Self::Altair(inner) => &mut inner.eth1_deposit_index,
            Self::Bellatrix(inner) => &mut inner.eth1_deposit_index,
            Self::Capella(inner) => &mut inner.eth1_deposit_index,
            Self::Deneb(inner) => &mut inner.eth1_deposit_index,
        }
    }
    pub fn validators(&self) -> &List<Validator, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.validators,
            Self::Altair(inner) => &inner.validators,
            Self::Bellatrix(inner) => &inner.validators,
            Self::Capella(inner) => &inner.validators,
            Self::Deneb(inner) => &inner.validators,
        }
    }
    pub fn validators_mut(&mut self) -> &mut List<Validator, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.validators,
            Self::Altair(inner) => &mut inner.validators,
            Self::Bellatrix(inner) => &mut inner.validators,
            Self::Capella(inner) => &mut inner.validators,
            Self::Deneb(inner) => &mut inner.validators,
        }
    }
    pub fn balances(&self) -> &List<Gwei, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.balances,
            Self::Altair(inner) => &inner.balances,
            Self::Bellatrix(inner) => &inner.balances,
            Self::Capella(inner) => &inner.balances,
            Self::Deneb(inner) => &inner.balances,
        }
    }
    pub fn balances_mut(&mut self) -> &mut List<Gwei, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.balances,
            Self::Altair(inner) => &mut inner.balances,
            Self::Bellatrix(inner) => &mut inner.balances,
            Self::Capella(inner) => &mut inner.balances,
            Self::Deneb(inner) => &mut inner.balances,
        }
    }
    pub fn randao_mixes(&self) -> &Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.randao_mixes,
            Self::Altair(inner) => &inner.randao_mixes,
            Self::Bellatrix(inner) => &inner.randao_mixes,
            Self::Capella(inner) => &inner.randao_mixes,
            Self::Deneb(inner) => &inner.randao_mixes,
        }
    }
    pub fn randao_mixes_mut(&mut self) -> &mut Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR> {
        match self {
            Self::Phase0(inner) => &mut inner.randao_mixes,
            Self::Altair(inner) => &mut inner.randao_mixes,
            Self::Bellatrix(inner) => &mut inner.randao_mixes,
            Self::Capella(inner) => &mut inner.randao_mixes,
            Self::Deneb(inner) => &mut inner.randao_mixes,
        }
    }
    pub fn slashings(&self) -> &Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.slashings,
            Self::Altair(inner) => &inner.slashings,
            Self::Bellatrix(inner) => &inner.slashings,
            Self::Capella(inner) => &inner.slashings,
            Self::Deneb(inner) => &inner.slashings,
        }
    }
    pub fn slashings_mut(&mut self) -> &mut Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> {
        match self {
            Self::Phase0(inner) => &mut inner.slashings,
            Self::Altair(inner) => &mut inner.slashings,
            Self::Bellatrix(inner) => &mut inner.slashings,
            Self::Capella(inner) => &mut inner.slashings,
            Self::Deneb(inner) => &mut inner.slashings,
        }
    }
    pub fn previous_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.previous_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn previous_epoch_attestations_mut(
        &mut self,
    ) -> Option<
        &mut List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>,
    > {
        match self {
            Self::Phase0(inner) => Some(&mut inner.previous_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn current_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.current_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn current_epoch_attestations_mut(
        &mut self,
    ) -> Option<
        &mut List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>,
    > {
        match self {
            Self::Phase0(inner) => Some(&mut inner.current_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
        }
    }
    pub fn justification_bits(&self) -> &Bitvector<JUSTIFICATION_BITS_LENGTH> {
        match self {
            Self::Phase0(inner) => &inner.justification_bits,
            Self::Altair(inner) => &inner.justification_bits,
            Self::Bellatrix(inner) => &inner.justification_bits,
            Self::Capella(inner) => &inner.justification_bits,
            Self::Deneb(inner) => &inner.justification_bits,
        }
    }
    pub fn justification_bits_mut(&mut self) -> &mut Bitvector<JUSTIFICATION_BITS_LENGTH> {
        match self {
            Self::Phase0(inner) => &mut inner.justification_bits,
            Self::Altair(inner) => &mut inner.justification_bits,
            Self::Bellatrix(inner) => &mut inner.justification_bits,
            Self::Capella(inner) => &mut inner.justification_bits,
            Self::Deneb(inner) => &mut inner.justification_bits,
        }
    }
    pub fn previous_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.previous_justified_checkpoint,
            Self::Altair(inner) => &inner.previous_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.previous_justified_checkpoint,
            Self::Capella(inner) => &inner.previous_justified_checkpoint,
            Self::Deneb(inner) => &inner.previous_justified_checkpoint,
        }
    }
    pub fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        match self {
            Self::Phase0(inner) => &mut inner.previous_justified_checkpoint,
            Self::Altair(inner) => &mut inner.previous_justified_checkpoint,
            Self::Bellatrix(inner) => &mut inner.previous_justified_checkpoint,
            Self::Capella(inner) => &mut inner.previous_justified_checkpoint,
            Self::Deneb(inner) => &mut inner.previous_justified_checkpoint,
        }
    }
    pub fn current_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.current_justified_checkpoint,
            Self::Altair(inner) => &inner.current_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.current_justified_checkpoint,
            Self::Capella(inner) => &inner.current_justified_checkpoint,
            Self::Deneb(inner) => &inner.current_justified_checkpoint,
        }
    }
    pub fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        match self {
            Self::Phase0(inner) => &mut inner.current_justified_checkpoint,
            Self::Altair(inner) => &mut inner.current_justified_checkpoint,
            Self::Bellatrix(inner) => &mut inner.current_justified_checkpoint,
            Self::Capella(inner) => &mut inner.current_justified_checkpoint,
            Self::Deneb(inner) => &mut inner.current_justified_checkpoint,
        }
    }
    pub fn finalized_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.finalized_checkpoint,
            Self::Altair(inner) => &inner.finalized_checkpoint,
            Self::Bellatrix(inner) => &inner.finalized_checkpoint,
            Self::Capella(inner) => &inner.finalized_checkpoint,
            Self::Deneb(inner) => &inner.finalized_checkpoint,
        }
    }
    pub fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint {
        match self {
            Self::Phase0(inner) => &mut inner.finalized_checkpoint,
            Self::Altair(inner) => &mut inner.finalized_checkpoint,
            Self::Bellatrix(inner) => &mut inner.finalized_checkpoint,
            Self::Capella(inner) => &mut inner.finalized_checkpoint,
            Self::Deneb(inner) => &mut inner.finalized_checkpoint,
        }
    }
    pub fn previous_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.previous_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.previous_epoch_participation),
            Self::Capella(inner) => Some(&inner.previous_epoch_participation),
            Self::Deneb(inner) => Some(&inner.previous_epoch_participation),
        }
    }
    pub fn previous_epoch_participation_mut(
        &mut self,
    ) -> Option<&mut List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.previous_epoch_participation),
            Self::Bellatrix(inner) => Some(&mut inner.previous_epoch_participation),
            Self::Capella(inner) => Some(&mut inner.previous_epoch_participation),
            Self::Deneb(inner) => Some(&mut inner.previous_epoch_participation),
        }
    }
    pub fn current_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.current_epoch_participation),
            Self::Capella(inner) => Some(&inner.current_epoch_participation),
            Self::Deneb(inner) => Some(&inner.current_epoch_participation),
        }
    }
    pub fn current_epoch_participation_mut(
        &mut self,
    ) -> Option<&mut List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.current_epoch_participation),
            Self::Bellatrix(inner) => Some(&mut inner.current_epoch_participation),
            Self::Capella(inner) => Some(&mut inner.current_epoch_participation),
            Self::Deneb(inner) => Some(&mut inner.current_epoch_participation),
        }
    }
    pub fn inactivity_scores(&self) -> Option<&List<u64, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.inactivity_scores),
            Self::Bellatrix(inner) => Some(&inner.inactivity_scores),
            Self::Capella(inner) => Some(&inner.inactivity_scores),
            Self::Deneb(inner) => Some(&inner.inactivity_scores),
        }
    }
    pub fn inactivity_scores_mut(&mut self) -> Option<&mut List<u64, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.inactivity_scores),
            Self::Bellatrix(inner) => Some(&mut inner.inactivity_scores),
            Self::Capella(inner) => Some(&mut inner.inactivity_scores),
            Self::Deneb(inner) => Some(&mut inner.inactivity_scores),
        }
    }
    pub fn current_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_sync_committee),
            Self::Bellatrix(inner) => Some(&inner.current_sync_committee),
            Self::Capella(inner) => Some(&inner.current_sync_committee),
            Self::Deneb(inner) => Some(&inner.current_sync_committee),
        }
    }
    pub fn current_sync_committee_mut(
        &mut self,
    ) -> Option<&mut SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.current_sync_committee),
            Self::Bellatrix(inner) => Some(&mut inner.current_sync_committee),
            Self::Capella(inner) => Some(&mut inner.current_sync_committee),
            Self::Deneb(inner) => Some(&mut inner.current_sync_committee),
        }
    }
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.next_sync_committee),
            Self::Bellatrix(inner) => Some(&inner.next_sync_committee),
            Self::Capella(inner) => Some(&inner.next_sync_committee),
            Self::Deneb(inner) => Some(&inner.next_sync_committee),
        }
    }
    pub fn next_sync_committee_mut(&mut self) -> Option<&mut SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&mut inner.next_sync_committee),
            Self::Bellatrix(inner) => Some(&mut inner.next_sync_committee),
            Self::Capella(inner) => Some(&mut inner.next_sync_committee),
            Self::Deneb(inner) => Some(&mut inner.next_sync_committee),
        }
    }
    pub fn latest_execution_payload_header(
        &self,
    ) -> Option<ExecutionPayloadHeaderRef<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(inner) => Some(From::from(&inner.latest_execution_payload_header)),
            Self::Capella(inner) => Some(From::from(&inner.latest_execution_payload_header)),
            Self::Deneb(inner) => Some(From::from(&inner.latest_execution_payload_header)),
        }
    }
    pub fn latest_execution_payload_header_mut(
        &mut self,
    ) -> Option<ExecutionPayloadHeaderRefMut<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(inner) => Some(From::from(&mut inner.latest_execution_payload_header)),
            Self::Capella(inner) => Some(From::from(&mut inner.latest_execution_payload_header)),
            Self::Deneb(inner) => Some(From::from(&mut inner.latest_execution_payload_header)),
        }
    }
    pub fn next_withdrawal_index(&self) -> Option<WithdrawalIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.next_withdrawal_index),
            Self::Deneb(inner) => Some(inner.next_withdrawal_index),
        }
    }
    pub fn next_withdrawal_index_mut(&mut self) -> Option<&mut WithdrawalIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.next_withdrawal_index),
            Self::Deneb(inner) => Some(&mut inner.next_withdrawal_index),
        }
    }
    pub fn next_withdrawal_validator_index(&self) -> Option<ValidatorIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.next_withdrawal_validator_index),
            Self::Deneb(inner) => Some(inner.next_withdrawal_validator_index),
        }
    }
    pub fn next_withdrawal_validator_index_mut(&mut self) -> Option<&mut ValidatorIndex> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.next_withdrawal_validator_index),
            Self::Deneb(inner) => Some(&mut inner.next_withdrawal_validator_index),
        }
    }
    pub fn historical_summaries(&self) -> Option<&List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&inner.historical_summaries),
            Self::Deneb(inner) => Some(&inner.historical_summaries),
        }
    }
    pub fn historical_summaries_mut(
        &mut self,
    ) -> Option<&mut List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.historical_summaries),
            Self::Deneb(inner) => Some(&mut inner.historical_summaries),
        }
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a mut phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    >
    for BeaconStateRefMut<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a mut phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    ) -> Self {
        Self::Phase0(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a mut altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    >
    for BeaconStateRefMut<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a mut altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    ) -> Self {
        Self::Altair(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a mut bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    >
    for BeaconStateRefMut<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a mut bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Bellatrix(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a mut capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    >
    for BeaconStateRefMut<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a mut capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Capella(value)
    }
}
impl<
        'a,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    >
    From<
        &'a mut deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    >
    for BeaconStateRefMut<
        'a,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(
        value: &'a mut deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Deneb(value)
    }
}
