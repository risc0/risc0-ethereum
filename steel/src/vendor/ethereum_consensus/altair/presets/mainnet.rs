use crate::ethereum_consensus::altair::spec;
pub use crate::ethereum_consensus::{
    altair::presets::Preset,
    phase0::presets::mainnet::{
        AggregateAndProof, Attestation, AttesterSlashing, HistoricalBatch, IndexedAttestation,
        PendingAttestation, SignedAggregateAndProof, EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR, ETH1_DATA_VOTES_BOUND, HISTORICAL_ROOTS_LIMIT,
        MAX_ATTESTATIONS, MAX_ATTESTER_SLASHINGS, MAX_DEPOSITS, MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE, MAX_VOLUNTARY_EXITS, SLOTS_PER_HISTORICAL_ROOT,
        VALIDATOR_REGISTRY_LIMIT,
    },
};

pub use spec::*;

pub const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = 50331648;
pub const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64 = 64;
pub const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64 = 2;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: Epoch = 256;
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: usize = 1;
pub const UPDATE_TIMEOUT: usize = 8192;

pub const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: usize = 16;
pub const SYNC_SUBCOMMITTEE_SIZE: usize = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;

pub const PRESET: Preset = Preset {
    inactivity_penalty_quotient_altair: INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
    min_slashing_penalty_quotient_altair: MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
    proportional_slashing_multiplier_altair: PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
    sync_committee_size: SYNC_COMMITTEE_SIZE,
    epochs_per_sync_committee_period: EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
    min_sync_committee_participants: MIN_SYNC_COMMITTEE_PARTICIPANTS,
    update_timeout: UPDATE_TIMEOUT,
};

pub type SyncAggregate = spec::SyncAggregate<SYNC_COMMITTEE_SIZE>;
pub type SyncCommittee = spec::SyncCommittee<SYNC_COMMITTEE_SIZE>;

pub type BeaconState = spec::BeaconState<
    SLOTS_PER_HISTORICAL_ROOT,
    HISTORICAL_ROOTS_LIMIT,
    ETH1_DATA_VOTES_BOUND,
    VALIDATOR_REGISTRY_LIMIT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    MAX_VALIDATORS_PER_COMMITTEE,
    SYNC_COMMITTEE_SIZE,
>;

pub type BeaconBlockBody = spec::BeaconBlockBody<
    MAX_PROPOSER_SLASHINGS,
    MAX_VALIDATORS_PER_COMMITTEE,
    MAX_ATTESTER_SLASHINGS,
    MAX_ATTESTATIONS,
    MAX_DEPOSITS,
    MAX_VOLUNTARY_EXITS,
    SYNC_COMMITTEE_SIZE,
>;

pub type BeaconBlock = spec::BeaconBlock<
    MAX_PROPOSER_SLASHINGS,
    MAX_VALIDATORS_PER_COMMITTEE,
    MAX_ATTESTER_SLASHINGS,
    MAX_ATTESTATIONS,
    MAX_DEPOSITS,
    MAX_VOLUNTARY_EXITS,
    SYNC_COMMITTEE_SIZE,
>;

pub type SignedBeaconBlock = spec::SignedBeaconBlock<
    MAX_PROPOSER_SLASHINGS,
    MAX_VALIDATORS_PER_COMMITTEE,
    MAX_ATTESTER_SLASHINGS,
    MAX_ATTESTATIONS,
    MAX_DEPOSITS,
    MAX_VOLUNTARY_EXITS,
    SYNC_COMMITTEE_SIZE,
>;

pub type SyncCommitteeContribution = spec::SyncCommitteeContribution<SYNC_SUBCOMMITTEE_SIZE>;
pub type ContributionAndProof = spec::ContributionAndProof<SYNC_SUBCOMMITTEE_SIZE>;
pub type SignedContributionAndProof = spec::SignedContributionAndProof<SYNC_SUBCOMMITTEE_SIZE>;

pub type LightClientBootstrap = spec::LightClientBootstrap<SYNC_COMMITTEE_SIZE>;
pub type LightClientUpdate = spec::LightClientUpdate<SYNC_COMMITTEE_SIZE>;
pub type LightClientFinalityUpdate = spec::LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>;
pub type LightClientOptimisticUpdate = spec::LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE>;
