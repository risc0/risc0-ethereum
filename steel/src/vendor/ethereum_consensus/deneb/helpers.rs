use crate::ethereum_consensus::{
    altair::constants::{
        TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
    },
    crypto::{hash, KzgCommitment},
    deneb::{
        beacon_state::BeaconState, blob_sidecar::VersionedHash, get_block_root,
        get_block_root_at_slot, get_current_epoch, get_validator_churn_limit, AttestationData,
        VERSIONED_HASH_VERSION_KZG,
    },
    error::{invalid_operation_error, InvalidAttestation, InvalidOperation},
    state_transition::{Context, Result},
};
use integer_sqrt::IntegerSquareRoot;

pub fn kzg_commitment_to_versioned_hash(kzg_commitment: &KzgCommitment) -> VersionedHash {
    let mut result = VersionedHash::default();
    result[0] = VERSIONED_HASH_VERSION_KZG;
    result[1..].copy_from_slice(&hash(kzg_commitment.as_ref())[1..]);
    result
}

pub fn get_attestation_participation_flag_indices<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    state: &BeaconState<
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
    data: &AttestationData,
    inclusion_delay: u64,
    context: &Context,
) -> Result<Vec<usize>> {
    let justified_checkpoint = if data.target.epoch == get_current_epoch(state, context) {
        &state.current_justified_checkpoint
    } else {
        &state.previous_justified_checkpoint
    };

    let is_matching_source = data.source == *justified_checkpoint;
    if !is_matching_source {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::InvalidSource {
                expected: justified_checkpoint.clone(),
                source_checkpoint: data.source.clone(),
                current: get_current_epoch(state, context),
            },
        )));
    }
    let is_matching_target = is_matching_source
        && (data.target.root == *get_block_root(state, data.target.epoch, context)?);
    let is_matching_head = is_matching_target
        && (data.beacon_block_root == *get_block_root_at_slot(state, data.slot)?);

    let mut participation_flag_indices = Vec::new();
    if is_matching_source && inclusion_delay <= context.slots_per_epoch.integer_sqrt() {
        participation_flag_indices.push(TIMELY_SOURCE_FLAG_INDEX);
    }
    if is_matching_target {
        participation_flag_indices.push(TIMELY_TARGET_FLAG_INDEX);
    }
    if is_matching_head && inclusion_delay == context.min_attestation_inclusion_delay {
        participation_flag_indices.push(TIMELY_HEAD_FLAG_INDEX);
    }

    Ok(participation_flag_indices)
}

pub fn get_validator_activation_churn_limit<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    state: &BeaconState<
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
    context: &Context,
) -> usize {
    let limit = context.max_per_epoch_activation_churn_limit as usize;
    limit.min(get_validator_churn_limit(state, context))
}
