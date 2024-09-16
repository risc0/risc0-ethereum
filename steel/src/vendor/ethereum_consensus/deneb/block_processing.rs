use crate::ethereum_consensus::{
    deneb::{
        add_flag, compute_domain, compute_epoch_at_slot, compute_timestamp_at_slot,
        get_attestation_participation_flag_indices, get_attesting_indices, get_base_reward,
        get_beacon_committee, get_beacon_proposer_index, get_committee_count_per_slot,
        get_current_epoch, get_indexed_attestation, get_previous_epoch, get_randao_mix, has_flag,
        increase_balance, initiate_validator_exit, is_active_validator,
        is_valid_indexed_attestation, kzg_commitment_to_versioned_hash, process_block_header,
        process_eth1_data, process_operations, process_randao, process_sync_aggregate,
        process_withdrawals, Attestation, BeaconBlock, BeaconBlockBody, BeaconState,
        ExecutionPayloadHeader, NewPayloadRequest, SignedVoluntaryExit, PARTICIPATION_FLAG_WEIGHTS,
        PROPOSER_WEIGHT, WEIGHT_DENOMINATOR,
    },
    domains::DomainType,
    error::{
        invalid_operation_error, InvalidAttestation, InvalidExecutionPayload, InvalidOperation,
        InvalidVoluntaryExit,
    },
    execution_engine::ExecutionEngine,
    primitives::FAR_FUTURE_EPOCH,
    signing::verify_signed_data,
    ssz::prelude::*,
    state_transition::{Context, Result},
};

pub fn process_attestation<
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
    state: &mut BeaconState<
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
    attestation: &Attestation<MAX_VALIDATORS_PER_COMMITTEE>,
    context: &Context,
) -> Result<()> {
    let data = &attestation.data;
    let is_previous = data.target.epoch == get_previous_epoch(state, context);
    let current_epoch = get_current_epoch(state, context);
    let is_current = data.target.epoch == current_epoch;
    let valid_target_epoch = is_previous || is_current;
    if !valid_target_epoch {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::InvalidTargetEpoch {
                target: data.target.epoch,
                current: current_epoch,
            },
        )));
    }
    let attestation_epoch = compute_epoch_at_slot(data.slot, context);
    if data.target.epoch != attestation_epoch {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::InvalidSlot {
                slot: data.slot,
                epoch: attestation_epoch,
                target: data.target.epoch,
            },
        )));
    }
    let attestation_is_timely = data.slot + context.min_attestation_inclusion_delay <= state.slot;
    if !attestation_is_timely {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::NoDelay {
                attestation_slot: data.slot,
                state_slot: state.slot,
                required_delay: context.min_attestation_inclusion_delay,
            },
        )));
    }
    let committee_count = get_committee_count_per_slot(state, data.target.epoch, context);
    if data.index >= committee_count {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::InvalidIndex {
                index: data.index,
                upper_bound: committee_count,
            },
        )));
    }
    let committee = get_beacon_committee(state, data.slot, data.index, context)?;
    if attestation.aggregation_bits.len() != committee.len() {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::Bitfield {
                expected_length: committee.len(),
                length: attestation.aggregation_bits.len(),
            },
        )));
    }
    let inclusion_delay = state.slot - data.slot;
    let participation_flag_indices =
        get_attestation_participation_flag_indices(state, data, inclusion_delay, context)?;
    is_valid_indexed_attestation(
        state,
        &get_indexed_attestation(state, attestation, context)?,
        context,
    )?;
    let attesting_indices =
        get_attesting_indices(state, data, &attestation.aggregation_bits, context)?;
    let mut proposer_reward_numerator = 0;
    for index in attesting_indices {
        for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
            if is_current {
                if participation_flag_indices.contains(&flag_index)
                    && !has_flag(state.current_epoch_participation[index], flag_index)
                {
                    state.current_epoch_participation[index] =
                        add_flag(state.current_epoch_participation[index], flag_index);
                    proposer_reward_numerator += get_base_reward(state, index, context)? * weight;
                }
            } else if participation_flag_indices.contains(&flag_index)
                && !has_flag(state.previous_epoch_participation[index], flag_index)
            {
                state.previous_epoch_participation[index] =
                    add_flag(state.previous_epoch_participation[index], flag_index);
                proposer_reward_numerator += get_base_reward(state, index, context)? * weight;
            }
        }
    }
    let proposer_reward_denominator =
        (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / proposer_reward_denominator;
    increase_balance(
        state,
        get_beacon_proposer_index(state, context)?,
        proposer_reward,
    );
    Ok(())
}

pub fn process_execution_payload<
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
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
>(
    state: &mut BeaconState<
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >,
    context: &Context,
) -> Result<()> {
    let payload = &body.execution_payload;

    let parent_hash_invalid =
        payload.parent_hash != state.latest_execution_payload_header.block_hash;
    if parent_hash_invalid {
        return Err(invalid_operation_error(
            InvalidExecutionPayload::InvalidParentHash {
                provided: payload.parent_hash.clone(),
                expected: state.latest_execution_payload_header.block_hash.clone(),
            }
            .into(),
        ));
    }

    let current_epoch = get_current_epoch(state, context);
    let randao_mix = get_randao_mix(state, current_epoch);
    if &payload.prev_randao != randao_mix {
        return Err(invalid_operation_error(
            InvalidExecutionPayload::InvalidPrevRandao {
                provided: payload.prev_randao.clone(),
                expected: randao_mix.clone(),
            }
            .into(),
        ));
    }

    let timestamp = compute_timestamp_at_slot(state, state.slot, context)?;
    if payload.timestamp != timestamp {
        return Err(invalid_operation_error(
            InvalidExecutionPayload::InvalidTimestamp {
                provided: payload.timestamp,
                expected: timestamp,
            }
            .into(),
        ));
    }

    if body.blob_kzg_commitments.len() > context.max_blobs_per_block {
        return Err(invalid_operation_error(
            InvalidExecutionPayload::InvalidBlobCommitments {
                provided: body.blob_kzg_commitments.len(),
                limit: context.max_blobs_per_block,
            }
            .into(),
        ));
    }

    let versioned_hashes = body
        .blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect::<Vec<_>>();

    let execution_engine = context.execution_engine();
    let new_payload_request = NewPayloadRequest {
        execution_payload: payload.clone(),
        versioned_hashes,
        parent_beacon_block_root: state.latest_block_header.parent_root,
    };
    execution_engine.verify_and_notify_new_payload(&new_payload_request)?;

    state.latest_execution_payload_header = ExecutionPayloadHeader {
        parent_hash: payload.parent_hash.clone(),
        fee_recipient: payload.fee_recipient.clone(),
        state_root: payload.state_root.clone(),
        receipts_root: payload.receipts_root.clone(),
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao.clone(),
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash.clone(),
        transactions_root: payload.transactions.hash_tree_root()?,
        withdrawals_root: payload.withdrawals.hash_tree_root()?,
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    };

    Ok(())
}

pub fn process_voluntary_exit<
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
    state: &mut BeaconState<
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
    signed_voluntary_exit: &SignedVoluntaryExit,
    context: &Context,
) -> Result<()> {
    let voluntary_exit = &signed_voluntary_exit.message;
    let validator = state
        .validators
        .get(voluntary_exit.validator_index)
        .ok_or_else(|| {
            invalid_operation_error(InvalidOperation::VoluntaryExit(
                InvalidVoluntaryExit::InvalidIndex(voluntary_exit.validator_index),
            ))
        })?;
    let current_epoch = get_current_epoch(state, context);
    if !is_active_validator(validator, current_epoch) {
        return Err(invalid_operation_error(InvalidOperation::VoluntaryExit(
            InvalidVoluntaryExit::InactiveValidator(current_epoch),
        )));
    }
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Err(invalid_operation_error(InvalidOperation::VoluntaryExit(
            InvalidVoluntaryExit::ValidatorAlreadyExited {
                index: voluntary_exit.validator_index,
                epoch: validator.exit_epoch,
            },
        )));
    }
    if current_epoch < voluntary_exit.epoch {
        return Err(invalid_operation_error(InvalidOperation::VoluntaryExit(
            InvalidVoluntaryExit::EarlyExit {
                current_epoch,
                exit_epoch: voluntary_exit.epoch,
            },
        )));
    }
    let minimum_time_active =
        validator.activation_eligibility_epoch + context.shard_committee_period;
    if current_epoch < minimum_time_active {
        return Err(invalid_operation_error(InvalidOperation::VoluntaryExit(
            InvalidVoluntaryExit::ValidatorIsNotActiveForLongEnough {
                current_epoch,
                minimum_time_active,
            },
        )));
    }
    let domain = compute_domain(
        DomainType::VoluntaryExit,
        Some(context.capella_fork_version),
        Some(state.genesis_validators_root),
        context,
    )?;
    let public_key = &validator.public_key;
    verify_signed_data(
        voluntary_exit,
        &signed_voluntary_exit.signature,
        public_key,
        domain,
    )
    .map_err(|_| {
        invalid_operation_error(InvalidOperation::VoluntaryExit(
            InvalidVoluntaryExit::InvalidSignature(signed_voluntary_exit.signature.clone()),
        ))
    })?;
    initiate_validator_exit(state, voluntary_exit.validator_index, context)?;
    Ok(())
}

pub fn process_block<
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
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
>(
    state: &mut BeaconState<
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
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >,
    context: &Context,
) -> Result<()> {
    process_block_header(state, block, context)?;
    process_withdrawals(state, &block.body.execution_payload, context)?;
    process_execution_payload(state, &block.body, context)?;
    process_randao(state, &block.body, context)?;
    process_eth1_data(state, &block.body, context);
    process_operations(state, &block.body, context)?;
    process_sync_aggregate(state, &block.body.sync_aggregate, context)?;
    Ok(())
}
