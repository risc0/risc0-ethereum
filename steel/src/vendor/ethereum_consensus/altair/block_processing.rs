use crate::ethereum_consensus::{
    altair::{
        beacon_block::BeaconBlock,
        beacon_state::BeaconState,
        compute_epoch_at_slot,
        constants::{
            PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR,
        },
        decrease_balance, get_attesting_indices, get_base_reward, get_beacon_committee,
        get_beacon_proposer_index, get_block_root_at_slot, get_committee_count_per_slot,
        get_current_epoch, get_domain, get_indexed_attestation, get_previous_epoch,
        get_total_active_balance, get_validator_from_deposit,
        helpers::{
            add_flag, get_attestation_participation_flag_indices, get_base_reward_per_increment,
            has_flag,
        },
        increase_balance, is_valid_indexed_attestation, process_block_header, process_eth1_data,
        process_operations, process_randao,
        sync::SyncAggregate,
        Attestation, Bytes32, Gwei,
    },
    crypto::eth_fast_aggregate_verify,
    domains::DomainType,
    error::{invalid_operation_error, InvalidAttestation, InvalidOperation, InvalidSyncAggregate},
    primitives::{BlsPublicKey, ParticipationFlags, ValidatorIndex},
    signing::compute_signing_root,
    state_transition::{Context, Result},
};
use std::{collections::HashMap, iter::zip};

pub fn process_attestation<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const SYNC_COMMITTEE_SIZE: usize,
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

    let attestation_has_delay = data.slot + context.min_attestation_inclusion_delay <= state.slot;
    let attestation_is_recent = state.slot <= data.slot + context.slots_per_epoch;
    let attestation_is_timely = attestation_has_delay && attestation_is_recent;
    if !attestation_is_timely {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::NotTimely {
                state_slot: state.slot,
                attestation_slot: data.slot,
                lower_bound: data.slot + context.slots_per_epoch,
                upper_bound: data.slot + context.min_attestation_inclusion_delay,
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

    // Participation flag indices
    let inclusion_delay = state.slot - data.slot;
    let participation_flag_indices =
        get_attestation_participation_flag_indices(state, data, inclusion_delay, context)?;

    // Verify signature
    is_valid_indexed_attestation(
        state,
        &get_indexed_attestation(state, attestation, context)?,
        context,
    )?;

    // Update epoch participation flags
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

    // Reward proposer
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

pub fn add_validator_to_registry<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const SYNC_COMMITTEE_SIZE: usize,
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
    >,
    public_key: BlsPublicKey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    context: &Context,
) {
    state.validators.push(get_validator_from_deposit(
        public_key,
        withdrawal_credentials,
        amount,
        context,
    ));
    state.balances.push(amount);
    state
        .previous_epoch_participation
        .push(ParticipationFlags::default());
    state
        .current_epoch_participation
        .push(ParticipationFlags::default());
    state.inactivity_scores.push(0);
}

pub fn process_sync_aggregate<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const SYNC_COMMITTEE_SIZE: usize,
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
    >,
    sync_aggregate: &SyncAggregate<SYNC_COMMITTEE_SIZE>,
    context: &Context,
) -> Result<()> {
    // Verify sync committee aggregate signature signing over the previous slot block root
    let committee_public_keys = &state.current_sync_committee.public_keys;
    let participant_public_keys = zip(
        committee_public_keys.iter(),
        sync_aggregate.sync_committee_bits.iter(),
    )
    .filter_map(|(public_key, bit)| if *bit { Some(public_key) } else { None })
    .collect::<Vec<_>>();
    let previous_slot = u64::max(state.slot, 1) - 1;
    let domain = get_domain(
        state,
        DomainType::SyncCommittee,
        Some(compute_epoch_at_slot(previous_slot, context)),
        context,
    )?;
    let root_at_slot = *get_block_root_at_slot(state, previous_slot)?;
    let signing_root = compute_signing_root(&root_at_slot, domain)?;
    if eth_fast_aggregate_verify(
        participant_public_keys.as_slice(),
        signing_root.as_ref(),
        &sync_aggregate.sync_committee_signature,
    )
    .is_err()
    {
        return Err(invalid_operation_error(InvalidOperation::SyncAggregate(
            InvalidSyncAggregate::InvalidSignature {
                signature: sync_aggregate.sync_committee_signature.clone(),
                root: signing_root,
            },
        )));
    }

    // Compute participant and proposer rewards
    let total_active_increments =
        get_total_active_balance(state, context)? / context.effective_balance_increment;
    let total_base_rewards =
        get_base_reward_per_increment(state, context)? * total_active_increments;
    let max_participant_rewards =
        total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR / context.slots_per_epoch;
    let participant_reward = max_participant_rewards / context.sync_committee_size as u64;
    let proposer_reward =
        participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

    // Apply participant and proposer rewards
    let all_public_keys = state
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| (&v.public_key, i))
        .collect::<HashMap<&BlsPublicKey, usize>>();
    let mut committee_indices: Vec<ValidatorIndex> = Vec::default();
    for public_key in state.current_sync_committee.public_keys.iter() {
        committee_indices.push(
            *all_public_keys
                .get(public_key)
                .expect("validator public_key should exist"),
        );
    }
    for (participant_index, participation_bit) in zip(
        committee_indices.iter(),
        sync_aggregate.sync_committee_bits.iter(),
    ) {
        if *participation_bit {
            increase_balance(state, *participant_index, participant_reward);
            increase_balance(
                state,
                get_beacon_proposer_index(state, context)?,
                proposer_reward,
            );
        } else {
            decrease_balance(state, *participant_index, participant_reward);
        }
    }

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
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const SYNC_COMMITTEE_SIZE: usize,
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
    >,
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        SYNC_COMMITTEE_SIZE,
    >,
    context: &Context,
) -> Result<()> {
    process_block_header(state, block, context)?;
    process_randao(state, &block.body, context)?;
    process_eth1_data(state, &block.body, context);
    process_operations(state, &block.body, context)?;
    process_sync_aggregate(state, &block.body.sync_aggregate, context)?;
    Ok(())
}
