use crate::ethereum_consensus::{
    electra::{
        compute_activation_exit_epoch, decrease_balance, get_current_epoch,
        has_compounding_withdrawal_credential,
        helpers::{
            get_activation_exit_churn_limit, get_active_balance, initiate_validator_exit,
            is_eligible_for_activation_queue, switch_to_compounding_validator,
        },
        increase_balance, is_active_validator, is_eligible_for_activation, process_eth1_data_reset,
        process_historical_summaries_update, process_inactivity_updates,
        process_justification_and_finalization, process_participation_flag_updates,
        process_randao_mixes_reset, process_rewards_and_penalties, process_slashings,
        process_slashings_reset, process_sync_committee_updates, BeaconState, Context, Error,
    },
    primitives::Gwei,
};

pub fn process_epoch<
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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
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
        PENDING_BALANCE_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    context: &Context,
) -> Result<(), Error> {
    process_justification_and_finalization(state, context)?;
    process_inactivity_updates(state, context)?;
    process_rewards_and_penalties(state, context)?;
    process_registry_updates(state, context)?;
    process_slashings(state, context)?;
    process_eth1_data_reset(state, context);
    process_pending_balance_deposits(state, context)?;
    process_pending_consolidations(state, context)?;
    process_effective_balance_updates(state, context);
    process_slashings_reset(state, context);
    process_randao_mixes_reset(state, context);
    process_historical_summaries_update(state, context)?;
    process_participation_flag_updates(state)?;
    process_sync_committee_updates(state, context)?;
    Ok(())
}

pub fn process_registry_updates<
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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
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
        PENDING_BALANCE_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    context: &Context,
) -> Result<(), Error> {
    let current_epoch = get_current_epoch(state, context);
    for i in 0..state.validators.len() {
        let validator = &mut state.validators[i];
        if is_eligible_for_activation_queue(validator, context) {
            validator.activation_eligibility_epoch = current_epoch + 1;
        }
        if is_active_validator(validator, current_epoch)
            && validator.effective_balance <= context.ejection_balance
        {
            initiate_validator_exit(state, i, context)?;
        }
    }

    let activation_epoch = compute_activation_exit_epoch(current_epoch, context);
    for i in 0..state.validators.len() {
        let validator = &state.validators[i];
        if is_eligible_for_activation(state, validator) {
            let validator = &mut state.validators[i];
            validator.activation_epoch = activation_epoch;
        }
    }

    Ok(())
}

pub fn process_pending_balance_deposits<
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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
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
        PENDING_BALANCE_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    context: &Context,
) -> Result<(), Error> {
    let available_for_processing =
        state.deposit_balance_to_consume + get_activation_exit_churn_limit(state, context)?;
    let mut processed_amount = 0;
    let mut next_deposit_index = 0;

    for i in 0..state.pending_balance_deposits.len() {
        let deposit = &state.pending_balance_deposits[i];
        let index = deposit.index;
        let amount = deposit.amount;
        if processed_amount + deposit.amount > available_for_processing {
            break;
        }
        increase_balance(state, index, amount);
        processed_amount += amount;
        next_deposit_index += 1;
    }

    state.pending_balance_deposits.drain(..next_deposit_index);

    if state.pending_balance_deposits.is_empty() {
        state.deposit_balance_to_consume = 0;
    } else {
        state.deposit_balance_to_consume = available_for_processing - processed_amount;
    }

    Ok(())
}

pub fn process_pending_consolidations<
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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
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
        PENDING_BALANCE_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    context: &Context,
) -> Result<(), Error> {
    let mut next_pending_consolidation = 0;
    for i in 0..state.pending_consolidations.len() {
        let pending_consolidation = &state.pending_consolidations[i];
        let source_index = pending_consolidation.source_index;
        let target_index = pending_consolidation.target_index;
        let source_validator = &state.validators[source_index];
        if source_validator.slashed {
            next_pending_consolidation += 1;
            continue;
        }
        if source_validator.withdrawable_epoch > get_current_epoch(state, context) {
            break;
        }

        switch_to_compounding_validator(state, target_index, context)?;
        let active_balance = get_active_balance(state, source_index, context);
        decrease_balance(state, source_index, active_balance);
        increase_balance(state, target_index, active_balance);
        next_pending_consolidation += 1;
    }

    state
        .pending_consolidations
        .drain(..next_pending_consolidation);

    Ok(())
}

pub fn process_effective_balance_updates<
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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
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
        PENDING_BALANCE_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    context: &Context,
) {
    // Update effective balances with hysteresis
    let hysteresis_increment = context.effective_balance_increment / context.hysteresis_quotient;
    let downward_threshold = hysteresis_increment * context.hysteresis_downward_multiplier;
    let upward_threshold = hysteresis_increment * context.hysteresis_upward_multiplier;
    for i in 0..state.validators.len() {
        let validator = &mut state.validators[i];
        let balance = state.balances[i];
        let effective_balance_limit = if has_compounding_withdrawal_credential(validator) {
            context.max_effective_balance_electra
        } else {
            context.min_activation_balance
        };

        if balance + downward_threshold < validator.effective_balance
            || validator.effective_balance + upward_threshold < balance
        {
            validator.effective_balance = Gwei::min(
                balance - balance % context.effective_balance_increment,
                effective_balance_limit,
            );
        }
    }
}
