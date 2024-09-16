use crate::ethereum_consensus::{
    deneb,
    electra::{
        beacon_state::BeaconState,
        constants::UNSET_DEPOSIT_RECEIPTS_START_INDEX,
        execution_payload::ExecutionPayloadHeader,
        helpers::{
            get_activation_exit_churn_limit, get_consolidation_churn_limit,
            has_compounding_withdrawal_credential, queue_entire_balance_and_reset_validator,
            queue_excess_active_balance,
        },
    },
    phase0::{helpers::compute_activation_exit_epoch, Fork},
    primitives::FAR_FUTURE_EPOCH,
    state_transition::Context,
    Error,
};

pub fn upgrade_to_electra<
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
    state: &deneb::BeaconState<
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
) -> Result<
    BeaconState<
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
    Error,
> {
    let epoch = deneb::get_current_epoch(state, context);
    let latest_execution_payload_header = &state.latest_execution_payload_header;
    let latest_execution_payload_header = ExecutionPayloadHeader {
        parent_hash: latest_execution_payload_header.parent_hash.clone(),
        fee_recipient: latest_execution_payload_header.fee_recipient.clone(),
        state_root: latest_execution_payload_header.state_root.clone(),
        receipts_root: latest_execution_payload_header.receipts_root.clone(),
        logs_bloom: latest_execution_payload_header.logs_bloom.clone(),
        prev_randao: latest_execution_payload_header.prev_randao.clone(),
        block_number: latest_execution_payload_header.block_number,
        gas_limit: latest_execution_payload_header.gas_limit,
        gas_used: latest_execution_payload_header.gas_used,
        timestamp: latest_execution_payload_header.timestamp,
        extra_data: latest_execution_payload_header.extra_data.clone(),
        base_fee_per_gas: latest_execution_payload_header.base_fee_per_gas,
        block_hash: latest_execution_payload_header.block_hash.clone(),
        transactions_root: latest_execution_payload_header.transactions_root,
        withdrawals_root: latest_execution_payload_header.withdrawals_root,
        blob_gas_used: latest_execution_payload_header.blob_gas_used,
        excess_blob_gas: latest_execution_payload_header.excess_blob_gas,
        deposit_receipts_root: Default::default(),
        withdrawal_requests_root: Default::default(),
    };

    let exit_epoch = state
        .validators
        .iter()
        .filter_map(|v| {
            if v.exit_epoch != FAR_FUTURE_EPOCH {
                Some(v.exit_epoch)
            } else {
                None
            }
        })
        .max()
        .or(Some(epoch));
    let earliest_exit_epoch = exit_epoch.unwrap() + 1;

    let mut post = BeaconState {
        genesis_time: state.genesis_time,
        genesis_validators_root: state.genesis_validators_root,
        slot: state.slot,
        fork: Fork {
            previous_version: state.fork.current_version,
            current_version: context.electra_fork_version,
            epoch,
        },
        latest_block_header: state.latest_block_header.clone(),
        block_roots: state.block_roots.clone(),
        state_roots: state.state_roots.clone(),
        historical_roots: state.historical_roots.clone(),
        eth1_data: state.eth1_data.clone(),
        eth1_data_votes: state.eth1_data_votes.clone(),
        eth1_deposit_index: state.eth1_deposit_index,
        validators: state.validators.clone(),
        balances: state.balances.clone(),
        randao_mixes: state.randao_mixes.clone(),
        slashings: state.slashings.clone(),
        previous_epoch_participation: state.previous_epoch_participation.clone(),
        current_epoch_participation: state.current_epoch_participation.clone(),
        justification_bits: state.justification_bits.clone(),
        previous_justified_checkpoint: state.previous_justified_checkpoint.clone(),
        current_justified_checkpoint: state.current_justified_checkpoint.clone(),
        finalized_checkpoint: state.finalized_checkpoint.clone(),
        inactivity_scores: state.inactivity_scores.clone(),
        current_sync_committee: state.current_sync_committee.clone(),
        next_sync_committee: state.next_sync_committee.clone(),
        latest_execution_payload_header,
        next_withdrawal_index: state.next_withdrawal_index,
        next_withdrawal_validator_index: state.next_withdrawal_validator_index,
        historical_summaries: state.historical_summaries.clone(),
        deposit_receipts_start_index: UNSET_DEPOSIT_RECEIPTS_START_INDEX,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: compute_activation_exit_epoch(epoch, context),
        pending_balance_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
    };
    post.exit_balance_to_consume = get_activation_exit_churn_limit(&post, context)?;
    post.consolidation_balance_to_consume = get_consolidation_churn_limit(&post, context)?;

    let mut pre_activation_validators = post
        .validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if validator.activation_epoch == FAR_FUTURE_EPOCH {
                Some((validator.activation_eligibility_epoch, index))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    pre_activation_validators.sort();

    for (_, index) in pre_activation_validators {
        queue_entire_balance_and_reset_validator(&mut post, index);
    }

    let indices_to_queue = post
        .validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if has_compounding_withdrawal_credential(validator) {
                Some(index)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for index in indices_to_queue {
        queue_excess_active_balance(&mut post, index, context)?;
    }

    Ok(post)
}
