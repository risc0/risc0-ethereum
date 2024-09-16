use crate::ethereum_consensus::{
    crypto::fast_aggregate_verify,
    electra::{
        add_flag, compute_consolidation_epoch_and_update_churn, compute_domain,
        compute_epoch_at_slot, compute_exit_epoch_and_update_churn, compute_signing_root,
        compute_timestamp_at_slot, decrease_balance, get_attestation_participation_flag_indices,
        get_attesting_indices, get_base_reward, get_beacon_committee, get_beacon_proposer_index,
        get_committee_count_per_slot, get_committee_indices, get_consolidation_churn_limit,
        get_current_epoch, get_indexed_attestation, get_pending_balance_to_withdraw,
        get_previous_epoch, get_randao_mix, get_validator_max_effective_balance,
        has_compounding_withdrawal_credential, has_eth1_withdrawal_credential,
        has_execution_withdrawal_credential, has_flag, increase_balance, initiate_validator_exit,
        invalid_operation_error, is_active_validator, is_compounding_withdrawal_credential,
        is_fully_withdrawable_validator, is_partially_withdrawable_validator,
        is_valid_indexed_attestation, kzg_commitment_to_versioned_hash, process_attester_slashing,
        process_bls_to_execution_change, process_deposit, process_proposer_slashing,
        switch_to_compounding_validator, verify_signed_data, Attestation, BeaconBlockBody,
        BeaconState, BlsPublicKey, BlsSignature, Bytes32, DepositMessage, DepositReceipt,
        DomainType, ExecutionAddress, ExecutionLayerWithdrawalRequest, ExecutionPayload,
        ExecutionPayloadHeader, Gwei, InvalidAttestation, InvalidConsolidation, InvalidDeposit,
        InvalidExecutionPayload, InvalidOperation, InvalidVoluntaryExit, InvalidWithdrawals,
        NewPayloadRequest, ParticipationFlags, PendingBalanceDeposit, PendingConsolidation,
        PendingPartialWithdrawal, SignedConsolidation, SignedVoluntaryExit, Validator, Withdrawal,
        FAR_FUTURE_EPOCH, FULL_EXIT_REQUEST_AMOUNT, PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT,
        UNSET_DEPOSIT_RECEIPTS_START_INDEX, WEIGHT_DENOMINATOR,
    },
    execution_engine::ExecutionEngine,
    ssz::prelude::HashTreeRoot,
    state_transition::Context,
    Error,
};

pub fn get_expected_withdrawals<
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
        PENDING_BALANCE_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >,
    context: &Context,
) -> (Vec<Withdrawal>, usize) {
    let epoch = get_current_epoch(state, context);
    let mut withdrawal_index = state.next_withdrawal_index;
    let mut validator_index = state.next_withdrawal_validator_index;

    let mut withdrawals = Vec::with_capacity(context.max_pending_partials_per_withdrawals_sweep);
    for withdrawal in state.pending_partial_withdrawals.iter() {
        if withdrawal.withdrawable_epoch > epoch {
            break;
        }
        if withdrawals.len() == context.max_pending_partials_per_withdrawals_sweep {
            break;
        }

        let validator = &state.validators[withdrawal.index];
        let balance = state.balances[withdrawal.index];

        let has_sufficient_effective_balance =
            validator.effective_balance > context.min_activation_balance;
        let has_excess_balance = balance > context.min_activation_balance;
        if validator.exit_epoch == FAR_FUTURE_EPOCH
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let withdrawable_balance =
                u64::min(balance - context.min_activation_balance, withdrawal.amount);
            let mut withdrawal_address = ExecutionAddress::default();
            withdrawal_address.copy_from_slice(&validator.withdrawal_credentials[12..]);
            let withdrawal = Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: withdrawal_address,
                amount: withdrawable_balance,
            };
            withdrawals.push(withdrawal);
            withdrawal_index += 1;
        }
    }

    let partial_withdrawals_count = withdrawals.len();

    let bound = usize::min(
        state.validators.len(),
        context.max_validators_per_withdrawals_sweep,
    );
    for _ in 0..bound {
        let validator = &state.validators[validator_index];
        let balance = state.balances[validator_index];

        let amount = if is_fully_withdrawable_validator(validator, balance, epoch) {
            Some(balance)
        } else if is_partially_withdrawable_validator(validator, balance, context) {
            Some(balance - get_validator_max_effective_balance(validator, context))
        } else {
            None
        };

        if let Some(amount) = amount {
            let mut withdrawal_address = ExecutionAddress::default();
            withdrawal_address.copy_from_slice(&validator.withdrawal_credentials[12..]);
            let withdrawal = Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: withdrawal_address,
                amount,
            };
            withdrawals.push(withdrawal);
            withdrawal_index += 1;
        }

        if withdrawals.len() == context.max_withdrawals_per_payload {
            break;
        }

        validator_index = (validator_index + 1) % state.validators.len();
    }

    (withdrawals, partial_withdrawals_count)
}

pub fn process_withdrawals<
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
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
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
    payload: &ExecutionPayload<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
    >,
    context: &Context,
) -> Result<(), Error> {
    let (expected_withdrawals, partial_withdrawals_count) =
        get_expected_withdrawals(state, context);
    if payload.withdrawals.as_ref() != expected_withdrawals {
        return Err(invalid_operation_error(InvalidOperation::Withdrawal(
            InvalidWithdrawals::IncorrectWithdrawals {
                provided: payload.withdrawals.to_vec(),
                expected: expected_withdrawals,
            },
        )));
    }

    for withdrawal in payload.withdrawals.iter() {
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount);
    }

    state
        .pending_partial_withdrawals
        .drain(..partial_withdrawals_count);

    if let Some(latest) = expected_withdrawals.last() {
        state.next_withdrawal_index = latest.index + 1;
    }

    if expected_withdrawals.len() == context.max_withdrawals_per_payload {
        let next_validator_index = expected_withdrawals
            .last()
            .map(|latest| (latest.index + 1) % state.validators.len());
        state.next_withdrawal_validator_index =
            next_validator_index.unwrap_or(state.next_withdrawal_validator_index);
    } else {
        let next_index =
            state.next_withdrawal_validator_index + context.max_validators_per_withdrawals_sweep;
        let next_validator_index = next_index % state.validators.len();
        state.next_withdrawal_validator_index = next_validator_index;
    }

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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_SLOT: usize,
    const MAX_COMMITTEES_PER_SLOT: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
    const MAX_CONSOLIDATIONS: usize,
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_SLOT,
        MAX_COMMITTEES_PER_SLOT,
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
        MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_CONSOLIDATIONS,
    >,
    context: &Context,
) -> Result<(), Error> {
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
        deposit_receipts_root: payload.deposit_receipts.hash_tree_root()?,
        withdrawal_requests_root: payload.withdrawal_requests.hash_tree_root()?,
    };

    Ok(())
}

pub fn process_operations<
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
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_SLOT: usize,
    const MAX_COMMITTEES_PER_SLOT: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
    const MAX_CONSOLIDATIONS: usize,
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
    body: &BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_SLOT,
        MAX_COMMITTEES_PER_SLOT,
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
        MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_CONSOLIDATIONS,
    >,
    context: &Context,
) -> Result<(), Error> {
    let eth1_deposit_index_limit = u64::min(
        state.eth1_data.deposit_count,
        state.deposit_receipts_start_index,
    );
    if state.eth1_deposit_index < eth1_deposit_index_limit {
        let expected = u64::min(
            context.max_deposits as u64,
            eth1_deposit_index_limit - state.eth1_deposit_index,
        ) as usize;
        if body.deposits.len() != expected {
            return Err(invalid_operation_error(InvalidOperation::Deposit(
                InvalidDeposit::IncorrectCount {
                    expected,
                    count: body.deposits.len(),
                },
            )));
        } else if !body.deposits.is_empty() {
            return Err(invalid_operation_error(InvalidOperation::Deposit(
                InvalidDeposit::IncorrectCount {
                    expected: 0,
                    count: body.deposits.len(),
                },
            )));
        }
    }

    body.proposer_slashings
        .iter()
        .try_for_each(|op| process_proposer_slashing(state, op, context))?;
    body.attester_slashings
        .iter()
        .try_for_each(|op| process_attester_slashing(state, op, context))?;
    body.attestations
        .iter()
        .try_for_each(|op| process_attestation(state, op, context))?;
    body.deposits
        .iter()
        .try_for_each(|op| process_deposit(state, op, context))?;
    body.voluntary_exits
        .iter()
        .try_for_each(|op| process_voluntary_exit(state, op, context))?;
    body.bls_to_execution_changes
        .iter()
        .try_for_each(|op| process_bls_to_execution_change(state, op, context))?;
    body.execution_payload
        .withdrawal_requests
        .iter()
        .try_for_each(|op| process_execution_layer_withdrawal_request(state, op, context))?;
    body.execution_payload
        .deposit_receipts
        .iter()
        .try_for_each(|op| process_deposit_receipt(state, op, context))?;
    body.consolidations
        .iter()
        .try_for_each(|op| process_consolidation(state, op, context))?;

    Ok(())
}

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
    const PENDING_BALANCE_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
    const MAX_VALIDATORS_PER_SLOT: usize,
    const MAX_COMMITTEES_PER_SLOT: usize,
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
    attestation: &Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>,
    context: &Context,
) -> Result<(), Error> {
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

    if data.index != 0 {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::InvalidIndex {
                index: data.index,
                upper_bound: 0,
            },
        )));
    }
    let mut participants_count = 0;
    let committee_indices = get_committee_indices(&attestation.committee_bits);
    let committee_count = get_committee_count_per_slot(state, data.target.epoch, context);
    for index in committee_indices {
        if index >= committee_count {
            return Err(invalid_operation_error(InvalidOperation::Attestation(
                InvalidAttestation::InvalidIndex {
                    index: data.index,
                    upper_bound: committee_count,
                },
            )));
        }
        let committee = get_beacon_committee(state, data.slot, index, context)?;
        participants_count += committee.len();
    }

    if attestation.aggregation_bits.len() != participants_count {
        return Err(invalid_operation_error(InvalidOperation::Attestation(
            InvalidAttestation::Bitfield {
                expected_length: participants_count,
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

    let attesting_indices = get_attesting_indices(state, attestation, context)?;
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

pub fn apply_deposit<
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
    public_key: &BlsPublicKey,
    withdrawal_credentials: &Bytes32,
    amount: Gwei,
    signature: &BlsSignature,
    context: &Context,
) -> Result<(), Error> {
    let validator = state
        .validators
        .iter()
        .enumerate()
        .find(|(_, v)| v.public_key == *public_key);
    if let Some((index, validator)) = validator {
        state
            .pending_balance_deposits
            .push(PendingBalanceDeposit { index, amount });

        is_valid_deposit_signature(
            public_key,
            withdrawal_credentials.clone(),
            amount,
            signature,
            context,
        )?;

        // NOTE: if we did not return from signature check, then we know the signature is valid
        if is_compounding_withdrawal_credential(withdrawal_credentials)
            && has_eth1_withdrawal_credential(validator)
        {
            switch_to_compounding_validator(state, index, context)?;
        }
        return Ok(());
    }

    is_valid_deposit_signature(
        public_key,
        withdrawal_credentials.clone(),
        amount,
        signature,
        context,
    )?;
    add_validator_to_registry(
        state,
        public_key.clone(),
        withdrawal_credentials.clone(),
        amount,
    );
    Ok(())
}

pub fn is_valid_deposit_signature(
    public_key: &BlsPublicKey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: &BlsSignature,
    context: &Context,
) -> Result<(), Error> {
    let deposit_message = DepositMessage {
        public_key: public_key.clone(),
        withdrawal_credentials,
        amount,
    };
    let domain = compute_domain(DomainType::Deposit, None, None, context)?;
    verify_signed_data(&deposit_message, signature, public_key, domain)
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
    public_key: BlsPublicKey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
) {
    let index = state.validators.len();
    state.validators.push(get_validator_from_deposit(
        public_key,
        withdrawal_credentials,
    ));
    state.balances.push(0);
    state
        .previous_epoch_participation
        .push(ParticipationFlags::default());
    state
        .current_epoch_participation
        .push(ParticipationFlags::default());
    state.inactivity_scores.push(0);
    state
        .pending_balance_deposits
        .push(PendingBalanceDeposit { index, amount });
}

pub fn get_validator_from_deposit(
    public_key: BlsPublicKey,
    withdrawal_credentials: Bytes32,
) -> Validator {
    Validator {
        public_key,
        withdrawal_credentials,
        effective_balance: 0,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    }
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
    signed_voluntary_exit: &SignedVoluntaryExit,
    context: &Context,
) -> Result<(), Error> {
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

    let pending_balance_to_withdraw =
        get_pending_balance_to_withdraw(state, voluntary_exit.validator_index);
    if pending_balance_to_withdraw != 0 {
        return Err(invalid_operation_error(InvalidOperation::VoluntaryExit(
            InvalidVoluntaryExit::NonZeroPendingBalanceToWithdraw,
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

pub fn process_execution_layer_withdrawal_request<
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
    execution_layer_withdrawal_request: &ExecutionLayerWithdrawalRequest,
    context: &Context,
) -> Result<(), Error> {
    let amount = execution_layer_withdrawal_request.amount;
    let is_full_exit_request = amount == FULL_EXIT_REQUEST_AMOUNT;

    if state.pending_partial_withdrawals.len() == PENDING_PARTIAL_WITHDRAWALS_LIMIT
        && !is_full_exit_request
    {
        return Ok(());
    }

    let request_public_key = &execution_layer_withdrawal_request.validator_public_key;
    let validator = state
        .validators
        .iter()
        .enumerate()
        .find(|(_, v)| &v.public_key == request_public_key);
    let Some((index, validator)) = validator else {
        return Ok(());
    };

    let has_correct_credential = has_execution_withdrawal_credential(validator);
    let is_correct_source_address = validator.withdrawal_credentials[12..]
        == execution_layer_withdrawal_request.source_address[..];
    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }

    let current_epoch = get_current_epoch(state, context);

    if !is_active_validator(validator, current_epoch) {
        return Ok(());
    }
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    if current_epoch < validator.activation_epoch + context.shard_committee_period {
        return Ok(());
    }

    let pending_balance_to_withdraw = get_pending_balance_to_withdraw(state, index);

    if is_full_exit_request {
        if pending_balance_to_withdraw == 0 {
            initiate_validator_exit(state, index, context)?;
        }
        return Ok(());
    }

    let has_compounding_withdrawal_credential = has_compounding_withdrawal_credential(validator);
    let has_sufficient_effective_balance =
        validator.effective_balance >= context.min_activation_balance;
    let has_excess_balance =
        state.balances[index] > context.min_activation_balance + pending_balance_to_withdraw;
    if has_compounding_withdrawal_credential
        && has_sufficient_effective_balance
        && has_excess_balance
    {
        let to_withdraw = u64::min(
            state.balances[index] - context.min_activation_balance - pending_balance_to_withdraw,
            amount,
        );
        let exit_queue_epoch = compute_exit_epoch_and_update_churn(state, to_withdraw, context)?;
        let withdrawable_epoch = exit_queue_epoch + context.min_validator_withdrawability_delay;
        state
            .pending_partial_withdrawals
            .push(PendingPartialWithdrawal {
                index,
                amount: to_withdraw,
                withdrawable_epoch,
            });
    }

    Ok(())
}

pub fn process_deposit_receipt<
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
    deposit_receipt: &DepositReceipt,
    context: &Context,
) -> Result<(), Error> {
    if state.deposit_receipts_start_index == UNSET_DEPOSIT_RECEIPTS_START_INDEX {
        state.deposit_receipts_start_index = deposit_receipt.index;
    }
    apply_deposit(
        state,
        &deposit_receipt.public_key,
        &deposit_receipt.withdrawal_credentials,
        deposit_receipt.amount,
        &deposit_receipt.signature,
        context,
    )
}

pub fn process_consolidation<
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
    signed_consolidation: &SignedConsolidation,
    context: &Context,
) -> Result<(), Error> {
    if state.pending_consolidations.len() >= context.pending_consolidations_limit {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::PendingConsolidationsQueueFull,
            ),
        ));
    }
    let consolidation_churn_limit = get_consolidation_churn_limit(state, context)?;
    if consolidation_churn_limit <= context.min_activation_balance {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::InsufficientConsolidationChurnLimit,
            ),
        ));
    }

    let consolidation = &signed_consolidation.message;
    if consolidation.source_index == consolidation.target_index {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::EqualSourceAndTargetIndices(consolidation.source_index),
            ),
        ));
    }

    if consolidation.source_index >= state.validators.len() {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(InvalidConsolidation::InvalidIndex(
                consolidation.source_index,
            )),
        ));
    }
    let source_validator = state.validators[consolidation.source_index].clone();
    if consolidation.target_index >= state.validators.len() {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(InvalidConsolidation::InvalidIndex(
                consolidation.target_index,
            )),
        ));
    }
    let target_validator = state.validators[consolidation.target_index].clone();

    let current_epoch = get_current_epoch(state, context);
    if !is_active_validator(&source_validator, current_epoch) {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(InvalidConsolidation::InactiveValidator(
                consolidation.source_index,
                current_epoch,
            )),
        ));
    }
    if !is_active_validator(&target_validator, current_epoch) {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(InvalidConsolidation::InactiveValidator(
                consolidation.target_index,
                current_epoch,
            )),
        ));
    }

    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::ExitInitiatedForValidator(consolidation.source_index),
            ),
        ));
    }
    if target_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::ExitInitiatedForValidator(consolidation.target_index),
            ),
        ));
    }

    if current_epoch < consolidation.epoch {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(InvalidConsolidation::EarlyConsolidation {
                current_epoch,
                consolidation_epoch: consolidation.epoch,
            }),
        ));
    }

    if !has_execution_withdrawal_credential(&source_validator) {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::MissingExecutionWithdrawalCredentials(
                    consolidation.source_index,
                ),
            ),
        ));
    }
    if !has_execution_withdrawal_credential(&target_validator) {
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::MissingExecutionWithdrawalCredentials(
                    consolidation.target_index,
                ),
            ),
        ));
    }

    let source_withdrawal_credentials = &source_validator.withdrawal_credentials;
    let target_withdrawal_credentials = &target_validator.withdrawal_credentials;
    if source_withdrawal_credentials[12..] != target_withdrawal_credentials[12..] {
        let mut source_address = ExecutionAddress::default();
        source_address.copy_from_slice(&source_withdrawal_credentials[12..]);
        let mut target_address = ExecutionAddress::default();
        target_address.copy_from_slice(&target_withdrawal_credentials[12..]);
        return Err(invalid_operation_error(
            InvalidOperation::InvalidConsolidation(
                InvalidConsolidation::WithdrawalCredentialsMismatch {
                    source_address,
                    target_address,
                },
            ),
        ));
    }

    let domain = compute_domain(
        DomainType::Consolidation,
        None,
        Some(state.genesis_validators_root),
        context,
    )?;
    let signing_root = compute_signing_root(consolidation, domain)?;
    let public_keys = [&source_validator.public_key, &target_validator.public_key];
    fast_aggregate_verify(
        &public_keys[..],
        &signing_root[..],
        &signed_consolidation.signature,
    )?;

    state.validators[consolidation.source_index].exit_epoch =
        compute_consolidation_epoch_and_update_churn(
            state,
            source_validator.effective_balance,
            context,
        )?;
    state.validators[consolidation.source_index].withdrawable_epoch =
        source_validator.exit_epoch + context.min_validator_withdrawability_delay;
    state.pending_consolidations.push(PendingConsolidation {
        source_index: consolidation.source_index,
        target_index: consolidation.target_index,
    });

    Ok(())
}
