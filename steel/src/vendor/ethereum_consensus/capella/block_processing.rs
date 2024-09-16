use crate::ethereum_consensus::{
    capella::{
        compute_domain, compute_timestamp_at_slot, decrease_balance, get_current_epoch,
        get_randao_mix, is_fully_withdrawable_validator, is_partially_withdrawable_validator,
        process_attestation, process_attester_slashing, process_block_header, process_deposit,
        process_eth1_data, process_proposer_slashing, process_randao, process_sync_aggregate,
        process_voluntary_exit, BeaconBlock, BeaconBlockBody, BeaconState, DomainType,
        ExecutionAddress, ExecutionPayload, ExecutionPayloadHeader, SignedBlsToExecutionChange,
        Withdrawal,
    },
    crypto::hash,
    error::{
        invalid_operation_error, InvalidBlsToExecutionChange, InvalidDeposit,
        InvalidExecutionPayload, InvalidOperation, InvalidWithdrawals,
    },
    execution_engine::ExecutionEngine,
    primitives::{BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX},
    signing::verify_signed_data,
    ssz::prelude::*,
    state_transition::{Context, Result},
};

pub fn process_bls_to_execution_change<
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
    signed_address_change: &SignedBlsToExecutionChange,
    context: &Context,
) -> Result<()> {
    let address_change = &signed_address_change.message;
    let signature = &signed_address_change.signature;

    if address_change.validator_index >= state.validators.len() {
        return Err(invalid_operation_error(
            InvalidOperation::BlsToExecutionChange(
                InvalidBlsToExecutionChange::ValidatorIndexOutOfBounds(
                    address_change.validator_index,
                ),
            ),
        ));
    }

    let withdrawal_credentials =
        &mut state.validators[address_change.validator_index].withdrawal_credentials;
    if withdrawal_credentials[0] != BLS_WITHDRAWAL_PREFIX {
        return Err(invalid_operation_error(
            InvalidOperation::BlsToExecutionChange(
                InvalidBlsToExecutionChange::WithdrawalCredentialsPrefix(withdrawal_credentials[0]),
            ),
        ));
    }

    let public_key = &address_change.from_bls_public_key;
    if withdrawal_credentials[1..] != hash(public_key.as_ref())[1..] {
        return Err(invalid_operation_error(
            InvalidOperation::BlsToExecutionChange(InvalidBlsToExecutionChange::PublicKeyMismatch(
                public_key.clone(),
            )),
        ));
    }

    let domain = compute_domain(
        DomainType::BlsToExecutionChange,
        None,
        Some(state.genesis_validators_root),
        context,
    )?;
    verify_signed_data(address_change, signature, public_key, domain)?;

    withdrawal_credentials[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    withdrawal_credentials[1..12].fill(0);
    withdrawal_credentials[12..].copy_from_slice(address_change.to_execution_address.as_ref());

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
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
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
    >,
    context: &Context,
) -> Result<()> {
    let expected_deposit_count = usize::min(
        context.max_deposits,
        (state.eth1_data.deposit_count - state.eth1_deposit_index) as usize,
    );
    if body.deposits.len() != expected_deposit_count {
        return Err(invalid_operation_error(InvalidOperation::Deposit(
            InvalidDeposit::IncorrectCount {
                expected: expected_deposit_count,
                count: body.deposits.len(),
            },
        )));
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
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
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
    block: &BeaconBlockBody<
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
    >,
    context: &Context,
) -> Result<()> {
    let payload = &block.execution_payload;

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

    let execution_engine = context.execution_engine();
    execution_engine.verify_and_notify_new_payload(&payload.clone())?;

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
    };

    Ok(())
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
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
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
    execution_payload: &ExecutionPayload<
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
    >,
    context: &Context,
) -> Result<()> {
    let expected_withdrawals = get_expected_withdrawals(state, context);

    if execution_payload.withdrawals.as_ref() != expected_withdrawals {
        return Err(invalid_operation_error(InvalidOperation::Withdrawal(
            InvalidWithdrawals::IncorrectWithdrawals {
                provided: execution_payload.withdrawals.to_vec(),
                expected: expected_withdrawals,
            },
        )));
    }

    for withdrawal in &expected_withdrawals {
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount);
    }

    // Update the next withdrawal index if this block contained withdrawals
    if let Some(latest_withdrawal) = expected_withdrawals.last() {
        state.next_withdrawal_index = latest_withdrawal.index + 1;
    }

    // Update the next validator index to start the next withdrawal sweep
    if expected_withdrawals.len() == context.max_withdrawals_per_payload {
        // Next sweep starts after the latest withdrawal's validator index
        let latest_withdrawal = expected_withdrawals.last().expect("empty withdrawals");
        let next_validator_index = (latest_withdrawal.validator_index + 1) % state.validators.len();
        state.next_withdrawal_validator_index = next_validator_index;
    } else {
        // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        let next_index =
            state.next_withdrawal_validator_index + context.max_validators_per_withdrawals_sweep;
        state.next_withdrawal_validator_index = next_index % state.validators.len();
    }
    Ok(())
}

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
) -> Vec<Withdrawal> {
    let epoch = get_current_epoch(state, context);
    let mut withdrawal_index = state.next_withdrawal_index;
    let mut validator_index = state.next_withdrawal_validator_index;
    let mut withdrawals = vec![];
    let bound = state
        .validators
        .len()
        .min(context.max_validators_per_withdrawals_sweep);
    for _ in 0..bound {
        let validator = &state.validators[validator_index];
        let balance = state.balances[validator_index];
        if is_fully_withdrawable_validator(validator, balance, epoch) {
            let address =
                ExecutionAddress::try_from(&validator.withdrawal_credentials.as_slice()[12..])
                    .expect("providing the correct amount of input to type");
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address,
                amount: balance,
            });
            withdrawal_index += 1;
        } else if is_partially_withdrawable_validator(validator, balance, context) {
            let address =
                ExecutionAddress::try_from(&validator.withdrawal_credentials.as_slice()[12..])
                    .expect("providing the correct amount of input to type");
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address,
                amount: balance - context.max_effective_balance,
            });
            withdrawal_index += 1;
        }
        if withdrawals.len() == context.max_withdrawals_per_payload {
            break;
        }
        validator_index = (validator_index + 1) % state.validators.len();
    }
    withdrawals
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
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
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
