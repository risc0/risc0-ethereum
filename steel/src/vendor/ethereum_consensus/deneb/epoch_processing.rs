use crate::ethereum_consensus::{
    deneb::{
        compute_activation_exit_epoch, get_current_epoch, get_validator_activation_churn_limit,
        initiate_validator_exit, is_active_validator, is_eligible_for_activation,
        is_eligible_for_activation_queue, BeaconState,
    },
    primitives::ValidatorIndex,
    state_transition::{Context, Result},
};

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
    context: &Context,
) -> Result<()> {
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
    let mut activation_queue = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if is_eligible_for_activation(state, validator) {
                Some(index)
            } else {
                None
            }
        })
        .collect::<Vec<ValidatorIndex>>();
    activation_queue.sort_by(|&i, &j| {
        let a = &state.validators[i];
        let b = &state.validators[j];
        (a.activation_eligibility_epoch, i).cmp(&(b.activation_eligibility_epoch, j))
    });
    let activation_exit_epoch = compute_activation_exit_epoch(current_epoch, context);
    for i in activation_queue
        .into_iter()
        .take(get_validator_activation_churn_limit(state, context))
    {
        let validator = &mut state.validators[i];
        validator.activation_epoch = activation_exit_epoch;
    }
    Ok(())
}
