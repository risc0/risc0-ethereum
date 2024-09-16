use crate::ethereum_consensus::{
    capella::{
        get_current_epoch, process_effective_balance_updates, process_eth1_data_reset,
        process_inactivity_updates, process_justification_and_finalization,
        process_participation_flag_updates, process_randao_mixes_reset, process_registry_updates,
        process_rewards_and_penalties, process_slashings, process_slashings_reset,
        process_sync_committee_updates, BeaconState, HistoricalSummary,
    },
    ssz::prelude::*,
    state_transition::{Context, Result},
};

pub fn process_historical_summaries_update<
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
    let next_epoch = get_current_epoch(state, context) + 1;
    if (next_epoch % (context.slots_per_historical_root / context.slots_per_epoch)) == 0 {
        let historical_summary = HistoricalSummary {
            block_summary_root: state.block_roots.hash_tree_root()?,
            state_summary_root: state.state_roots.hash_tree_root()?,
        };
        state.historical_summaries.push(historical_summary);
    }
    Ok(())
}

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
    process_justification_and_finalization(state, context)?;
    process_inactivity_updates(state, context)?;
    process_rewards_and_penalties(state, context)?;
    process_registry_updates(state, context)?;
    process_slashings(state, context)?;
    process_eth1_data_reset(state, context);
    process_effective_balance_updates(state, context);
    process_slashings_reset(state, context);
    process_randao_mixes_reset(state, context);
    process_historical_summaries_update(state, context)?;
    process_participation_flag_updates(state)?;
    process_sync_committee_updates(state, context)?;
    Ok(())
}
