use crate::ethereum_consensus::{
    altair, bellatrix, capella, deneb, phase0,
    state_transition::{Context, Result, Validation},
    types::{BeaconState, SignedBeaconBlock},
    Error, Fork,
};

pub struct Executor<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
> {
    pub state: BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    pub context: Context,
}

impl<
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const PENDING_ATTESTATIONS_BOUND: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_PROPOSER_SLASHINGS: usize,
        const MAX_ATTESTER_SLASHINGS: usize,
        const MAX_ATTESTATIONS: usize,
        const MAX_DEPOSITS: usize,
        const MAX_VOLUNTARY_EXITS: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_BLS_TO_EXECUTION_CHANGES: usize,
        const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
    >
    Executor<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    >
{
    pub fn new(
        state: BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
        context: Context,
    ) -> Self {
        Self { state, context }
    }

    pub fn apply_block(
        &mut self,
        signed_block: &SignedBeaconBlock<
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
    ) -> Result<()> {
        self.apply_block_with_validation(signed_block, Validation::Enabled)
    }

    pub fn apply_block_with_validation(
        &mut self,
        signed_block: &SignedBeaconBlock<
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
        validation: Validation,
    ) -> Result<()> {
        match signed_block {
            SignedBeaconBlock::Phase0(signed_block) => {
                self.apply_phase0_block_with_validation(signed_block, validation)
            }
            SignedBeaconBlock::Altair(signed_block) => {
                self.apply_altair_block_with_validation(signed_block, validation)
            }
            SignedBeaconBlock::Bellatrix(signed_block) => {
                self.apply_bellatrix_block_with_validation(signed_block, validation)
            }
            SignedBeaconBlock::Capella(signed_block) => {
                self.apply_capella_block_with_validation(signed_block, validation)
            }
            SignedBeaconBlock::Deneb(signed_block) => {
                self.apply_deneb_block_with_validation(signed_block, validation)
            }
        }
    }

    pub fn apply_phase0_block_with_validation(
        &mut self,
        signed_block: &phase0::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
        >,
        validation: Validation,
    ) -> Result<()> {
        match &mut self.state {
            BeaconState::Phase0(state) => {
                phase0::state_transition(state, signed_block, validation, &self.context)
            }
            state => Err(Error::InvalidForkTransition {
                source_fork: state.version(),
                destination_fork: Fork::Phase0,
            }),
        }
    }

    pub fn apply_altair_block_with_validation(
        &mut self,
        signed_block: &altair::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
        >,
        validation: Validation,
    ) -> Result<()> {
        match &mut self.state {
            BeaconState::Phase0(state) => {
                let fork_slot = self.context.altair_fork_epoch * self.context.slots_per_epoch;
                phase0::process_slots(state, fork_slot, &self.context)?;
                let mut state = altair::upgrade_to_altair(state, &self.context)?;
                if signed_block.message.slot == state.slot {
                    altair::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    altair::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Altair(state);
                Ok(())
            }
            BeaconState::Altair(state) => {
                altair::state_transition(state, signed_block, validation, &self.context)
            }
            state => Err(Error::InvalidForkTransition {
                source_fork: state.version(),
                destination_fork: Fork::Altair,
            }),
        }
    }

    pub fn apply_bellatrix_block_with_validation(
        &mut self,
        signed_block: &bellatrix::SignedBeaconBlock<
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
        >,
        validation: Validation,
    ) -> Result<()> {
        match &mut self.state {
            BeaconState::Phase0(state) => {
                let fork_slot = self.context.altair_fork_epoch * self.context.slots_per_epoch;
                phase0::process_slots(state, fork_slot, &self.context)?;
                let mut state = altair::upgrade_to_altair(state, &self.context)?;

                let fork_slot = self.context.bellatrix_fork_epoch * self.context.slots_per_epoch;
                altair::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = bellatrix::upgrade_to_bellatrix(&state, &self.context);
                if signed_block.message.slot == state.slot {
                    bellatrix::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    bellatrix::state_transition(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                }
                self.state = BeaconState::Bellatrix(state);
                Ok(())
            }
            BeaconState::Altair(state) => {
                let fork_slot = self.context.bellatrix_fork_epoch * self.context.slots_per_epoch;
                altair::process_slots(state, fork_slot, &self.context)?;
                let mut state = bellatrix::upgrade_to_bellatrix(state, &self.context);
                if signed_block.message.slot == state.slot {
                    bellatrix::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    bellatrix::state_transition(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                }
                self.state = BeaconState::Bellatrix(state);
                Ok(())
            }
            BeaconState::Bellatrix(state) => {
                bellatrix::state_transition(state, signed_block, validation, &self.context)
            }
            state => Err(Error::InvalidForkTransition {
                source_fork: state.version(),
                destination_fork: Fork::Bellatrix,
            }),
        }
    }

    pub fn apply_capella_block_with_validation(
        &mut self,
        signed_block: &capella::SignedBeaconBlock<
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
        validation: Validation,
    ) -> Result<()> {
        match &mut self.state {
            BeaconState::Phase0(state) => {
                let fork_slot = self.context.altair_fork_epoch * self.context.slots_per_epoch;
                phase0::process_slots(state, fork_slot, &self.context)?;
                let mut state = altair::upgrade_to_altair(state, &self.context)?;

                let fork_slot = self.context.bellatrix_fork_epoch * self.context.slots_per_epoch;
                altair::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = bellatrix::upgrade_to_bellatrix(&state, &self.context);

                let fork_slot = self.context.capella_fork_epoch * self.context.slots_per_epoch;
                bellatrix::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = capella::upgrade_to_capella(&state, &self.context);

                if signed_block.message.slot == state.slot {
                    capella::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    capella::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Capella(state);
                Ok(())
            }
            BeaconState::Altair(state) => {
                let fork_slot = self.context.bellatrix_fork_epoch * self.context.slots_per_epoch;
                altair::process_slots(state, fork_slot, &self.context)?;
                let mut state = bellatrix::upgrade_to_bellatrix(state, &self.context);

                let fork_slot = self.context.capella_fork_epoch * self.context.slots_per_epoch;
                bellatrix::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = capella::upgrade_to_capella(&state, &self.context);

                if signed_block.message.slot == state.slot {
                    capella::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    capella::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Capella(state);
                Ok(())
            }
            BeaconState::Bellatrix(state) => {
                let fork_slot = self.context.capella_fork_epoch * self.context.slots_per_epoch;
                bellatrix::process_slots(state, fork_slot, &self.context)?;
                let mut state = capella::upgrade_to_capella(state, &self.context);

                if signed_block.message.slot == state.slot {
                    capella::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    capella::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Capella(state);
                Ok(())
            }
            BeaconState::Capella(state) => {
                capella::state_transition(state, signed_block, validation, &self.context)
            }
            state => Err(Error::InvalidForkTransition {
                source_fork: state.version(),
                destination_fork: Fork::Capella,
            }),
        }
    }

    pub fn apply_deneb_block_with_validation(
        &mut self,
        signed_block: &deneb::SignedBeaconBlock<
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
        validation: Validation,
    ) -> Result<()> {
        match &mut self.state {
            BeaconState::Phase0(state) => {
                let fork_slot = self.context.altair_fork_epoch * self.context.slots_per_epoch;
                phase0::process_slots(state, fork_slot, &self.context)?;
                let mut state = altair::upgrade_to_altair(state, &self.context)?;

                let fork_slot = self.context.bellatrix_fork_epoch * self.context.slots_per_epoch;
                altair::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = bellatrix::upgrade_to_bellatrix(&state, &self.context);

                let fork_slot = self.context.capella_fork_epoch * self.context.slots_per_epoch;
                bellatrix::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = capella::upgrade_to_capella(&state, &self.context);

                let fork_slot = self.context.deneb_fork_epoch * self.context.slots_per_epoch;
                capella::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = deneb::upgrade_to_deneb(&state, &self.context);

                if signed_block.message.slot == state.slot {
                    deneb::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    deneb::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Deneb(state);
                Ok(())
            }
            BeaconState::Altair(state) => {
                let fork_slot = self.context.bellatrix_fork_epoch * self.context.slots_per_epoch;
                altair::process_slots(state, fork_slot, &self.context)?;
                let mut state = bellatrix::upgrade_to_bellatrix(state, &self.context);

                let fork_slot = self.context.capella_fork_epoch * self.context.slots_per_epoch;
                bellatrix::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = capella::upgrade_to_capella(&state, &self.context);

                let fork_slot = self.context.deneb_fork_epoch * self.context.slots_per_epoch;
                capella::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = deneb::upgrade_to_deneb(&state, &self.context);

                if signed_block.message.slot == state.slot {
                    deneb::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    deneb::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Deneb(state);
                Ok(())
            }
            BeaconState::Bellatrix(state) => {
                let fork_slot = self.context.capella_fork_epoch * self.context.slots_per_epoch;
                bellatrix::process_slots(state, fork_slot, &self.context)?;
                let mut state = capella::upgrade_to_capella(state, &self.context);

                let fork_slot = self.context.deneb_fork_epoch * self.context.slots_per_epoch;
                capella::process_slots(&mut state, fork_slot, &self.context)?;
                let mut state = deneb::upgrade_to_deneb(&state, &self.context);

                if signed_block.message.slot == state.slot {
                    deneb::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    deneb::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Deneb(state);
                Ok(())
            }
            BeaconState::Capella(state) => {
                let fork_slot = self.context.deneb_fork_epoch * self.context.slots_per_epoch;
                capella::process_slots(state, fork_slot, &self.context)?;
                let mut state = deneb::upgrade_to_deneb(state, &self.context);

                if signed_block.message.slot == state.slot {
                    deneb::state_transition_block_in_slot(
                        &mut state,
                        signed_block,
                        validation,
                        &self.context,
                    )?;
                } else {
                    deneb::state_transition(&mut state, signed_block, validation, &self.context)?;
                }
                self.state = BeaconState::Deneb(state);
                Ok(())
            }
            BeaconState::Deneb(state) => {
                deneb::state_transition(state, signed_block, validation, &self.context)
            }
        }
    }
}
