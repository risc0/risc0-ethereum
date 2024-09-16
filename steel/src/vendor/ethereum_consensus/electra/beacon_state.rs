use crate::ethereum_consensus::{
    altair::SyncCommittee,
    capella::HistoricalSummary,
    electra::ExecutionPayloadHeader,
    phase0::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork, Validator, JUSTIFICATION_BITS_LENGTH},
    primitives::{
        BlsPublicKey, BlsSignature, Bytes32, Epoch, ExecutionAddress, Gwei, ParticipationFlags,
        Root, Slot, ValidatorIndex, WithdrawalIndex,
    },
    ssz::prelude::*,
};

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct DepositReceipt {
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub amount: Gwei,
    pub signature: BlsSignature,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub index: u64,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct PendingBalanceDeposit {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub index: ValidatorIndex,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub amount: Gwei,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct PendingPartialWithdrawal {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub index: ValidatorIndex,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub amount: Gwei,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub withdrawable_epoch: Epoch,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct PendingConsolidation {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub source_index: ValidatorIndex,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub target_index: ValidatorIndex,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionLayerWithdrawalRequest {
    pub source_address: ExecutionAddress,
    #[serde(rename = "pubkey")]
    pub validator_public_key: BlsPublicKey,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub amount: Gwei,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconState<
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
> {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub slot: Slot,
    pub fork: Fork,
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: List<Eth1Data, ETH1_DATA_VOTES_BOUND>,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub eth1_deposit_index: u64,
    pub validators: List<Validator, VALIDATOR_REGISTRY_LIMIT>,
    #[serde(with = "crate::ethereum_consensus::serde::seq_of_str")]
    pub balances: List<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    pub randao_mixes: Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR>,
    #[serde(with = "crate::ethereum_consensus::serde::seq_of_str")]
    pub slashings: Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
    #[serde(with = "crate::ethereum_consensus::serde::seq_of_str")]
    pub previous_epoch_participation: List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    #[serde(with = "crate::ethereum_consensus::serde::seq_of_str")]
    pub current_epoch_participation: List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    #[serde(with = "crate::ethereum_consensus::serde::seq_of_str")]
    pub inactivity_scores: List<u64, VALIDATOR_REGISTRY_LIMIT>,
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub latest_execution_payload_header:
        ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub next_withdrawal_index: WithdrawalIndex,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub next_withdrawal_validator_index: ValidatorIndex,
    pub historical_summaries: List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub deposit_receipts_start_index: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub deposit_balance_to_consume: Gwei,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub exit_balance_to_consume: Gwei,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub earliest_exit_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub consolidation_balance_to_consume: Gwei,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub earliest_consolidation_epoch: Epoch,
    pub pending_balance_deposits: List<PendingBalanceDeposit, PENDING_BALANCE_DEPOSITS_LIMIT>,
    pub pending_partial_withdrawals:
        List<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>,
    pub pending_consolidations: List<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>,
}
