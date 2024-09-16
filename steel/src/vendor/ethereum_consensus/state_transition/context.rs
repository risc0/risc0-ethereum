use crate::ethereum_consensus::{
    altair, bellatrix, capella,
    clock::{self, Clock, SystemTimeProvider},
    configs::{self, Config},
    crypto::{kzg_settings_from_json, KzgSettings},
    deneb::{self, presets::TRUSTED_SETUP_JSON},
    electra,
    execution_engine::ExecutionEngine,
    networks::Network,
    phase0,
    primitives::{Epoch, ExecutionAddress, Gwei, Hash32, Slot, Version, U256},
    Error, Fork,
};
use std::sync::Arc;

// Controls the default behavior of the execution engine via the `bool` impl of `ExecutionEngine`.
pub const DEFAULT_EXECUTION_ENGINE_VALIDITY: bool = true;

#[derive(Clone)]
pub struct Context {
    // phase0 preset
    pub max_committees_per_slot: u64,
    pub target_committee_size: u64,
    pub max_validators_per_committee: usize,
    pub shuffle_round_count: u64,
    pub hysteresis_quotient: u64,
    pub hysteresis_downward_multiplier: u64,
    pub hysteresis_upward_multiplier: u64,
    pub min_deposit_amount: Gwei,
    pub max_effective_balance: Gwei,
    pub effective_balance_increment: Gwei,
    pub min_attestation_inclusion_delay: Slot,
    pub slots_per_epoch: Slot,
    pub min_seed_lookahead: Epoch,
    pub max_seed_lookahead: Epoch,
    pub min_epochs_to_inactivity_penalty: Epoch,
    pub epochs_per_eth1_voting_period: Epoch,
    pub slots_per_historical_root: Slot,
    pub epochs_per_historical_vector: Epoch,
    pub epochs_per_slashings_vector: Epoch,
    pub historical_roots_limit: usize,
    pub validator_registry_limit: usize,
    pub base_reward_factor: u64,
    pub whistleblower_reward_quotient: u64,
    pub proposer_reward_quotient: u64,
    pub inactivity_penalty_quotient: u64,
    pub min_slashing_penalty_quotient: u64,
    pub proportional_slashing_multiplier: u64,
    pub max_proposer_slashings: usize,
    pub max_attester_slashings: usize,
    pub max_attestations: usize,
    pub max_deposits: usize,
    pub max_voluntary_exits: usize,

    // altair preset
    pub inactivity_penalty_quotient_altair: u64,
    pub min_slashing_penalty_quotient_altair: u64,
    pub proportional_slashing_multiplier_altair: u64,
    pub sync_committee_size: usize,
    pub epochs_per_sync_committee_period: Epoch,
    pub min_sync_committee_participants: usize,
    pub update_timeout: usize,

    // bellatrix preset
    pub inactivity_penalty_quotient_bellatrix: u64,
    pub min_slashing_penalty_quotient_bellatrix: u64,
    pub proportional_slashing_multiplier_bellatrix: u64,
    pub max_bytes_per_transaction: usize,
    pub max_transactions_per_payload: usize,
    pub bytes_per_logs_bloom: usize,
    pub max_extra_data_bytes: usize,

    // capella preset
    pub max_bls_to_execution_changes: usize,
    pub max_withdrawals_per_payload: usize,
    pub max_validators_per_withdrawals_sweep: usize,

    // deneb preset
    pub field_elements_per_blob: usize,
    pub max_blob_commitments_per_block: usize,
    pub max_blobs_per_block: usize,

    // electra preset
    pub min_activation_balance: Gwei,
    pub max_effective_balance_electra: Gwei,
    pub min_slashing_penalty_quotient_electra: u64,
    pub whistleblower_reward_quotient_electra: u64,
    pub pending_balance_deposits_limit: usize,
    pub pending_partial_withdrawals_limit: usize,
    pub pending_consolidations_limit: usize,
    pub max_attester_slashings_electra: usize,
    pub max_attestations_electra: usize,
    pub max_consolidations: usize,
    pub max_deposit_receipts_per_payload: usize,
    pub max_withdrawal_requests_per_payload: usize,
    pub max_pending_partials_per_withdrawals_sweep: usize,

    // config
    pub name: Network,

    pub terminal_total_difficulty: U256,
    pub terminal_block_hash: Hash32,
    pub terminal_block_hash_activation_epoch: Epoch,

    pub min_genesis_active_validator_count: usize,
    pub min_genesis_time: u64,
    pub genesis_fork_version: Version,
    pub genesis_delay: u64,

    pub altair_fork_version: Version,
    pub altair_fork_epoch: Epoch,
    pub bellatrix_fork_version: Version,
    pub bellatrix_fork_epoch: Epoch,
    pub capella_fork_version: Version,
    pub capella_fork_epoch: Epoch,
    pub deneb_fork_version: Version,
    pub deneb_fork_epoch: Epoch,
    pub electra_fork_version: Version,
    pub electra_fork_epoch: Epoch,

    pub seconds_per_slot: u64,
    pub seconds_per_eth1_block: u64,
    pub min_validator_withdrawability_delay: Epoch,
    pub shard_committee_period: Epoch,
    pub eth1_follow_distance: u64,

    pub inactivity_score_bias: u64,
    pub inactivity_score_recovery_rate: u64,
    pub ejection_balance: Gwei,
    pub min_per_epoch_churn_limit: u64,
    pub max_per_epoch_activation_churn_limit: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    pub max_per_epoch_activation_exit_churn_limit: u64,
    pub churn_limit_quotient: u64,

    pub proposer_score_boost: u64,

    pub deposit_chain_id: usize,
    pub deposit_network_id: usize,
    pub deposit_contract_address: ExecutionAddress,

    // Provides an implementation of `execution_engine::ExecutionEngine`.
    execution_engine: bool,

    pub kzg_settings: Arc<KzgSettings>,
}

impl Context {
    pub fn try_from_file<P: AsRef<std::path::Path>>(config_file: P) -> Result<Self, Error> {
        let mut file = std::fs::File::open(config_file)?;
        let config: Config = serde_yaml::from_reader(&mut file)?;
        let context = match config.preset_base.as_ref() {
            "mainnet" => {
                let phase0_preset = &phase0::mainnet::PRESET;
                let altair_preset = &altair::mainnet::PRESET;
                let bellatrix_preset = &bellatrix::mainnet::PRESET;
                let capella_preset = &capella::mainnet::PRESET;
                let deneb_preset = &deneb::mainnet::PRESET;
                let electra_preset = &electra::mainnet::PRESET;
                Self::from(
                    phase0_preset,
                    altair_preset,
                    bellatrix_preset,
                    capella_preset,
                    deneb_preset,
                    electra_preset,
                    &config,
                )
            }
            "minimal" => {
                let phase0_preset = &phase0::minimal::PRESET;
                let altair_preset = &altair::minimal::PRESET;
                let bellatrix_preset = &bellatrix::minimal::PRESET;
                let capella_preset = &capella::minimal::PRESET;
                let deneb_preset = &deneb::minimal::PRESET;
                let electra_preset = &electra::minimal::PRESET;
                Self::from(
                    phase0_preset,
                    altair_preset,
                    bellatrix_preset,
                    capella_preset,
                    deneb_preset,
                    electra_preset,
                    &config,
                )
            }
            other => return Err(Error::UnknownPreset(other.to_string())),
        };
        Ok(context)
    }

    pub fn from(
        phase0_preset: &phase0::Preset,
        altair_preset: &altair::Preset,
        bellatrix_preset: &bellatrix::Preset,
        capella_preset: &capella::Preset,
        deneb_preset: &deneb::Preset,
        electra_preset: &electra::Preset,
        config: &Config,
    ) -> Self {
        let kzg_settings = kzg_settings_from_json(TRUSTED_SETUP_JSON).unwrap();

        Self {
            // phase0
            max_committees_per_slot: phase0_preset.max_committees_per_slot,
            target_committee_size: phase0_preset.target_committee_size,
            max_validators_per_committee: phase0_preset.max_validators_per_committee,
            shuffle_round_count: phase0_preset.shuffle_round_count,
            hysteresis_quotient: phase0_preset.hysteresis_quotient,
            hysteresis_downward_multiplier: phase0_preset.hysteresis_downward_multiplier,
            hysteresis_upward_multiplier: phase0_preset.hysteresis_upward_multiplier,
            min_deposit_amount: phase0_preset.min_deposit_amount,
            max_effective_balance: phase0_preset.max_effective_balance,
            effective_balance_increment: phase0_preset.effective_balance_increment,
            min_attestation_inclusion_delay: phase0_preset.min_attestation_inclusion_delay,
            slots_per_epoch: phase0_preset.slots_per_epoch,
            min_seed_lookahead: phase0_preset.min_seed_lookahead,
            max_seed_lookahead: phase0_preset.max_seed_lookahead,
            min_epochs_to_inactivity_penalty: phase0_preset.min_epochs_to_inactivity_penalty,
            epochs_per_eth1_voting_period: phase0_preset.epochs_per_eth1_voting_period,
            slots_per_historical_root: phase0_preset.slots_per_historical_root,
            epochs_per_historical_vector: phase0_preset.epochs_per_historical_vector,
            epochs_per_slashings_vector: phase0_preset.epochs_per_slashings_vector,
            historical_roots_limit: phase0_preset.historical_roots_limit,
            validator_registry_limit: phase0_preset.validator_registry_limit,
            base_reward_factor: phase0_preset.base_reward_factor,
            whistleblower_reward_quotient: phase0_preset.whistleblower_reward_quotient,
            proposer_reward_quotient: phase0_preset.proposer_reward_quotient,
            inactivity_penalty_quotient: phase0_preset.inactivity_penalty_quotient,
            min_slashing_penalty_quotient: phase0_preset.min_slashing_penalty_quotient,
            proportional_slashing_multiplier: phase0_preset.proportional_slashing_multiplier,
            max_proposer_slashings: phase0_preset.max_proposer_slashings,
            max_attester_slashings: phase0_preset.max_attester_slashings,
            max_attestations: phase0_preset.max_attestations,
            max_deposits: phase0_preset.max_deposits,
            max_voluntary_exits: phase0_preset.max_voluntary_exits,
            // altair
            inactivity_penalty_quotient_altair: altair_preset.inactivity_penalty_quotient_altair,
            min_slashing_penalty_quotient_altair: altair_preset
                .min_slashing_penalty_quotient_altair,
            proportional_slashing_multiplier_altair: altair_preset
                .proportional_slashing_multiplier_altair,
            sync_committee_size: altair_preset.sync_committee_size,
            epochs_per_sync_committee_period: altair_preset.epochs_per_sync_committee_period,
            min_sync_committee_participants: altair_preset.min_sync_committee_participants,
            update_timeout: altair_preset.update_timeout,
            // bellatrix
            inactivity_penalty_quotient_bellatrix: bellatrix_preset
                .inactivity_penalty_quotient_bellatrix,
            min_slashing_penalty_quotient_bellatrix: bellatrix_preset
                .min_slashing_penalty_quotient_bellatrix,
            proportional_slashing_multiplier_bellatrix: bellatrix_preset
                .proportional_slashing_multiplier_bellatrix,
            max_bytes_per_transaction: bellatrix_preset.max_bytes_per_transaction,
            max_transactions_per_payload: bellatrix_preset.max_transactions_per_payload,
            bytes_per_logs_bloom: bellatrix_preset.bytes_per_logs_bloom,
            max_extra_data_bytes: bellatrix_preset.max_extra_data_bytes,
            // capella
            max_bls_to_execution_changes: capella_preset.max_bls_to_execution_changes,
            max_withdrawals_per_payload: capella_preset.max_withdrawals_per_payload,
            max_validators_per_withdrawals_sweep: capella_preset
                .max_validators_per_withdrawals_sweep,
            // deneb
            field_elements_per_blob: deneb_preset.field_elements_per_blob,
            max_blob_commitments_per_block: deneb_preset.max_blob_commitments_per_block,
            max_blobs_per_block: deneb_preset.max_blobs_per_block,
            // electra
            min_activation_balance: electra_preset.min_activation_balance,
            max_effective_balance_electra: electra_preset.max_effective_balance_electra,
            min_slashing_penalty_quotient_electra: electra_preset
                .min_slashing_penalty_quotient_electra,
            whistleblower_reward_quotient_electra: electra_preset
                .whistleblower_reward_quotient_electra,
            pending_balance_deposits_limit: electra_preset.pending_balance_deposits_limit,
            pending_partial_withdrawals_limit: electra_preset.pending_partial_withdrawals_limit,
            pending_consolidations_limit: electra_preset.pending_consolidations_limit,
            max_attester_slashings_electra: electra_preset.max_attester_slashings_electra,
            max_attestations_electra: electra_preset.max_attestations_electra,
            max_consolidations: electra_preset.max_consolidations,
            max_deposit_receipts_per_payload: electra_preset.max_deposit_receipts_per_payload,
            max_withdrawal_requests_per_payload: electra_preset.max_withdrawal_requests_per_payload,
            max_pending_partials_per_withdrawals_sweep: electra_preset
                .max_pending_partials_per_withdrawals_sweep,
            // config
            name: config.name.clone(),
            terminal_total_difficulty: config.terminal_total_difficulty,
            terminal_block_hash: config.terminal_block_hash.clone(),
            terminal_block_hash_activation_epoch: config.terminal_block_hash_activation_epoch,
            min_genesis_active_validator_count: config.min_genesis_active_validator_count,
            min_genesis_time: config.min_genesis_time,
            genesis_fork_version: config.genesis_fork_version,
            genesis_delay: config.genesis_delay,
            altair_fork_version: config.altair_fork_version,
            altair_fork_epoch: config.altair_fork_epoch,
            bellatrix_fork_version: config.bellatrix_fork_version,
            bellatrix_fork_epoch: config.bellatrix_fork_epoch,
            capella_fork_version: config.capella_fork_version,
            capella_fork_epoch: config.capella_fork_epoch,
            deneb_fork_version: config.deneb_fork_version,
            deneb_fork_epoch: config.deneb_fork_epoch,
            electra_fork_version: config.electra_fork_version,
            electra_fork_epoch: config.electra_fork_epoch,
            seconds_per_slot: config.seconds_per_slot,
            seconds_per_eth1_block: config.seconds_per_eth1_block,
            min_validator_withdrawability_delay: config.min_validator_withdrawability_delay,
            shard_committee_period: config.shard_committee_period,
            eth1_follow_distance: config.eth1_follow_distance,
            inactivity_score_bias: config.inactivity_score_bias,
            inactivity_score_recovery_rate: config.inactivity_score_recovery_rate,
            ejection_balance: config.ejection_balance,
            min_per_epoch_churn_limit: config.min_per_epoch_churn_limit,
            max_per_epoch_activation_churn_limit: config.max_per_epoch_activation_churn_limit,
            min_per_epoch_churn_limit_electra: config.min_per_epoch_churn_limit_electra,
            max_per_epoch_activation_exit_churn_limit: config
                .max_per_epoch_activation_exit_churn_limit,
            churn_limit_quotient: config.churn_limit_quotient,
            proposer_score_boost: config.proposer_score_boost,
            deposit_chain_id: config.deposit_chain_id,
            deposit_network_id: config.deposit_network_id,
            deposit_contract_address: config.deposit_contract_address.clone(),
            execution_engine: DEFAULT_EXECUTION_ENGINE_VALIDITY,
            kzg_settings: Arc::new(kzg_settings),
        }
    }

    pub fn for_mainnet() -> Self {
        let config = &configs::mainnet::config();
        let phase0_preset = &phase0::mainnet::PRESET;
        let altair_preset = &altair::mainnet::PRESET;
        let bellatrix_preset = &bellatrix::mainnet::PRESET;
        let capella_preset = &capella::mainnet::PRESET;
        let deneb_preset = &deneb::mainnet::PRESET;
        let electra_preset = &electra::mainnet::PRESET;
        Self::from(
            phase0_preset,
            altair_preset,
            bellatrix_preset,
            capella_preset,
            deneb_preset,
            electra_preset,
            config,
        )
    }

    pub fn for_minimal() -> Self {
        let config = &configs::minimal::config();
        let phase0_preset = &phase0::minimal::PRESET;
        let altair_preset = &altair::minimal::PRESET;
        let bellatrix_preset = &bellatrix::minimal::PRESET;
        let capella_preset = &capella::minimal::PRESET;
        let deneb_preset = &deneb::minimal::PRESET;
        let electra_preset = &electra::minimal::PRESET;
        Self::from(
            phase0_preset,
            altair_preset,
            bellatrix_preset,
            capella_preset,
            deneb_preset,
            electra_preset,
            config,
        )
    }

    pub fn for_goerli() -> Self {
        let config = &configs::goerli::config();
        let phase0_preset = &phase0::mainnet::PRESET;
        let altair_preset = &altair::mainnet::PRESET;
        let bellatrix_preset = &bellatrix::mainnet::PRESET;
        let capella_preset = &capella::mainnet::PRESET;
        let deneb_preset = &deneb::mainnet::PRESET;
        let electra_preset = &electra::mainnet::PRESET;
        Self::from(
            phase0_preset,
            altair_preset,
            bellatrix_preset,
            capella_preset,
            deneb_preset,
            electra_preset,
            config,
        )
    }

    pub fn for_sepolia() -> Self {
        let config = &configs::sepolia::config();
        let phase0_preset = &phase0::mainnet::PRESET;
        let altair_preset = &altair::mainnet::PRESET;
        let bellatrix_preset = &bellatrix::mainnet::PRESET;
        let capella_preset = &capella::mainnet::PRESET;
        let deneb_preset = &deneb::mainnet::PRESET;
        let electra_prest = &electra::mainnet::PRESET;
        Self::from(
            phase0_preset,
            altair_preset,
            bellatrix_preset,
            capella_preset,
            deneb_preset,
            electra_prest,
            config,
        )
    }

    pub fn for_holesky() -> Self {
        let config = &configs::holesky::config();
        let phase0_preset = &phase0::mainnet::PRESET;
        let altair_preset = &altair::mainnet::PRESET;
        let bellatrix_preset = &bellatrix::mainnet::PRESET;
        let capella_preset = &capella::mainnet::PRESET;
        let deneb_preset = &deneb::mainnet::PRESET;
        let electra_preset = &electra::mainnet::PRESET;
        Self::from(
            phase0_preset,
            altair_preset,
            bellatrix_preset,
            capella_preset,
            deneb_preset,
            electra_preset,
            config,
        )
    }

    pub fn fork_for(&self, slot: Slot) -> Fork {
        let epoch = slot / self.slots_per_epoch;
        if epoch >= self.electra_fork_epoch {
            Fork::Electra
        } else if epoch >= self.deneb_fork_epoch {
            Fork::Deneb
        } else if epoch >= self.capella_fork_epoch {
            Fork::Capella
        } else if epoch >= self.bellatrix_fork_epoch {
            Fork::Bellatrix
        } else if epoch >= self.altair_fork_epoch {
            Fork::Altair
        } else {
            Fork::Phase0
        }
    }

    pub fn fork_version_for(&self, fork: Fork) -> Version {
        match fork {
            Fork::Phase0 => self.genesis_fork_version,
            Fork::Altair => self.altair_fork_version,
            Fork::Bellatrix => self.bellatrix_fork_version,
            Fork::Capella => self.capella_fork_version,
            Fork::Deneb => self.deneb_fork_version,
            Fork::Electra => self.electra_fork_version,
        }
    }

    pub fn genesis_time(&self) -> Result<u64, Error> {
        match &self.name {
            Network::Mainnet => Ok(crate::ethereum_consensus::clock::MAINNET_GENESIS_TIME),
            Network::Sepolia => Ok(crate::ethereum_consensus::clock::SEPOLIA_GENESIS_TIME),
            Network::Goerli => Ok(crate::ethereum_consensus::clock::GOERLI_GENESIS_TIME),
            Network::Holesky => Ok(crate::ethereum_consensus::clock::HOLESKY_GENESIS_TIME),
            name => Err(Error::UnknownGenesisTime(name.to_string())),
        }
    }

    pub fn clock(&self) -> Option<Clock<SystemTimeProvider>> {
        match self.name {
            Network::Mainnet => Some(clock::for_mainnet()),
            Network::Sepolia => Some(clock::for_sepolia()),
            Network::Goerli => Some(clock::for_goerli()),
            Network::Holesky => Some(clock::for_holesky()),
            _ => None,
        }
    }

    pub fn clock_at(&self, genesis_time: u64) -> Clock<SystemTimeProvider> {
        clock::from_system_time(genesis_time, self.seconds_per_slot, self.slots_per_epoch)
    }

    pub fn network(&self) -> &Network {
        &self.name
    }

    pub fn execution_engine(&self) -> impl ExecutionEngine {
        self.execution_engine
    }
}
