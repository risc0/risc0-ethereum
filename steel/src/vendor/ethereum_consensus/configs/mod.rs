pub mod goerli;
pub mod holesky;
pub mod mainnet;
pub mod minimal;
pub mod sepolia;

use crate::ethereum_consensus::{
    networks::Network,
    primitives::{Epoch, ExecutionAddress, Gwei, Hash32, Version, U256},
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Config {
    pub preset_base: String,
    #[serde(rename = "CONFIG_NAME")]
    pub name: Network,

    pub terminal_total_difficulty: U256,
    pub terminal_block_hash: Hash32,
    pub terminal_block_hash_activation_epoch: Epoch,

    pub min_genesis_active_validator_count: usize,
    pub min_genesis_time: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_hex")]
    pub genesis_fork_version: Version,
    pub genesis_delay: u64,

    #[serde(with = "crate::ethereum_consensus::serde::as_hex")]
    pub altair_fork_version: Version,
    pub altair_fork_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_hex")]
    pub bellatrix_fork_version: Version,
    pub bellatrix_fork_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_hex")]
    pub capella_fork_version: Version,
    pub capella_fork_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_hex")]
    pub deneb_fork_version: Version,
    pub deneb_fork_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_hex")]
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
    pub churn_limit_quotient: u64,
    pub min_per_epoch_churn_limit_electra: u64,
    pub max_per_epoch_activation_exit_churn_limit: u64,

    pub proposer_score_boost: u64,

    pub deposit_chain_id: usize,
    pub deposit_network_id: usize,
    pub deposit_contract_address: ExecutionAddress,
}
