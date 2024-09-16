use crate::ethereum_consensus::primitives::Gwei;

pub mod mainnet;
pub mod minimal;

pub struct Preset {
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
}
