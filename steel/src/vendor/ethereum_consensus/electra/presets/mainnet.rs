pub use crate::ethereum_consensus::electra::presets::Preset;
use crate::ethereum_consensus::electra::spec;

pub use spec::*;

pub const MIN_ACTIVATION_BALANCE: Gwei = 32 * 10u64.pow(9);
pub const MAX_EFFECTIVE_BALANCE_ELECTRA: Gwei = 2048 * 10u64.pow(9);
pub const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64 = 4096;
pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;
pub const PENDING_BALANCE_DEPOSITS_LIMIT: usize = 2usize.pow(27);
pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 2usize.pow(27);
pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 2usize.pow(18);
pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
pub const MAX_CONSOLIDATIONS: usize = 1;
pub const MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD: usize = 8192;
pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
pub const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: usize = 8;

pub const PRESET: Preset = Preset {
    min_activation_balance: MIN_ACTIVATION_BALANCE,
    max_effective_balance_electra: MAX_EFFECTIVE_BALANCE_ELECTRA,
    min_slashing_penalty_quotient_electra: MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
    whistleblower_reward_quotient_electra: WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
    pending_balance_deposits_limit: PENDING_BALANCE_DEPOSITS_LIMIT,
    pending_partial_withdrawals_limit: PENDING_PARTIAL_WITHDRAWALS_LIMIT,
    pending_consolidations_limit: PENDING_CONSOLIDATIONS_LIMIT,
    max_attester_slashings_electra: MAX_ATTESTER_SLASHINGS_ELECTRA,
    max_attestations_electra: MAX_ATTESTATIONS_ELECTRA,
    max_consolidations: MAX_CONSOLIDATIONS,
    max_deposit_receipts_per_payload: MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD,
    max_withdrawal_requests_per_payload: MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
    max_pending_partials_per_withdrawals_sweep: MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
};
